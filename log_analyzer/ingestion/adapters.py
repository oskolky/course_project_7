from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable

from pydantic import ValidationError

from log_analyzer.config import DEFAULT_TIMEZONE
from log_analyzer.contracts import CanonicalEvent, IngestionIssue, IngestionResult
from log_analyzer.processing.masking import mask_secrets, protect_value
from log_analyzer.processing.normalization import (
    NormalizationError, as_float, as_int, normalize_route, parse_timestamp,
)

# Строка запроса допускает пустое значение ("-"), бинарные данные и экранированные
# кавычки; код состояния и объём ответа могут быть прочерками.
ACCESS_RE = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?:[^"\\]|\\.)*)?)|(?:[^"\\]|\\.)*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<body>\d+|-)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?'
    r'(?:\s+(?P<request_time>\d+(?:\.\d+)?))?'
    r'(?:\s+(?P<upstream_time>[\d.]+|-))?'
    r'(?:\s+(?P<request_id>[A-Za-z0-9_-]+))?\s*$'
)
NGINX_ERROR_RE = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<severity>[^\]]+)\]\s+(?P<message>.*)$'
)
APACHE_ERROR_RE = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+\[(?:(?P<module>[^:]+):)?(?P<severity>[^\]]+)\]\s+(?P<message>.*)$'
)
ADAPTERS = ("auto", "nginx", "apache", "error", "jsonl")

MSG_ACCESS = "строка не соответствует формату журнала доступа NGINX или Apache"
MSG_ERROR = "строка не соответствует формату журнала ошибок NGINX или Apache"
MSG_JSON = "повреждённая запись JSON"
MSG_JSON_SHAPE = "запись JSON не является объектом с полями события"
MSG_EVENT = "запись не соответствует схеме события"
MSG_ADAPTER = "указан неизвестный тип источника"
MSG_UNEXPECTED = "не удалось обработать строку"


def event_id_for(dataset_id: str, source: str, line_number: int, raw: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{dataset_id}:{source}:{line_number}:{raw}"))


def protect_event(event: CanonicalEvent) -> CanonicalEvent:
    """Скрывает секреты до сохранения события в базе данных. Идентификатор события
    вычисляется по исходной строке, поэтому маскирование на него не влияет."""
    event.raw = mask_secrets(event.raw)
    if event.message:
        event.message = mask_secrets(event.message)
    if event.original_uri:
        event.original_uri = mask_secrets(event.original_uri)
    event.attributes = protect_value(event.attributes) or {}
    return event


def canonical_from_mapping(
    mapping: dict[str, Any], *, dataset_id: str, source_name: str, line_number: int,
    raw: str, service: str = "unknown", file_offset: int | None = None,
) -> CanonicalEvent:
    source = mapping.get("source") if isinstance(mapping.get("source"), dict) else {}
    request = mapping.get("request") if isinstance(mapping.get("request"), dict) else {}
    observed = mapping.get("observed_at", mapping.get("timestamp", mapping.get("time")))
    uri = request.get("original_uri", request.get("uri", mapping.get("uri", mapping.get("path"))))
    status = as_int(request.get("status", mapping.get("status")))
    request_id = request.get("request_id", mapping.get("request_id"))
    trace_id = request.get("trace_id", mapping.get("trace_id"))
    message = mapping.get("message", mapping.get("body"))
    if isinstance(message, dict):
        message = json.dumps(message, ensure_ascii=False)
    warnings: list[str] = []
    if mapping.get("status") is not None and request.get("status") is not None:
        if as_int(mapping.get("status")) != as_int(request.get("status")):
            warnings.append("conflicting_status_fields")
    duration = request.get("duration_ms", mapping.get("duration_ms"))
    if duration is None:
        duration = as_float(mapping.get("request_time"), 1000)
    return protect_event(CanonicalEvent(
        event_id=event_id_for(dataset_id, source_name, line_number, raw),
        dataset_id=dataset_id,
        observed_at=parse_timestamp(observed),
        source_type=str(source.get("type", mapping.get("source_type", "application_json"))),
        service=str(source.get("service", mapping.get("service", service))),
        host=source.get("host", mapping.get("host")),
        client=mapping.get("client", request.get("client")),
        file_offset=file_offset,
        line_number=line_number,
        severity=str(mapping.get("severity", "info")).lower(),
        request_id=str(request_id) if request_id not in (None, "", "-") else None,
        trace_id=str(trace_id) if trace_id not in (None, "", "-") else None,
        method=request.get("method", mapping.get("method")),
        route=normalize_route(request.get("route", mapping.get("route")) or uri),
        original_uri=uri,
        status=status,
        duration_ms=as_float(duration),
        message=str(message) if message is not None else raw,
        raw=raw,
        attributes=mapping.get("attributes", {}) or {},
        warnings=warnings,
    ))


def parse_access_line(line: str, dataset_id: str, source_name: str, line_number: int,
                      service: str, source_type: str, file_offset: int) -> CanonicalEvent:
    match = ACCESS_RE.match(line)
    if not match:
        raise NormalizationError(MSG_ACCESS, "ожидается формат common или combined")
    data = match.groupdict()
    uri = data["uri"]
    status = as_int(data["status"])
    request = data["request"] or "-"
    message = f'{data["method"]} {uri} -> {status}' if data["method"] else f'"{request}" -> {status}'
    return protect_event(CanonicalEvent(
        event_id=event_id_for(dataset_id, source_name, line_number, line),
        dataset_id=dataset_id,
        observed_at=parse_timestamp(data["time"]),
        source_type=source_type,
        service=service,
        client=data["client"],
        file_offset=file_offset,
        line_number=line_number,
        severity="warn" if status is not None and status >= 400 else "info",
        request_id=data.get("request_id") if data.get("request_id") != "-" else None,
        method=data["method"], route=normalize_route(uri), original_uri=uri,
        status=status,
        duration_ms=as_float(data.get("request_time"), 1000),
        message=message,
        raw=line,
        attributes={"user_agent": data.get("agent"), "upstream_time_s": data.get("upstream_time")},
    ))


def parse_error_line(line: str, dataset_id: str, source_name: str, line_number: int,
                     service: str, file_offset: int) -> CanonicalEvent:
    match = NGINX_ERROR_RE.match(line) or APACHE_ERROR_RE.match(line)
    if not match:
        raise NormalizationError(MSG_ERROR, "ожидается запись вида «дата [уровень] сообщение»")
    data = match.groupdict()
    message = data["message"]
    client = _search(r',\s*client:\s*([^,]+)', message)
    request = _search(r',\s*request:\s*"([A-Z]+)\s+([^\s"]+)[^"]*"', message)
    request_id = _search(r'(?:request_id|request id)[=:]\s*["\']?([A-Za-z0-9_-]+)', message)
    trace_id = _search(r'(?:trace_id|trace id)[=:]\s*["\']?([A-Za-z0-9_-]+)', message)
    method, uri = (request[0], request[1]) if request else (None, None)
    host = _search(r',\s*server:\s*([^,]+)', message)
    return protect_event(CanonicalEvent(
        event_id=event_id_for(dataset_id, source_name, line_number, line),
        dataset_id=dataset_id,
        observed_at=parse_timestamp(data["time"], DEFAULT_TIMEZONE),
        source_type="error_log", service=service, host=host, client=client,
        file_offset=file_offset, line_number=line_number,
        severity=data["severity"].lower(), request_id=request_id, trace_id=trace_id,
        method=method, route=normalize_route(uri), original_uri=uri,
        status=504 if "upstream timed out" in message.lower() else None,
        message=message, raw=line,
    ))


def _search(pattern: str, text: str):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.groups() if match and len(match.groups()) > 1 else (match.group(1) if match else None)


def describe_issue(exc: Exception, adapter: str) -> tuple[str, str | None]:
    """Возвращает понятное описание причины отклонения записи и техническую деталь."""
    if isinstance(exc, NormalizationError):
        return exc.message, exc.detail
    detail = str(exc) or type(exc).__name__
    if isinstance(exc, json.JSONDecodeError):
        return MSG_JSON, detail
    if isinstance(exc, ValidationError):
        return MSG_EVENT, detail
    if adapter in {"nginx", "apache"}:
        return MSG_ACCESS, detail
    if adapter == "error":
        return MSG_ERROR, detail
    return MSG_UNEXPECTED, detail


def ingest_text_sources(
    sources: Iterable[tuple[str, str, str, str]], dataset_id: str,
) -> IngestionResult:
    result = IngestionResult()
    for source_name, text, adapter, service in sources:
        result.source_names.append(source_name)
        offset = 0
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            current_offset = offset
            offset += len((line + "\n").encode("utf-8"))
            if not stripped:
                continue
            result.read_count += 1
            selected = adapter
            try:
                if selected == "auto":
                    selected = "jsonl" if stripped.startswith("{") else (
                        "error" if NGINX_ERROR_RE.match(stripped) or APACHE_ERROR_RE.match(stripped) else "nginx")
                if selected == "jsonl":
                    mapping = json.loads(stripped)
                    if not isinstance(mapping, dict):
                        raise NormalizationError(MSG_JSON_SHAPE, "ожидается объект в фигурных скобках")
                    event = canonical_from_mapping(
                        mapping, dataset_id=dataset_id, source_name=source_name,
                        line_number=line_number, raw=line, service=service, file_offset=current_offset,
                    )
                elif selected in {"nginx", "apache"}:
                    event = parse_access_line(line, dataset_id, source_name, line_number, service, f"{selected}_access", current_offset)
                elif selected == "error":
                    event = parse_error_line(line, dataset_id, source_name, line_number, service, current_offset)
                else:
                    raise NormalizationError(MSG_ADAPTER, f"«{selected}»; допустимы {', '.join(ADAPTERS)}")
                result.events.append(event)
            except Exception as exc:
                result.rejected_count += 1
                message, detail = describe_issue(exc, selected)
                result.issues.append(IngestionIssue(
                    source=source_name, line_number=line_number, error=message, detail=detail,
                    raw_excerpt=mask_secrets(line[:240]),
                ))
    return result


def ingest_api_records(records: list[dict[str, Any]], dataset_id: str, source_name: str = "api") -> IngestionResult:
    result = IngestionResult(read_count=len(records), source_names=[source_name])
    for index, record in enumerate(records, start=1):
        raw = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        try:
            result.events.append(canonical_from_mapping(
                record, dataset_id=dataset_id, source_name=source_name,
                line_number=index, raw=raw,
            ))
        except Exception as exc:
            result.rejected_count += 1
            message, detail = describe_issue(exc, "jsonl")
            result.issues.append(IngestionIssue(source=source_name, line_number=index, error=message, detail=detail, raw_excerpt=mask_secrets(raw[:240])))
    return result
