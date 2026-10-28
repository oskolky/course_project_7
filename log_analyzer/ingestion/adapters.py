from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable

from log_analyzer.config import DEFAULT_TIMEZONE
from log_analyzer.contracts import CanonicalEvent, IngestionIssue, IngestionResult
from log_analyzer.processing.normalization import as_float, as_int, normalize_route, parse_timestamp

ACCESS_RE = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+[^"]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<body>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    r'(?:\s+(?P<request_time>[\d.]+))?'
    r'(?:\s+(?P<upstream_time>[\d.-]+))?'
    r'(?:\s+(?P<request_id>[A-Za-z0-9_-]+))?\s*$'
)
NGINX_ERROR_RE = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<severity>[^\]]+)\]\s+(?P<message>.*)$'
)
APACHE_ERROR_RE = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+\[(?:(?P<module>[^:]+):)?(?P<severity>[^\]]+)\]\s+(?P<message>.*)$'
)


def event_id_for(dataset_id: str, source: str, line_number: int, raw: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{dataset_id}:{source}:{line_number}:{raw}"))


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
    return CanonicalEvent(
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
        attributes=mapping.get("attributes", {}),
        warnings=warnings,
    )


def parse_access_line(line: str, dataset_id: str, source_name: str, line_number: int,
                      service: str, source_type: str, file_offset: int) -> CanonicalEvent:
    match = ACCESS_RE.match(line)
    if not match:
        raise ValueError("Access log format not recognized")
    data = match.groupdict()
    uri = data["uri"]
    return CanonicalEvent(
        event_id=event_id_for(dataset_id, source_name, line_number, line),
        dataset_id=dataset_id,
        observed_at=parse_timestamp(data["time"]),
        source_type=source_type,
        service=service,
        client=data["client"],
        file_offset=file_offset,
        line_number=line_number,
        severity="warn" if int(data["status"]) >= 400 else "info",
        request_id=data.get("request_id") if data.get("request_id") != "-" else None,
        method=data["method"], route=normalize_route(uri), original_uri=uri,
        status=int(data["status"]),
        duration_ms=as_float(data.get("request_time"), 1000),
        message=f'{data["method"]} {uri} -> {data["status"]}',
        raw=line,
        attributes={"user_agent": data.get("agent"), "upstream_time_s": data.get("upstream_time")},
    )


def parse_error_line(line: str, dataset_id: str, source_name: str, line_number: int,
                     service: str, file_offset: int) -> CanonicalEvent:
    match = NGINX_ERROR_RE.match(line) or APACHE_ERROR_RE.match(line)
    if not match:
        raise ValueError("Error log format not recognized")
    data = match.groupdict()
    message = data["message"]
    client = _search(r',\s*client:\s*([^,]+)', message)
    request = _search(r',\s*request:\s*"([A-Z]+)\s+([^\s"]+)[^"]*"', message)
    request_id = _search(r'(?:request_id|request id)[=:]\s*["\']?([A-Za-z0-9_-]+)', message)
    trace_id = _search(r'(?:trace_id|trace id)[=:]\s*["\']?([A-Za-z0-9_-]+)', message)
    method, uri = (request[0], request[1]) if request else (None, None)
    host = _search(r',\s*server:\s*([^,]+)', message)
    return CanonicalEvent(
        event_id=event_id_for(dataset_id, source_name, line_number, line),
        dataset_id=dataset_id,
        observed_at=parse_timestamp(data["time"], DEFAULT_TIMEZONE),
        source_type="error_log", service=service, host=host, client=client,
        file_offset=file_offset, line_number=line_number,
        severity=data["severity"].lower(), request_id=request_id, trace_id=trace_id,
        method=method, route=normalize_route(uri), original_uri=uri,
        status=504 if "upstream timed out" in message.lower() else None,
        message=message, raw=line,
    )


def _search(pattern: str, text: str):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.groups() if match and len(match.groups()) > 1 else (match.group(1) if match else None)


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
            try:
                selected = adapter
                if selected == "auto":
                    selected = "jsonl" if stripped.startswith("{") else ("error" if NGINX_ERROR_RE.match(stripped) or APACHE_ERROR_RE.match(stripped) else "nginx")
                if selected == "jsonl":
                    mapping = json.loads(stripped)
                    if not isinstance(mapping, dict):
                        raise ValueError("JSON line must contain an object")
                    event = canonical_from_mapping(
                        mapping, dataset_id=dataset_id, source_name=source_name,
                        line_number=line_number, raw=line, service=service, file_offset=current_offset,
                    )
                elif selected in {"nginx", "apache"}:
                    event = parse_access_line(line, dataset_id, source_name, line_number, service, f"{selected}_access", current_offset)
                elif selected == "error":
                    event = parse_error_line(line, dataset_id, source_name, line_number, service, current_offset)
                else:
                    raise ValueError(f"Unknown adapter: {selected}")
                result.events.append(event)
            except Exception as exc:
                result.rejected_count += 1
                result.issues.append(IngestionIssue(
                    source=source_name, line_number=line_number,
                    error=str(exc), raw_excerpt=line[:240],
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
            result.issues.append(IngestionIssue(source=source_name, line_number=index, error=str(exc), raw_excerpt=raw[:240]))
    return result
