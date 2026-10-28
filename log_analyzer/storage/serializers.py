from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from log_analyzer.storage.models import (
    AnalysisRunRecord, DatasetRecord, EventRecord, IncidentRecord,
    ModelVersionRecord, RuleRecord,
)

SECRET_RE = re.compile(
    r"(?i)\b(authorization|token|access_token|refresh_token|password|passwd|secret|api_key|cookie)"
    r"(\s*[:=]\s*|\s+)(?:bearer\s+)?([^\s,;&\"']+)"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b((?:\d{1,3}\.){3})\d{1,3}\b")


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def mask_sensitive(text: str) -> str:
    text = SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<masked>", text)
    text = EMAIL_RE.sub("<masked-email>", text)
    return IP_RE.sub(r"\1<masked>", text)


def dataset_dict(record: DatasetRecord) -> dict[str, Any]:
    return {
        "id": record.id, "name": record.name, "created_at": iso(record.created_at),
        "status": record.status, "sources": record.sources or [], "stats": record.stats or {},
    }


def run_dict(record: AnalysisRunRecord) -> dict[str, Any]:
    return {
        "id": record.id, "dataset_id": record.dataset_id, "model_id": record.model_id,
        "status": record.status, "created_at": iso(record.created_at),
        "started_at": iso(record.started_at), "finished_at": iso(record.finished_at),
        "stats": {key: value for key, value in (record.stats or {}).items() if key != "fail_model"},
        "warnings": record.warnings or [], "error": record.error,
    }


def event_dict(record: EventRecord) -> dict[str, Any]:
    return {
        "event_id": record.id, "dataset_id": record.dataset_id,
        "observed_at": iso(record.observed_at),
        "source": {"type": record.source_type, "service": record.service, "host": record.host,
                   "file_offset": record.file_offset, "line_number": record.line_number},
        "severity": record.severity,
        "request": {"request_id": record.request_id, "trace_id": record.trace_id,
                    "method": record.method, "route": record.route,
                    "original_uri": record.original_uri, "status": record.status,
                    "duration_ms": record.duration_ms, "client": record.client},
        "template_id": record.template_id, "group_id": record.group_id,
        "message": mask_sensitive(record.message) if record.message else None,
        "raw": mask_sensitive(record.raw), "attributes": record.attributes or {},
        "warnings": record.warnings or [],
    }


def rule_dict(record: RuleRecord) -> dict[str, Any]:
    return {
        "key": record.key, "id": record.id, "version": record.version, "scope": record.scope,
        "when": record.condition, "then": {"hypothesis": record.hypothesis,
        "severity": record.severity, "recommendation": record.recommendation,
        "evidence": record.evidence or []}, "created_at": iso(record.created_at),
    }


def model_dict(record: ModelVersionRecord) -> dict[str, Any]:
    return {
        "id": record.id, "algorithm": record.algorithm, "feature_schema": record.feature_schema,
        "parameters": record.parameters, "trained_at": iso(record.trained_at),
        "dataset_id": record.dataset_id, "training_summary": record.training_summary or {},
    }


def incident_dict(record: IncidentRecord, include_evidence: bool = False) -> dict[str, Any]:
    payload = {
        "incident_id": record.id, "run_id": record.run_id, "dataset_id": record.dataset_id,
        "window_start": iso(record.window_start), "window_end": iso(record.window_end),
        "service": record.service, "route": record.route, "kind": record.kind,
        "severity": record.severity, "hypothesis": record.hypothesis,
        "confidence": record.confidence, "anomaly_score": record.anomaly_score,
        "anomaly_threshold": record.anomaly_threshold, "review_required": record.review_required,
        "reviewed_at": iso(record.reviewed_at), "rule_ids": record.rule_ids or [],
        "model_id": record.model_id, "recommendation": record.recommendation,
        "features": record.features or {}, "warnings": record.warnings or [],
        "created_at": iso(record.created_at),
        "evidence_event_ids": [item.event_id for item in record.evidence_items],
    }
    if include_evidence:
        payload["evidence"] = [
            {"evidence_id": item.id, "event_id": item.event_id, "role": item.role,
             "excerpt": mask_sensitive(item.excerpt), "event": event_dict(item.event)}
            for item in record.evidence_items
        ]
    return payload
