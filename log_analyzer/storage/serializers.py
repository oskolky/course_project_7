from __future__ import annotations

from datetime import datetime
from typing import Any

from log_analyzer.processing.masking import mask_for_display, mask_ip, mask_value
from log_analyzer.storage.models import (
    AnalysisRunRecord, DatasetRecord, EventRecord, IncidentRecord,
    ModelVersionRecord, RuleRecord, TemplateRecord,
)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def mask_sensitive(text: str) -> str:
    """Маскирование при выводе: секреты, адреса электронной почты и последний
    октет IPv4-адресов."""
    return mask_for_display(text)


def _issue_dict(issue: dict[str, Any]) -> dict[str, Any]:
    return {**issue, "raw_excerpt": mask_for_display(issue.get("raw_excerpt"))}


def dataset_dict(record: DatasetRecord) -> dict[str, Any]:
    stats = dict(record.stats or {})
    if stats.get("issues"):
        stats["issues"] = [_issue_dict(issue) for issue in stats["issues"]]
    return {
        "id": record.id, "name": record.name, "created_at": iso(record.created_at),
        "status": record.status, "sources": record.sources or [], "stats": stats,
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
        "source": {"type": record.source_type, "service": record.service,
                   "host": mask_for_display(record.host),
                   "file_offset": record.file_offset, "line_number": record.line_number},
        "severity": record.severity,
        "request": {"request_id": record.request_id, "trace_id": record.trace_id,
                    "method": record.method, "route": record.route,
                    "original_uri": mask_for_display(record.original_uri),
                    "status": record.status,
                    "duration_ms": record.duration_ms, "client": mask_ip(record.client)},
        "template_id": record.template_id, "group_id": record.group_id,
        "message": mask_for_display(record.message) if record.message else None,
        "raw": mask_for_display(record.raw),
        "attributes": mask_value(record.attributes or {}),
        "warnings": mask_value(record.warnings or []),
    }


def template_dict(record: TemplateRecord) -> dict[str, Any]:
    return {
        "template_id": record.id, "dataset_id": record.dataset_id,
        "pattern": mask_for_display(record.pattern), "parser_version": record.parser_version,
        "first_seen": iso(record.first_seen), "occurrences": record.occurrences,
    }


def rule_dict(record: RuleRecord) -> dict[str, Any]:
    presentation = record.presentation or {}
    return {
        "key": record.key, "id": record.id, "version": record.version, "scope": record.scope,
        "when": record.condition,
        "then": {"hypothesis": record.hypothesis, "severity": record.severity,
                 "recommendation": record.recommendation,
                 "evidence": record.evidence or [],
                 "title": presentation.get("title"),
                 "recommendation_text": presentation.get("recommendation_text")},
        "created_at": iso(record.created_at),
    }


def model_dict(record: ModelVersionRecord) -> dict[str, Any]:
    return {
        "id": record.id, "algorithm": record.algorithm, "feature_schema": record.feature_schema,
        "parameters": record.parameters, "trained_at": iso(record.trained_at),
        "dataset_id": record.dataset_id, "training_summary": record.training_summary or {},
    }


def incident_dict(record: IncidentRecord, include_evidence: bool = False) -> dict[str, Any]:
    features = record.features or {}
    outcomes = features.get("rule_outcomes", [])
    if not features.get("hypotheses"):
        features = {
            **features,
            "hypotheses": _fallback_hypotheses(record, outcomes),
        }
    return {
        "incident_id": record.id, "run_id": record.run_id, "dataset_id": record.dataset_id,
        "window_start": iso(record.window_start), "window_end": iso(record.window_end),
        "service": record.service, "route": record.route, "kind": record.kind,
        "severity": record.severity, "hypothesis": record.hypothesis,
        "confidence": record.confidence, "anomaly_score": record.anomaly_score,
        "anomaly_threshold": record.anomaly_threshold, "review_required": record.review_required,
        "reviewed_at": iso(record.reviewed_at), "rule_ids": record.rule_ids or [],
        "model_id": record.model_id, "recommendation": record.recommendation,
        "hypotheses": features.get("hypotheses", []),
        "recommendation_text": features.get("recommendation_text"),
        "affected_requests": features.get("affected_requests"),
        "rule_matches": features.get("rule_matches", len(outcomes)),
        "deviations": features.get("deviations", []),
        "features": mask_value(features),
        "warnings": record.warnings or [],
        "created_at": iso(record.created_at),
        "evidence_event_ids": [item.event_id for item in record.evidence_items],
    }


def _fallback_hypotheses(record: IncidentRecord, outcomes: list[dict]) -> list[dict]:
    """Перечень гипотез для инцидентов, сохранённых до появления поля hypotheses."""
    if record.kind in ("known", "known_with_anomaly"):
        return [{"hypothesis": record.hypothesis, "title": None, "severity": record.severity,
                 "rules": list(record.rule_ids or [])}]
    return []


def incident_detail_dict(record: IncidentRecord) -> dict[str, Any]:
    payload = incident_dict(record, include_evidence=True)
    payload["evidence"] = [
        {"evidence_id": item.id, "event_id": item.event_id, "role": item.role,
         "excerpt": mask_for_display(item.excerpt), "event": event_dict(item.event)}
        for item in record.evidence_items
    ]
    return payload
