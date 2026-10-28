from __future__ import annotations

import time
from datetime import timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from log_analyzer.arbitration.engine import arbitrate
from log_analyzer.contracts import (
    AnalysisRequest, CanonicalEvent, IngestionResult, WindowFeatures, utc_now,
)
from log_analyzer.ingestion.adapters import ingest_api_records, ingest_text_sources
from log_analyzer.knowledge.rules import RuleEngine, latest_rules, sync_default_rules
from log_analyzer.models.isolation import ModelWindowResult, evaluate_isolation_forest, train_isolation_forest
from log_analyzer.processing.correlation import correlate_events
from log_analyzer.processing.templates import apply_templates
from log_analyzer.processing.windows import build_windows
from log_analyzer.storage.models import (
    AnalysisRunRecord, DatasetRecord, EventRecord, ModelVersionRecord,
    RequestGroupRecord, TemplateRecord,
)


def create_dataset_from_text(
    db: Session, dataset_id: str, name: str,
    sources: Iterable[tuple[str, str, str, str]],
) -> DatasetRecord:
    started = time.perf_counter()
    ingestion = ingest_text_sources(sources, dataset_id)
    return _store_dataset(db, dataset_id, name, ingestion, started)


def create_dataset_from_records(
    db: Session, dataset_id: str, name: str, records: list[dict],
) -> DatasetRecord:
    started = time.perf_counter()
    ingestion = ingest_api_records(records, dataset_id)
    return _store_dataset(db, dataset_id, name, ingestion, started)


def _store_dataset(
    db: Session, dataset_id: str, name: str, ingestion: IngestionResult, started: float,
) -> DatasetRecord:
    normalize_started = time.perf_counter()
    events = sorted(ingestion.events, key=lambda event: event.observed_at)
    templates = apply_templates(events)
    groups = correlate_events(events)
    windows = build_windows(events, groups, templates)
    processing_ms = (time.perf_counter() - normalize_started) * 1000
    dataset = DatasetRecord(
        id=dataset_id, name=name, status="ingested",
        sources=[{"name": source} for source in ingestion.source_names],
        stats={
            "read_count": ingestion.read_count,
            "normalized_count": len(events),
            "rejected_count": ingestion.rejected_count,
            "issues": [issue.model_dump(mode="json") for issue in ingestion.issues],
            "template_count": len(templates), "group_count": len(groups),
            "window_count": len(windows),
            "processing_ms": round(processing_ms, 3),
            "total_ingestion_ms": round((time.perf_counter() - started) * 1000, 3),
        },
    )
    db.add(dataset)
    db.add_all(templates)
    db.add_all(groups)
    db.add_all([event_record(event) for event in events])
    db.commit()
    return dataset


def event_record(event: CanonicalEvent) -> EventRecord:
    return EventRecord(
        id=event.event_id, dataset_id=event.dataset_id, observed_at=event.observed_at,
        source_type=event.source_type, service=event.service, host=event.host,
        client=event.client, file_offset=event.file_offset, line_number=event.line_number,
        severity=event.severity, request_id=event.request_id, trace_id=event.trace_id,
        method=event.method, route=event.route, original_uri=event.original_uri,
        status=event.status, duration_ms=event.duration_ms, template_id=event.template_id,
        group_id=event.group_id, message=event.message, raw=event.raw,
        attributes=event.attributes, warnings=event.warnings,
    )


def canonical_event(record: EventRecord) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=record.id, dataset_id=record.dataset_id,
        observed_at=_aware(record.observed_at), source_type=record.source_type,
        service=record.service, host=record.host, client=record.client,
        file_offset=record.file_offset, line_number=record.line_number,
        severity=record.severity, request_id=record.request_id, trace_id=record.trace_id,
        method=record.method, route=record.route, original_uri=record.original_uri,
        status=record.status, duration_ms=record.duration_ms,
        template_id=record.template_id, group_id=record.group_id,
        message=record.message, raw=record.raw,
        attributes=record.attributes or {}, warnings=record.warnings or [],
    )


def load_context(db: Session, dataset_id: str):
    event_records = list(db.scalars(select(EventRecord).where(EventRecord.dataset_id == dataset_id).order_by(EventRecord.observed_at)).all())
    events = [canonical_event(record) for record in event_records]
    groups = list(db.scalars(select(RequestGroupRecord).where(RequestGroupRecord.dataset_id == dataset_id)).all())
    for group in groups:
        group.started_at = _aware(group.started_at)
        group.ended_at = _aware(group.ended_at)
    templates = list(db.scalars(select(TemplateRecord).where(TemplateRecord.dataset_id == dataset_id)).all())
    for template in templates:
        template.first_seen = _aware(template.first_seen)
    windows = build_windows(events, groups, templates)
    return events, groups, templates, windows


def execute_analysis(db: Session, run_id: str) -> None:
    run = db.get(AnalysisRunRecord, run_id)
    if run is None:
        return
    run.status = "running"
    run.started_at = utc_now()
    db.commit()
    started = time.perf_counter()
    try:
        sync_default_rules(db)
        events, groups, _, windows = load_context(db, run.dataset_id)
        rules = latest_rules(db)
        engine = RuleEngine(rules)
        rule_matches = engine.evaluate_groups(groups, events) + engine.evaluate_windows(windows, events)
        model_results: list[ModelWindowResult] = []
        model_warning: str | None = None
        model_status = "not_requested"
        if run.model_id:
            try:
                model = db.get(ModelVersionRecord, run.model_id)
                if model is None:
                    raise ValueError(f"Unknown model: {run.model_id}")
                if run.stats.get("fail_model"):
                    raise RuntimeError("Simulated model unavailability")
                model_results = evaluate_isolation_forest(model, windows)
                model_status = "completed"
            except Exception as exc:
                model_warning = f"model_unavailable: {exc}"
                model_status = "unavailable"
        incidents = arbitrate(
            run_id=run.id, dataset_id=run.dataset_id, windows=windows,
            events=events, rule_matches=rule_matches, model_results=model_results,
            model_id=run.model_id if model_results else None, model_warning=model_warning,
        )
        db.add_all(incidents)
        run.status = "completed"
        run.finished_at = utc_now()
        run.warnings = [model_warning] if model_warning else []
        run.stats = {
            "events": len(events), "windows": len(windows),
            "ready_windows": sum(window.status == "ready" for window in windows),
            "insufficient_windows": sum(window.status == "insufficient_data" for window in windows),
            "rule_matches": len(rule_matches), "incidents": len(incidents),
            "incidents_with_evidence": sum(bool(incident.evidence_items) for incident in incidents),
            "evidence_coverage": round(100 * sum(bool(incident.evidence_items) for incident in incidents) / len(incidents), 2) if incidents else 100.0,
            "model_status": model_status,
            "analysis_ms": round((time.perf_counter() - started) * 1000, 3),
        }
        db.commit()
    except Exception as exc:
        db.rollback()
        failed = db.get(AnalysisRunRecord, run_id)
        failed.status = "failed"
        failed.finished_at = utc_now()
        failed.error = str(exc)
        db.commit()


def train_model(db: Session, dataset_id: str, contamination: float, threshold_quantile: float) -> ModelVersionRecord:
    *_, windows = load_context(db, dataset_id)
    return train_isolation_forest(db, dataset_id, windows, contamination, threshold_quantile)


def new_run(db: Session, request: AnalysisRequest) -> AnalysisRunRecord:
    import uuid
    run = AnalysisRunRecord(
        id=str(uuid.uuid4()), dataset_id=request.dataset_id, model_id=request.model_id,
        status="queued", stats={"fail_model": request.fail_model},
    )
    db.add(run)
    db.commit()
    return run


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
