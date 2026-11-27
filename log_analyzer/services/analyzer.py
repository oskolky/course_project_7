from __future__ import annotations

import hashlib
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from log_analyzer.arbitration.engine import arbitrate
from log_analyzer.config import MIN_WINDOW_REQUESTS, RULES_IN_INSUFFICIENT_WINDOWS
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
    AnalysisRunRecord, DatasetRecord, EventRecord, EvidenceRecord, IncidentRecord,
    ModelVersionRecord, RequestGroupRecord, TemplateRecord, WindowDecisionRecord,
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
    processing_started = time.perf_counter()
    events = sorted(ingestion.events, key=lambda event: event.observed_at)
    templates = apply_templates(events)
    groups = correlate_events(events)
    windows = build_windows(events, groups, templates)
    processing_ms = (time.perf_counter() - processing_started) * 1000
    quality = Counter(group.link_quality for group in groups)
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
            "groups_by_quality": {
                "exact": quality.get("exact", 0),
                "presumed": quality.get("presumed", 0),
                "uncertain": quality.get("uncertain", 0),
            },
            "events_with_request_ids": sum(1 for event in events if event.request_id or event.trace_id),
            "processing_ms": round(processing_ms, 3),
        },
    )
    storage_started = time.perf_counter()
    db.add(dataset)
    db.flush()
    db.add_all(templates)
    db.add_all(groups)
    db.add_all([event_record(event) for event in events])
    db.commit()
    dataset.stats = {
        **dataset.stats,
        "storage_ms": round((time.perf_counter() - storage_started) * 1000, 3),
        "total_ms": round((time.perf_counter() - started) * 1000, 3),
    }
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


def run_identity(db: Session, request: AnalysisRequest) -> str:
    """Идентификатор запуска, однозначно определяемый набором данных, моделью,
    составом действующих правил базы знаний и режимом отказа модели. Повторный
    анализ того же набора в той же конфигурации получает тот же идентификатор,
    а значит и те же идентификаторы инцидентов."""
    fingerprint = hashlib.sha1(
        "\n".join(rule.key for rule in latest_rules(db)).encode("utf-8")
    ).hexdigest()[:12]
    key = f"run:{request.dataset_id}:{request.model_id or ''}:{fingerprint}:{int(request.fail_model)}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, key))


def clear_run_results(db: Session, run_id: str) -> None:
    """Удаляет результаты запуска (инциденты, доказательства, протокол), не
    затрагивая сам запуск."""
    incident_ids = select(IncidentRecord.id).where(IncidentRecord.run_id == run_id)
    db.execute(delete(EvidenceRecord).where(EvidenceRecord.incident_id.in_(incident_ids)))
    db.execute(delete(IncidentRecord).where(IncidentRecord.run_id == run_id))
    db.execute(delete(WindowDecisionRecord).where(WindowDecisionRecord.run_id == run_id))


def new_run(db: Session, request: AnalysisRequest) -> AnalysisRunRecord:
    run_id = run_identity(db, request)
    run = db.get(AnalysisRunRecord, run_id)
    if run is not None and run.status in ("queued", "running"):
        return run
    if run is None:
        run = AnalysisRunRecord(
            id=run_id, dataset_id=request.dataset_id, model_id=request.model_id,
            status="queued", stats={"fail_model": request.fail_model},
        )
        db.add(run)
    else:
        run.status = "queued"
        run.model_id = request.model_id
        run.started_at = None
        run.finished_at = None
        run.error = None
        run.warnings = []
        run.stats = {"fail_model": request.fail_model}
    db.commit()
    return run


def _step(steps: list[dict], component: str, title: str, started: float, **summary) -> None:
    steps.append({
        "component": component,
        "title": title,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "summary": summary,
    })


def decision_record(run_id: str, dataset_id: str, decision: dict) -> WindowDecisionRecord:
    return WindowDecisionRecord(
        id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:{decision['window_start']}:decision")),
        run_id=run_id, dataset_id=dataset_id,
        window_start=datetime.fromisoformat(decision["window_start"]),
        window_end=datetime.fromisoformat(decision["window_end"]),
        status=decision["status"], kind=decision["decision"]["kind"],
        details=decision,
    )


def build_notices(dataset: DatasetRecord, decisions: list[dict], model_status: str) -> list[dict]:
    """Сообщения о границах применимости полученного результата: что не удалось
    обработать, какие виды анализа не выполнялись и почему."""
    notices: list[dict] = []
    stats = dataset.stats or {}
    rejected = stats.get("rejected_count", 0)
    if rejected:
        notices.append({
            "code": "rejected_lines", "level": "warning",
            "text": f"Отклонено записей: {rejected}. Они не распознаны и в анализе не учитывались.",
        })
    if not decisions:
        notices.append({
            "code": "nothing_to_analyse", "level": "warning",
            "text": "В наборе нет событий с распознанной отметкой времени: анализировать нечего.",
        })
    sparse = [decision for decision in decisions if decision["status"] != "ready"]
    if sparse:
        text = (
            f"Окон с недостатком данных: {len(sparse)} из {len(decisions)}. "
            f"Число запросов в них меньше {MIN_WINDOW_REQUESTS}, поэтому модель их не оценивала."
        )
        flagged = [decision for decision in sparse if decision["rule_matches"]]
        if flagged:
            text += (
                f" Правила сработали в {len(flagged)} из них: инциденты созданы без статистического подтверждения."
                if RULES_IN_INSUFFICIENT_WINDOWS
                else f" Правила сработали в {len(flagged)} из них; инциденты по ним не созданы."
            )
        notices.append({"code": "insufficient_data", "level": "warning", "text": text})
    if model_status == "not_requested":
        notices.append({
            "code": "model_not_requested", "level": "info",
            "text": "Модель не применялась: анализ выполнен только по правилам базы знаний. "
                    "Отклонения, для которых правила не составлены, не выявляются.",
        })
    elif model_status == "unavailable":
        notices.append({
            "code": "model_unavailable", "level": "warning",
            "text": "Модель недоступна: анализ выполнен только по правилам базы знаний.",
        })
    return notices


def execute_analysis(db: Session, run_id: str) -> None:
    run = db.get(AnalysisRunRecord, run_id)
    if run is None:
        return
    claimed = db.execute(
        update(AnalysisRunRecord)
        .where(AnalysisRunRecord.id == run_id, AnalysisRunRecord.status != "running")
        .values(status="running", started_at=utc_now(), finished_at=None, error=None)
    )
    db.commit()
    if not claimed.rowcount:
        return
    db.expire(run)
    started = time.perf_counter()
    steps: list[dict] = []
    try:
        sync_default_rules(db)
        dataset = db.get(DatasetRecord, run.dataset_id)
        if dataset is None:
            raise ValueError(f"Dataset {run.dataset_id} is not found")
        stage = time.perf_counter()
        events, groups, templates, windows = load_context(db, run.dataset_id)
        _step(steps, "events", "Загрузка нормализованных событий, шаблонов и групп", stage,
              events=len(events), templates=len(templates), groups=len(groups), windows=len(windows))
        stage = time.perf_counter()
        rules = latest_rules(db)
        engine = RuleEngine(rules, templates)
        rule_matches = engine.evaluate(groups, windows, events)
        by_rule = Counter(match.rule_key for match in rule_matches)
        _step(steps, "rules", "Проверка правил базы знаний", stage,
              rules=len(rules), matches=len(rule_matches), by_rule=dict(sorted(by_rule.items())))
        stage = time.perf_counter()
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
        _step(steps, "model", "Оценка аномальности моделью Isolation Forest", stage,
              status=model_status, model_id=run.model_id,
              **dict(Counter(result.status for result in model_results)))
        stage = time.perf_counter()
        decisions: list[dict] = []
        incidents = arbitrate(
            run_id=run.id, dataset_id=run.dataset_id, windows=windows,
            events=events, rule_matches=rule_matches, model_results=model_results,
            model_id=run.model_id if model_results else None, model_warning=model_warning,
            decisions=decisions,
        )
        _step(steps, "arbitration", "Согласование результатов контуров", stage,
              incidents=len(incidents), by_kind=dict(Counter(incident.kind for incident in incidents)))
        stage = time.perf_counter()

        reviewed = dict(db.execute(
            select(IncidentRecord.id, IncidentRecord.reviewed_at).where(IncidentRecord.run_id == run.id)
        ).all())
        clear_run_results(db, run.id)
        for incident in incidents:
            if reviewed.get(incident.id):
                incident.reviewed_at = reviewed[incident.id]
                incident.review_required = False
        db.add_all(incidents)
        db.add_all([decision_record(run.id, run.dataset_id, decision) for decision in decisions])
        db.flush()
        _step(steps, "storage", "Сохранение инцидентов, доказательств и протокола", stage,
              incidents=len(incidents), windows=len(decisions),
              evidence=sum(len(incident.evidence_items) for incident in incidents))
        insufficient = sum(window.status == "insufficient_data" for window in windows)
        with_evidence = sum(bool(incident.evidence_items) for incident in incidents)
        run.status = "completed"
        run.finished_at = utc_now()
        run.warnings = [model_warning] if model_warning else []
        run.stats = {
            "events": len(events), "windows": len(windows),
            "ready_windows": len(windows) - insufficient,
            "insufficient_windows": insufficient,
            "rule_matches": len(rule_matches), "incidents": len(incidents),
            "incidents_with_evidence": with_evidence,
            "evidence_coverage": round(100 * with_evidence / len(incidents), 2) if incidents else 100.0,
            "by_kind": dict(Counter(incident.kind for incident in incidents)),
            "model_status": model_status,
            "notices": build_notices(dataset, decisions, model_status),
            "protocol": steps,
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


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
