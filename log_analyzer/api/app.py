from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import (
    BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Query, Response, UploadFile,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from log_analyzer.config import MAX_UPLOAD_BYTES, SAMPLES_DIR
from log_analyzer.contracts import (
    AnalysisRequest, ApiDataset, ReviewRequest, RuleUpload, TrainModelRequest, utc_now,
)
from log_analyzer.knowledge.rules import add_rule_version, sync_default_rules
from log_analyzer.services.analyzer import (
    create_dataset_from_records, create_dataset_from_text, execute_analysis,
    load_context, new_run, train_model,
)
from log_analyzer.services.maintenance import delete_dataset_with_data, purge_datasets
from log_analyzer.storage.database import SessionLocal, get_db
from log_analyzer.storage.models import (
    AnalysisRunRecord, DatasetRecord, EventRecord, IncidentRecord,
    ModelVersionRecord, RequestGroupRecord, RuleRecord, TemplateRecord, WindowDecisionRecord,
)
from log_analyzer.storage.serializers import (
    dataset_dict, event_dict, incident_detail_dict, incident_dict, iso, model_dict,
    rule_dict, run_dict, template_dict,
)

APP_VERSION = "1.1.0"
STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"

STATIC_HEADERS = {"Cache-Control": "no-cache"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    with SessionLocal() as db:
        sync_default_rules(db)
    yield


app = FastAPI(title="Log Analyzer", version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def analysis_task(run_id: str) -> None:
    with SessionLocal() as db:
        execute_analysis(db, run_id)


def dataset_or_404(db: Session, dataset_id: str) -> DatasetRecord:
    dataset = db.get(DatasetRecord, dataset_id)
    if dataset is None:
        raise HTTPException(404, "Dataset not found")
    return dataset


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _storage_time(value: datetime, db: Session) -> datetime:
    """Отметка времени для сравнения с хранимыми: во всемирном времени, а для SQLite
    ещё и без часового пояса, поскольку SQLite хранит только поля даты и времени."""
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    aware = aware.astimezone(timezone.utc)
    if db.bind is not None and db.bind.dialect.name == "sqlite":
        return aware.replace(tzinfo=None)
    return aware


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", headers=STATIC_HEADERS)


@app.get("/api/health")
def health(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "time": utc_now().isoformat(), "version": APP_VERSION}


@app.get("/api/datasets")
def datasets(db: Session = Depends(get_db)) -> list[dict]:
    records = db.scalars(select(DatasetRecord).order_by(DatasetRecord.created_at.desc())).all()
    return [dataset_dict(record) for record in records]


@app.post("/api/datasets", status_code=202)
def upload_dataset(
    background: BackgroundTasks,
    files: list[UploadFile] = File(...),
    adapter: str = Form("auto"), service: str = Form("unknown"),
    name: str | None = Form(None), analyze: bool = Form(True),
    model_id: str | None = Form(None), db: Session = Depends(get_db),
) -> dict:
    sources = []
    total = 0
    for file in files:
        content = file.file.read()
        total += len(content)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Upload size limit exceeded")
        try:
            text_content = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(400, f"{file.filename}: UTF-8 is required") from exc
        sources.append((file.filename or "upload.log", text_content, adapter, service))
    dataset_id = str(uuid.uuid4())
    dataset = create_dataset_from_text(db, dataset_id, name or sources[0][0], sources)
    run = None
    if analyze:
        run = new_run(db, AnalysisRequest(dataset_id=dataset.id, model_id=model_id))
        background.add_task(analysis_task, run.id)
    return {"dataset": dataset_dict(dataset), "run": run_dict(run) if run else None}


@app.post("/api/datasets/json", status_code=202)
def upload_json_dataset(payload: ApiDataset, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    dataset_id = str(uuid.uuid4())
    dataset = create_dataset_from_records(db, dataset_id, payload.name, payload.records)
    run = None
    if payload.analyze:
        run = new_run(db, AnalysisRequest(dataset_id=dataset.id))
        background.add_task(analysis_task, run.id)
    return {"dataset": dataset_dict(dataset), "run": run_dict(run) if run else None}


@app.get("/api/datasets/{dataset_id}")
def dataset_detail(dataset_id: str, db: Session = Depends(get_db)) -> dict:
    dataset = dataset_or_404(db, dataset_id)
    runs = db.scalars(select(AnalysisRunRecord).where(AnalysisRunRecord.dataset_id == dataset_id).order_by(AnalysisRunRecord.created_at.desc())).all()
    return {**dataset_dict(dataset), "runs": [run_dict(run) for run in runs]}


@app.delete("/api/datasets/{dataset_id}", status_code=204)
def delete_dataset(dataset_id: str, db: Session = Depends(get_db)) -> Response:
    dataset_or_404(db, dataset_id)
    delete_dataset_with_data(db, dataset_id)
    return Response(status_code=204)


@app.post("/api/maintenance/purge")
def purge_registry(db: Session = Depends(get_db)) -> dict:
    deleted = purge_datasets(db)
    return {"deleted": deleted}


@app.post("/api/analysis", status_code=202)
def analyze(payload: AnalysisRequest, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    dataset_or_404(db, payload.dataset_id)
    run = new_run(db, payload)
    background.add_task(analysis_task, run.id)
    return run_dict(run)


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(AnalysisRunRecord, run_id)
    if run is None:
        raise HTTPException(404, "Analysis run not found")
    return run_dict(run)


@app.get("/api/runs/{run_id}/protocol")
def run_protocol(run_id: str, db: Session = Depends(get_db)) -> dict:
    """Пошаговый протокол запуска: этапы обработки с затратами времени и решение
    по каждому окну — какие правила проверялись, что дала модель и что решил арбитраж."""
    run = db.get(AnalysisRunRecord, run_id)
    if run is None:
        raise HTTPException(404, "Analysis run not found")
    records = db.scalars(
        select(WindowDecisionRecord).where(WindowDecisionRecord.run_id == run_id)
        .order_by(WindowDecisionRecord.window_start)
    ).all()
    stats = run.stats or {}
    return {
        "run_id": run_id, "dataset_id": run.dataset_id, "status": run.status,
        "model_id": run.model_id, "steps": stats.get("protocol", []),
        "notices": stats.get("notices", []), "warnings": run.warnings or [],
        "windows": [
            {**record.details, "window_start": iso(record.window_start), "window_end": iso(record.window_end)}
            for record in records
        ],
    }


def event_filters(
    dataset_id: str, service: str | None = None, route: str | None = None,
    source_type: str | None = None, request_id: str | None = None,
    template_id: str | None = None,
    status: list[int] | None = Query(None), severity: list[str] | None = Query(None),
    time_from: datetime | None = None, time_to: datetime | None = None,
    q: str | None = None, db: Session = Depends(get_db),
) -> list:
    """Условия поиска записей журналов: по времени, источнику, сервису и маршруту,
    коду ответа, уровню серьёзности, идентификатору запроса или трассировки,
    шаблону сообщения и тексту. Общие для выдачи записей и подсчёта их числа."""
    criteria = [EventRecord.dataset_id == dataset_id]
    if service:
        criteria.append(EventRecord.service == service)
    if route:
        criteria.append(EventRecord.route == route)
    if source_type:
        criteria.append(EventRecord.source_type == source_type)
    if template_id:
        criteria.append(EventRecord.template_id == template_id)
    if request_id:
        criteria.append(or_(EventRecord.request_id == request_id, EventRecord.trace_id == request_id))
    if status:
        criteria.append(EventRecord.status.in_(status))
    if severity:
        criteria.append(func.lower(EventRecord.severity).in_([item.lower() for item in severity]))
    if time_from:
        criteria.append(EventRecord.observed_at >= _storage_time(time_from, db))
    if time_to:
        criteria.append(EventRecord.observed_at <= _storage_time(time_to, db))
    if q:
        pattern = f"%{_escape_like(q)}%"
        criteria.append(or_(
            EventRecord.message.ilike(pattern, escape="\\"),
            EventRecord.raw.ilike(pattern, escape="\\"),
            EventRecord.original_uri.ilike(pattern, escape="\\"),
        ))
    return criteria


@app.get("/api/events")
def events(
    filters: list = Depends(event_filters),
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    records = db.scalars(
        select(EventRecord).where(*filters)
        .order_by(EventRecord.observed_at, EventRecord.id).offset(offset).limit(limit)
    ).all()
    return [event_dict(record) for record in records]


@app.get("/api/events/count")
def events_count(filters: list = Depends(event_filters), db: Session = Depends(get_db)) -> dict:
    """Число записей, удовлетворяющих условиям поиска."""
    count = db.scalar(select(func.count()).select_from(EventRecord).where(*filters))
    return {"count": int(count or 0)}


@app.get("/api/templates")
def templates(
    dataset_id: str, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Шаблоны сообщений набора: результат объединения повторяющихся записей."""
    records = db.scalars(
        select(TemplateRecord).where(TemplateRecord.dataset_id == dataset_id)
        .order_by(TemplateRecord.occurrences.desc(), TemplateRecord.first_seen, TemplateRecord.id)
        .offset(offset).limit(limit)
    ).all()
    return [template_dict(record) for record in records]


def _group_stats(db: Session, dataset_id: str, group_ids: set[str]) -> dict[str, dict]:
    stats: dict[str, dict] = defaultdict(lambda: {"event_count": 0, "request_ids": [], "statuses": []})
    if group_ids:
        rows = db.execute(
            select(EventRecord.group_id, EventRecord.request_id, EventRecord.status)
            .where(EventRecord.dataset_id == dataset_id, EventRecord.group_id.in_(group_ids))
        )
        for group_id, request_id, status in rows:
            item = stats[group_id]
            item["event_count"] += 1
            if request_id and request_id not in item["request_ids"]:
                item["request_ids"].append(request_id)
            if status is not None and status not in item["statuses"]:
                item["statuses"].append(status)
    for item in stats.values():
        item["statuses"] = sorted(item["statuses"])
    return stats


def _group_dict(record: RequestGroupRecord, stats: dict) -> dict:
    return {
        "group_id": record.id, "link_quality": record.link_quality,
        "service": record.service, "route": record.route,
        "started_at": iso(record.started_at), "ended_at": iso(record.ended_at),
        "event_count": stats["event_count"], "request_ids": stats["request_ids"],
        "statuses": stats["statuses"],
    }


@app.get("/api/groups")
def groups(
    dataset_id: str, link_quality: str | None = None,
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Группы связанных событий одного запроса с качеством связи."""
    query = select(RequestGroupRecord).where(RequestGroupRecord.dataset_id == dataset_id)
    if link_quality:
        query = query.where(RequestGroupRecord.link_quality == link_quality)
    records = db.scalars(
        query.order_by(RequestGroupRecord.started_at, RequestGroupRecord.id).offset(offset).limit(limit)
    ).all()
    stats = _group_stats(db, dataset_id, {record.id for record in records})
    return [_group_dict(record, stats.get(record.id) or {"event_count": 0, "request_ids": [], "statuses": []}) for record in records]


@app.get("/api/groups/{group_id}")
def group_detail(group_id: str, db: Session = Depends(get_db)) -> dict:
    record = db.get(RequestGroupRecord, group_id)
    if record is None:
        raise HTTPException(404, "Request group not found")
    records = db.scalars(
        select(EventRecord).where(EventRecord.group_id == group_id).order_by(EventRecord.observed_at, EventRecord.id)
    ).all()
    return _group_dict(record, _group_stats(db, record.dataset_id, {record.id}).get(record.id) or {
        "event_count": 0, "request_ids": [], "statuses": [],
    }) | {"events": [event_dict(item) for item in records]}


@app.get("/api/incidents")
def incidents(
    dataset_id: str | None = None, run_id: str | None = None,
    service: str | None = None, route: str | None = None,
    kind: str | None = None, severity: str | None = None,
    review_required: bool | None = None,
    limit: int = Query(500, ge=1, le=2000), db: Session = Depends(get_db),
) -> list[dict]:
    query = select(IncidentRecord)
    if dataset_id:
        query = query.where(IncidentRecord.dataset_id == dataset_id)
    if run_id:
        query = query.where(IncidentRecord.run_id == run_id)
    if service:
        query = query.where(IncidentRecord.service == service)
    if route:
        query = query.where(IncidentRecord.route == route)
    if kind:
        query = query.where(IncidentRecord.kind == kind)
    if severity:
        query = query.where(IncidentRecord.severity == severity)
    if review_required is not None:
        query = query.where(IncidentRecord.review_required == review_required)
    records = db.scalars(
        query.order_by(IncidentRecord.created_at.desc(), IncidentRecord.window_start.desc()).limit(limit)
    ).all()
    return [incident_dict(record) for record in records]


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str, db: Session = Depends(get_db)) -> dict:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    payload = incident_detail_dict(incident)
    if incident.model_id:
        model = db.get(ModelVersionRecord, incident.model_id)
        payload["model"] = model_dict(model) if model else None
    payload["rules"] = [rule_dict(rule) for key in incident.rule_ids if (rule := db.get(RuleRecord, key))]
    return payload


@app.patch("/api/incidents/{incident_id}/review")
def review_incident(incident_id: str, payload: ReviewRequest, db: Session = Depends(get_db)) -> dict:
    """Отметка ручной проверки. Проверенный инцидент больше не числится среди
    требующих проверки; снятие отметки возвращает его в этот перечень, если он
    был создан из-за конфликта правил."""
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    incident.reviewed_at = utc_now() if payload.reviewed else None
    incident.review_required = incident.kind == "rule_conflict" and not payload.reviewed
    db.commit()
    return incident_detail_dict(incident)


@app.get("/api/rules")
def rules(db: Session = Depends(get_db)) -> list[dict]:
    records = db.scalars(select(RuleRecord).order_by(RuleRecord.id, RuleRecord.version.desc())).all()
    return [rule_dict(record) for record in records]


@app.post("/api/rules", status_code=201)
def create_rule(payload: RuleUpload, db: Session = Depends(get_db)) -> dict:
    try:
        return rule_dict(add_rule_version(db, payload.yaml_text))
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/models")
def models(db: Session = Depends(get_db)) -> list[dict]:
    records = db.scalars(select(ModelVersionRecord).order_by(ModelVersionRecord.trained_at.desc())).all()
    return [model_dict(record) for record in records]


@app.post("/api/models/train", status_code=201)
def train(payload: TrainModelRequest, db: Session = Depends(get_db)) -> dict:
    dataset_or_404(db, payload.dataset_id)
    try:
        record = train_model(db, payload.dataset_id, payload.contamination, payload.threshold_quantile)
        return model_dict(record)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/overview")
def overview(dataset_id: str, run_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    dataset_or_404(db, dataset_id)
    *_, windows = load_context(db, dataset_id)
    if run_id:
        run = db.get(AnalysisRunRecord, run_id)
    else:
        run = db.scalars(select(AnalysisRunRecord).where(AnalysisRunRecord.dataset_id == dataset_id).order_by(AnalysisRunRecord.created_at.desc())).first()
    incident_query = select(IncidentRecord).where(IncidentRecord.dataset_id == dataset_id)
    if run:
        incident_query = incident_query.where(IncidentRecord.run_id == run.id)
    incidents_now = db.scalars(incident_query).all()
    return {
        "dataset_id": dataset_id, "run": run_dict(run) if run else None,
        "windows": [window.model_dump(mode="json", exclude={"event_ids", "group_ids"}) for window in windows],
        "summary": {
            "events": sum(window.n_req for window in windows),
            "incidents": len(incidents_now),
            "review_required": sum(incident.review_required for incident in incidents_now),
            "insufficient_windows": sum(window.status == "insufficient_data" for window in windows),
            "max_error_ratio": max((window.r_4xx + window.r_5xx for window in windows), default=0),
            "evidence_coverage": (run.stats or {}).get("evidence_coverage") if run else None,
            "by_kind": dict(Counter(incident.kind for incident in incidents_now)),
            "by_severity": dict(Counter(incident.severity for incident in incidents_now)),
            "by_hypothesis": dict(Counter(incident.hypothesis or "unknown_anomaly" for incident in incidents_now)),
        },
        "notices": (run.stats or {}).get("notices", []) if run else [],
    }


@app.post("/api/demo", status_code=202)
def demo(background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    baseline_id = str(uuid.uuid4())
    baseline_text = (SAMPLES_DIR / "baseline.jsonl").read_text(encoding="utf-8")
    baseline = create_dataset_from_text(db, baseline_id, "Базовый период", [("baseline.jsonl", baseline_text, "jsonl", "shop-web")])
    model = train_model(db, baseline.id, 0.08, 0.95)
    dataset_id = str(uuid.uuid4())
    sources = [
        ("demo_access.log", (SAMPLES_DIR / "demo_access.log").read_text(encoding="utf-8"), "nginx", "shop-web"),
        ("demo_application.jsonl", (SAMPLES_DIR / "demo_application.jsonl").read_text(encoding="utf-8"), "jsonl", "auth-api"),
        ("demo_upstream_error.log", (SAMPLES_DIR / "demo_upstream_error.log").read_text(encoding="utf-8"), "error", "shop-web"),
    ]
    dataset = create_dataset_from_text(db, dataset_id, "Демонстрация: 401 и upstream", sources)
    run = new_run(db, AnalysisRequest(dataset_id=dataset.id, model_id=model.id))
    background.add_task(analysis_task, run.id)
    return {"dataset": dataset_dict(dataset), "model": model_dict(model), "run": run_dict(run)}
