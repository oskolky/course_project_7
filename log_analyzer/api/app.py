from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from log_analyzer.config import MAX_UPLOAD_BYTES, SAMPLES_DIR
from log_analyzer.contracts import AnalysisRequest, ApiDataset, ReviewRequest, RuleUpload, TrainModelRequest, utc_now
from log_analyzer.knowledge.rules import add_rule_version, sync_default_rules
from log_analyzer.services.analyzer import (
    create_dataset_from_records, create_dataset_from_text, execute_analysis,
    load_context, new_run, train_model,
)
from log_analyzer.services.maintenance import delete_dataset_with_data, purge_datasets
from log_analyzer.storage.database import SessionLocal, get_db
from log_analyzer.storage.models import (
    AnalysisRunRecord, DatasetRecord, EventRecord, IncidentRecord,
    ModelVersionRecord, RuleRecord,
)
from log_analyzer.storage.serializers import (
    dataset_dict, event_dict, incident_dict, model_dict, rule_dict, run_dict,
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"
app = FastAPI(title="Log Analyzer", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def startup() -> None:
    with SessionLocal() as db:
        sync_default_rules(db)


def analysis_task(run_id: str) -> None:
    with SessionLocal() as db:
        execute_analysis(db, run_id)


def dataset_or_404(db: Session, dataset_id: str) -> DatasetRecord:
    dataset = db.get(DatasetRecord, dataset_id)
    if dataset is None:
        raise HTTPException(404, "Dataset not found")
    return dataset


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "time": utc_now().isoformat()}


@app.get("/api/datasets")
def datasets(db: Session = Depends(get_db)) -> list[dict]:
    records = db.scalars(select(DatasetRecord).order_by(DatasetRecord.created_at.desc())).all()
    return [dataset_dict(record) for record in records]


@app.post("/api/datasets", status_code=202)
async def upload_dataset(
    background: BackgroundTasks,
    files: list[UploadFile] = File(...),
    adapter: str = Form("auto"), service: str = Form("unknown"),
    name: str | None = Form(None), analyze: bool = Form(True),
    model_id: str | None = Form(None), db: Session = Depends(get_db),
) -> dict:
    sources = []
    total = 0
    for file in files:
        content = await file.read()
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


@app.get("/api/events")
def events(
    dataset_id: str, service: str | None = None, route: str | None = None,
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    query = select(EventRecord).where(EventRecord.dataset_id == dataset_id)
    if service:
        query = query.where(EventRecord.service == service)
    if route:
        query = query.where(EventRecord.route == route)
    records = db.scalars(query.order_by(EventRecord.observed_at).offset(offset).limit(limit)).all()
    return [event_dict(record) for record in records]


@app.get("/api/incidents")
def incidents(
    dataset_id: str | None = None, run_id: str | None = None,
    service: str | None = None, route: str | None = None,
    kind: str | None = None, severity: str | None = None,
    review_required: bool | None = None, db: Session = Depends(get_db),
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
    records = db.scalars(query.order_by(IncidentRecord.created_at.desc()).limit(500)).all()
    return [incident_dict(record) for record in records]


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str, db: Session = Depends(get_db)) -> dict:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    payload = incident_dict(incident, include_evidence=True)
    if incident.model_id:
        model = db.get(ModelVersionRecord, incident.model_id)
        payload["model"] = model_dict(model) if model else None
    payload["rules"] = [rule_dict(rule) for key in incident.rule_ids if (rule := db.get(RuleRecord, key))]
    return payload


@app.patch("/api/incidents/{incident_id}/review")
def review_incident(incident_id: str, payload: ReviewRequest, db: Session = Depends(get_db)) -> dict:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    incident.reviewed_at = utc_now() if payload.reviewed else None
    db.commit()
    return incident_dict(incident, include_evidence=True)


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
        },
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
