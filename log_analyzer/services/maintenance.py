from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from log_analyzer.storage.models import (
    AnalysisRunRecord, DatasetRecord, EventRecord, EvidenceRecord,
    IncidentRecord, RequestGroupRecord, TemplateRecord,
)


def delete_dataset_with_data(db: Session, dataset_id: str) -> dict[str, int]:
    """Удаляет набор данных вместе со всеми производными записями:
    событиями, шаблонами, группами, запусками, инцидентами и доказательствами."""
    incident_ids = select(IncidentRecord.id).where(IncidentRecord.dataset_id == dataset_id)
    deleted: dict[str, int] = {}
    deleted["evidence"] = db.execute(
        delete(EvidenceRecord).where(EvidenceRecord.incident_id.in_(incident_ids))
    ).rowcount or 0
    deleted["incidents"] = db.execute(
        delete(IncidentRecord).where(IncidentRecord.dataset_id == dataset_id)
    ).rowcount or 0
    deleted["runs"] = db.execute(
        delete(AnalysisRunRecord).where(AnalysisRunRecord.dataset_id == dataset_id)
    ).rowcount or 0
    deleted["events"] = db.execute(
        delete(EventRecord).where(EventRecord.dataset_id == dataset_id)
    ).rowcount or 0
    deleted["groups"] = db.execute(
        delete(RequestGroupRecord).where(RequestGroupRecord.dataset_id == dataset_id)
    ).rowcount or 0
    deleted["templates"] = db.execute(
        delete(TemplateRecord).where(TemplateRecord.dataset_id == dataset_id)
    ).rowcount or 0
    deleted["datasets"] = db.execute(
        delete(DatasetRecord).where(DatasetRecord.id == dataset_id)
    ).rowcount or 0
    db.commit()
    return deleted


def purge_datasets(db: Session) -> dict[str, int]:
    """Полностью очищает реестр журналов: все наборы и производные данные.
    База знаний (правила) и реестр моделей сохраняются."""
    totals = {key: 0 for key in ("evidence", "incidents", "runs", "events", "groups", "templates", "datasets")}
    for dataset_id in db.scalars(select(DatasetRecord.id)):
        deleted = delete_dataset_with_data(db, dataset_id)
        for key, value in deleted.items():
            totals[key] += value
    return totals
