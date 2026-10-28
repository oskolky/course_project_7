from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from log_analyzer.contracts import utc_now


class Base(DeclarativeBase):
    pass


class DatasetRecord(Base):
    __tablename__ = "datasets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    status: Mapped[str] = mapped_column(String(32), default="ingested")
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    events = relationship("EventRecord", back_populates="dataset", cascade="all, delete-orphan")
    runs = relationship("AnalysisRunRecord", back_populates="dataset", cascade="all, delete-orphan")


class AnalysisRunRecord(Base):
    __tablename__ = "analysis_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), index=True)
    model_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset = relationship("DatasetRecord", back_populates="runs")
    incidents = relationship("IncidentRecord", back_populates="run", cascade="all, delete-orphan")


class TemplateRecord(Base):
    __tablename__ = "templates"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), index=True)
    pattern: Mapped[str] = mapped_column(Text)
    parser_version: Mapped[str] = mapped_column(String(40))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    occurrences: Mapped[int] = mapped_column(Integer, default=0)


class RequestGroupRecord(Base):
    __tablename__ = "request_groups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), index=True)
    link_quality: Mapped[str] = mapped_column(String(24))
    route: Mapped[str | None] = mapped_column(String(512), nullable=True)
    service: Mapped[str | None] = mapped_column(String(120), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EventRecord(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_type: Mapped[str] = mapped_column(String(40))
    service: Mapped[str] = mapped_column(String(120), index=True)
    host: Mapped[str | None] = mapped_column(String(160), nullable=True)
    client: Mapped[str | None] = mapped_column(String(160), nullable=True)
    file_offset: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(24), default="info")
    request_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    trace_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    route: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    original_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    template_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    group_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[str] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    dataset = relationship("DatasetRecord", back_populates="events")


class RuleRecord(Base):
    __tablename__ = "rules"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    id: Mapped[str] = mapped_column(String(80), index=True)
    version: Mapped[int] = mapped_column(Integer)
    scope: Mapped[str] = mapped_column(String(16))
    condition: Mapped[dict[str, Any]] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(16))
    hypothesis: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (UniqueConstraint("id", "version", name="uq_rule_version"),)


class ModelVersionRecord(Base):
    __tablename__ = "model_versions"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    algorithm: Mapped[str] = mapped_column(String(80))
    feature_schema: Mapped[dict[str, Any]] = mapped_column(JSON)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"))
    artifact_path: Mapped[str] = mapped_column(Text)
    training_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class IncidentRecord(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    service: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    route: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    hypothesis: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[str] = mapped_column(String(40))
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    review_required: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    model_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    run = relationship("AnalysisRunRecord", back_populates="incidents")
    evidence_items = relationship("EvidenceRecord", back_populates="incident", cascade="all, delete-orphan")


class EvidenceRecord(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    role: Mapped[str] = mapped_column(String(32))
    excerpt: Mapped[str] = mapped_column(Text)
    incident = relationship("IncidentRecord", back_populates="evidence_items")
    event = relationship("EventRecord")


Index("ix_events_dataset_time", EventRecord.dataset_id, EventRecord.observed_at)
Index("ix_incidents_dataset_kind", IncidentRecord.dataset_id, IncidentRecord.kind)
