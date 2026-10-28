from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CanonicalEvent(BaseModel):
    event_id: str
    dataset_id: str
    observed_at: datetime
    source_type: str
    service: str = "unknown"
    host: str | None = None
    client: str | None = None
    file_offset: int | None = None
    line_number: int | None = None
    severity: str = "info"
    request_id: str | None = None
    trace_id: str | None = None
    method: str | None = None
    route: str | None = None
    original_uri: str | None = None
    status: int | None = None
    duration_ms: float | None = None
    template_id: str | None = None
    group_id: str | None = None
    message: str | None = None
    raw: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class IngestionIssue(BaseModel):
    source: str
    line_number: int | None = None
    error: str
    raw_excerpt: str | None = None


class IngestionResult(BaseModel):
    events: list[CanonicalEvent] = Field(default_factory=list)
    issues: list[IngestionIssue] = Field(default_factory=list)
    read_count: int = 0
    rejected_count: int = 0
    source_names: list[str] = Field(default_factory=list)


class WindowFeatures(BaseModel):
    window_start: datetime
    window_end: datetime
    n_req: int
    r_401: float
    r_4xx: float
    r_5xx: float
    q_095_duration_ms: float
    n_retry: int
    n_tpl: int
    n_new: int
    r_uncertain: float
    event_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    service: str | None = None
    route: str | None = None
    status: Literal["ready", "insufficient_data"] = "ready"

    @property
    def vector(self) -> list[float]:
        return [
            float(self.n_req), self.r_401, self.r_4xx, self.r_5xx,
            self.q_095_duration_ms, float(self.n_retry), float(self.n_tpl),
            float(self.n_new), self.r_uncertain,
        ]


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=2, max_length=80, pattern=r"^[A-Z][A-Z0-9_]+$")
    version: int = Field(ge=1)
    scope: Literal["event", "group", "window"] = "group"
    when: dict[str, Any]
    then: dict[str, Any]

    @field_validator("when")
    @classmethod
    def validate_conditions(cls, value: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "template_contains", "message_contains", "status_in",
            "related_events_gte", "status_ratio_gte", "min_requests",
            "route_contains", "service_equals",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"Unsupported conditions: {sorted(unknown)}")
        if not value:
            raise ValueError("Rule must contain at least one condition")
        return value

    @field_validator("then")
    @classmethod
    def validate_outcome(cls, value: dict[str, Any]) -> dict[str, Any]:
        required = {"hypothesis", "severity", "recommendation", "evidence"}
        missing = required - set(value)
        if missing:
            raise ValueError(f"Missing outcome fields: {sorted(missing)}")
        if value["severity"] not in {"low", "medium", "high", "critical"}:
            raise ValueError("Unsupported severity")
        return value


class AnalysisRequest(BaseModel):
    dataset_id: str
    model_id: str | None = None
    fail_model: bool = False


class TrainModelRequest(BaseModel):
    dataset_id: str
    contamination: float = Field(default=0.08, gt=0, le=0.5)
    threshold_quantile: float = Field(default=0.95, ge=0.5, lt=1)


class RuleUpload(BaseModel):
    yaml_text: str = Field(min_length=10)


class ReviewRequest(BaseModel):
    reviewed: bool = True


class ApiRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    observed_at: datetime
    raw: str | None = None
    message: str | None = None
    service: str = "api"
    source_type: str = "application_json"


class ApiDataset(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    records: list[dict[str, Any]] = Field(min_length=1)
    analyze: bool = False
