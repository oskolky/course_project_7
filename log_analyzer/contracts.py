from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    detail: str | None = None
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


SCOPE_CONDITIONS: dict[str, frozenset[str]] = {
    "event": frozenset({"template_contains", "message_contains", "status_in", "route_contains", "service_equals"}),
    "group": frozenset({"template_contains", "message_contains", "status_in", "related_events_gte", "route_contains", "service_equals"}),
    "window": frozenset({"status_in", "status_ratio_gte", "min_requests", "route_contains", "service_equals"}),
}
ALL_CONDITIONS: frozenset[str] = frozenset().union(*SCOPE_CONDITIONS.values())
SEVERITIES = {"low", "medium", "high", "critical"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


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
        unknown = set(value) - ALL_CONDITIONS
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
        if value["severity"] not in SEVERITIES:
            raise ValueError("Unsupported severity")
        for key in ("hypothesis", "recommendation"):
            if not isinstance(value[key], str) or not value[key].strip():
                raise ValueError(f"Outcome field {key} must be a non-empty string")
        if not isinstance(value["evidence"], list):
            raise ValueError("Outcome field evidence must be a list")
        for key in ("title", "recommendation_text"):
            if key in value and (not isinstance(value[key], str) or not value[key].strip()):
                raise ValueError(f"Outcome field {key} must be a non-empty string")
        return value

    @model_validator(mode="after")
    def validate_against_scope(self) -> "RuleDefinition":
        inapplicable = sorted(set(self.when) - SCOPE_CONDITIONS[self.scope])
        if inapplicable:
            raise ValueError(
                f"Conditions {inapplicable} are not applicable to scope '{self.scope}'; "
                f"allowed: {sorted(SCOPE_CONDITIONS[self.scope])}"
            )
        when = self.when
        if "status_ratio_gte" in when and "status_in" not in when:
            raise ValueError("Condition status_ratio_gte requires status_in")
        statuses = when.get("status_in")
        if statuses is not None and (
            not isinstance(statuses, list) or not statuses
            or not all(_is_int(item) and 100 <= item <= 599 for item in statuses)
        ):
            raise ValueError("status_in must be a non-empty list of HTTP status codes from 100 to 599")
        for name in ("template_contains", "message_contains", "route_contains", "service_equals"):
            if name in when and (not isinstance(when[name], str) or not when[name].strip()):
                raise ValueError(f"Condition {name} must be a non-empty string")
        for name in ("related_events_gte", "min_requests"):
            if name in when and (not _is_int(when[name]) or when[name] < 1):
                raise ValueError(f"Condition {name} must be a positive integer")
        ratio = when.get("status_ratio_gte")
        if ratio is not None and (
            isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 0 < ratio <= 1
        ):
            raise ValueError("Condition status_ratio_gte must be a number from 0 (exclusive) to 1")
        return self


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
