from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from log_analyzer.contracts import AnalysisRequest
from log_analyzer.knowledge.rules import add_rule_version
from log_analyzer.services.analyzer import (
    create_dataset_from_records, create_dataset_from_text, execute_analysis,
    new_run, train_model,
)
from log_analyzer.storage.models import IncidentRecord

START = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def record(index, request_id, status=200, message="request completed", route="/api/catalog", service="web", seconds=0):
    return {
        "observed_at": (START + timedelta(seconds=seconds or index)).isoformat(),
        "source": {"type": "application_json", "service": service, "host": "web-01"},
        "request": {"request_id": request_id, "method": "GET", "route": route, "status": status, "duration_ms": 30 + index, "client": "10.0.0.1"},
        "message": message,
    }


def make_dataset(db, records, name="test"):
    return create_dataset_from_records(db, str(uuid.uuid4()), name, records)


def analyze(db, dataset, model_id=None, fail_model=False):
    run = new_run(db, AnalysisRequest(dataset_id=dataset.id, model_id=model_id, fail_model=fail_model))
    execute_analysis(db, run.id)
    return run


def incidents(db, run):
    return list(db.scalars(select(IncidentRecord).where(IncidentRecord.run_id == run.id)).all())


def auth_records(count=2):
    records = []
    for index in range(count):
        records.append(record(index * 2, f"auth-{index}", 401, "POST /api/session -> 401", "/api/session", seconds=index * 2))
        records.append(record(index * 2 + 1, f"auth-{index}", 401, "token rejected: unexpected issuer", "/api/session", "auth-api", seconds=index * 2))
    return records


def baseline_dataset(db):
    records = []
    for window in range(6):
        for index in range(4):
            records.append(record(index, f"base-{window}-{index}", seconds=window * 60 + index * 3))
    return make_dataset(db, records, "baseline")


def test_e2e_01_auth_growth_has_rule_and_evidence(db):
    dataset = make_dataset(db, auth_records())
    run = analyze(db, dataset)
    found = incidents(db, run)
    assert len(found) == 1
    assert found[0].hypothesis == "authentication_issuer_mismatch"
    assert found[0].rule_ids == ["AUTH_ISSUER_MISMATCH@1"]
    assert len(found[0].evidence_items) == 4


def test_e2e_02_mass_404_is_anomaly_without_confirmed_cause(db):
    baseline = baseline_dataset(db)
    model = train_model(db, baseline.id, .08, .95)
    target_records = [record(index, f"404-{index}", 404, "GET /assets/app.js -> 404", "/assets/app.js", seconds=index) for index in range(12)]
    target = make_dataset(db, target_records, "404")
    run = analyze(db, target, model.id)
    found = incidents(db, run)
    assert len(found) == 1
    assert found[0].kind == "unknown_anomaly"
    assert found[0].hypothesis is None
    assert found[0].anomaly_score >= found[0].anomaly_threshold


def test_e2e_03_upstream_timeout_rule(db):
    records = []
    for index in range(2):
        records.append(record(index * 2, f"up-{index}", 504, "GET /api/checkout -> 504", "/api/checkout", seconds=index * 2))
        records.append(record(index * 2 + 1, f"up-{index}", 504, "upstream timed out while reading response header", "/api/checkout", seconds=index * 2))
    dataset = make_dataset(db, records)
    run = analyze(db, dataset)
    found = incidents(db, run)
    assert found[0].hypothesis == "upstream_timeout"
    assert found[0].rule_ids == ["UPSTREAM_TIMEOUT@1"]


def test_e2e_04_missing_ids_are_not_exact_links(db):
    records = [record(index, None, seconds=index) for index in range(2)]
    dataset = make_dataset(db, records)
    from log_analyzer.services.analyzer import load_context
    events, groups, _, _ = load_context(db, dataset.id)
    assert all(event.request_id is None and event.trace_id is None for event in events)
    assert all(group.link_quality != "exact" for group in groups)


def test_e2e_05_broken_json_does_not_drop_dataset(db):
    valid = '{"observed_at":"2026-10-27T12:00:00Z","service":"web","request":{"request_id":"ok","status":200},"message":"ok"}'
    dataset = create_dataset_from_text(db, str(uuid.uuid4()), "broken", [("app.jsonl", valid + "\n{bad\n", "jsonl", "web")])
    assert dataset.stats["read_count"] == 2
    assert dataset.stats["normalized_count"] == 1
    assert dataset.stats["rejected_count"] == 1


def test_e2e_06_unavailable_model_leaves_rules_and_warning(db):
    baseline = baseline_dataset(db)
    model = train_model(db, baseline.id, .08, .95)
    dataset = make_dataset(db, auth_records())
    run = analyze(db, dataset, model.id, fail_model=True)
    found = incidents(db, run)
    assert run.status == "completed"
    assert run.stats["model_status"] == "unavailable"
    assert run.warnings[0].startswith("model_unavailable")
    assert found[0].hypothesis == "authentication_issuer_mismatch"


def test_e2e_07_small_observation_returns_insufficient_data(db):
    baseline = baseline_dataset(db)
    model = train_model(db, baseline.id, .08, .95)
    dataset = make_dataset(db, [record(0, "one"), record(1, "two")])
    run = analyze(db, dataset, model.id)
    assert run.stats["insufficient_windows"] == 1
    assert incidents(db, run) == []


def test_e2e_08_rule_conflict_requires_manual_review(db):
    add_rule_version(db, """
id: AUTH_CONFLICT
version: 1
scope: group
when:
  template_contains: unexpected issuer
  status_in: [401]
then:
  hypothesis: alternative_authentication_cause
  severity: medium
  recommendation: review_manually
  evidence: [request_id, status]
""")
    dataset = make_dataset(db, auth_records())
    run = analyze(db, dataset)
    found = incidents(db, run)
    assert found[0].kind == "rule_conflict"
    assert found[0].review_required is True
    assert set(found[0].rule_ids) == {"AUTH_ISSUER_MISMATCH@1", "AUTH_CONFLICT@1"}
    assert len(found[0].features["rule_outcomes"]) == 4
