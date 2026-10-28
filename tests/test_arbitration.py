from __future__ import annotations

from datetime import datetime, timedelta, timezone

from log_analyzer.arbitration.engine import arbitrate
from log_analyzer.knowledge.rules import RuleMatch
from log_analyzer.models.isolation import ModelWindowResult
from tests.test_processing import make_event


def window_and_event():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event = make_event(0, observed_at=start)
    from log_analyzer.contracts import WindowFeatures
    window = WindowFeatures(
        window_start=start, window_end=start + timedelta(seconds=60), n_req=4,
        r_401=0, r_4xx=0, r_5xx=0, q_095_duration_ms=30,
        n_retry=0, n_tpl=1, n_new=1, r_uncertain=0,
        event_ids=[event.event_id], group_ids=[event.group_id] if event.group_id else [],
    )
    return window, event


def test_unknown_anomaly_has_no_invented_cause():
    window, event = window_and_event()
    incidents = arbitrate(
        run_id="run", dataset_id="dataset-test", windows=[window], events=[event],
        rule_matches=[], model_results=[ModelWindowResult(window.window_start, "anomaly", .97, .9)], model_id="model",
    )
    assert incidents[0].kind == "unknown_anomaly"
    assert incidents[0].hypothesis is None
    assert incidents[0].confidence == "model_only"
    assert incidents[0].evidence_items


def test_conflicting_rules_require_review_and_keep_both():
    window, event = window_and_event()
    event.group_id = "g1"
    window.group_ids = ["g1"]
    matches = [
        RuleMatch("RULE_A@1", "cause_a", "high", "check_a", [event.event_id], group_id=event.group_id),
        RuleMatch("RULE_B@1", "cause_b", "medium", "check_b", [event.event_id], group_id=event.group_id),
    ]
    incidents = arbitrate(
        run_id="run", dataset_id="dataset-test", windows=[window], events=[event],
        rule_matches=matches, model_results=[], model_id=None,
    )
    incident = incidents[0]
    assert incident.kind == "rule_conflict"
    assert incident.review_required is True
    assert incident.rule_ids == ["RULE_A@1", "RULE_B@1"]


def test_insufficient_window_does_not_create_normal_or_anomaly_incident():
    window, event = window_and_event()
    window.status = "insufficient_data"
    incidents = arbitrate(
        run_id="run", dataset_id="dataset-test", windows=[window], events=[event],
        rule_matches=[], model_results=[ModelWindowResult(window.window_start, "insufficient_data", None, .9)], model_id="model",
    )
    assert incidents == []
