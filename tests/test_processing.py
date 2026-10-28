from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from log_analyzer.contracts import CanonicalEvent
from log_analyzer.ingestion.adapters import ingest_text_sources
from log_analyzer.processing.correlation import correlate_events
from log_analyzer.processing.templates import apply_templates
from log_analyzer.processing.windows import build_windows


def make_event(index=0, **overrides):
    dataset_id = "dataset-test"
    values = dict(
        event_id=str(uuid.uuid4()), dataset_id=dataset_id,
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index),
        source_type="application_json", service="web", host="web-01", client="10.0.0.1",
        request_id=None, trace_id=None, method="GET", route="/api/item/{id}",
        original_uri=f"/api/item/{index}", status=200, duration_ms=25.0 + index,
        message="request completed", raw=f"raw-{index}",
    )
    values.update(overrides)
    return CanonicalEvent(**values)


def test_nginx_normalization_and_uuid_route():
    line = '10.0.0.1 - - [27/Oct/2026:10:00:00 +0300] "GET /api/item/123e4567-e89b-12d3-a456-426614174000 HTTP/1.1" 200 10 "-" "agent" 0.025 - req-1'
    result = ingest_text_sources([("access.log", line, "nginx", "web")], "dataset-test")
    assert result.rejected_count == 0
    event = result.events[0]
    assert event.route == "/api/item/{id}"
    assert event.observed_at.hour == 7
    assert event.duration_ms == 25
    assert event.raw == line


def test_broken_json_is_isolated():
    valid = '{"observed_at":"2026-10-27T10:00:00Z","service":"web","status":200,"message":"ok"}'
    result = ingest_text_sources([("app.jsonl", valid + "\n{broken\n", "jsonl", "web")], "dataset-test")
    assert result.read_count == 2
    assert len(result.events) == 1
    assert result.rejected_count == 1
    assert result.issues[0].line_number == 2


def test_lcs_templates_group_similar_messages():
    first = make_event(0, message="token rejected: unexpected issuer token_id=1001")
    second = make_event(1, message="token rejected: unexpected issuer token_id=1002")
    templates = apply_templates([first, second])
    assert first.template_id == second.template_id
    assert len(templates) == 1
    assert templates[0].occurrences == 2


def test_exact_and_limited_heuristic_correlation():
    exact_a = make_event(0, request_id="req-1")
    exact_b = make_event(1, request_id="req-1", message="token rejected")
    heuristic_a = make_event(2)
    heuristic_b = make_event(3)
    ambiguous = make_event(2, client="10.0.0.2")
    groups = correlate_events([exact_a, exact_b, heuristic_a, heuristic_b, ambiguous])
    assert exact_a.group_id == exact_b.group_id
    assert heuristic_a.group_id == heuristic_b.group_id
    qualities = {group.id: group.link_quality for group in groups}
    assert qualities[exact_a.group_id] == "exact"
    assert qualities[heuristic_a.group_id] == "presumed"
    assert qualities[ambiguous.group_id] == "uncertain"


def test_small_window_is_not_false_normal():
    events = [make_event(0), make_event(1)]
    templates = apply_templates(events)
    groups = correlate_events(events)
    windows = build_windows(events, groups, templates)
    assert windows[0].status == "insufficient_data"
    assert windows[0].n_req == 2
