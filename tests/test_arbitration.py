from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import log_analyzer.arbitration.engine as engine_module
from log_analyzer.arbitration.engine import arbitrate
from log_analyzer.knowledge.rules import RuleMatch
from log_analyzer.models.isolation import ModelWindowResult
from log_analyzer.processing.correlation import correlate_events
from log_analyzer.processing.templates import apply_templates
from log_analyzer.processing.windows import build_windows
from tests.test_processing import make_event

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def arbitrate_events(events, matches=(), model=None, model_window=0, **kwargs):
    """Строит окна из событий и прогоняет арбитраж. model — результат модели для окна
    с номером model_window, например {"status": "anomaly", "score": 0.95}."""
    templates = apply_templates(events)
    groups = correlate_events(events)
    windows = build_windows(events, groups, templates)
    by_id = {event.event_id: event for event in events}
    for match in matches:
        # группе события присваиваются при связывании; срабатыванию правила,
        # созданному в тесте заранее, группа подставляется по его доказательству
        if match.group_id is None and match.evidence_event_ids:
            match.group_id = by_id[match.evidence_event_ids[0]].group_id
    results = []
    if model is not None:
        window = windows[model_window]
        results.append(ModelWindowResult(
            window.window_start, model["status"], model.get("score"),
            model.get("threshold", .9), model.get("deviations", []),
        ))
    decisions: list[dict] = []
    incidents = arbitrate(
        run_id="run", dataset_id="dataset-test", windows=windows, events=events,
        rule_matches=list(matches), model_results=results,
        model_id="model" if results else None, decisions=decisions, **kwargs,
    )
    return incidents, decisions, windows


def four_requests():
    return [make_event(index, request_id=f"r-{index}", status=200) for index in range(4)]


@pytest.mark.typical
def test_rule_with_anomaly_is_reported_as_confirmed_known_cause():
    """Совпадение правила и аномалии даёт инцидент известного типа с подтверждённой гипотезой и поясняющими полями.

    Компоненты: решатель задач (арбитраж)
    Ожидается: вид known_with_anomaly, уверенность rule_confirmed, гипотеза правила, число затронутых запросов и повторов признака, отклонившиеся признаки
    """
    events = four_requests()
    matches = [RuleMatch("RULE_A@1", "cause_a", "high", "check_a", [event.event_id for event in events], group_id=events[0].group_id, title="Причина А")]
    incidents, _, _ = arbitrate_events(events, matches, {
        "status": "anomaly", "score": .93,
        "deviations": [{"feature": "r_5xx", "value": 1.0, "baseline_mean": 0.0, "baseline_std": 0.0, "z": 12.0}],
    })
    incident = incidents[0]
    assert incident.kind == "known_with_anomaly"
    assert incident.confidence == "rule_confirmed"
    assert incident.hypothesis == "cause_a"
    assert incident.severity == "high"
    assert incident.features["affected_requests"] == 4
    assert incident.features["rule_matches"] == 1
    assert incident.features["hypotheses"] == [{"hypothesis": "cause_a", "title": "Причина А", "severity": "high", "rules": ["RULE_A@1"]}]
    assert incident.features["deviations"][0]["feature"] == "r_5xx"
    assert incident.review_required is False


@pytest.mark.typical
def test_unknown_anomaly_has_no_invented_cause():
    """Аномалия без сработавшего правила не получает предметной причины.

    Компоненты: решатель задач (арбитраж)
    Ожидается: вид unknown_anomaly, гипотеза пуста, уверенность model_only, в доказательствах все записи окна как контекст
    """
    events = four_requests()
    incidents, _, _ = arbitrate_events(events, model={"status": "anomaly", "score": .97})
    incident = incidents[0]
    assert incident.kind == "unknown_anomaly"
    assert incident.hypothesis is None
    assert incident.confidence == "model_only"
    assert incident.recommendation == "inspect_feature_values"
    assert incident.severity == "high"
    assert incident.evidence_items
    assert {item.role for item in incident.evidence_items} == {"context"}
    assert incident.features["affected_requests"] == 4
    assert incident.features["rule_matches"] == 0


@pytest.mark.boundary
def test_anomaly_severity_depends_on_model_score():
    """Аномалия без правил получает высокую значимость только при оценке не ниже 0,9.

    Компоненты: решатель задач (арбитраж)
    Ожидается: оценка 0,89 — средняя значимость, оценка 0,9 — высокая
    """
    events = four_requests()
    medium = arbitrate_events(events, model={"status": "anomaly", "score": .89, "threshold": .85})[0][0]
    high = arbitrate_events(events, model={"status": "anomaly", "score": .9, "threshold": .85})[0][0]
    assert (medium.severity, high.severity) == ("medium", "high")


@pytest.mark.typical
def test_conflicting_rules_require_review_and_keep_both():
    """Правила с разными гипотезами дают конфликт: инцидент требует ручной проверки, обе гипотезы сохранены.

    Компоненты: решатель задач (арбитраж)
    Ожидается: вид rule_conflict, флаг review_required, в перечне гипотез обе причины, сработавшие правила сохранены
    """
    events = four_requests()
    event = events[0]
    matches = [
        RuleMatch("RULE_A@1", "cause_a", "high", "check_a", [event.event_id], group_id=event.group_id, title="Причина А"),
        RuleMatch("RULE_B@1", "cause_b", "medium", "check_b", [event.event_id], group_id=event.group_id),
    ]
    incidents, _, _ = arbitrate_events(events, matches)
    incident = incidents[0]
    assert incident.kind == "rule_conflict"
    assert incident.review_required is True
    assert incident.severity == "high"
    assert incident.rule_ids == ["RULE_A@1", "RULE_B@1"]
    assert [item["hypothesis"] for item in incident.features["hypotheses"]] == ["cause_a", "cause_b"]
    assert len(incident.features["rule_outcomes"]) == 2


@pytest.mark.typical
def test_incident_service_follows_error_signature():
    """Сервис инцидента берётся из записей с приметой ошибки, даже если в окне преобладает другой сервис.

    Компоненты: решатель задач (арбитраж)
    Ожидается: инцидент отнесён к auth-api по сообщению приложения, а не к shop-web, записей которого в окне больше
    """
    access = [make_event(index, request_id=f"auth-{index}", service="shop-web", route="/api/session", status=401) for index in range(3)]
    application = make_event(3, request_id="auth-0", service="auth-api", route="/api/session", status=401, message="token rejected: unexpected issuer")
    events = access + [application]
    match = RuleMatch(
        "AUTH@1", "authentication_issuer_mismatch", "high", "compare", [event.event_id for event in events],
        group_id=application.group_id, signature_event_ids=[application.event_id],
    )
    incident = arbitrate_events(events, [match])[0][0]
    assert incident.service == "auth-api"
    assert incident.route == "/api/session"


@pytest.mark.typical
def test_protocol_records_decision_for_every_window():
    """Протокол содержит решение по каждому окну, включая окна без инцидента.

    Компоненты: решатель задач (арбитраж)
    Ожидается: два окна: в первом признаков нет и указана причина no_signals, во втором правило и модель дали инцидент
    """
    quiet = [make_event(index, request_id=f"q-{index}") for index in range(4)]
    busy = [make_event(0, observed_at=START + timedelta(seconds=70 + index), request_id=f"b-{index}", status=504) for index in range(4)]
    events = quiet + busy
    match = RuleMatch("UP@1", "upstream_timeout", "high", "check", [event.event_id for event in busy], group_id=busy[0].group_id)
    incidents, decisions, windows = arbitrate_events(
        events, [match], {"status": "anomaly", "score": .96}, model_window=1,
    )
    assert len(decisions) == 2 == len(windows)
    assert decisions[0]["decision"] == {"kind": None, "reason": "no_signals", "incident_id": None}
    assert decisions[1]["decision"]["kind"] == "known_with_anomaly"
    assert decisions[1]["rule_matches"][0]["rule"] == "UP@1"
    assert decisions[1]["model"]["status"] == "anomaly"
    assert set(decisions[0]["features"]) == {"n_req", "r_401", "r_4xx", "r_5xx", "q_095_duration_ms", "n_retry", "n_tpl", "n_new", "r_uncertain"}
    assert incidents[0].id == decisions[1]["decision"]["incident_id"]


@pytest.mark.boundary
def test_insufficient_window_does_not_create_normal_or_anomaly_incident():
    """Окно с недостатком данных не даёт инцидента по модели: оценка не выполняется.

    Компоненты: решатель задач (арбитраж), модель Isolation Forest
    Ожидается: инцидентов нет; в протоколе причина insufficient_data
    """
    events = [make_event(0), make_event(1)]
    incidents, decisions, windows = arbitrate_events(events, model={"status": "insufficient_data"})
    assert len(windows) == 1
    assert incidents == []
    assert decisions[0]["decision"]["reason"] == "insufficient_data"


@pytest.mark.boundary
def test_rule_in_insufficient_window_is_flagged_as_unconfirmed(monkeypatch):
    """Срабатывание правила в окне с малым числом запросов по умолчанию даёт инцидент с предупреждением, а при запрете — только запись в протоколе.

    Компоненты: решатель задач (арбитраж)
    Ожидается: по умолчанию инцидент known с предупреждением о малом числе запросов; при RULES_IN_INSUFFICIENT_WINDOWS=false инцидента нет
    """
    events = [make_event(0, status=504), make_event(1, status=504)]
    match = RuleMatch("UP@1", "upstream_timeout", "high", "check", [event.event_id for event in events], group_id=events[0].group_id)
    incidents, _, _ = arbitrate_events(events, [match], {"status": "insufficient_data"})
    assert incidents[0].kind == "known"
    assert incidents[0].warnings == [engine_module.INSUFFICIENT_WARNING]
    monkeypatch.setattr(engine_module, "RULES_IN_INSUFFICIENT_WINDOWS", False)
    incidents, decisions, _ = arbitrate_events(events, [match], {"status": "insufficient_data"})
    assert incidents == []
    assert decisions[0]["decision"] == {"kind": None, "reason": "insufficient_data", "incident_id": None}


@pytest.mark.negative
def test_unavailable_model_is_recorded_in_incident_warnings():
    """Недоступность модели не мешает правилу дать инцидент; ограничение фиксируется в предупреждении.

    Компоненты: решатель задач (арбитраж)
    Ожидается: инцидент known с предупреждением model_unavailable
    """
    events = four_requests()
    event = events[0]
    match = RuleMatch("RULE_A@1", "cause_a", "medium", "check_a", [event.event_id], group_id=event.group_id)
    incidents, _, _ = arbitrate_events(events, [match], model_warning="model_unavailable: Simulated model unavailability")
    assert incidents[0].kind == "known"
    assert incidents[0].severity == "medium"
    assert incidents[0].warnings == ["model_unavailable: Simulated model unavailability"]
