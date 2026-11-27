from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from log_analyzer.contracts import CanonicalEvent, RuleDefinition
from log_analyzer.knowledge.rules import (
    RuleEngine, add_rule_version, latest_rules, read_rule_file, record_from_definition, sync_default_rules,
)
from log_analyzer.processing.correlation import correlate_events
from log_analyzer.processing.templates import apply_templates
from log_analyzer.processing.windows import build_windows
from log_analyzer.storage.models import RuleRecord

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
OUTCOME = {
    "hypothesis": "test_cause", "severity": "low",
    "recommendation": "test_recommendation", "evidence": ["status"],
}


def event(index, **overrides):
    values = dict(
        event_id=f"e{index}", dataset_id="d", observed_at=START + timedelta(seconds=index),
        source_type="application_json", service="web", request_id=f"r-{index}",
        method="GET", route="/api/x", status=200, message="request completed", raw=f"raw-{index}",
    )
    values.update(overrides)
    return CanonicalEvent(**values)


def definition(**fields):
    values = {"id": "TEST_RULE", "version": 1, "scope": "group", "when": {"status_in": [500]}, "then": dict(OUTCOME)}
    values.update(fields)
    return RuleDefinition.model_validate(values)


def rule(**fields):
    return record_from_definition(definition(**fields))


def pipeline(events):
    templates = apply_templates(events)
    groups = correlate_events(events)
    return templates, groups, build_windows(events, groups, templates)


@pytest.mark.typical
def test_default_knowledge_base_is_valid():
    """Файл базы знаний по умолчанию проходит проверку и содержит правила с заголовками для интерфейса.

    Компоненты: база знаний
    Ожидается: два правила уровня группы, у каждого заполнены гипотеза, значимость, рекомендация, доказательства и заголовок
    """
    rules = read_rule_file()
    assert [item.id for item in rules] == ["AUTH_ISSUER_MISMATCH", "UPSTREAM_TIMEOUT"]
    for item in rules:
        assert item.scope == "group"
        assert {"hypothesis", "severity", "recommendation", "evidence"} <= set(item.then)
        assert item.then["title"]
        assert record_from_definition(item).presentation["title"] == item.then["title"]


@pytest.mark.typical
def test_event_scope_rule_fires_on_single_event():
    """Правило с областью действия «событие» применяется к отдельной записи, а не к группе или окну.

    Компоненты: база знаний, решатель задач (машина правил)
    Ожидается: правило находит единственную запись с кодом 500 и текстом примеси; записи с другими кодами не затронуты
    """
    events = [event(0, status=200), event(1, status=500, message="unhandled exception in checkout"), event(2, status=500, message="all good")]
    templates, groups, windows = pipeline(events)
    engine = RuleEngine([rule(scope="event", when={"status_in": [500], "message_contains": "exception"})], templates)
    matches = engine.evaluate(groups, windows, events)
    assert [match.event_id for match in matches] == ["e1"]
    assert matches[0].scope == "event"
    assert matches[0].group_id == events[1].group_id
    assert matches[0].evidence_event_ids == ["e1"]


@pytest.mark.typical
def test_template_condition_checks_template_not_each_message():
    """Условие template_contains проверяет шаблон сообщения, а не текст каждой записи.

    Компоненты: база знаний, решатель задач (машина правил), шаблонизация сообщений
    Ожидается: оба сообщения относятся к шаблону первого; условие по примете первого сообщения срабатывает дважды, по примете второго — ни разу
    """
    events = [event(0, message="payment error code=17"), event(1, message="payment error code=18")]
    templates, groups, windows = pipeline(events)
    assert events[0].template_id == events[1].template_id
    by_first = RuleEngine([rule(when={"template_contains": "code=17"})], templates).evaluate(groups, windows, events)
    by_second = RuleEngine([rule(when={"template_contains": "code=18"})], templates).evaluate(groups, windows, events)
    assert len(by_first) == 2
    assert by_second == []


@pytest.mark.typical
def test_rules_of_all_scopes_are_evaluated_together():
    """Правила трёх областей действия применяются за один проход и попадают в общий перечень срабатываний.

    Компоненты: решатель задач (машина правил)
    Ожидается: по одному срабатыванию для областей event, group и window
    """
    events = [event(index, status=504, message="upstream timed out") for index in range(4)]
    templates, groups, windows = pipeline(events)
    engine = RuleEngine([
        rule(id="E_RULE", scope="event", when={"status_in": [504]}),
        rule(id="G_RULE", scope="group", when={"status_in": [504]}, then={**OUTCOME, "hypothesis": "group_cause"}),
        rule(id="W_RULE", scope="window", when={"min_requests": 3, "status_ratio_gte": 1.0, "status_in": [504]}, then={**OUTCOME, "hypothesis": "window_cause"}),
    ], templates)
    matches = engine.evaluate(groups, windows, events)
    assert sorted({match.scope for match in matches}) == ["event", "group", "window"]
    window_match = next(match for match in matches if match.scope == "window")
    assert window_match.window_start == windows[0].window_start


@pytest.mark.typical
def test_versions_are_immutable_and_latest_is_applied(db):
    """Новая версия правила добавляется, старая сохраняется, применяется только последняя.

    Компоненты: база знаний
    Ожидается: версия 2 принята; повторная публикация версии 1 отклонена; действует версия 2
    """
    text = """
id: VERSIONED
version: 1
scope: group
when:
  status_in: [500]
then:
  hypothesis: first_cause
  severity: low
  recommendation: check
  evidence: [status]
"""
    add_rule_version(db, text)
    updated = add_rule_version(db, text.replace("version: 1", "version: 2").replace("first_cause", "second_cause"))
    assert updated.key == "VERSIONED@2"
    with pytest.raises(ValueError, match="old versions are immutable"):
        add_rule_version(db, text)
    assert [item.key for item in latest_rules(db)] == ["VERSIONED@2"]
    assert db.get(RuleRecord, "VERSIONED@1") is not None


@pytest.mark.boundary
def test_conditions_are_checked_against_scope():
    """Условие, не относящееся к области действия правила, отклоняется при проверке.

    Компоненты: база знаний
    Ожидается: min_requests не допускается для группы, related_events_gte — для события, message_contains — для окна
    """
    cases = [
        ("group", {"min_requests": 5}),
        ("group", {"status_ratio_gte": 0.5, "status_in": [500]}),
        ("event", {"related_events_gte": 2}),
        ("event", {"min_requests": 5}),
        ("window", {"message_contains": "timeout"}),
        ("window", {"template_contains": "timeout"}),
    ]
    for scope, when in cases:
        with pytest.raises(ValidationError, match="not applicable to scope"):
            definition(scope=scope, when=when)


@pytest.mark.boundary
def test_condition_values_are_validated():
    """Недопустимые значения условий и бессмысленные сочетания отклоняются.

    Компоненты: база знаний
    Ожидается: status_ratio_gte без status_in, коды вне диапазона 100–599, доля больше 1, пустая строка и нулевой порог отклонены
    """
    bad = [
        {"status_ratio_gte": 0.5},
        {"status_in": []},
        {"status_in": [999]},
        {"status_in": ["500"]},
        {"status_in": [500], "status_ratio_gte": 1.5},
        {"message_contains": "   "},
        {"related_events_gte": 0},
    ]
    for when in bad:
        with pytest.raises(ValidationError):
            definition(when=when)


@pytest.mark.negative
def test_malformed_rules_are_rejected():
    """Правила с опечатками, без обязательных полей и с неверной значимостью не проходят проверку.

    Компоненты: база знаний
    Ожидается: неизвестное условие, отсутствующая рекомендация и недопустимая значимость дают ошибку проверки
    """
    with pytest.raises(ValidationError, match="Unsupported conditions"):
        definition(when={"status_contains": [500]})
    with pytest.raises(ValidationError, match="Missing outcome fields"):
        definition(then={"hypothesis": "h", "severity": "low", "evidence": []})
    with pytest.raises(ValidationError, match="Unsupported severity"):
        definition(then={**OUTCOME, "severity": "urgent"})


@pytest.mark.negative
def test_duplicate_of_existing_rule_is_rejected(db):
    """Правило, дублирующее условия уже опубликованного под другим именем, отклоняется.

    Компоненты: база знаний
    Ожидается: ошибка с указанием правила-оригинала; в базе остаётся одно правило
    """
    add_rule_version(db, """
id: ORIGINAL
version: 1
scope: group
when:
  status_in: [502]
then:
  hypothesis: gateway_down
  severity: high
  recommendation: check_gateway
  evidence: [status]
""")
    with pytest.raises(ValueError, match="duplicates ORIGINAL@1"):
        add_rule_version(db, """
id: COPY
version: 1
scope: group
when:
  status_in: [502]
then:
  hypothesis: other_cause
  severity: low
  recommendation: other
  evidence: [status]
""")
    assert [item.key for item in latest_rules(db)] == ["ORIGINAL@1"]


@pytest.mark.negative
def test_sync_keeps_stored_version_when_file_diverges(db):
    """Синхронизация с файлом не перезаписывает опубликованную версию, о расхождении сообщается.

    Компоненты: база знаний
    Ожидается: изменённое в базе правило не перезаписано; его ключ возвращён как расходящийся
    """
    sync_default_rules(db)
    stored = next(item for item in latest_rules(db) if item.id == "UPSTREAM_TIMEOUT")
    stored.hypothesis = "edited_in_database"
    db.commit()
    diverged = sync_default_rules(db)
    assert diverged == ["UPSTREAM_TIMEOUT@1"]
    assert next(item for item in latest_rules(db) if item.id == "UPSTREAM_TIMEOUT").hypothesis == "edited_in_database"


@pytest.mark.boundary
def test_engine_without_rules_and_templates_makes_no_matches():
    """Пустая база знаний и отсутствие шаблонов не приводят к ошибке машины правил.

    Компоненты: решатель задач (машина правил)
    Ожидается: срабатываний нет; условие template_contains без шаблона проверяется по тексту сообщения
    """
    events = [event(0, status=500, message="database refused connection")]
    templates, groups, windows = pipeline(events)
    assert RuleEngine([]).evaluate(groups, windows, events) == []
    fallback = RuleEngine([rule(when={"template_contains": "refused"})]).evaluate(groups, windows, events)
    assert len(fallback) == 1
