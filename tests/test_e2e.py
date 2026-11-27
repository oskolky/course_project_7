from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from log_analyzer.contracts import AnalysisRequest
from log_analyzer.knowledge.rules import add_rule_version
from log_analyzer.services.analyzer import (
    create_dataset_from_records, create_dataset_from_text, execute_analysis,
    new_run, train_model,
)
from log_analyzer.storage.models import IncidentRecord, WindowDecisionRecord

START = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
SAMPLES = Path(__file__).resolve().parent.parent / "samples"


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


@pytest.mark.typical
def test_e2e_01_auth_growth_has_rule_and_evidence(db):
    """E2E-01. Рост ответов 401 с приметой «unexpected issuer» распознаётся правилом базы знаний.

    Компоненты: загрузка, шаблонизация, корреляция, база знаний, решатель (арбитраж), хранилище
    Ожидается: один инцидент known с гипотезой authentication_issuer_mismatch, правилом AUTH_ISSUER_MISMATCH@1 и четырьмя доказательствами
    """
    dataset = make_dataset(db, auth_records())
    run = analyze(db, dataset)
    found = incidents(db, run)
    assert len(found) == 1
    assert found[0].hypothesis == "authentication_issuer_mismatch"
    assert found[0].rule_ids == ["AUTH_ISSUER_MISMATCH@1"]
    assert len(found[0].evidence_items) == 4
    assert found[0].service == "auth-api"


@pytest.mark.typical
def test_e2e_02_mass_404_is_anomaly_without_confirmed_cause(db):
    """E2E-02. Массовые ответы 404 не описаны правилом; отклонение находит модель.

    Компоненты: модель Isolation Forest, решатель (арбитраж)
    Ожидается: инцидент unknown_anomaly без гипотезы, оценка не ниже порога
    """
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


@pytest.mark.typical
def test_e2e_03_upstream_timeout_rule(db):
    """E2E-03. Тайм-ауты upstream (запись доступа с 504 и сообщение приложения) связываются и распознаются правилом.

    Компоненты: загрузка, корреляция, база знаний, решатель (арбитраж)
    Ожидается: инцидент с гипотезой upstream_timeout, правило UPSTREAM_TIMEOUT@1
    """
    records = []
    for index in range(2):
        records.append(record(index * 2, f"up-{index}", 504, "GET /api/checkout -> 504", "/api/checkout", seconds=index * 2))
        records.append(record(index * 2 + 1, f"up-{index}", 504, "upstream timed out while reading response header", "/api/checkout", seconds=index * 2))
    dataset = make_dataset(db, records)
    run = analyze(db, dataset)
    found = incidents(db, run)
    assert found[0].hypothesis == "upstream_timeout"
    assert found[0].rule_ids == ["UPSTREAM_TIMEOUT@1"]


@pytest.mark.boundary
def test_e2e_04_missing_ids_are_not_exact_links(db):
    """E2E-04. Записи без идентификаторов запроса и трассировки не выдаются за точные связи.

    Компоненты: корреляция событий
    Ожидается: у всех событий нет идентификаторов; ни одна группа не имеет качество exact
    """
    from log_analyzer.services.analyzer import load_context

    dataset = make_dataset(db, [record(index, None, seconds=index) for index in range(2)])
    events, groups, _, _ = load_context(db, dataset.id)
    assert all(event.request_id is None and event.trace_id is None for event in events)
    assert all(group.link_quality != "exact" for group in groups)


@pytest.mark.negative
def test_e2e_05_broken_json_does_not_drop_dataset(db):
    """E2E-05. Повреждённая строка JSON регистрируется как замечание и не теряет набор данных.

    Компоненты: загрузка и нормализация, диагностика загрузки
    Ожидается: прочитано 2, принято 1, отклонено 1; набор сохранён
    """
    valid = '{"observed_at":"2026-10-27T12:00:00Z","service":"web","request":{"request_id":"ok","status":200},"message":"ok"}'
    dataset = create_dataset_from_text(db, str(uuid.uuid4()), "broken", [("app.jsonl", valid + "\n{bad\n", "jsonl", "web")])
    assert dataset.stats["read_count"] == 2
    assert dataset.stats["normalized_count"] == 1
    assert dataset.stats["rejected_count"] == 1


@pytest.mark.negative
def test_e2e_06_unavailable_model_leaves_rules_and_warning(db):
    """E2E-06. При недоступности модели запуск завершается, правило срабатывает, ограничение зафиксировано.

    Компоненты: модель Isolation Forest, решатель (арбитраж)
    Ожидается: статус completed, model_status unavailable, предупреждение model_unavailable, инцидент по правилу сохранён
    """
    baseline = baseline_dataset(db)
    model = train_model(db, baseline.id, .08, .95)
    dataset = make_dataset(db, auth_records())
    run = analyze(db, dataset, model.id, fail_model=True)
    found = incidents(db, run)
    assert run.status == "completed"
    assert run.stats["model_status"] == "unavailable"
    assert run.warnings[0].startswith("model_unavailable")
    assert found[0].hypothesis == "authentication_issuer_mismatch"
    assert any(notice["code"] == "model_unavailable" for notice in run.stats["notices"])


@pytest.mark.boundary
def test_e2e_07_small_observation_returns_insufficient_data(db):
    """E2E-07. Окно с числом запросов ниже порога получает insufficient_data и не даёт инцидента.

    Компоненты: временные окна и признаки, модель Isolation Forest, решатель (арбитраж)
    Ожидается: одно окно insufficient_data, инцидентов нет, в уведомлениях — сообщение о недостатке данных
    """
    baseline = baseline_dataset(db)
    model = train_model(db, baseline.id, .08, .95)
    dataset = make_dataset(db, [record(0, "one"), record(1, "two")])
    run = analyze(db, dataset, model.id)
    assert run.stats["insufficient_windows"] == 1
    assert incidents(db, run) == []
    assert any(notice["code"] == "insufficient_data" for notice in run.stats["notices"])


@pytest.mark.negative
def test_e2e_08_rule_conflict_requires_manual_review(db):
    """E2E-08. Два правила с разными гипотезами для одной группы дают конфликт и ручную проверку.

    Компоненты: база знаний, решатель (арбитраж)
    Ожидается: инцидент rule_conflict, review_required, сохранены оба правила, четыре записи в rule_outcomes
    """
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


@pytest.mark.typical
def test_e2e_09_full_hybrid_path_on_demo_logs(db):
    """E2E-09. Сквозной путь на журналах трёх форматов: загрузка → шаблоны и группы → окна → правила → модель → арбитраж → протокол.

    Компоненты: загрузка, шаблонизация, корреляция, временные окна, база знаний, модель Isolation Forest, решатель (арбитраж), хранилище
    Ожидается: 23 события, 2 окна, 8 срабатываний правил, 2 инцидента known_with_anomaly с доказательствами; протокол содержит пять шагов и решение по каждому окну
    """
    baseline_text = (SAMPLES / "baseline.jsonl").read_text(encoding="utf-8")
    baseline = create_dataset_from_text(db, str(uuid.uuid4()), "Базовый период", [("baseline.jsonl", baseline_text, "jsonl", "shop-web")])
    model = train_model(db, baseline.id, .08, .95)
    sources = [
        ("demo_access.log", (SAMPLES / "demo_access.log").read_text(encoding="utf-8"), "nginx", "shop-web"),
        ("demo_application.jsonl", (SAMPLES / "demo_application.jsonl").read_text(encoding="utf-8"), "jsonl", "auth-api"),
        ("demo_upstream_error.log", (SAMPLES / "demo_upstream_error.log").read_text(encoding="utf-8"), "error", "shop-web"),
    ]
    dataset = create_dataset_from_text(db, str(uuid.uuid4()), "Демонстрация", sources)
    assert (dataset.stats["read_count"], dataset.stats["normalized_count"], dataset.stats["rejected_count"]) == (24, 23, 1)
    run = analyze(db, dataset, model.id)
    found = sorted(incidents(db, run), key=lambda item: item.window_start)
    assert run.status == "completed"
    assert run.stats["by_kind"] == {"known_with_anomaly": 2}
    assert run.stats["rule_matches"] == 8
    assert [incident.hypothesis for incident in found] == ["authentication_issuer_mismatch", "upstream_timeout"]
    assert [len(incident.evidence_items) for incident in found] == [15, 8]
    assert found[0].service == "auth-api"
    assert (found[0].features["affected_requests"], found[0].features["rule_matches"]) == (4, 4)
    assert found[0].features["title"] == "Несовпадение издателя токена при аутентификации"
    assert [step["component"] for step in run.stats["protocol"]] == ["events", "rules", "model", "arbitration", "storage"]
    decisions = list(db.scalars(select(WindowDecisionRecord).where(WindowDecisionRecord.run_id == run.id)).all())
    assert len(decisions) == run.stats["windows"] == 2
    assert all(record.kind == "known_with_anomaly" for record in decisions)


@pytest.mark.typical
def test_e2e_10_rules_only_run_is_separate_from_hybrid(db):
    """E2E-10. Для сравнения подходов один набор можно проанализировать только по правилам и гибридно; запуски не смешиваются.

    Компоненты: база знаний, модель Isolation Forest, решатель (арбитраж)
    Ожидается: два разных запуска; запуск без модели помечен model_not_requested; повторный запуск в той же конфигурации возвращает тот же идентификатор
    """
    baseline = baseline_dataset(db)
    model = train_model(db, baseline.id, .08, .95)
    target_records = [record(index, f"404-{index}", 404, "GET /assets/app.js -> 404", "/assets/app.js", seconds=index) for index in range(12)]
    dataset = make_dataset(db, target_records, "404")
    rules_only = analyze(db, dataset)
    hybrid = analyze(db, dataset, model.id)
    assert rules_only.id != hybrid.id
    assert rules_only.stats["model_status"] == "not_requested"
    assert rules_only.stats["notices"][0]["code"] == "model_not_requested"
    assert incidents(db, rules_only) == []
    assert len(incidents(db, hybrid)) == 1
    assert analyze(db, dataset, model.id).id == hybrid.id


@pytest.mark.boundary
def test_e2e_11_error_log_alone_is_enough_for_rule(db):
    """E2E-11. Набор из одного журнала ошибок без идентификаторов запросов: две записи связываются эвристикой, окно мало данных, правило находит тайм-аут.

    Компоненты: загрузка, корреляция, база знаний, решатель (арбитраж)
    Ожидается: инцидент known с предупреждением о малом числе запросов и уведомлением о недостатке данных
    """
    lines = "".join(
        f'2026/10/27 10:01:0{index} [error] 42#42: *{100 + index} upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.0.23, server: shop.local, request: "GET /api/checkout HTTP/1.1"\n'
        for index in range(2)
    )
    dataset = create_dataset_from_text(db, str(uuid.uuid4()), "errors", [("error.log", lines, "error", "shop-web")])
    assert dataset.stats["groups_by_quality"] == {"exact": 0, "presumed": 1, "uncertain": 0}
    run = analyze(db, dataset)
    found = incidents(db, run)
    assert found[0].hypothesis == "upstream_timeout"
    assert found[0].kind == "known"
    assert len(found[0].evidence_items) == 2
    assert any("мало запросов" in warning for warning in found[0].warnings)
    assert any(notice["code"] == "insufficient_data" for notice in run.stats["notices"])


@pytest.mark.negative
def test_e2e_12_nothing_recognizable_completes_with_notice(db):
    """E2E-12. Набор, в котором не распознана ни одна запись, не ломает анализ: запуск завершается с уведомлениями.

    Компоненты: загрузка и нормализация, решатель (арбитраж)
    Ожидается: статус completed, 0 окон и инцидентов, уведомления rejected_lines, nothing_to_analyse и model_not_requested
    """
    dataset = create_dataset_from_text(db, str(uuid.uuid4()), "garbage", [("g.log", "not a log line\nanother one\n", "nginx", "web")])
    run = analyze(db, dataset)
    assert run.status == "completed"
    assert (run.stats["windows"], run.stats["incidents"]) == (0, 0)
    assert {notice["code"] for notice in run.stats["notices"]} == {"rejected_lines", "nothing_to_analyse", "model_not_requested"}
