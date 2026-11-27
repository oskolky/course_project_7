from __future__ import annotations

import pytest


def upload(client, content, analyze="false", adapter="nginx", service="web", filename="access.log"):
    return client.post(
        "/api/datasets",
        data={"adapter": adapter, "service": service, "analyze": analyze},
        files=[("files", (filename, content, "text/plain"))],
    )


def start_demo(client):
    response = client.post("/api/demo")
    assert response.status_code == 202, response.text
    return response.json()


def repeat_analysis(client, dataset_id, model_id=None):
    response = client.post("/api/analysis", json={"dataset_id": dataset_id, "model_id": model_id})
    assert response.status_code == 202, response.text
    return response.json()


def events(client, **params):
    return client.get("/api/events", params=params).json()


@pytest.mark.typical
def test_api_upload_analysis_and_masking(client):
    """API-01. Загрузка журнала доступа, анализ и маскирование адреса и токена в ответе.

    Компоненты: интерфейс (REST API), загрузка, защита данных
    Ожидается: 202; маршрут нормализован; в ответе IP и токен скрыты; повторный запрос состояния запуска даёт completed
    """
    line = '10.0.0.25 - - [27/Oct/2026:10:00:00 +0000] "GET /api/item/42?token=secret-value HTTP/1.1" 200 10 "-" "agent" 0.025 - req-1'
    response = upload(client, line, adapter="nginx", service="web", analyze="false")
    assert response.status_code == 202
    dataset = response.json()["dataset"]
    assert dataset["stats"]["total_ms"] >= dataset["stats"]["processing_ms"]
    listed = client.get("/api/events", params={"dataset_id": dataset["id"]})
    first = listed.json()[0]
    assert first["request"]["route"] == "/api/item/{id}"
    assert first["request"]["original_uri"] == "/api/item/42?token=<masked>"
    assert first["raw"].startswith("10.0.0.<masked>")
    assert first["request"]["client"] == "10.0.0.<masked>"
    assert "secret-value" not in listed.text
    run = client.post("/api/analysis", json={"dataset_id": dataset["id"]})
    assert run.status_code == 202
    assert client.get(f"/api/runs/{run.json()['id']}").json()["status"] == "completed"


@pytest.mark.typical
def test_api_demo_and_incident_evidence(client):
    """API-02. Демонстрационный сценарий: обучение модели, анализ, карточка инцидента с доказательствами и правилами.

    Компоненты: интерфейс (REST API), модель Isolation Forest, решатель (арбитраж), хранилище
    Ожидается: запуск completed; покрытие доказательствами 100 %; гипотезы authentication_issuer_mismatch и upstream_timeout; в карточке есть доказательства и правила
    """
    payload = start_demo(client)
    run = client.get(f"/api/runs/{payload['run']['id']}").json()
    assert run["status"] == "completed"
    assert run["stats"]["evidence_coverage"] == 100.0
    incidents = client.get("/api/incidents", params={"dataset_id": payload["dataset"]["id"]}).json()
    assert {item["hypothesis"] for item in incidents} == {"authentication_issuer_mismatch", "upstream_timeout"}
    detail = client.get(f"/api/incidents/{incidents[0]['incident_id']}").json()
    assert detail["evidence"]
    assert detail["rules"]
    assert detail["model"]["id"] == payload["model"]["id"]
    overview = client.get("/api/overview", params={"dataset_id": payload["dataset"]["id"]}).json()
    assert overview["summary"]["by_kind"] == {"known_with_anomaly": 2}
    assert overview["summary"]["by_severity"] == {"high": 2}
    assert overview["summary"]["by_hypothesis"] == {"authentication_issuer_mismatch": 1, "upstream_timeout": 1}


@pytest.mark.typical
def test_rule_versions_are_immutable(client):
    """API-03. Версии правил неизменяемы: повторная публикация той же версии отклоняется.

    Компоненты: интерфейс (REST API), база знаний
    Ожидается: первая публикация 201, повторная 400 с сообщением old versions are immutable
    """
    yaml_text = """
id: TEST_RULE
version: 1
scope: group
when:
  status_in: [500]
then:
  hypothesis: test_cause
  severity: low
  recommendation: test
  evidence: [status]
"""
    created = client.post("/api/rules", json={"yaml_text": yaml_text})
    assert created.status_code == 201
    assert created.json()["key"] == "TEST_RULE@1"
    duplicate = client.post("/api/rules", json={"yaml_text": yaml_text})
    assert duplicate.status_code == 400
    assert "immutable" in duplicate.json()["detail"]


@pytest.mark.typical
def test_api_events_search_filters(client):
    """API-04. Поиск записей по коду ответа, уровню, времени, источнику, идентификатору запроса, шаблону и тексту.

    Компоненты: интерфейс (REST API)
    Ожидается: каждый фильтр возвращает только подходящие записи; счётчик совпадает с числом выданных записей
    """
    lines = "\n".join([
        '10.0.0.1 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "agent" 0.010 - r-1',
        '10.0.0.2 - - [27/Oct/2026:10:00:30 +0000] "GET /missing HTTP/1.1" 404 10 "-" "agent" 0.010 - r-2',
        '10.0.0.3 - - [27/Oct/2026:10:01:10 +0000] "GET /api/checkout HTTP/1.1" 504 10 "-" "agent" 3.000 - r-3',
        '10.0.0.4 - - [27/Oct/2026:10:01:20 +0000] "POST /api/session HTTP/1.1" 401 10 "-" "agent" 0.030 - r-4',
    ]) + "\n"
    application = '{"observed_at": "2026-10-27T10:01:11Z", "source": {"type": "application_json", "service": "checkout"}, "request": {"request_id": "r-3", "status": 504}, "message": "upstream timed out"}\n'
    response = client.post("/api/datasets", data={"adapter": "auto", "service": "web", "analyze": "false"},
                           files=[("files", ("a.log", lines, "text/plain")), ("files", ("app.jsonl", application, "text/plain"))])
    dataset_id = response.json()["dataset"]["id"]
    assert len(events(client, dataset_id=dataset_id)) == 5

    def found(**params):
        return events(client, dataset_id=dataset_id, **params)

    assert len(found(status=504)) == 2
    assert len(found(status=[401, 404])) == 2
    assert len(found(severity="warn")) == 3
    assert len(found(source_type="application_json")) == 1
    assert len(found(request_id="r-3")) == 2
    assert len(found(q="checkout")) == 2
    assert len(found(route="/api/checkout")) == 1
    assert len(found(time_from="2026-10-27T10:00:20Z", time_to="2026-10-27T10:01:05Z")) == 1
    assert len(found(time_from="2026-10-27T13:00:20+03:00", time_to="2026-10-27T13:01:05+03:00")) == 1
    templates = client.get("/api/templates", params={"dataset_id": dataset_id}).json()
    assert len(found(template_id=templates[0]["template_id"])) == templates[0]["occurrences"]
    counted = client.get("/api/events/count", params={"dataset_id": dataset_id, "status": 504}).json()
    assert counted == {"count": 2}
    page = client.get("/api/events", params={"dataset_id": dataset_id, "limit": 2, "offset": 2}).json()
    assert [item["request"]["request_id"] for item in page] == ["r-3", "r-3"]


@pytest.mark.typical
def test_api_templates_and_groups_expose_grouping(client):
    """API-05. Результаты объединения записей доступны пользователю: шаблоны сообщений и группы связанных событий.

    Компоненты: интерфейс (REST API), шаблонизация сообщений, корреляция событий
    Ожидается: шаблоны отсортированы по числу вхождений; карточка группы содержит её записи и качество связи
    """
    payload = start_demo(client)
    dataset_id = payload["dataset"]["id"]
    templates = client.get("/api/templates", params={"dataset_id": dataset_id}).json()
    assert [item["occurrences"] for item in templates] == sorted((item["occurrences"] for item in templates), reverse=True)
    # 11 записей доступа с методом GET и кодами 200, 404 и 504 после маскирования чисел
    # сходны на 3 из 4 лексем и объединяются; записи POST образуют отдельный шаблон
    assert templates[0]["occurrences"] == 11
    assert sum(item["occurrences"] for item in templates) == 23
    groups = client.get("/api/groups", params={"dataset_id": dataset_id}).json()
    assert len(groups) == 15
    assert {group["link_quality"] for group in groups} == {"exact"}
    assert client.get("/api/groups", params={"dataset_id": dataset_id, "link_quality": "presumed"}).json() == []
    upstream = next(group for group in groups if group["route"] == "/api/checkout")
    detail = client.get(f"/api/groups/{upstream['group_id']}").json()
    assert detail["event_count"] == 2
    assert detail["statuses"] == [504]
    assert len(detail["events"]) == 2
    assert client.get("/api/groups/does-not-exist").status_code == 404


@pytest.mark.typical
def test_api_protocol_of_run(client):
    """API-06. Протокол запуска: этапы обработки с затратами времени и решение по каждому окну.

    Компоненты: интерфейс (REST API), решатель (арбитраж), хранилище
    Ожидается: пять шагов в порядке выполнения; по каждому окну — признаки, сработавшие правила, оценка модели и решение
    """
    payload = start_demo(client)
    protocol = client.get(f"/api/runs/{payload['run']['id']}/protocol").json()
    assert [step["component"] for step in protocol["steps"]] == ["events", "rules", "model", "arbitration", "storage"]
    assert all(step["duration_ms"] >= 0 for step in protocol["steps"])
    assert protocol["steps"][1]["summary"]["matches"] == 8
    assert protocol["steps"][2]["summary"]["status"] == "completed"
    assert len(protocol["windows"]) == 2
    for window in protocol["windows"]:
        assert window["decision"]["kind"] == "known_with_anomaly"
        assert window["model"]["status"] == "anomaly"
        assert window["rule_matches"]
    assert client.get("/api/runs/does-not-exist/protocol").status_code == 404


@pytest.mark.typical
def test_api_incident_card_separates_facts_and_interpretation(client):
    """API-07. Карточка инцидента разделяет факты, результат автоматического анализа и диагностическое предположение.

    Компоненты: интерфейс (REST API), решатель (арбитраж)
    Ожидается: указаны вид, уверенность, затронутые запросы, повторы признака, перечень гипотез, рекомендация и отклонившиеся признаки
    """
    payload = start_demo(client)
    incidents = client.get("/api/incidents", params={"dataset_id": payload["dataset"]["id"]}).json()
    auth = next(item for item in incidents if item["hypothesis"] == "authentication_issuer_mismatch")
    assert auth["kind"] == "known_with_anomaly"
    assert auth["confidence"] == "rule_confirmed"
    assert auth["service"] == "auth-api"
    assert auth["affected_requests"] == 4
    assert auth["rule_matches"] == 4
    assert auth["hypotheses"][0]["title"] == "Несовпадение издателя токена при аутентификации"
    assert "издателя токенов" in auth["recommendation_text"]
    assert auth["deviations"]
    detail = client.get(f"/api/incidents/{auth['incident_id']}").json()
    assert detail["rules"][0]["then"]["title"] == "Несовпадение издателя токена при аутентификации"
    assert any("token rejected" in item["excerpt"] for item in detail["evidence"])


@pytest.mark.typical
def test_api_review_clears_pending_flag(client):
    """API-08. Отметка ручной проверки снимает инцидент с учёта требующих проверки; снятие отметки возвращает его.

    Компоненты: интерфейс (REST API), решатель (арбитраж)
    Ожидается: после проверки review_required=False и счётчик требующих проверки равен нулю; после снятия отметки — снова истина
    """
    payload = start_demo(client)
    dataset_id = payload["dataset"]["id"]
    client.post("/api/rules", json={"yaml_text": """
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
"""})
    run = repeat_analysis(client, dataset_id, payload["model"]["id"])
    assert client.get(f"/api/runs/{run['id']}").json()["status"] == "completed"
    pending = client.get("/api/incidents", params={"dataset_id": dataset_id, "run_id": run["id"], "review_required": "true"}).json()
    assert len(pending) == 1 and pending[0]["kind"] == "rule_conflict"
    conflict_id = pending[0]["incident_id"]
    reviewed = client.patch(f"/api/incidents/{conflict_id}/review", json={"reviewed": True}).json()
    assert reviewed["reviewed_at"] is not None
    assert reviewed["review_required"] is False
    assert reviewed["hypotheses"][0]["hypothesis"] in {"authentication_issuer_mismatch", "alternative_authentication_cause"}
    assert client.get("/api/incidents", params={"dataset_id": dataset_id, "review_required": "true"}).json() == []
    overview = client.get("/api/overview", params={"dataset_id": dataset_id, "run_id": run["id"]}).json()
    assert overview["summary"]["review_required"] == 0
    reopened = client.patch(f"/api/incidents/{conflict_id}/review", json={"reviewed": False}).json()
    assert reopened["reviewed_at"] is None
    assert reopened["review_required"] is True


@pytest.mark.typical
def test_api_repeated_analysis_is_idempotent(client):
    """API-09. Повторный анализ того же набора в той же конфигурации даёт те же идентификаторы запуска и инцидентов.

    Компоненты: интерфейс (REST API), решатель (арбитраж), хранилище
    Ожидается: идентификаторы запуска и инцидентов совпадают; инциденты не дублируются; отметка проверки сохраняется
    """
    payload = start_demo(client)
    dataset_id = payload["dataset"]["id"]
    first = repeat_analysis(client, dataset_id, payload["model"]["id"])
    assert first["id"] == payload["run"]["id"]
    before = sorted(item["incident_id"] for item in client.get("/api/incidents", params={"dataset_id": dataset_id, "run_id": first["id"]}).json())
    client.patch(f"/api/incidents/{before[0]}/review", json={"reviewed": True})
    second = repeat_analysis(client, dataset_id, payload["model"]["id"])
    assert second["id"] == first["id"]
    after = sorted(item["incident_id"] for item in client.get("/api/incidents", params={"dataset_id": dataset_id, "run_id": second["id"]}).json())
    assert after == before
    assert client.get(f"/api/incidents/{before[0]}").json()["reviewed_at"] is not None
    assert len(client.get("/api/incidents", params={"dataset_id": dataset_id}).json()) == len(before)
    runs = client.get(f"/api/datasets/{dataset_id}").json()["runs"]
    assert len(runs) == 1
    assert len(client.get(f"/api/runs/{first['id']}/protocol").json()["windows"]) == 2


@pytest.mark.typical
def test_api_rules_only_run_reports_its_limits(client):
    """API-10. Запуск без модели доступен для сравнения подходов и прямо сообщает о границах результата.

    Компоненты: интерфейс (REST API), база знаний, решатель (арбитраж)
    Ожидается: model_status not_requested; уведомление model_not_requested в сводке и протоколе
    """
    payload = start_demo(client)
    dataset_id = payload["dataset"]["id"]
    run = repeat_analysis(client, dataset_id)
    stats = client.get(f"/api/runs/{run['id']}").json()["stats"]
    assert stats["model_status"] == "not_requested"
    assert stats["by_kind"] == {"known": 2}
    overview = client.get("/api/overview", params={"dataset_id": dataset_id, "run_id": run["id"]}).json()
    assert "model_not_requested" in {notice["code"] for notice in overview["notices"]}
    assert overview["run"]["id"] != payload["run"]["id"]


@pytest.mark.boundary
def test_api_delete_dataset_removes_derived_data(client):
    """API-11. Удаление набора данных удаляет события, инциденты и протокол; повторное удаление даёт 404.

    Компоненты: интерфейс (REST API), хранилище
    Ожидается: 204, затем 404; связанные записи отсутствуют
    """
    line = '10.0.0.1 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "agent" 0.01 - req-1\n'
    response = upload(client, line * 5, analyze="true")
    assert response.status_code == 202
    dataset_id = response.json()["dataset"]["id"]
    run_id = response.json()["run"]["id"]
    assert client.get(f"/api/runs/{run_id}").json()["status"] == "completed"
    assert client.delete(f"/api/datasets/{dataset_id}").status_code == 204
    assert client.get(f"/api/datasets/{dataset_id}").status_code == 404
    assert client.get("/api/events", params={"dataset_id": dataset_id}).json() == []
    assert client.get("/api/incidents", params={"dataset_id": dataset_id}).json() == []
    assert client.get(f"/api/runs/{run_id}/protocol").status_code == 404
    assert client.delete(f"/api/datasets/{dataset_id}").status_code == 404


@pytest.mark.boundary
def test_api_purge_keeps_rules_and_models(client):
    """API-12. Полная очистка реестра сохраняет базу знаний и модели; ссылка модели на удалённый набор очищается.

    Компоненты: интерфейс (REST API), хранилище, база знаний
    Ожидается: наборов и инцидентов нет; правила и модель на месте; у модели dataset_id пуст
    """
    demo = start_demo(client)
    baseline_id = next(item["id"] for item in client.get("/api/datasets").json() if item["name"] == "Базовый период")
    assert client.post("/api/maintenance/purge").status_code == 200
    assert client.get("/api/datasets").json() == []
    assert client.get("/api/incidents").json() == []
    models = client.get("/api/models").json()
    assert [model["id"] for model in models] == [demo["model"]["id"]]
    assert models[0]["dataset_id"] is None
    assert models[0]["training_summary"]["dataset_id"] == baseline_id
    assert {rule["id"] for rule in client.get("/api/rules").json()} == {"AUTH_ISSUER_MISMATCH", "UPSTREAM_TIMEOUT"}
    assert client.post("/api/models/train", json={"dataset_id": baseline_id}).status_code == 404


@pytest.mark.boundary
def test_api_small_dataset_reports_insufficient_data(client):
    """API-13. Набор с малым числом запросов анализируется, но прямо сообщает о недостатке данных.

    Компоненты: интерфейс (REST API), временные окна и признаки, решатель (арбитраж)
    Ожидается: запуск completed; в сводке одно окно с недостатком данных и соответствующее уведомление; инцидентов нет
    """
    line = '10.0.0.1 - - [27/Oct/2026:10:00:0{} +0000] "GET /a HTTP/1.1" 200 10 "-" "agent" 0.01 - req-{}\n'
    response = upload(client, line.format(1, 1) + line.format(2, 2), analyze="true")
    dataset_id = response.json()["dataset"]["id"]
    overview = client.get("/api/overview", params={"dataset_id": dataset_id}).json()
    assert overview["run"]["status"] == "completed"
    assert overview["summary"]["insufficient_windows"] == 1
    assert "insufficient_data" in {notice["code"] for notice in overview["notices"]}
    assert client.get("/api/incidents", params={"dataset_id": dataset_id}).json() == []


@pytest.mark.boundary
def test_api_upload_size_limit_is_enforced(client):
    """API-14. Ограничение размера загрузки срабатывает до обработки файла.

    Компоненты: интерфейс (REST API)
    Ожидается: файл, на одну строку превышающий 10 МиБ, отклонён с кодом 413
    """
    line = '10.0.0.1 - - [27/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "agent" 0.001 - r\n'
    count = 10 * 1024 * 1024 // len(line) + 1
    response = upload(client, line * count)
    assert response.status_code == 413
    assert client.get("/api/datasets").json() == []


@pytest.mark.negative
def test_api_rejects_invalid_inputs(client):
    """API-15. Некорректные запросы отклоняются с понятными кодами и не ломают систему.

    Компоненты: интерфейс (REST API), база знаний
    Ожидается: 400 для не-UTF-8; 413 для превышения размера; 422 для отсутствующих параметров и битого JSON; 404 для неизвестных идентификаторов; 400 для неверных правил
    """
    bad_encoding = client.post("/api/datasets", data={"adapter": "auto", "service": "x", "analyze": "false"},
                               files=[("files", ("bad.log", b"caf\xe9 broken utf8\n", "text/plain"))])
    assert bad_encoding.status_code == 400 and "UTF-8" in bad_encoding.json()["detail"]
    assert client.get("/api/events").status_code == 422
    assert client.get("/api/events", params={"dataset_id": "d", "limit": 0}).status_code == 422
    assert client.post("/api/datasets/json", content=b"{not json", headers={"Content-Type": "application/json"}).status_code == 422
    assert client.post("/api/analysis", json={"dataset_id": "nope"}).status_code == 404
    assert client.get("/api/overview", params={"dataset_id": "nope"}).status_code == 404
    assert client.post("/api/models/train", json={"dataset_id": "nope"}).status_code == 404
    assert client.get("/api/runs/nope").status_code == 404
    assert client.get("/api/incidents/nope").status_code == 404
    assert client.patch("/api/incidents/nope/review", json={"reviewed": True}).status_code == 404
    assert client.delete("/api/datasets/nope").status_code == 404
    inapplicable = client.post("/api/rules", json={"yaml_text": "id: BAD_SCOPE\nversion: 1\nscope: group\nwhen:\n  min_requests: 5\nthen:\n  hypothesis: h\n  severity: low\n  recommendation: r\n  evidence: [status]\n"})
    assert inapplicable.status_code == 400
    assert "not applicable to scope" in inapplicable.json()["detail"]
    assert client.post("/api/rules", json={"yaml_text": "not: [valid"}).status_code == 400
    assert client.post("/api/rules", json={"yaml_text": "short"}).status_code == 422
    assert client.get("/api/health").json()["status"] == "ok"


@pytest.mark.negative
def test_api_wrong_adapter_reports_every_line(client):
    """API-16. Неизвестный тип источника не теряет набор: каждая строка отклонена с понятной причиной.

    Компоненты: интерфейс (REST API), диагностика загрузки
    Ожидается: 202; нормализовано 0, отклонено все; в замечании название причины и список допустимых типов
    """
    line = '10.0.0.1 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "agent" 0.01 - req-1\n'
    response = upload(client, line * 3, adapter="foo")
    assert response.status_code == 202
    stats = response.json()["dataset"]["stats"]
    assert (stats["normalized_count"], stats["rejected_count"]) == (0, 3)
    assert stats["issues"][0]["error"] == "указан неизвестный тип источника"
    assert "jsonl" in stats["issues"][0]["detail"]


@pytest.mark.negative
def test_api_unknown_model_leaves_rules_working(client):
    """API-17. Неизвестная модель не срывает анализ: работают правила, ограничение зафиксировано.

    Компоненты: интерфейс (REST API), модель Isolation Forest, решатель (арбитраж)
    Ожидается: запуск completed; model_status unavailable; предупреждение и уведомление model_unavailable
    """
    payload = start_demo(client)
    run = repeat_analysis(client, payload["dataset"]["id"], "iforest_does_not_exist")
    stats = client.get(f"/api/runs/{run['id']}").json()
    assert stats["status"] == "completed"
    assert stats["stats"]["model_status"] == "unavailable"
    assert stats["warnings"][0].startswith("model_unavailable")
    assert "model_unavailable" in {notice["code"] for notice in stats["stats"]["notices"]}
    assert stats["stats"]["by_kind"] == {"known": 2}
