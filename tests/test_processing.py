from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from log_analyzer.contracts import CanonicalEvent
from log_analyzer.ingestion.adapters import MSG_ACCESS, ingest_text_sources
from log_analyzer.processing.correlation import correlate_events
from log_analyzer.processing.normalization import NormalizationError, as_float, parse_timestamp
from log_analyzer.processing.templates import apply_templates
from log_analyzer.processing.windows import build_windows, window_start_of
from log_analyzer.storage.models import RequestGroupRecord


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


@pytest.mark.typical
def test_nginx_normalization_and_uuid_route():
    """Запись журнала доступа NGINX разбирается, идентификатор в пути заменяется плейсхолдером, время приводится к UTC.

    Компоненты: загрузка и нормализация
    Ожидается: запись принята, маршрут /api/item/{id}, смещение +0300 учтено, исходная строка сохранена
    """
    line = '10.0.0.1 - - [27/Oct/2026:10:00:00 +0300] "GET /api/item/123e4567-e89b-12d3-a456-426614174000 HTTP/1.1" 200 10 "-" "agent" 0.025 - req-1'
    result = ingest_text_sources([("access.log", line, "nginx", "web")], "dataset-test")
    assert result.rejected_count == 0
    event = result.events[0]
    assert event.route == "/api/item/{id}"
    assert event.observed_at.hour == 7
    assert event.duration_ms == 25
    assert event.raw == line


@pytest.mark.typical
def test_access_log_variants_are_accepted():
    """Распространённые нестандартные записи журнала доступа принимаются: пустой запрос, формат common, экранированные кавычки, бинарный запрос, прочерки.

    Компоненты: загрузка и нормализация
    Ожидается: пять записей приняты; у записи без запроса метод не определён; прочерк вместо кода даёт пустой код ответа
    """
    lines = [
        '10.0.0.5 - - [27/Oct/2026:10:00:00 +0000] "-" 400 0 "-" "-"',
        '10.0.0.6 - - [27/Oct/2026:10:00:01 +0000] "GET / HTTP/1.0" 200 612',
        '10.0.0.9 - - [27/Oct/2026:10:00:03 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla \\"x\\" 5.0"',
        '10.0.0.10 - - [27/Oct/2026:10:00:04 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"',
        '10.0.0.11 - - [27/Oct/2026:10:00:05 +0000] "GET / HTTP/1.1" - - "-" "-"',
    ]
    result = ingest_text_sources([("access.log", "\n".join(lines), "nginx", "web")], "dataset-test")
    assert result.rejected_count == 0
    events = result.events
    assert [event.status for event in events] == [400, 200, 200, 400, None]
    assert events[0].method is None
    assert events[2].attributes["user_agent"] == 'Mozilla \\"x\\" 5.0'


@pytest.mark.typical
def test_timestamp_formats():
    """Отметки времени в текстовых форматах, в секундах и в миллисекундах эпохи распознаются.

    Компоненты: нормализация
    Ожидается: все значения дают одно и то же время в UTC
    """
    expected = datetime(2026, 10, 27, 10, 0, 10, tzinfo=timezone.utc)
    assert parse_timestamp("27.10.2026 10:00:10") == expected
    assert parse_timestamp("27/Oct/2026:10:00:10 +0000") == expected
    assert parse_timestamp("2026-10-27T10:00:10.020000Z") == expected + timedelta(milliseconds=20)
    epoch = expected.timestamp()
    assert parse_timestamp(int(epoch)) == expected
    assert parse_timestamp(int(epoch * 1000)) == expected
    assert parse_timestamp(str(int(epoch * 1000))) == expected


@pytest.mark.negative
def test_bad_timestamp_is_reported_understandably():
    """Нераспознанная отметка времени отклоняется с понятным описанием, а не внутренним кодом ошибки.

    Компоненты: нормализация, диагностика загрузки
    Ожидается: для каждого недопустимого значения — NormalizationError с текстом на русском языке
    """
    for value in (None, "", "not a date", "27.13.2026 10:00:10", 1e30, float("nan"), True, [2026]):
        with pytest.raises(NormalizationError) as info:
            parse_timestamp(value)
        assert info.value.message in ("отсутствует обязательное поле отметки времени", "отметка времени не распознана")
    result = ingest_text_sources([("app.jsonl", '{"observed_at": 179309521100000000000, "message": "x"}', "jsonl", "web")], "d")
    issue = result.issues[0]
    assert issue.error == "отметка времени не распознана"
    assert issue.detail and "значение" in issue.detail


@pytest.mark.negative
def test_unrecognized_line_is_reported_with_reason():
    """Строка, не соответствующая ни одному формату, отклоняется с описанием причины и обработка продолжается.

    Компоненты: загрузка и нормализация, диагностика загрузки
    Ожидается: строка отклонена, в замечании указан формат, которого ожидала система
    """
    result = ingest_text_sources([("x.log", "это не журнал\n", "nginx", "web")], "dataset-test")
    assert result.rejected_count == 1
    assert result.issues[0].error == MSG_ACCESS
    assert result.issues[0].line_number == 1


@pytest.mark.typical
def test_broken_json_is_isolated():
    """Повреждённая строка JSON не мешает обработке соседних корректных записей.

    Компоненты: загрузка и нормализация
    Ожидается: прочитано 2 строки, принято 1, отклонена 1 с номером строки
    """
    valid = '{"observed_at":"2026-10-27T10:00:00Z","service":"web","status":200,"message":"ok"}'
    result = ingest_text_sources([("app.jsonl", valid + "\n{broken\n", "jsonl", "web")], "dataset-test")
    assert result.read_count == 2
    assert len(result.events) == 1
    assert result.rejected_count == 1
    assert result.issues[0].line_number == 2
    assert result.issues[0].error == "повреждённая запись JSON"


@pytest.mark.typical
def test_lcs_templates_group_similar_messages():
    """Похожие сообщения с разными числовыми параметрами относятся к одному шаблону.

    Компоненты: шаблонизация сообщений
    Ожидается: один шаблон с двумя вхождениями
    """
    first = make_event(0, message="connection refused: retry 3")
    second = make_event(1, message="connection refused: retry 7")
    templates = apply_templates([first, second])
    assert first.template_id == second.template_id
    assert len(templates) == 1
    assert templates[0].pattern == "connection refused: retry <*>"
    assert templates[0].occurrences == 2


@pytest.mark.typical
def test_exact_and_limited_heuristic_correlation():
    """События с общим идентификатором связываются точно; без идентификаторов — по эвристике или остаются неопределёнными.

    Компоненты: корреляция событий
    Ожидается: точная связь по request_id, предполагаемая связь для одного кандидата, неопределённая при конфликте клиентов
    """
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


def _compatible(left, right):
    if left is None or right is None:
        return True
    return left // 100 == right // 100 or left >= 500 or right >= 500


def _reference_correlate(events, delta_seconds=2.0):
    """Исходный вариант связи событий: каждое событие без идентификаторов сравнивается
    со всеми ранее созданными группами. Используется как эталон для индексированного варианта."""
    exact, heuristic, all_groups = {}, [], []

    def create(event, key, quality):
        group = RequestGroupRecord(
            id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{event.dataset_id}:group:{key}")),
            dataset_id=event.dataset_id, link_quality=quality, route=event.route,
            service=event.service, started_at=event.observed_at, ended_at=event.observed_at,
        )
        state = [group, []]
        all_groups.append(state)
        return state

    for event in sorted(events, key=lambda item: item.observed_at):
        if event.trace_id:
            key = f"trace:{event.trace_id}"
            state = exact.setdefault(key, create(event, key, "exact"))
        elif event.request_id:
            key = f"request:{event.request_id}"
            state = exact.setdefault(key, create(event, key, "exact"))
        elif event.client or event.route:
            candidates = []
            for candidate in heuristic:
                group = candidate[0]
                elapsed = (event.observed_at - group.ended_at).total_seconds()
                same_context = (
                    group.service == event.service and group.route == event.route
                    and (not event.client or not candidate[1][-1].client or candidate[1][-1].client == event.client)
                    and (not event.host or not candidate[1][-1].host or candidate[1][-1].host == event.host)
                )
                if same_context and 0 <= elapsed <= delta_seconds and _compatible(candidate[1][-1].status, event.status):
                    candidates.append(candidate)
            if len(candidates) == 1:
                state = candidates[0]
                state[0].link_quality = "presumed"
            else:
                state = create(event, f"unlinked:{event.event_id}", "uncertain")
            if state not in heuristic:
                heuristic.append(state)
        else:
            state = create(event, f"unlinked:{event.event_id}", "uncertain")
        state[1].append(event)
        state[0].ended_at = event.observed_at
        if state[0].route is None:
            state[0].route = event.route
        event.group_id = state[0].id
    return [state[0] for state in all_groups]


def _links(events, groups):
    quality = {group.id: group.link_quality for group in groups}
    return {event.event_id: (event.group_id, quality[event.group_id]) for event in events}


@pytest.mark.boundary
def test_indexed_correlation_matches_full_scan():
    """Связывание с индексом даёт те же группы, что и полный перебор, на случайных потоках событий.

    Компоненты: корреляция событий
    Ожидается: на 30 случайных наборах по 120 событий распределение по группам и качество связи совпадают с эталоном
    """
    rng = random.Random(7)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for _ in range(30):
        events = []
        for index in range(120):
            kind = rng.random()
            event = make_event(
                index, observed_at=base + timedelta(seconds=rng.uniform(0, 40)),
                client=rng.choice(["10.0.0.1", "10.0.0.2", None]),
                route=rng.choice(["/a", "/b", None]),
                host=rng.choice(["h1", "h2", None]),
                service=rng.choice(["s1", "s2"]),
                status=rng.choice([200, 404, 500, None]),
            )
            if kind < 0.3:
                event.request_id = f"r-{rng.randint(0, 40)}"
            elif kind < 0.4:
                event.trace_id = f"t-{rng.randint(0, 20)}"
            events.append(event)
        reference_events = [event.model_copy() for event in events]
        expected = _links(reference_events, _reference_correlate(reference_events))
        actual_events = [event.model_copy() for event in events]
        actual = _links(actual_events, correlate_events(actual_events))
        assert actual == expected


@pytest.mark.boundary
def test_correlation_without_ids_stays_fast_on_large_log():
    """Связывание 16 000 событий без идентификаторов укладывается в секунды, а не в минуты.

    Компоненты: корреляция событий
    Ожидается: время связывания меньше 20 секунд; все события распределены по группам
    """
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        make_event(index, observed_at=base + timedelta(seconds=index), client=f"10.0.{index % 250}.{index // 250 % 250}")
        for index in range(16000)
    ]
    started = time.perf_counter()
    groups = correlate_events(events)
    elapsed = time.perf_counter() - started
    assert elapsed < 20
    assert len(groups) == len(events)
    assert all(event.group_id for event in events)


@pytest.mark.boundary
def test_small_window_is_not_false_normal():
    """Окно с числом запросов меньше порога получает статус недостатка данных, а не оценку «норма».

    Компоненты: временные окна и признаки
    Ожидается: один окно со статусом insufficient_data и двумя запросами
    """
    events = [make_event(0), make_event(1)]
    templates = apply_templates(events)
    groups = correlate_events(events)
    windows = build_windows(events, groups, templates)
    assert windows[0].status == "insufficient_data"
    assert windows[0].n_req == 2


@pytest.mark.boundary
def test_window_start_is_aligned_and_non_finite_durations_are_dropped():
    """Начало окна выровнено по эпохе; бесконечные длительности не попадают в признаки.

    Компоненты: временные окна и признаки, нормализация
    Ожидается: события одной минуты попадают в одно окно; NaN и inf дают пустую длительность
    """
    moment = datetime(2026, 10, 27, 10, 0, 37, tzinfo=timezone.utc)
    assert window_start_of(moment) == moment.replace(second=0)
    assert as_float("nan") is None
    assert as_float("inf") is None
    assert as_float("0.025", 1000) == 25.0
