from __future__ import annotations

import pytest

from log_analyzer.ingestion.adapters import ingest_api_records, ingest_text_sources
from log_analyzer.processing.masking import mask_for_display, mask_ip, mask_secrets, mask_value


@pytest.mark.typical
def test_secrets_are_masked_in_common_formats():
    """Пароли, токены, заголовки авторизации и cookie скрываются в текстовом, JSON и URL видах.

    Компоненты: защита данных (маскирование)
    Ожидается: секретные значения заменены на <masked>, структура текста сохранена
    """
    text = (
        'password=hunter2 token=abc123 "api_key":"AKIA1234" Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.eyJzaWduIjoiYWJjIn0 '
        'Cookie: a=1; b=2 GET /reset?token=secret-value&x=1'
    )
    masked = mask_secrets(text)
    for secret in ("hunter2", "abc123", "AKIA1234", "eyJhbGciOiJIUzI1NiJ9", "a=1; b=2", "secret-value"):
        assert secret not in masked
    assert "password=<masked>" in masked
    assert "Authorization: Bearer <masked>" in masked
    assert "token=<masked>&x=1" in masked
    assert mask_secrets(masked) == masked


@pytest.mark.typical
def test_ordinary_words_are_not_masked():
    """Обычные слова после token, secret, session не скрываются: доказательства остаются читаемыми.

    Компоненты: защита данных (маскирование)
    Ожидается: фразы «token rejected», «session issued», «token_id=1001» не изменены
    """
    for text in ("token rejected: unexpected issuer", "session issued", "token_id=1001", "secret name of the service"):
        assert mask_secrets(text) == text


@pytest.mark.typical
def test_display_masking_covers_ip_email_and_nested_attributes():
    """При выводе скрываются последний октет IPv4, адреса электронной почты и секреты во вложенных атрибутах.

    Компоненты: защита данных (маскирование), REST API
    Ожидается: 10.0.0.25 → 10.0.0.<masked>, почта и секрет в атрибутах скрыты, прочие значения не тронуты
    """
    assert mask_ip("10.0.0.25") == "10.0.0.<masked>"
    assert mask_ip("example.host") == "example.host"
    assert mask_for_display("ops@example.com from 10.0.0.25") == "<masked-email> from 10.0.0.<masked>"
    assert mask_for_display("nginx/1.18.0 Mozilla/5.0") == "nginx/1.18.0 Mozilla/5.0"
    masked = mask_value({"token": "secret-value", "n": 5, "inner": {"password": "p"}, "items": ["x=10.0.0.9"]})
    assert masked == {"token": "<masked>", "n": 5, "inner": {"password": "<masked>"}, "items": ["x=10.0.0.<masked>"]}


@pytest.mark.typical
def test_secrets_are_masked_before_storage():
    """Секреты скрываются при загрузке: в хранилище они не попадают, идентификатор события не меняется.

    Компоненты: загрузка и нормализация, защита данных
    Ожидается: в исходной строке и атрибутах сохранённого события секреты уже заменены; события без секретов не изменены
    """
    line = '10.0.0.1 - - [27/Oct/2026:10:00:00 +0000] "GET /reset?token=secret-value HTTP/1.1" 200 10 "-" "agent" 0.025 - r-1'
    result = ingest_text_sources([("a.log", line, "nginx", "web")], "d")
    event = result.events[0]
    assert "secret-value" not in event.raw
    assert "token=<masked>" in event.raw
    assert event.route == "/reset"
    plain = ingest_text_sources([("a.log", '10.0.0.1 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "agent" 0.025 - r-1', "nginx", "web")], "d")
    assert plain.events[0].message == "GET /a -> 200"
    records = ingest_api_records([{"observed_at": "2026-10-27T10:00:00Z", "message": "login", "attributes": {"password": "hunter2"}}], "d")
    assert records.events[0].attributes == {"password": "<masked>"}
    assert "hunter2" not in records.events[0].raw


@pytest.mark.negative
def test_rejected_line_excerpt_is_masked_in_upload_report():
    """Фрагмент отклонённой строки в отчёте о загрузке не раскрывает секрет.

    Компоненты: защита данных (маскирование), диагностика загрузки
    Ожидается: в raw_excerpt замечания значение пароля скрыто
    """
    result = ingest_text_sources([("app.jsonl", '{"password": "hunter2", broken', "jsonl", "web")], "d")
    assert result.rejected_count == 1
    assert "hunter2" not in result.issues[0].raw_excerpt
