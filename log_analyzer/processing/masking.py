from __future__ import annotations

import re
from typing import Any

MASK = "<masked>"

_SECRET_KEY = (
    r"(?:authorization|proxy[-_ ]authorization|token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|password|passwd|pwd|secret|client[-_]?secret|api[-_]?key|x[-_]api[-_]key|"
    r"access[-_]?key|private[-_]?key|jwt|otp|credential(?:s)?|session(?:[-_]?id)?|signature|sig)"
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.+?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])"
)
_SCHEME_RE = re.compile(r"\b(bearer|basic|token)\s+([A-Za-z0-9\-._~+/=]{12,})", re.IGNORECASE)
_SET_COOKIE_RE = re.compile(
    r"([\"']?\bset[-_]cookie\b[\"']?\s*[:=]\s*[\"']?)([^\r\n\"']+)", re.IGNORECASE
)
_COOKIE_RE = re.compile(
    r"([\"']?\bcookie\b[\"']?\s*[:=]\s*[\"']?)([^\s\"';=]+=[^\s\"';]*(?:;\s*[^\s\"';=]+=[^\s\"';]*)*)",
    re.IGNORECASE,
)
_KV_RE = re.compile(
    rf"([\"']?\b{_SECRET_KEY}\b[\"']?\s*[:=]\s*[\"']?(?:(?:bearer|basic)\s+)?)"
    rf"([^\s,;&\"'}}\]]+)",
    re.IGNORECASE,
)
_SECRET_KEY_RE = re.compile(rf"^{_SECRET_KEY}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP_RE = re.compile(r"\b((?:\d{1,3}\.){3})\d{1,3}\b")


def _looks_like_token(value: str) -> bool:
    """Отличает секрет от обычного слова после scheme: у секрета есть цифры,
    символы или смешанный регистр."""
    if any(ch.isdigit() for ch in value):
        return True
    return any(ch.islower() for ch in value) and any(ch.isupper() for ch in value)


def _mask_scheme(match: re.Match) -> str:
    value = match.group(2)
    if _looks_like_token(value):
        return f"{match.group(1)} {MASK}"
    return match.group(0)


def mask_secrets(text: str) -> str:
    """Скрывает учётные данные и ключи в свободном тексте: пары «ключ: значение»,
    заголовки Authorization и Cookie, JWT и блоки закрытых ключей. Обычные слова
    после слов token, secret и подобных не затрагиваются. Повторное применение
    не меняет результат."""
    text = _PRIVATE_KEY_RE.sub(MASK, text)
    text = _JWT_RE.sub(MASK, text)
    text = _SCHEME_RE.sub(_mask_scheme, text)
    text = _SET_COOKIE_RE.sub(lambda match: f"{match.group(1)}{MASK}", text)
    text = _COOKIE_RE.sub(lambda match: f"{match.group(1)}{MASK}", text)
    return _KV_RE.sub(lambda match: f"{match.group(1)}{MASK}", text)


def mask_ip(value: str | None) -> str | None:
    """Скрывает последний октет IPv4-адресов, прочий текст не меняет."""
    if not value:
        return value
    return _IP_RE.sub(r"\1" + MASK, value)


def mask_for_display(text: str | None) -> str:
    """Маскирование при выводе: секреты, адреса электронной почты, последний
    октет IPv4-адресов."""
    if not text:
        return text or ""
    return _IP_RE.sub(r"\1" + MASK, _EMAIL_RE.sub("<masked-email>", mask_secrets(text)))


def _map_value(value: Any, mask_text, key: str | None = None) -> Any:
    if isinstance(value, str):
        # Значение поля с именем секрета (password, token, api_key...) скрывается целиком.
        if key is not None and _SECRET_KEY_RE.match(key):
            return MASK
        return mask_text(value)
    if isinstance(value, dict):
        return {name: _map_value(item, mask_text, name) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_map_value(item, mask_text) for item in value]
    return value


def protect_value(value: Any) -> Any:
    """Рекурсивно скрывает секреты в строках вложенной структуры (для хранения)."""
    return _map_value(value, mask_secrets)


def mask_value(value: Any) -> Any:
    """Рекурсивно применяет маскирование при выводе к вложенной структуре."""
    return _map_value(value, mask_for_display)
