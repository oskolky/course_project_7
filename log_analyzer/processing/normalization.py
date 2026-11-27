from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")

TIMESTAMP_MISSING = "отсутствует обязательное поле отметки времени"
TIMESTAMP_UNRECOGNIZED = "отметка времени не распознана"

TEXT_TIMESTAMP_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%d/%b/%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y %H:%M",
    "%d.%m.%Y",
)


class NormalizationError(ValueError):
    """Ошибка разбора с описанием, понятным пользователю."""

    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message if detail is None else f"{message}: {detail}")
        self.message = message
        self.detail = detail


def _from_epoch(value: object) -> datetime:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise NormalizationError(TIMESTAMP_UNRECOGNIZED, f"значение {value!r}") from exc
    if not math.isfinite(number):
        raise NormalizationError(TIMESTAMP_UNRECOGNIZED, f"значение {value!r}")

    if number > 1e14:
        number /= 1e6
    elif number > 1e11:
        number /= 1e3
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise NormalizationError(TIMESTAMP_UNRECOGNIZED, f"значение {value!r} вне допустимого диапазона") from exc


def parse_timestamp(value: object, default_timezone: str = "UTC") -> datetime:
    if isinstance(value, bool):
        raise NormalizationError(TIMESTAMP_UNRECOGNIZED, "логическое значение")
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, (int, float)):
        result = _from_epoch(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise NormalizationError(TIMESTAMP_MISSING, "пустое значение")
        if text.isdigit():
            result = _from_epoch(text)
        else:
            parsed = None
            for fmt in TEXT_TIMESTAMP_FORMATS:
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    pass
            if parsed is None:
                try:
                    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                except ValueError:
                    try:
                        parsed = parsedate_to_datetime(text)
                    except (TypeError, ValueError) as exc:
                        raise NormalizationError(TIMESTAMP_UNRECOGNIZED, f"значение {value!r}") from exc
            result = parsed
    elif value is None:
        raise NormalizationError(TIMESTAMP_MISSING, "поле observed_at не задано")
    else:
        raise NormalizationError(TIMESTAMP_UNRECOGNIZED, f"тип {type(value).__name__}")
    if result.tzinfo is None:
        result = result.replace(tzinfo=ZoneInfo(default_timezone))
    return result.astimezone(timezone.utc)


def normalize_route(uri: str | None) -> str | None:
    if not uri:
        return None
    path = urlsplit(uri).path or "/"
    normalized: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit() or UUID_RE.match(segment) or HEX_RE.match(segment):
            normalized.append("{id}")
        else:
            normalized.append(segment)
    return "/" + "/".join(normalized) if normalized else "/"


def as_float(value: object, multiplier: float = 1.0) -> float | None:
    if value in (None, "", "-"):
        return None
    try:
        result = float(value) * multiplier
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def as_int(value: object) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
