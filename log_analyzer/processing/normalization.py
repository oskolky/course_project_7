from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def parse_timestamp(value: object, default_timezone: str = "UTC") -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, (int, float)):
        result = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        parsed = None
        formats = (
            "%d/%b/%Y:%H:%M:%S %z", "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S", "%Y-%m-%d %H:%M:%S",
        )
        for fmt in formats:
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
                    raise ValueError(f"Unsupported timestamp: {value!r}") from exc
        result = parsed
    else:
        raise ValueError("Timestamp is required")
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
        return float(value) * multiplier
    except (TypeError, ValueError):
        return None


def as_int(value: object) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
