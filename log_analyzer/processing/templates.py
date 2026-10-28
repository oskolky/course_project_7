from __future__ import annotations

import hashlib
import re

from log_analyzer.config import TEMPLATE_VERSION
from log_analyzer.contracts import CanonicalEvent
from log_analyzer.storage.models import TemplateRecord

DYNAMIC_RE = re.compile(
    r"^(?:\d+(?:\.\d+)?|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|"
    r"(?:\d{1,3}\.){3}\d{1,3}|0x[0-9a-fA-F]+|[0-9a-fA-F]{16,})$"
)


def _tokens(message: str) -> list[str]:
    return re.findall(r"[\w./:=-]+|<\*>", message, flags=re.UNICODE)


def _mask_dynamic(tokens: list[str]) -> list[str]:
    return ["<*>" if DYNAMIC_RE.match(token.strip(",;[]()")) else token for token in tokens]


def _lcs(left: list[str], right: list[str]) -> list[str]:
    rows = len(left) + 1
    cols = len(right) + 1
    table = [[0] * cols for _ in range(rows)]
    for i in range(1, rows):
        for j in range(1, cols):
            if left[i - 1] == right[j - 1]:
                table[i][j] = table[i - 1][j - 1] + 1
            else:
                table[i][j] = max(table[i - 1][j], table[i][j - 1])
    result: list[str] = []
    i, j = len(left), len(right)
    while i and j:
        if left[i - 1] == right[j - 1]:
            result.append(left[i - 1])
            i -= 1
            j -= 1
        elif table[i - 1][j] >= table[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return list(reversed(result))


def apply_templates(events: list[CanonicalEvent]) -> list[TemplateRecord]:
    templates: list[TemplateRecord] = []
    token_patterns: dict[str, list[str]] = {}
    for event in sorted(events, key=lambda item: item.observed_at):
        if not event.message:
            continue
        tokens = _mask_dynamic(_tokens(event.message))
        if not tokens:
            continue
        best: TemplateRecord | None = None
        best_ratio = 0.0
        for template in templates:
            candidate = token_patterns[template.id]
            shared = _lcs(tokens, candidate)
            ratio = len(shared) / max(len(tokens), len(candidate), 1)
            if ratio > best_ratio:
                best, best_ratio = template, ratio
        if best is not None and best_ratio >= 0.6:
            best.occurrences += 1
            best.first_seen = min(best.first_seen, event.observed_at)
            event.template_id = best.id
            continue
        pattern = " ".join(tokens)
        digest = hashlib.sha256(
            f"{TEMPLATE_VERSION}:{event.dataset_id}:{pattern}".encode()
        ).hexdigest()[:20]
        template = TemplateRecord(
            id=f"tpl_{digest}", dataset_id=event.dataset_id, pattern=pattern,
            parser_version=TEMPLATE_VERSION, first_seen=event.observed_at, occurrences=1,
        )
        templates.append(template)
        token_patterns[template.id] = tokens
        event.template_id = template.id
    return templates
