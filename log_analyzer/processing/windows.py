from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from math import ceil

from log_analyzer.config import MIN_WINDOW_REQUESTS, WINDOW_SECONDS
from log_analyzer.contracts import CanonicalEvent, WindowFeatures
from log_analyzer.storage.models import RequestGroupRecord, TemplateRecord

FEATURE_NAMES = [
    "n_req", "r_401", "r_4xx", "r_5xx", "q_095_duration_ms",
    "n_retry", "n_tpl", "n_new", "r_uncertain",
]


def percentile95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, ceil(0.95 * len(ordered)) - 1)]


def build_windows(
    events: list[CanonicalEvent], groups: list[RequestGroupRecord],
    templates: list[TemplateRecord], window_seconds: int = WINDOW_SECONDS,
) -> list[WindowFeatures]:
    if not events:
        return []
    group_quality = {group.id: group.link_quality for group in groups}
    template_seen = {template.id: template.first_seen for template in templates}
    buckets: dict[datetime, list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        epoch = int(event.observed_at.timestamp())
        start_epoch = epoch - epoch % window_seconds
        buckets[datetime.fromtimestamp(start_epoch, tz=timezone.utc)].append(event)

    windows: list[WindowFeatures] = []
    for start, items in sorted(buckets.items(), key=lambda pair: pair[0]):
        requests = [event for event in items if event.status is not None]
        n_req = len(requests)
        end = start + timedelta(seconds=window_seconds)
        durations = [event.duration_ms for event in requests if event.duration_ms is not None]
        signatures = Counter((event.client, event.method, event.route) for event in requests)
        retries = sum(max(0, count - 1) for count in signatures.values())
        template_ids = {event.template_id for event in items if event.template_id}
        new_templates = sum(
            1 for template_id in template_ids
            if template_id in template_seen and start <= template_seen[template_id] < end
        )
        uncertain = sum(1 for event in items if group_quality.get(event.group_id) != "exact")
        service = Counter(event.service for event in items).most_common(1)[0][0]
        routes = Counter(event.route for event in items if event.route)
        windows.append(WindowFeatures(
            window_start=start, window_end=end, n_req=n_req,
            r_401=sum(event.status == 401 for event in requests) / n_req if n_req else 0.0,
            r_4xx=sum(event.status is not None and 400 <= event.status < 500 for event in requests) / n_req if n_req else 0.0,
            r_5xx=sum(event.status is not None and event.status >= 500 for event in requests) / n_req if n_req else 0.0,
            q_095_duration_ms=percentile95(durations), n_retry=retries,
            n_tpl=len(template_ids), n_new=new_templates,
            r_uncertain=uncertain / len(items) if items else 0.0,
            event_ids=[event.event_id for event in items],
            group_ids=sorted({event.group_id for event in items if event.group_id}),
            service=service, route=routes.most_common(1)[0][0] if routes else None,
            status="ready" if n_req >= MIN_WINDOW_REQUESTS else "insufficient_data",
        ))
    return windows
