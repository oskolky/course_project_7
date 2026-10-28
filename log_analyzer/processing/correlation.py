from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from log_analyzer.config import CORRELATION_DELTA_SECONDS
from log_analyzer.contracts import CanonicalEvent
from log_analyzer.storage.models import RequestGroupRecord


@dataclass
class _GroupState:
    record: RequestGroupRecord
    events: list[CanonicalEvent] = field(default_factory=list)


def correlate_events(events: list[CanonicalEvent], delta_seconds: float = CORRELATION_DELTA_SECONDS) -> list[RequestGroupRecord]:
    exact: dict[str, _GroupState] = {}
    heuristic: list[_GroupState] = []
    all_groups: list[_GroupState] = []

    def create(event: CanonicalEvent, key: str, quality: str) -> _GroupState:
        group = RequestGroupRecord(
            id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{event.dataset_id}:group:{key}")),
            dataset_id=event.dataset_id, link_quality=quality,
            route=event.route, service=event.service,
            started_at=event.observed_at, ended_at=event.observed_at,
        )
        state = _GroupState(group)
        all_groups.append(state)
        return state

    for event in sorted(events, key=lambda item: item.observed_at):
        state: _GroupState | None = None
        if event.trace_id:
            key = f"trace:{event.trace_id}"
            state = exact.get(key)
            if state is None:
                state = create(event, key, "exact")
                exact[key] = state
        elif event.request_id:
            key = f"request:{event.request_id}"
            state = exact.get(key)
            if state is None:
                state = create(event, key, "exact")
                exact[key] = state
        elif event.client or event.route:
            candidates: list[_GroupState] = []
            for candidate in heuristic:
                group = candidate.record
                elapsed = (event.observed_at - group.ended_at).total_seconds()
                same_context = (
                    group.service == event.service and group.route == event.route
                    and (not event.client or not candidate.events[-1].client or candidate.events[-1].client == event.client)
                    and (not event.host or not candidate.events[-1].host or candidate.events[-1].host == event.host)
                )
                if same_context and 0 <= elapsed <= delta_seconds and _compatible_status(candidate.events[-1].status, event.status):
                    candidates.append(candidate)
            if len(candidates) == 1:
                state = candidates[0]
                state.record.link_quality = "presumed"
            else:
                state = create(event, f"unlinked:{event.event_id}", "uncertain")
            if state not in heuristic:
                heuristic.append(state)
        else:
            state = create(event, f"unlinked:{event.event_id}", "uncertain")

        state.events.append(event)
        state.record.ended_at = event.observed_at
        if state.record.route is None:
            state.record.route = event.route
        event.group_id = state.record.id
    return [state.record for state in all_groups]


def _compatible_status(left: int | None, right: int | None) -> bool:
    if left is None or right is None:
        return True
    return left // 100 == right // 100 or left >= 500 or right >= 500
