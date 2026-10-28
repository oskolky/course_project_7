from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime

from log_analyzer.contracts import CanonicalEvent, WindowFeatures
from log_analyzer.knowledge.rules import RuleMatch
from log_analyzer.models.isolation import ModelWindowResult
from log_analyzer.storage.models import EvidenceRecord, IncidentRecord

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def arbitrate(
    *, run_id: str, dataset_id: str, windows: list[WindowFeatures],
    events: list[CanonicalEvent], rule_matches: list[RuleMatch],
    model_results: list[ModelWindowResult], model_id: str | None,
    model_warning: str | None = None,
) -> list[IncidentRecord]:
    by_id = {event.event_id: event for event in events}
    model_by_window = {result.window_start: result for result in model_results}
    group_matches: dict[str, list[RuleMatch]] = defaultdict(list)
    window_matches: dict[datetime, list[RuleMatch]] = defaultdict(list)
    for match in rule_matches:
        if match.scope == "window" and match.window_start:
            window_matches[match.window_start].append(match)
        elif match.group_id:
            group_matches[match.group_id].append(match)

    incidents: list[IncidentRecord] = []
    for window in windows:
        matches = list(window_matches[window.window_start])
        for group_id in window.group_ids:
            matches.extend(group_matches[group_id])
        model = model_by_window.get(window.window_start)
        anomaly = bool(model and model.status == "anomaly")
        if not matches and not anomaly:
            continue
        hypotheses = {match.hypothesis for match in matches}
        conflict = len(hypotheses) > 1
        incident_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:{window.window_start.isoformat()}"))
        rule_keys = list(dict.fromkeys(match.rule_key for match in matches))
        warnings = [model_warning] if model_warning else []
        if conflict:
            kind = "rule_conflict"
            hypothesis = "conflicting_rule_hypotheses"
            confidence = "rule_conflict"
            recommendation = "review_conflicting_rules_and_evidence"
        elif matches and anomaly:
            kind = "known_with_anomaly"
            hypothesis = matches[0].hypothesis
            confidence = "rule_confirmed"
            recommendation = matches[0].recommendation
        elif matches:
            kind = "known"
            hypothesis = matches[0].hypothesis
            confidence = "rule_confirmed"
            recommendation = matches[0].recommendation
        else:
            kind = "unknown_anomaly"
            hypothesis = None
            confidence = "model_only"
            recommendation = "inspect_feature_values_and_linked_events"
        if conflict or anomaly and not matches:
            severity = "high" if conflict or (model and model.score is not None and model.score >= 0.9) else "medium"
        else:
            severity = max(matches, key=lambda match: SEVERITY_RANK[match.severity]).severity
        feature_payload = window.model_dump(mode="json", exclude={"event_ids", "group_ids"})
        feature_payload["rule_outcomes"] = [
            {"rule": match.rule_key, "hypothesis": match.hypothesis, "severity": match.severity}
            for match in matches
        ]
        incident = IncidentRecord(
            id=incident_id, run_id=run_id, dataset_id=dataset_id,
            window_start=window.window_start, window_end=window.window_end,
            service=window.service, route=window.route, kind=kind, severity=severity,
            hypothesis=hypothesis, confidence=confidence,
            anomaly_score=model.score if model else None,
            anomaly_threshold=model.threshold if model else None,
            review_required=conflict, rule_ids=rule_keys, model_id=model_id if model else None,
            recommendation=recommendation, features=feature_payload, warnings=warnings,
        )
        evidence_roles: dict[str, str] = {}
        for match in matches:
            for event_id in match.evidence_event_ids:
                event = by_id.get(event_id)
                if event is None:
                    continue
                role = "http_response" if event.status is not None else "primary_error"
                evidence_roles[event_id] = role
        if anomaly:
            for event_id in window.event_ids:
                evidence_roles.setdefault(event_id, "context")
        for event_id, role in evidence_roles.items():
            event = by_id.get(event_id)
            if event is None:
                continue
            incident.evidence_items.append(EvidenceRecord(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{incident_id}:{event_id}:{role}")),
                incident_id=incident_id, event_id=event_id, role=role, excerpt=event.raw,
            ))
        incidents.append(incident)
    return incidents
