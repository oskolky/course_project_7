from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import datetime

from log_analyzer.config import RULES_IN_INSUFFICIENT_WINDOWS
from log_analyzer.contracts import CanonicalEvent, WindowFeatures
from log_analyzer.knowledge.rules import RuleMatch
from log_analyzer.models.isolation import ModelWindowResult
from log_analyzer.processing.windows import FEATURE_NAMES, window_start_of
from log_analyzer.storage.models import EvidenceRecord, IncidentRecord

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
INSUFFICIENT_WARNING = "Окно содержит мало запросов: статистическая оценка моделью не выполнялась"


def arbitrate(
    *, run_id: str, dataset_id: str, windows: list[WindowFeatures],
    events: list[CanonicalEvent], rule_matches: list[RuleMatch],
    model_results: list[ModelWindowResult], model_id: str | None,
    model_warning: str | None = None, decisions: list[dict] | None = None,
) -> list[IncidentRecord]:
    """Согласует для каждого окна результаты контура правил и контура модели.
    В decisions дополнительно записывается решение по каждому окну, включая окна,
    инцидент не создавшие (протокол запуска)."""
    by_id = {event.event_id: event for event in events}
    event_window = {event.event_id: window_start_of(event.observed_at) for event in events}
    model_by_window = {result.window_start: result for result in model_results}
    group_matches: dict[str, list[RuleMatch]] = defaultdict(list)
    window_matches: dict[datetime, list[RuleMatch]] = defaultdict(list)
    for match in rule_matches:
        if match.scope == "window" and match.window_start is not None:
            window_matches[match.window_start].append(match)
        elif match.group_id:
            group_matches[match.group_id].append(match)
        elif match.event_id in event_window:
            window_matches[event_window[match.event_id]].append(match)

    incidents: list[IncidentRecord] = []
    for window in windows:
        matches = list(window_matches[window.window_start])
        for group_id in window.group_ids:
            matches.extend(group_matches[group_id])
        model = model_by_window.get(window.window_start)
        anomaly = bool(model and model.status == "anomaly")
        sparse = window.status != "ready"

        if sparse and not RULES_IN_INSUFFICIENT_WINDOWS:
            _decide(decisions, window, matches, model, None, "insufficient_data")
            continue
        if not matches and not anomaly:
            _decide(decisions, window, matches, model, None, "insufficient_data" if sparse else "no_signals")
            continue

        hypotheses = {match.hypothesis for match in matches}
        conflict = len(hypotheses) > 1
        incident_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:{window.window_start.isoformat()}"))
        rule_keys = list(dict.fromkeys(match.rule_key for match in matches))
        warnings = [model_warning] if model_warning else []
        if sparse:
            warnings.append(INSUFFICIENT_WARNING)
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
            recommendation = "inspect_feature_values"
        if conflict or (anomaly and not matches):
            severity = "high" if conflict or (model and model.score is not None and model.score >= 0.9) else "medium"
        else:
            severity = max(matches, key=lambda match: SEVERITY_RANK[match.severity]).severity
        service, route = _attribute(matches, by_id, window)
        feature_payload: dict = window.model_dump(mode="json", exclude={"event_ids", "group_ids"})
        feature_payload["rule_outcomes"] = [
            {"rule": match.rule_key, "hypothesis": match.hypothesis, "severity": match.severity}
            for match in matches
        ]
        feature_payload["hypotheses"] = _hypotheses(matches)
        feature_payload["deviations"] = list(model.deviations) if anomaly and model else []
        feature_payload["rule_matches"] = len(matches)
        feature_payload["affected_requests"] = 0
        if matches and not conflict:
            feature_payload["title"] = matches[0].title
            feature_payload["recommendation_text"] = matches[0].recommendation_text
        incident = IncidentRecord(
            id=incident_id, run_id=run_id, dataset_id=dataset_id,
            window_start=window.window_start, window_end=window.window_end,
            service=service, route=route, kind=kind, severity=severity,
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
        feature_payload["affected_requests"] = _affected_requests(by_id, evidence_roles)
        for event_id, role in evidence_roles.items():
            event = by_id.get(event_id)
            if event is None:
                continue
            incident.evidence_items.append(EvidenceRecord(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{incident_id}:{event_id}:{role}")),
                incident_id=incident_id, event_id=event_id, role=role, excerpt=event.raw,
            ))
        incidents.append(incident)
        _decide(decisions, window, matches, model, incident_id, None, kind)
    return incidents


def _decide(
    decisions: list[dict] | None, window: WindowFeatures, matches: list[RuleMatch],
    model: ModelWindowResult | None, incident_id: str | None, reason: str | None, kind: str | None = None,
) -> None:
    if decisions is None:
        return
    values = window.model_dump(mode="json", exclude={"event_ids", "group_ids"})
    decisions.append({
        "window_start": window.window_start.isoformat(),
        "window_end": window.window_end.isoformat(),
        "status": window.status,
        "features": {name: values.get(name) for name in FEATURE_NAMES},
        "service": window.service,
        "route": window.route,
        "rule_matches": [
            {"rule": match.rule_key, "hypothesis": match.hypothesis, "severity": match.severity, "scope": match.scope}
            for match in matches
        ],
        "model": (
            {"status": model.status, "score": model.score, "threshold": model.threshold, "deviations": model.deviations}
            if model else None
        ),
        "decision": {"kind": kind, "reason": reason, "incident_id": incident_id},
    })


def _hypotheses(matches: list[RuleMatch]) -> list[dict]:
    """Перечень гипотез сработавших правил без повторов: при конфликте правил
    пользователь видит все возможные интерпретации."""
    grouped: dict[str, dict] = {}
    for match in matches:
        item = grouped.setdefault(match.hypothesis, {
            "hypothesis": match.hypothesis, "title": match.title, "severity": match.severity, "rules": [],
        })
        if match.rule_key not in item["rules"]:
            item["rules"].append(match.rule_key)
    return list(grouped.values())


def _attribute(matches: list[RuleMatch], by_id: dict[str, CanonicalEvent], window: WindowFeatures) -> tuple[str | None, str | None]:
    """Сервис и маршрут инцидента. Сервис берётся из событий с текстовой приметой
    ошибки (например, сообщение приложения о причине сбоя), а не из самого частого
    сервиса окна; маршрут — из всех событий-доказательств."""
    matched = [by_id[event_id] for match in matches for event_id in match.evidence_event_ids if event_id in by_id]
    signature = [by_id[event_id] for match in matches for event_id in match.signature_event_ids if event_id in by_id]
    pool = signature or matched
    service = Counter(event.service for event in pool).most_common(1)[0][0] if pool else window.service
    routes = Counter(event.route for event in matched if event.route)
    route = routes.most_common(1)[0][0] if routes else window.route
    return service, route


def _affected_requests(by_id: dict[str, CanonicalEvent], evidence_roles: dict[str, str]) -> int:
    """Число различных запросов, записи которых включены в доказательства."""
    def request_keys(roles: set[str]) -> set[str]:
        keys = set()
        for event_id, role in evidence_roles.items():
            event = by_id.get(event_id)
            if event is not None and role in roles:
                keys.add(event.request_id or event.group_id or event.event_id)
        return keys

    keys = request_keys({"http_response", "primary_error"})
    if not keys:
        keys = request_keys({"http_response", "primary_error", "context"})
    return len(keys)
