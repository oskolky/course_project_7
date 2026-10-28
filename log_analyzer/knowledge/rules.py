from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from log_analyzer.config import RULES_PATH
from log_analyzer.contracts import CanonicalEvent, RuleDefinition, WindowFeatures
from log_analyzer.storage.models import RuleRecord


@dataclass
class RuleMatch:
    rule_key: str
    hypothesis: str
    severity: str
    recommendation: str
    evidence_event_ids: list[str] = field(default_factory=list)
    scope: str = "group"
    group_id: str | None = None
    window_start: datetime | None = None


def read_rule_file(path: Path = RULES_PATH) -> list[RuleDefinition]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [RuleDefinition.model_validate(item) for item in payload.get("rules", [])]


def record_from_definition(definition: RuleDefinition) -> RuleRecord:
    outcome = definition.then
    return RuleRecord(
        key=f"{definition.id}@{definition.version}", id=definition.id,
        version=definition.version, scope=definition.scope,
        condition=definition.when, severity=outcome["severity"],
        hypothesis=outcome["hypothesis"], recommendation=outcome["recommendation"],
        evidence=outcome["evidence"],
    )


def sync_default_rules(db: Session) -> None:
    for definition in read_rule_file():
        record = record_from_definition(definition)
        if db.get(RuleRecord, record.key) is None:
            db.add(record)
    db.commit()


def latest_rules(db: Session) -> list[RuleRecord]:
    records = list(db.scalars(select(RuleRecord).order_by(RuleRecord.id, RuleRecord.version)).all())
    latest: dict[str, RuleRecord] = {}
    for record in records:
        latest[record.id] = record
    return list(latest.values())


def add_rule_version(db: Session, yaml_text: str) -> RuleRecord:
    payload = yaml.safe_load(yaml_text)
    if isinstance(payload, dict) and "rules" in payload:
        rules = payload["rules"]
        if len(rules) != 1:
            raise ValueError("Upload exactly one rule")
        payload = rules[0]
    definition = RuleDefinition.model_validate(payload)
    current_max = db.scalar(select(func.max(RuleRecord.version)).where(RuleRecord.id == definition.id)) or 0
    if definition.version <= current_max:
        raise ValueError(f"Version must be greater than {current_max}; old versions are immutable")
    record = record_from_definition(definition)
    db.add(record)
    db.commit()
    return record


class RuleEngine:
    def __init__(self, rules: list[RuleRecord]):
        self.rules = rules

    def evaluate_groups(self, groups: list[RequestGroupRecord], events: list[CanonicalEvent]) -> list[RuleMatch]:
        by_group: dict[str, list[CanonicalEvent]] = {}
        for event in events:
            if event.group_id:
                by_group.setdefault(event.group_id, []).append(event)
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if rule.scope != "group":
                continue
            for group in groups:
                items = by_group.get(group.id, [])
                if items and self._matches_group(rule.condition, items):
                    matches.append(self._match(rule, self._relevant_events(rule.condition, items), group.id))
        return matches

    def evaluate_windows(self, windows: list[WindowFeatures], events: list[CanonicalEvent]) -> list[RuleMatch]:
        by_id = {event.event_id: event for event in events}
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if rule.scope != "window":
                continue
            for window in windows:
                items = [by_id[event_id] for event_id in window.event_ids]
                requests = [event for event in items if event.status is not None]
                condition = rule.condition
                if len(requests) < int(condition.get("min_requests", 1)):
                    continue
                if "status_in" in condition and not any(event.status in condition["status_in"] for event in requests):
                    continue
                if "status_ratio_gte" in condition:
                    statuses = set(condition.get("status_in", []))
                    ratio = sum(event.status in statuses for event in requests) / len(requests) if requests else 0
                    if ratio < float(condition["status_ratio_gte"]):
                        continue
                if "route_contains" in condition and not any(condition["route_contains"] in (event.route or "") for event in items):
                    continue
                if "service_equals" in condition and window.service != condition["service_equals"]:
                    continue
                match = self._match(rule, self._relevant_events(condition, items))
                match.scope = "window"
                match.window_start = window.window_start
                matches.append(match)
        return matches

    @staticmethod
    def _matches_group(condition: dict[str, Any], events: list[CanonicalEvent]) -> bool:
        messages = [(event.message or "").lower() for event in events]
        if "template_contains" in condition and not any(condition["template_contains"].lower() in message for message in messages):
            return False
        if "message_contains" in condition and not any(condition["message_contains"].lower() in message for message in messages):
            return False
        if "status_in" in condition and not any(event.status in condition["status_in"] for event in events):
            return False
        if len(events) < int(condition.get("related_events_gte", 1)):
            return False
        if "route_contains" in condition and not any(condition["route_contains"] in (event.route or "") for event in events):
            return False
        if "service_equals" in condition and not any(event.service == condition["service_equals"] for event in events):
            return False
        return True

    @staticmethod
    def _relevant_events(condition: dict[str, Any], events: list[CanonicalEvent]) -> list[CanonicalEvent]:
        relevant = []
        for event in events:
            message = (event.message or "").lower()
            if "status_in" in condition and event.status in condition["status_in"]:
                relevant.append(event)
            elif "template_contains" in condition and condition["template_contains"].lower() in message:
                relevant.append(event)
            elif "message_contains" in condition and condition["message_contains"].lower() in message:
                relevant.append(event)
        return relevant or events

    @staticmethod
    def _match(rule: RuleRecord, events: list[CanonicalEvent], group_id: str | None = None) -> RuleMatch:
        return RuleMatch(
            rule_key=rule.key, hypothesis=rule.hypothesis, severity=rule.severity,
            recommendation=rule.recommendation,
            evidence_event_ids=list(dict.fromkeys(event.event_id for event in events))[:50],
            scope=rule.scope, group_id=group_id,
        )
