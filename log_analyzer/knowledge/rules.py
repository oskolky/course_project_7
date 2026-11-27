from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from log_analyzer.config import RULES_PATH
from log_analyzer.contracts import CanonicalEvent, RuleDefinition, WindowFeatures
from log_analyzer.storage.models import RequestGroupRecord, RuleRecord, TemplateRecord

logger = logging.getLogger(__name__)
TEXT_CONDITIONS = ("template_contains", "message_contains")
PRESENTATION_FIELDS = ("title", "recommendation_text")


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
    event_id: str | None = None
    signature_event_ids: list[str] = field(default_factory=list)
    title: str | None = None
    recommendation_text: str | None = None


def read_rule_file(path: Path = RULES_PATH) -> list[RuleDefinition]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [RuleDefinition.model_validate(item) for item in payload.get("rules", [])]


def record_from_definition(definition: RuleDefinition) -> RuleRecord:
    outcome = definition.then
    presentation = {key: outcome[key] for key in PRESENTATION_FIELDS if outcome.get(key)}
    return RuleRecord(
        key=f"{definition.id}@{definition.version}", id=definition.id,
        version=definition.version, scope=definition.scope,
        condition=definition.when, severity=outcome["severity"],
        hypothesis=outcome["hypothesis"], recommendation=outcome["recommendation"],
        evidence=outcome["evidence"], presentation=presentation or None,
    )


def _content(record: RuleRecord) -> tuple:
    """Содержание правила, влияющее на результаты анализа. Поля представления
    (заголовок, текст рекомендации) в сравнение не входят."""
    return (
        record.scope, record.condition, record.severity, record.hypothesis,
        record.recommendation, list(record.evidence or []),
    )


def sync_default_rules(db: Session) -> list[str]:
    """Добавляет в базу недостающие версии правил из файла базы знаний. Опубликованные
    версии не изменяются: если сохранённая версия расходится с файлом по условиям
    или следствию, ключ такого правила возвращается и фиксируется в журнале сервера.
    Заголовок и текст рекомендации на выводы не влияют, поэтому берутся из файла."""
    diverged: list[str] = []
    for definition in read_rule_file():
        record = record_from_definition(definition)
        stored = db.get(RuleRecord, record.key)
        if stored is None:
            db.add(record)
        elif _content(stored) != _content(record):
            diverged.append(record.key)
        elif (stored.presentation or {}) != (record.presentation or {}):
            stored.presentation = record.presentation
    db.commit()
    for key in diverged:
        logger.warning("Rule %s in the database differs from the knowledge base file; the stored version is kept", key)
    return diverged


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
    for other in latest_rules(db):
        if other.id != definition.id and other.scope == definition.scope and other.condition == definition.when:
            raise ValueError(
                f"Rule duplicates {other.key}: the same scope and conditions are already defined there"
            )
    record = record_from_definition(definition)
    db.add(record)
    db.commit()
    return record


class RuleEngine:
    def __init__(self, rules: list[RuleRecord], templates: Iterable[TemplateRecord] | None = None):
        self.rules = rules
        self.patterns = {template.id: template.pattern for template in (templates or [])}

    def evaluate(self, groups: list[RequestGroupRecord], windows: list[WindowFeatures], events: list[CanonicalEvent]) -> list[RuleMatch]:
        return self.evaluate_events(events) + self.evaluate_groups(groups, events) + self.evaluate_windows(windows, events)

    def evaluate_events(self, events: list[CanonicalEvent]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if rule.scope != "event":
                continue
            for event in events:
                if self._matches_event(rule.condition, event):
                    matches.append(self._match(rule, [event], group_id=event.group_id, scope="event"))
        return matches

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

    def _text_matches(self, name: str, condition: dict[str, Any], event: CanonicalEvent) -> bool:
        needle = str(condition[name]).lower()
        if name == "template_contains":
            pattern = self.patterns.get(event.template_id or "")
            if pattern is not None:
                return needle in pattern.lower()
        return needle in (event.message or "").lower()

    @staticmethod
    def _has_text(condition: dict[str, Any]) -> bool:
        return any(name in condition for name in TEXT_CONDITIONS)

    def _matches_event(self, condition: dict[str, Any], event: CanonicalEvent) -> bool:
        for name in TEXT_CONDITIONS:
            if name in condition and not self._text_matches(name, condition, event):
                return False
        if "status_in" in condition and event.status not in condition["status_in"]:
            return False
        if "route_contains" in condition and condition["route_contains"] not in (event.route or ""):
            return False
        if "service_equals" in condition and event.service != condition["service_equals"]:
            return False
        return True

    def _matches_group(self, condition: dict[str, Any], events: list[CanonicalEvent]) -> bool:
        for name in TEXT_CONDITIONS:
            if name in condition and not any(self._text_matches(name, condition, event) for event in events):
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

    def _relevant_events(self, condition: dict[str, Any], events: list[CanonicalEvent]) -> list[CanonicalEvent]:
        relevant = []
        for event in events:
            if "status_in" in condition and event.status in condition["status_in"]:
                relevant.append(event)
            elif self._has_text(condition) and any(
                self._text_matches(name, condition, event) for name in TEXT_CONDITIONS if name in condition
            ):
                relevant.append(event)
        return relevant or events

    def _match(self, rule: RuleRecord, events: list[CanonicalEvent], group_id: str | None = None, scope: str | None = None) -> RuleMatch:
        scope = scope or rule.scope
        condition = rule.condition
        presentation = rule.presentation or {}
        signature = [
            event.event_id for event in events
            if self._has_text(condition) and any(
                self._text_matches(name, condition, event) for name in TEXT_CONDITIONS if name in condition
            )
        ]
        return RuleMatch(
            rule_key=rule.key, hypothesis=rule.hypothesis, severity=rule.severity,
            recommendation=rule.recommendation,
            evidence_event_ids=list(dict.fromkeys(event.event_id for event in events))[:50],
            scope=scope, group_id=group_id,
            event_id=events[0].event_id if scope == "event" else None,
            signature_event_ids=signature[:50],
            title=presentation.get("title"),
            recommendation_text=presentation.get("recommendation_text"),
        )
