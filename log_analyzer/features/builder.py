from __future__ import annotations

from log_analyzer.config import FEATURE_SCHEMA_VERSION
from log_analyzer.contracts import WindowFeatures
from log_analyzer.processing.windows import FEATURE_NAMES


def feature_schema() -> dict:
    return {"version": FEATURE_SCHEMA_VERSION, "names": FEATURE_NAMES, "missing": "zero_duration", "scaling": "standard"}


def vectors(windows: list[WindowFeatures]) -> list[list[float]]:
    return [window.vector for window in windows]
