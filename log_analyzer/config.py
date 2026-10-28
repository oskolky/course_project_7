from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("LOG_ANALYZER_DATA_DIR", BASE_DIR / "data"))
MODEL_DIR = DATA_DIR / "models"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'log_analyzer.db'}")
RULES_PATH = Path(os.getenv("LOG_ANALYZER_RULES_PATH", BASE_DIR / "configs" / "rules.yaml"))
SAMPLES_DIR = BASE_DIR / "samples"
PARSER_VERSION = "normalizer-1.0"
TEMPLATE_VERSION = "lcs-1.0"
FEATURE_SCHEMA_VERSION = "window-v1"
DEFAULT_TIMEZONE = os.getenv("LOG_ANALYZER_TIMEZONE", "UTC")
CORRELATION_DELTA_SECONDS = float(os.getenv("CORRELATION_DELTA_SECONDS", "2.0"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
MIN_WINDOW_REQUESTS = int(os.getenv("MIN_WINDOW_REQUESTS", "3"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)
