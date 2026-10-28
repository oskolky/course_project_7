from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from log_analyzer.config import MODEL_DIR
from log_analyzer.contracts import WindowFeatures, utc_now
from log_analyzer.features.builder import feature_schema, vectors
from log_analyzer.storage.models import ModelVersionRecord


@dataclass
class ModelWindowResult:
    window_start: datetime
    status: str
    score: float | None
    threshold: float | None


def train_isolation_forest(
    db: Session, dataset_id: str, windows: list[WindowFeatures],
    contamination: float = 0.08, threshold_quantile: float = 0.95,
) -> ModelVersionRecord:
    ready = [window for window in windows if window.status == "ready"]
    if len(ready) < 2:
        raise ValueError("At least two sufficiently populated windows are required for training")
    matrix = np.asarray(vectors(ready), dtype=float)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit(scaled)
    raw_train = -model.score_samples(scaled)
    median = float(np.median(raw_train))
    q05, q95 = np.quantile(raw_train, [0.05, 0.95])
    scale = max(float((q95 - q05) / 4), 1e-6)
    transformed = np.asarray([_sigmoid((value - median) / scale) for value in raw_train])
    threshold = float(np.quantile(transformed, threshold_quantile))
    schema = feature_schema()
    payload_hash = hashlib.sha256(matrix.tobytes() + str(sorted(schema.items())).encode()).hexdigest()[:12]
    model_id = f"iforest_{payload_hash}"
    parameters: dict[str, Any] = {
        "n_estimators": 150, "contamination": contamination, "random_state": 42,
        "threshold": threshold, "threshold_quantile": threshold_quantile,
        "score_transform": "logistic", "raw_median": median, "raw_scale": scale,
    }
    artifact_path = MODEL_DIR / f"{model_id}.joblib"
    joblib.dump({"model": model, "scaler": scaler, "parameters": parameters}, artifact_path)
    record = db.get(ModelVersionRecord, model_id)
    if record is None:
        record = ModelVersionRecord(
            id=model_id, algorithm="IsolationForest", feature_schema=schema,
            parameters=parameters, dataset_id=dataset_id, artifact_path=str(artifact_path),
            training_summary={"windows": len(ready), "events": sum(window.n_req for window in ready)},
            trained_at=utc_now(),
        )
        db.add(record)
    else:
        record.parameters = parameters
        record.artifact_path = str(artifact_path)
        record.trained_at = utc_now()
    db.commit()
    return record


def evaluate_isolation_forest(record: ModelVersionRecord, windows: list[WindowFeatures]) -> list[ModelWindowResult]:
    path = Path(record.artifact_path)
    if not path.is_file():
        raise FileNotFoundError(f"Model artifact is unavailable: {record.id}")
    artifact = joblib.load(path)
    model = artifact["model"]
    scaler = artifact["scaler"]
    parameters = artifact["parameters"]
    results: list[ModelWindowResult] = []
    for window in windows:
        if window.status != "ready":
            results.append(ModelWindowResult(window.window_start, "insufficient_data", None, parameters["threshold"]))
            continue
        scaled = scaler.transform(np.asarray([window.vector], dtype=float))
        raw = float(-model.score_samples(scaled)[0])
        score = _sigmoid((raw - parameters["raw_median"]) / parameters["raw_scale"])
        status = "anomaly" if score >= parameters["threshold"] else "normal"
        results.append(ModelWindowResult(window.window_start, status, score, parameters["threshold"]))
    return results


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1 / (1 + math.exp(-value))
    exp = math.exp(value)
    return exp / (1 + exp)
