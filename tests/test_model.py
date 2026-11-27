from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from log_analyzer.models.isolation import evaluate_isolation_forest
from log_analyzer.services.analyzer import create_dataset_from_records, load_context, train_model
from log_analyzer.storage.models import ModelVersionRecord

START = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
FEATURE_NAMES = {"n_req", "q_095_duration_ms", "r_401", "r_4xx", "r_5xx", "n_retry", "n_tpl", "n_new", "r_uncertain"}


def record(index, request_id, status=200, seconds=None, duration=None, route="/api/catalog", service="web"):
    moment = (START + timedelta(seconds=seconds if seconds is not None else index)).isoformat()
    return {
        "observed_at": moment,
        "source": {"type": "application_json", "service": service, "host": "web-01"},
        "request": {"request_id": request_id, "method": "GET", "route": route, "status": status,
                    "duration_ms": duration if duration is not None else 30 + index},
        "message": "request completed",
    }


def baseline_records(windows=6, per_window=4, flat=False):
    """Штатный период: при flat=False число запросов и длительности меняются от окна
    к окну, при flat=True каждое окно одинаково."""
    rng = random.Random(7)
    records = []
    for window in range(windows):
        count = per_window if flat else per_window + rng.randint(-1, 1)
        for index in range(count):
            duration = 40.0 if flat else round(rng.uniform(20, 70), 1)
            records.append(record(index, f"base-{window}-{index}", seconds=window * 60 + index * 5, duration=duration))
    return records


def make_dataset(db, records, name="test"):
    return create_dataset_from_records(db, str(uuid.uuid4()), name, records)


@pytest.mark.typical
def test_training_sets_threshold_as_requested_quantile(db):
    """Модель обучается на окнах штатного периода; порог равен квантилю оценок обучающей выборки.

    Компоненты: модель Isolation Forest
    Ожидается: модель сохранена под идентификатором iforest_<hash>; доля обучающих окон выше порога не превышает заданную
    """
    dataset = make_dataset(db, baseline_records(10, 4))
    model = train_model(db, dataset.id, 0.08, 0.95)
    assert model.id.startswith("iforest_")
    assert model.training_summary["windows"] == 10
    assert not {"n_req", "q_095_duration_ms"} & set(model.parameters["constant_features"])
    _, _, _, windows = load_context(db, dataset.id)
    results = evaluate_isolation_forest(model, windows)
    assert len([item for item in results if item.status == "anomaly"]) <= 1
    assert all(item.threshold == model.parameters["threshold"] for item in results)


@pytest.mark.typical
def test_training_is_reproducible(db):
    """Повторное обучение на тех же данных даёт тот же идентификатор модели и тот же порог.

    Компоненты: модель Isolation Forest
    Ожидается: идентификатор и порог совпадают; дубликата модели в реестре нет
    """
    dataset = make_dataset(db, baseline_records())
    first = train_model(db, dataset.id, 0.08, 0.95)
    second = train_model(db, dataset.id, 0.08, 0.95)
    assert first.id == second.id
    assert first.parameters["threshold"] == second.parameters["threshold"]
    assert db.scalar(select(func.count()).select_from(ModelVersionRecord)) == 1


@pytest.mark.typical
def test_anomalous_window_gets_score_and_deviations(db):
    """Окно, выделенное моделью, получает оценку не ниже порога и перечень отклонившихся признаков.

    Компоненты: модель Isolation Forest
    Ожидается: окно, отличающееся от прочих (в нём впервые появился новый шаблон сообщения), имеет статус anomaly; в отклонениях указаны признаки с именами из схемы признаков
    """
    baseline = make_dataset(db, baseline_records(10, 4), "baseline")
    model = train_model(db, baseline.id, 0.08, 0.95)
    _, _, _, windows = load_context(db, baseline.id)
    results = evaluate_isolation_forest(model, windows)
    flagged = [item for item in results if item.status == "anomaly"]
    assert flagged
    for result in results:
        assert result.score >= result.threshold if result.status == "anomaly" else result.score < result.threshold
    for result in flagged:
        assert result.deviations
        assert {item["feature"] for item in result.deviations} <= FEATURE_NAMES
        assert all(abs(item["z"]) >= 1 for item in result.deviations)


@pytest.mark.boundary
def test_constant_baseline_features_are_reported_as_invisible(db):
    """Если признак в штатном периоде не менялся, модель не заметит его изменения; о таких признаках сообщается.

    Компоненты: модель Isolation Forest
    Ожидается: в параметрах модели перечислены постоянные признаки; окно с аномальным числом запросов не выделено
    """
    baseline = make_dataset(db, baseline_records(10, 4, flat=True), "flat")
    model = train_model(db, baseline.id, 0.08, 0.95)
    assert {"n_req", "q_095_duration_ms", "r_5xx"} <= set(model.parameters["constant_features"])
    _, _, _, windows = load_context(db, baseline.id)
    target = windows[-1].model_copy(update={"n_req": 400})
    assert evaluate_isolation_forest(model, [target])[0].status == "normal"


@pytest.mark.boundary
def test_insufficient_window_has_no_score(db):
    """Окно с малым числом запросов не оценивается моделью и не получает оценки.

    Компоненты: модель Isolation Forest
    Ожидается: статус insufficient_data, оценка пустая, порог указан
    """
    baseline = make_dataset(db, baseline_records(), "baseline")
    model = train_model(db, baseline.id, 0.08, 0.95)
    tiny = make_dataset(db, [record(0, "one"), record(1, "two")], "tiny")
    _, _, _, windows = load_context(db, tiny.id)
    result = evaluate_isolation_forest(model, windows)[0]
    assert result.status == "insufficient_data"
    assert result.score is None
    assert result.threshold == model.parameters["threshold"]
    assert result.deviations == []


@pytest.mark.negative
def test_training_on_tiny_dataset_is_refused(db):
    """Обучение на наборе с одним готовым окном отклоняется: выборка статистически незначима.

    Компоненты: модель Isolation Forest
    Ожидается: ValueError; модель в реестре не появилась
    """
    dataset = make_dataset(db, [record(0, "a"), record(1, "b"), record(2, "c")])
    with pytest.raises(ValueError, match="At least two"):
        train_model(db, dataset.id, 0.08, 0.95)
    assert db.scalar(select(func.count()).select_from(ModelVersionRecord)) == 0


@pytest.mark.negative
def test_missing_artifact_is_reported(db):
    """Отсутствие файла модели обнаруживается при применении, а не приводит к неверной оценке.

    Компоненты: модель Isolation Forest
    Ожидается: исключение FileNotFoundError
    """
    baseline = make_dataset(db, baseline_records(), "baseline")
    model = train_model(db, baseline.id, 0.08, 0.95)
    model.artifact_path = str(model.artifact_path) + ".missing"
    _, _, _, windows = load_context(db, baseline.id)
    with pytest.raises(FileNotFoundError):
        evaluate_isolation_forest(model, windows)
