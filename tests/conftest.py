from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DATA = tempfile.mkdtemp(prefix="logoscope-tests-")
os.environ["LOG_ANALYZER_DATA_DIR"] = TEST_DATA
os.environ["DATABASE_URL"] = f"sqlite:///{Path(TEST_DATA) / 'test.db'}"

import pytest
from fastapi.testclient import TestClient

from log_analyzer.api.app import app
from log_analyzer.storage.database import SessionLocal, engine
from log_analyzer.storage.models import Base

# Группы методики испытаний: каждый тест относится ровно к одной из них.
TEST_GROUPS = {"typical", "boundary", "negative"}


def pytest_collection_modifyitems(items):
    for item in items:
        if not TEST_GROUPS & {marker.name for marker in item.iter_markers()}:
            raise pytest.UsageError(
                f"Тест {item.nodeid} не отмечен ни одной группой: {', '.join(sorted(TEST_GROUPS))}"
            )


@pytest.fixture()
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db):
    with TestClient(app) as test_client:
        yield test_client
