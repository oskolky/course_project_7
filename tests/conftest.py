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
