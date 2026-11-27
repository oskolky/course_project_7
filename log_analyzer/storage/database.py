from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from log_analyzer.config import DATABASE_URL
from log_analyzer.storage.models import Base

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:

    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


if engine.dialect.name == "sqlite":
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base.metadata.create_all(engine)


def migrate_schema(engine) -> list[str]:
    """Доводит схему, созданную прежними версиями программы, до текущей. Новые
    таблицы создаёт create_all; здесь добавляются только недостающие столбцы
    и правила внешних ключей. Возвращает перечень внесённых изменений."""
    applied: list[str] = []
    inspector = inspect(engine)
    with engine.begin() as connection:
        columns = {column["name"] for column in inspector.get_columns("rules")}
        if "presentation" not in columns:
            connection.execute(text("ALTER TABLE rules ADD COLUMN presentation JSON"))
            applied.append("rules.presentation")
        if engine.dialect.name == "postgresql":
            nullable = connection.execute(text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name = 'model_versions' AND column_name = 'dataset_id'"
            )).scalar()
            if nullable == "NO":
                connection.execute(text("ALTER TABLE model_versions ALTER COLUMN dataset_id DROP NOT NULL"))
                applied.append("model_versions.dataset_id nullable")
            delete_rule = connection.execute(text(
                "SELECT confdeltype FROM pg_constraint "
                "WHERE conname = 'model_versions_dataset_id_fkey' "
                "AND conrelid = 'model_versions'::regclass"
            )).scalar()
            if delete_rule is not None and delete_rule != "n":
                connection.execute(text("ALTER TABLE model_versions DROP CONSTRAINT model_versions_dataset_id_fkey"))
                connection.execute(text(
                    "ALTER TABLE model_versions ADD CONSTRAINT model_versions_dataset_id_fkey "
                    "FOREIGN KEY (dataset_id) REFERENCES datasets (id) ON DELETE SET NULL"
                ))
                applied.append("model_versions.dataset_id on delete set null")
    return applied


migrate_schema(engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
