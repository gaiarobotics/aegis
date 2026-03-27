"""Tests for embedding_model column migration."""

import sqlite3
import pytest
from monitor.backends._sqlite import SqliteBackend
from monitor.db import Database
from monitor.models import CompromiseRecord


class TestSqliteMigration:
    def test_new_db_has_embedding_model_column(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        backend = SqliteBackend(db_path)
        backend.init_schema()
        conn = sqlite3.connect(db_path)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(compromises)").fetchall()]
        assert "embedding_model" in cols

    def test_legacy_rows_have_empty_embedding_model(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        backend = SqliteBackend(db_path)
        backend.init_schema()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO compromises (record_id, reporter_agent_id, compromised_agent_id, timestamp) "
            "VALUES ('r1', 'a1', 'a2', 1.0)"
        )
        conn.commit()
        row = conn.execute("SELECT embedding_model FROM compromises WHERE record_id='r1'").fetchone()
        assert row[0] == ""


class TestCompromiseRecordModel:
    def test_embedding_model_default(self):
        record = CompromiseRecord()
        assert record.embedding_model == ""

    def test_embedding_model_set(self):
        record = CompromiseRecord(embedding_model="all-MiniLM-L6-v2")
        assert record.embedding_model == "all-MiniLM-L6-v2"


class TestDatabaseInsertWithModel:
    def test_insert_stores_embedding_model(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        backend = SqliteBackend(db_path)
        backend.init_schema()
        db = Database(backend)

        record = CompromiseRecord(
            record_id="r1",
            reporter_agent_id="a1",
            compromised_agent_id="a2",
            content_hash_hex="abcd" * 8,
            embedding_model="gemini-embedding-2-preview",
        )
        db.insert_compromise(record)
        records = db.get_compromises()
        assert len(records) == 1
        assert records[0].embedding_model == "gemini-embedding-2-preview"
