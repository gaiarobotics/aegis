"""Tests for database transaction support."""

from __future__ import annotations

import os

import pytest

from monitor.backends._sqlite import SqliteBackend


# ---------------------------------------------------------------------------
# SQLite transaction tests
# ---------------------------------------------------------------------------


class TestSqliteTransaction:
    """Tests for SqliteBackend.transaction()."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.backend = SqliteBackend(":memory:")
        self.backend.init_schema()

    def test_commit_on_success(self):
        with self.backend.transaction() as txn:
            txn.execute(
                "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("a1", "op1", 1, 0.5, 0, 0, 0, 0.0, "{}"),
            )
        # Should be visible after commit
        row = self.backend.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("a1",))
        assert row is not None
        assert row["agent_id"] == "a1"

    def test_rollback_on_exception(self):
        with pytest.raises(RuntimeError):
            with self.backend.transaction() as txn:
                txn.execute(
                    "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                    "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("a2", "op1", 1, 0.5, 0, 0, 0, 0.0, "{}"),
                )
                raise RuntimeError("boom")
        # Should NOT be visible
        row = self.backend.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("a2",))
        assert row is None

    def test_batch_multiple_writes(self):
        with self.backend.transaction() as txn:
            for i in range(5):
                txn.execute(
                    "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                    "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f"batch-{i}", "op1", 1, 0.0, 0, 0, 0, 0.0, "{}"),
                )
        rows = self.backend.fetchall("SELECT * FROM agents")
        assert len(rows) == 5

    def test_fetchone_within_transaction(self):
        self.backend.execute(
            "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
            "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("existing", "op1", 2, 0.9, 0, 0, 0, 0.0, "{}"),
        )
        with self.backend.transaction() as txn:
            row = txn.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("existing",))
            assert row is not None
            assert row["trust_tier"] == 2

    def test_fetchall_within_transaction(self):
        for i in range(3):
            self.backend.execute(
                "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"agent-{i}", "op1", 1, 0.0, 0, 0, 0, 0.0, "{}"),
            )
        with self.backend.transaction() as txn:
            rows = txn.fetchall("SELECT * FROM agents ORDER BY agent_id")
            assert len(rows) == 3
            assert rows[0]["agent_id"] == "agent-0"


# ---------------------------------------------------------------------------
# Postgres transaction tests
# ---------------------------------------------------------------------------

_PG_URL = os.environ.get("TEST_POSTGRES_URL")
_skip_pg = pytest.mark.skipif(not _PG_URL, reason="TEST_POSTGRES_URL not set")


@pytest.mark.postgres
@_skip_pg
class TestPostgresTransaction:
    """Tests for PostgresBackend.transaction()."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from monitor.backends._postgres import PostgresBackend

        self.backend = PostgresBackend(_PG_URL)
        self.backend.init_schema()
        # Clean slate
        self.backend.execute("DELETE FROM agents")
        yield
        self.backend.execute("DELETE FROM agents")
        self.backend.close()

    def test_commit_on_success(self):
        with self.backend.transaction() as txn:
            txn.execute(
                "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("a1", "op1", 1, 0.5, False, False, False, 0.0, "{}"),
            )
        row = self.backend.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("a1",))
        assert row is not None
        assert row["agent_id"] == "a1"

    def test_rollback_on_exception(self):
        with pytest.raises(RuntimeError):
            with self.backend.transaction() as txn:
                txn.execute(
                    "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                    "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("a2", "op1", 1, 0.5, False, False, False, 0.0, "{}"),
                )
                raise RuntimeError("boom")
        row = self.backend.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("a2",))
        assert row is None

    def test_batch_multiple_writes(self):
        with self.backend.transaction() as txn:
            for i in range(5):
                txn.execute(
                    "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                    "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f"batch-{i}", "op1", 1, 0.0, False, False, False, 0.0, "{}"),
                )
        rows = self.backend.fetchall("SELECT * FROM agents")
        assert len(rows) == 5

    def test_fetchone_within_transaction(self):
        self.backend.execute(
            "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
            "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("existing", "op1", 2, 0.9, False, False, False, 0.0, "{}"),
        )
        with self.backend.transaction() as txn:
            row = txn.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("existing",))
            assert row is not None
            assert row["trust_tier"] == 2

    def test_fetchall_within_transaction(self):
        for i in range(3):
            self.backend.execute(
                "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"agent-{i}", "op1", 1, 0.0, False, False, False, 0.0, "{}"),
            )
        with self.backend.transaction() as txn:
            rows = txn.fetchall("SELECT * FROM agents ORDER BY agent_id")
            assert len(rows) == 3
            assert rows[0]["agent_id"] == "agent-0"


# ---------------------------------------------------------------------------
# Database facade transaction tests
# ---------------------------------------------------------------------------


class TestDatabaseTransaction:
    """Tests for Database.transaction() (facade over SQLite backend)."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from monitor.db import Database

        self.db = Database(":memory:")

    def test_commit_on_success(self):
        with self.db.transaction() as txn:
            txn.execute(
                "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("a1", "op1", 1, 0.5, 0, 0, 0, 0.0, "{}"),
            )
        row = self.db._backend.fetchone(
            "SELECT * FROM agents WHERE agent_id = ?", ("a1",)
        )
        assert row is not None
        assert row["agent_id"] == "a1"

    def test_rollback_on_exception(self):
        with pytest.raises(RuntimeError):
            with self.db.transaction() as txn:
                txn.execute(
                    "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                    "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("a2", "op1", 1, 0.5, 0, 0, 0, 0.0, "{}"),
                )
                raise RuntimeError("boom")
        row = self.db._backend.fetchone(
            "SELECT * FROM agents WHERE agent_id = ?", ("a2",)
        )
        assert row is None

    def test_delegates_to_backend(self):
        """The facade transaction should produce same handle type as backend."""
        with self.db.transaction() as txn:
            from monitor.backends._sqlite import _SqliteTransaction

            assert isinstance(txn, _SqliteTransaction)


# ---------------------------------------------------------------------------
# Concurrency safety tests
# ---------------------------------------------------------------------------


class TestSqliteConcurrency:
    """Verify that the lock prevents interleaving on :memory: backends."""

    def test_concurrent_transactions_are_serialised(self):
        """Two threads writing via transactions should not corrupt each other."""
        import concurrent.futures

        backend = SqliteBackend(":memory:")
        backend.init_schema()

        def insert_batch(prefix: str) -> list[str]:
            ids = []
            with backend.transaction() as txn:
                for i in range(20):
                    aid = f"{prefix}-{i}"
                    txn.execute(
                        "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                        "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (aid, "op", 0, 0.0, 0, 0, 0, 0.0, "{}"),
                    )
                    ids.append(aid)
            return ids

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(insert_batch, f"t{t}") for t in range(4)]
            all_ids = []
            for f in concurrent.futures.as_completed(futures):
                all_ids.extend(f.result())

        rows = backend.fetchall("SELECT agent_id FROM agents ORDER BY agent_id")
        assert len(rows) == 80
        assert {r["agent_id"] for r in rows} == set(all_ids)

    def test_concurrent_mixed_reads_writes(self):
        """Reads and writes from multiple threads should not raise."""
        import concurrent.futures

        backend = SqliteBackend(":memory:")
        backend.init_schema()

        # Seed some data
        for i in range(10):
            backend.execute(
                "INSERT INTO agents (agent_id, operator_id, trust_tier, trust_score, "
                "is_compromised, is_quarantined, is_killswitched, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"seed-{i}", "op", 0, 0.0, 0, 0, 0, 0.0, "{}"),
            )

        errors: list[Exception] = []

        def reader():
            for _ in range(50):
                backend.fetchall("SELECT * FROM agents")

        def writer(prefix: str):
            for i in range(20):
                backend.execute(
                    "INSERT OR REPLACE INTO agents (agent_id, operator_id, trust_tier, "
                    "trust_score, is_compromised, is_quarantined, is_killswitched, "
                    "last_heartbeat, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f"{prefix}-{i}", "op", 0, 0.0, 0, 0, 0, 0.0, "{}"),
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futs = []
            futs.append(pool.submit(reader))
            futs.append(pool.submit(reader))
            futs.extend(pool.submit(writer, f"w{t}") for t in range(4))
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result()
                except Exception as e:
                    errors.append(e)

        assert errors == [], f"Concurrency errors: {errors}"
