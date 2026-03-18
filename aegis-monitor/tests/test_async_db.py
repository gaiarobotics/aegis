"""Tests for async database helpers."""

import pytest
from monitor.db import Database
from monitor.models import AgentNode
from monitor.async_db import run_db, run_in_transaction


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.mark.asyncio
class TestRunDb:
    async def test_run_db_offloads_to_thread(self, db):
        db.upsert_agent(AgentNode(agent_id="async-1", last_heartbeat=0))
        agent = await run_db(db.get_agent, "async-1")
        assert agent is not None
        assert agent.agent_id == "async-1"

    async def test_run_db_returns_none(self, db):
        agent = await run_db(db.get_agent, "nonexistent")
        assert agent is None


@pytest.mark.asyncio
class TestRunInTransaction:
    async def test_transaction_commits(self, db):
        def do_writes(tx):
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-async-1", "op", 0, "{}"),
            )
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-async-2", "op", 0, "{}"),
            )

        await run_in_transaction(db, do_writes)
        a1 = db.get_agent("tx-async-1")
        a2 = db.get_agent("tx-async-2")
        assert a1 is not None
        assert a2 is not None

    async def test_transaction_rolls_back(self, db):
        def do_writes(tx):
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-doomed", "op", 0, "{}"),
            )
            raise ValueError("boom")

        with pytest.raises(ValueError):
            await run_in_transaction(db, do_writes)
        agent = db.get_agent("tx-doomed")
        assert agent is None
