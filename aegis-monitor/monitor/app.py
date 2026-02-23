"""AEGIS Monitor — FastAPI application."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from monitor.auth import verify_api_key
from monitor.clustering import ThreatClusterer
from monitor.config import MonitorConfig
from monitor.db import Database
from monitor.epidemiology import R0Estimator
from monitor.graph import AgentGraph
from monitor.models import AgentNode, CompromiseRecord, KillswitchRule, QuarantineRule, StoredEvent

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = MonitorConfig.load()
    app.state.config = cfg
    app.state.db = Database(cfg.effective_database_url)
    app.state.graph = AgentGraph()
    app.state.r0 = R0Estimator()
    app.state.clusterer = ThreatClusterer()
    app.state.ws_clients: set[WebSocket] = set()

    # Load existing compromise records into R0 estimator
    records = app.state.db.get_compromises()
    app.state.r0.load_records(records)

    # Rebuild graph from persisted agents and edges
    for agent in app.state.db.get_all_agents():
        app.state.graph.update_from_heartbeat(
            agent_id=agent.agent_id,
            operator_id=agent.operator_id,
            trust_tier=agent.trust_tier,
            trust_score=agent.trust_score,
            is_quarantined=agent.is_quarantined,
        )
        if agent.is_compromised:
            app.state.graph.mark_compromised(agent.agent_id)
        if agent.is_killswitched:
            app.state.graph.mark_killswitched(agent.agent_id)

    yield


app = FastAPI(title="AEGIS Monitor", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

async def _broadcast(app_state: Any, event: dict) -> None:
    """Push an event to all connected WebSocket clients."""
    dead: set[WebSocket] = set()
    message = json.dumps(event)
    for ws in app_state.ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    app_state.ws_clients -= dead


# ------------------------------------------------------------------
# Report endpoints
# ------------------------------------------------------------------

@app.post("/api/v1/reports/compromise")
async def receive_compromise(data: dict, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph
    r0: R0Estimator = app.state.r0

    record = CompromiseRecord(
        record_id=data.get("report_id", str(uuid.uuid4())),
        reporter_agent_id=data.get("agent_id", ""),
        compromised_agent_id=data.get("compromised_agent_id", ""),
        source=data.get("source", ""),
        nk_score=data.get("nk_score", 0.0),
        nk_verdict=data.get("nk_verdict", ""),
        recommended_action=data.get("recommended_action", "quarantine"),
        timestamp=data.get("timestamp", time.time()),
    )
    db.insert_compromise(record)
    r0.add_record(record)
    graph.mark_compromised(record.compromised_agent_id)

    # Persist agent state
    node = graph.graph.nodes.get(record.compromised_agent_id, {})
    db.upsert_agent(AgentNode(
        agent_id=record.compromised_agent_id,
        is_compromised=True,
        trust_tier=0,
        trust_score=0.0,
        last_heartbeat=node.get("last_heartbeat", 0),
    ))

    # Store as event
    db.insert_event(StoredEvent(
        event_id=record.record_id,
        event_type="compromise",
        agent_id=record.reporter_agent_id,
        operator_id=data.get("operator_id", ""),
        timestamp=record.timestamp,
        payload=data,
    ))

    at_risk = graph.get_at_risk_agents(record.compromised_agent_id)

    await _broadcast(app.state, {
        "type": "compromise",
        "compromised_agent_id": record.compromised_agent_id,
        "at_risk": at_risk,
    })

    return {"status": "ok", "at_risk_agents": at_risk}


@app.post("/api/v1/reports/trust")
async def receive_trust(data: dict, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db

    db.insert_event(StoredEvent(
        event_id=data.get("report_id", str(uuid.uuid4())),
        event_type="trust",
        agent_id=data.get("agent_id", ""),
        operator_id=data.get("operator_id", ""),
        timestamp=data.get("timestamp", time.time()),
        payload=data,
    ))

    target_id = data.get("target_agent_id", "")
    if target_id:
        db.upsert_agent(AgentNode(
            agent_id=target_id,
            trust_tier=data.get("trust_tier", 0),
            trust_score=data.get("trust_score", 0.0),
            last_heartbeat=time.time(),
        ))

    return {"status": "ok"}


@app.post("/api/v1/reports/threat")
async def receive_threat(data: dict, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db
    clusterer: ThreatClusterer = app.state.clusterer

    event_id = data.get("report_id", str(uuid.uuid4()))
    db.insert_event(StoredEvent(
        event_id=event_id,
        event_type="threat",
        agent_id=data.get("agent_id", ""),
        operator_id=data.get("operator_id", ""),
        timestamp=data.get("timestamp", time.time()),
        payload=data,
    ))

    # Build metadata text for clustering (no raw content)
    meta_parts = [
        f"score:{data.get('threat_score', 0)}",
        f"matches:{data.get('scanner_match_count', 0)}",
        f"nk:{data.get('nk_verdict', '')}",
        f"agent:{data.get('agent_id', '')}",
    ]
    clusterer.add_event(event_id, " ".join(meta_parts))

    await _broadcast(app.state, {
        "type": "threat",
        "agent_id": data.get("agent_id", ""),
        "threat_score": data.get("threat_score", 0.0),
    })

    return {"status": "ok"}


@app.post("/api/v1/heartbeat")
async def receive_heartbeat(data: dict, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph

    agent_id = data.get("agent_id", "")
    edges = data.get("edges", [])

    graph.update_from_heartbeat(
        agent_id=agent_id,
        operator_id=data.get("operator_id", ""),
        trust_tier=data.get("trust_tier", 0),
        trust_score=data.get("trust_score", 0.0),
        is_quarantined=data.get("is_quarantined", False),
        edges=edges,
    )

    # Persist
    db.upsert_agent(AgentNode(
        agent_id=agent_id,
        operator_id=data.get("operator_id", ""),
        trust_tier=data.get("trust_tier", 0),
        trust_score=data.get("trust_score", 0.0),
        is_quarantined=data.get("is_quarantined", False),
        last_heartbeat=time.time(),
    ))
    from monitor.models import AgentEdge
    for edge in edges:
        db.upsert_edge(AgentEdge(
            source_agent_id=agent_id,
            target_agent_id=edge.get("target_agent_id", ""),
            direction=edge.get("direction", "outbound"),
            last_seen=edge.get("last_seen", time.time()),
            message_count=edge.get("message_count", 0),
        ))

    await _broadcast(app.state, {"type": "heartbeat", "agent_id": agent_id})

    return {"status": "ok"}


# ------------------------------------------------------------------
# Query endpoints
# ------------------------------------------------------------------

@app.get("/api/v1/graph")
async def get_graph(_key: str = Depends(verify_api_key)):
    graph: AgentGraph = app.state.graph
    return graph.get_graph_state()


@app.get("/api/v1/metrics")
async def get_metrics(_key: str = Depends(verify_api_key)):
    r0: R0Estimator = app.state.r0
    graph: AgentGraph = app.state.graph
    clusterer: ThreatClusterer = app.state.clusterer
    db: Database = app.state.db
    cfg: MonitorConfig = app.state.config

    graph_state = graph.get_graph_state()
    compromised = sum(1 for n in graph_state["nodes"] if n["is_compromised"])
    quarantined = sum(1 for n in graph_state["nodes"] if n["is_quarantined"])
    killswitched = sum(1 for n in graph_state["nodes"] if n["is_killswitched"])

    threat_events = db.get_events(event_type="threat", limit=0)

    cluster_info = clusterer.get_cluster_info()
    # Filter out noise cluster
    real_clusters = [c for c in cluster_info if c["cluster_id"] >= 0]

    return {
        "r0": r0.estimate_r0(cfg.r0_window_hours),
        "r0_trend": r0.get_r0_trend(cfg.r0_window_hours),
        "active_threats": len(db.get_events(event_type="threat",
                                            since=time.time() - 3600)),
        "total_agents": len(graph_state["nodes"]),
        "compromised_agents": compromised,
        "quarantined_agents": quarantined,
        "killswitched_agents": killswitched,
        "cluster_count": len(real_clusters),
        "clusters": cluster_info,
    }


@app.get("/api/v1/trust/{agent_id}")
async def get_trust(agent_id: str, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph

    agent = db.get_agent(agent_id)
    if agent is None:
        return {"agent_id": agent_id, "found": False}

    at_risk = graph.get_at_risk_agents(agent_id) if agent.is_compromised else []

    return {
        "agent_id": agent_id,
        "found": True,
        "trust_tier": agent.trust_tier,
        "trust_score": agent.trust_score,
        "is_compromised": agent.is_compromised,
        "is_quarantined": agent.is_quarantined,
        "is_killswitched": agent.is_killswitched,
        "at_risk_agents": at_risk,
    }


# ------------------------------------------------------------------
# Killswitch endpoints
# ------------------------------------------------------------------

@app.get("/api/v1/killswitch/status")
async def killswitch_status(
    agent_id: str = "",
    operator_id: str = "",
    _key: str = Depends(verify_api_key),
):
    """Agent polling endpoint — returns block status."""
    db: Database = app.state.db
    blocked, reason, scope = db.check_killswitch(agent_id, operator_id)
    return {"blocked": blocked, "reason": reason, "scope": scope}


@app.post("/api/v1/killswitch/rules")
async def create_killswitch_rule(data: dict, _key: str = Depends(verify_api_key)):
    """Create a killswitch rule."""
    db: Database = app.state.db
    rule_id = data.get("rule_id", str(uuid.uuid4()))
    rule = KillswitchRule(
        rule_id=rule_id,
        scope=data.get("scope", "agent"),
        target=data.get("target", ""),
        blocked=data.get("blocked", True),
        reason=data.get("reason", ""),
        created_at=data.get("created_at", time.time()),
        created_by=data.get("created_by", ""),
    )
    db.insert_killswitch_rule(rule)

    # Update agent killswitched status in DB and graph
    graph: AgentGraph = app.state.graph
    if rule.blocked and rule.scope == "agent" and rule.target:
        db.set_agent_killswitched(rule.target, True)
        graph.mark_killswitched(rule.target, True)
    elif rule.blocked and rule.scope == "swarm":
        # Mark all known agents as killswitched
        for agent in db.get_all_agents():
            db.set_agent_killswitched(agent.agent_id, True)
            graph.mark_killswitched(agent.agent_id, True)

    await _broadcast(app.state, {
        "type": "killswitch",
        "action": "created",
        "rule_id": rule_id,
        "scope": rule.scope,
        "target": rule.target,
        "blocked": rule.blocked,
        "reason": rule.reason,
    })

    return {"rule_id": rule_id, "status": "ok"}


@app.get("/api/v1/killswitch/rules")
async def list_killswitch_rules(_key: str = Depends(verify_api_key)):
    """List all active killswitch rules."""
    db: Database = app.state.db
    rules = db.get_killswitch_rules()
    return {
        "rules": [
            {
                "rule_id": r.rule_id,
                "scope": r.scope,
                "target": r.target,
                "blocked": r.blocked,
                "reason": r.reason,
                "created_at": r.created_at,
                "created_by": r.created_by,
            }
            for r in rules
        ]
    }


@app.delete("/api/v1/killswitch/rules/{rule_id}")
async def delete_killswitch_rule(rule_id: str, _key: str = Depends(verify_api_key)):
    """Remove a killswitch rule."""
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph
    deleted = db.delete_killswitch_rule(rule_id)

    if deleted:
        # Re-evaluate killswitch status for all agents
        for agent in db.get_all_agents():
            still_blocked, _, _ = db.check_killswitch(agent.agent_id, agent.operator_id)
            if not still_blocked and agent.is_killswitched:
                db.set_agent_killswitched(agent.agent_id, False)
                graph.mark_killswitched(agent.agent_id, False)

        await _broadcast(app.state, {
            "type": "killswitch",
            "action": "deleted",
            "rule_id": rule_id,
        })

    return {"status": "ok" if deleted else "not_found"}


# ------------------------------------------------------------------
# Quarantine endpoints
# ------------------------------------------------------------------

@app.get("/api/v1/quarantine/status")
async def quarantine_status(
    agent_id: str = "",
    operator_id: str = "",
    _key: str = Depends(verify_api_key),
):
    """Agent polling endpoint — returns quarantine status."""
    db: Database = app.state.db
    quarantined, reason, scope, severity = db.check_quarantine(agent_id, operator_id)
    return {"quarantined": quarantined, "reason": reason, "scope": scope, "severity": severity}


@app.post("/api/v1/quarantine/rules")
async def create_quarantine_rule(data: dict, _key: str = Depends(verify_api_key)):
    """Create a quarantine rule."""
    db: Database = app.state.db
    rule_id = data.get("rule_id", str(uuid.uuid4()))
    rule = QuarantineRule(
        rule_id=rule_id,
        scope=data.get("scope", "agent"),
        target=data.get("target", ""),
        quarantined=data.get("quarantined", True),
        reason=data.get("reason", ""),
        severity=data.get("severity", "low"),
        created_at=data.get("created_at", time.time()),
        created_by=data.get("created_by", ""),
    )
    db.insert_quarantine_rule(rule)

    # Update agent quarantine status in DB and graph
    graph: AgentGraph = app.state.graph
    if rule.quarantined and rule.scope == "agent" and rule.target:
        db.set_agent_quarantined(rule.target, True)
        graph.mark_quarantined(rule.target, True)
    elif rule.quarantined and rule.scope == "swarm":
        for agent in db.get_all_agents():
            db.set_agent_quarantined(agent.agent_id, True)
            graph.mark_quarantined(agent.agent_id, True)

    await _broadcast(app.state, {
        "type": "quarantine",
        "action": "created",
        "rule_id": rule_id,
        "scope": rule.scope,
        "target": rule.target,
        "quarantined": rule.quarantined,
        "reason": rule.reason,
        "severity": rule.severity,
    })

    return {"rule_id": rule_id, "status": "ok"}


@app.get("/api/v1/quarantine/rules")
async def list_quarantine_rules(_key: str = Depends(verify_api_key)):
    """List all active quarantine rules."""
    db: Database = app.state.db
    rules = db.get_quarantine_rules()
    return {
        "rules": [
            {
                "rule_id": r.rule_id,
                "scope": r.scope,
                "target": r.target,
                "quarantined": r.quarantined,
                "reason": r.reason,
                "severity": r.severity,
                "created_at": r.created_at,
                "created_by": r.created_by,
            }
            for r in rules
        ]
    }


@app.delete("/api/v1/quarantine/rules/{rule_id}")
async def delete_quarantine_rule(rule_id: str, _key: str = Depends(verify_api_key)):
    """Remove a quarantine rule (release quarantine)."""
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph
    deleted = db.delete_quarantine_rule(rule_id)

    if deleted:
        # Re-evaluate quarantine status for all agents
        for agent in db.get_all_agents():
            still_quarantined, _, _, _ = db.check_quarantine(agent.agent_id, agent.operator_id)
            if not still_quarantined and agent.is_quarantined:
                db.set_agent_quarantined(agent.agent_id, False)
                graph.mark_quarantined(agent.agent_id, False)

        await _broadcast(app.state, {
            "type": "quarantine",
            "action": "deleted",
            "rule_id": rule_id,
        })

    return {"status": "ok" if deleted else "not_found"}


# ------------------------------------------------------------------
# WebSocket
# ------------------------------------------------------------------

@app.websocket("/ws/dashboard")
async def ws_dashboard(ws: WebSocket):
    await ws.accept()
    app.state.ws_clients.add(ws)
    try:
        while True:
            # Keep connection alive; client can send pings
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        app.state.ws_clients.discard(ws)


# ------------------------------------------------------------------
# Dashboard
# ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    index = STATIC_DIR / "index.html"
    if index.is_file():
        return HTMLResponse(content=index.read_text())
    return HTMLResponse(content="<h1>AEGIS Monitor</h1><p>Dashboard not found.</p>")
