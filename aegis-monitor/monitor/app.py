"""AEGIS Monitor — FastAPI application."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from monitor.async_db import run_db, run_in_transaction
from monitor.auth import verify_api_key
from monitor.clustering import ThreatClusterer
from monitor.config import MonitorConfig
from monitor.contagion import ContagionDetector, TopicClusterer as TopicHashClusterer
from monitor.db import Database
from monitor.epidemiology import R0Estimator
from monitor.graph import AgentGraph
from monitor.models import AgentNode, CompromiseRecord, KillswitchRule, QuarantineRule, StoredEvent
from monitor.validation import ReportValidator

STATIC_DIR = Path(__file__).parent / "static"


async def _periodic_recluster(app_state, interval: float = 30.0):
    """Run topic reclustering periodically instead of per-heartbeat."""
    while True:
        await asyncio.sleep(interval)
        try:
            graph_state = app_state.graph.get_graph_state()
            agent_statuses = {}
            for n in graph_state["nodes"]:
                if n["is_compromised"]:
                    agent_statuses[n["id"]] = "compromised"
                elif n["is_quarantined"]:
                    agent_statuses[n["id"]] = "quarantined"
                else:
                    agent_statuses[n["id"]] = "active"
            app_state.topic_clusterer.update_stable_clusters(agent_statuses)

            centroids = app_state.topic_clusterer.get_cluster_centroids()
            active_count = sum(1 for c in centroids if c["active"])
            await _broadcast(app_state, {
                "type": "topic_clusters_updated",
                "active_cluster_count": active_count,
            })
        except Exception:
            logging.getLogger(__name__).debug("Recluster failed", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: C901
    cfg = MonitorConfig.load()
    app.state.config = cfg
    app.state.db = Database(cfg.effective_database_url)
    app.state.graph = AgentGraph()
    app.state.r0 = R0Estimator()
    app.state.clusterer = ThreatClusterer()
    app.state.ws_clients: set[WebSocket] = set()
    app.state.topic_clusterer = TopicHashClusterer()
    app.state.contagion_detector = ContagionDetector()
    app.state.report_validator = ReportValidator(cfg)

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

    # Simulator state is initialised by register_routes() below;
    # do NOT re-assign here or it will overwrite the PresetManager.

    recluster_task = asyncio.create_task(_periodic_recluster(app.state))
    yield
    recluster_task.cancel()


app = FastAPI(title="AEGIS Monitor", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Register simulator routes
from monitor.simulator.routes import register_routes as _register_sim_routes  # noqa: E402

_register_sim_routes(app)


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
        content_hash_hex=data.get("content_hash_hex", ""),
        timestamp=data.get("timestamp", time.time()),
    )
    # Synchronous in-memory mutations first
    r0.add_record(record)
    graph.mark_compromised(record.compromised_agent_id)

    # Prepare models for DB persistence
    node = graph.graph.nodes.get(record.compromised_agent_id, {})
    agent_node = AgentNode(
        agent_id=record.compromised_agent_id,
        is_compromised=True,
        trust_tier=0,
        trust_score=0.0,
        last_heartbeat=node.get("last_heartbeat", 0),
    )
    event = StoredEvent(
        event_id=record.record_id,
        event_type="compromise",
        agent_id=record.reporter_agent_id,
        operator_id=data.get("operator_id", ""),
        timestamp=record.timestamp,
        payload=data,
    )

    def _persist_compromise(tx):
        # Insert compromise record
        tx.execute(
            """INSERT INTO compromises
                   (record_id, reporter_agent_id, compromised_agent_id,
                    source, nk_score, nk_verdict, recommended_action,
                    content_hash_hex, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(record_id) DO UPDATE SET
                   reporter_agent_id    = excluded.reporter_agent_id,
                   compromised_agent_id = excluded.compromised_agent_id,
                   source               = excluded.source,
                   nk_score             = excluded.nk_score,
                   nk_verdict           = excluded.nk_verdict,
                   recommended_action   = excluded.recommended_action,
                   content_hash_hex     = excluded.content_hash_hex,
                   timestamp            = excluded.timestamp
            """,
            (
                record.record_id,
                record.reporter_agent_id,
                record.compromised_agent_id,
                record.source,
                record.nk_score,
                record.nk_verdict,
                record.recommended_action,
                record.content_hash_hex,
                record.timestamp,
            ),
        )
        # Upsert agent state
        tx.execute(
            """INSERT INTO agents
                   (agent_id, operator_id, trust_tier, trust_score,
                    is_compromised, is_quarantined, is_killswitched,
                    last_heartbeat, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                   operator_id     = excluded.operator_id,
                   trust_tier      = excluded.trust_tier,
                   trust_score     = excluded.trust_score,
                   is_compromised  = excluded.is_compromised,
                   is_quarantined  = excluded.is_quarantined,
                   is_killswitched = excluded.is_killswitched,
                   last_heartbeat  = excluded.last_heartbeat,
                   metadata        = excluded.metadata
            """,
            (
                agent_node.agent_id,
                agent_node.operator_id,
                agent_node.trust_tier,
                agent_node.trust_score,
                int(agent_node.is_compromised),
                int(agent_node.is_quarantined),
                int(agent_node.is_killswitched),
                agent_node.last_heartbeat,
                json.dumps(agent_node.metadata),
            ),
        )
        # Insert event
        tx.execute(
            """INSERT INTO events
                   (event_id, event_type, agent_id, operator_id, timestamp, payload)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(event_id) DO UPDATE SET
                   event_type  = excluded.event_type,
                   agent_id    = excluded.agent_id,
                   operator_id = excluded.operator_id,
                   timestamp   = excluded.timestamp,
                   payload     = excluded.payload
            """,
            (
                event.event_id,
                event.event_type,
                event.agent_id,
                event.operator_id,
                event.timestamp,
                json.dumps(event.payload),
            ),
        )
        # Look up reporter info within same transaction
        row = tx.fetchone(
            "SELECT * FROM agents WHERE agent_id = ?",
            (record.reporter_agent_id,),
        )
        return row

    reporter_row = await run_in_transaction(db, _persist_compromise)
    reporter_node = Database._row_to_agent(reporter_row) if reporter_row else None

    # Validate the compromise report hash before adding to contagion cloud
    contagion_detector: ContagionDetector = app.state.contagion_detector
    validator: ReportValidator = app.state.report_validator
    comp_hash = data.get("content_hash_hex", "")

    reporter_trust_tier = reporter_node.trust_tier if reporter_node else 0
    reporter_is_quarantined = reporter_node.is_quarantined if reporter_node else False

    vr = validator.validate(
        reporter_id=record.reporter_agent_id,
        compromised_id=record.compromised_agent_id,
        hash_hex=comp_hash,
        reporter_trust_tier=reporter_trust_tier,
        reporter_is_quarantined=reporter_is_quarantined,
    )

    if not vr.accepted:
        validation_status = "rate_limited"
    elif vr.hash_confirmed:
        validation_status = "confirmed"
    elif vr.rejection_reason == "pending_quorum":
        validation_status = "pending_quorum"
    else:
        validation_status = "rejected" if vr.rejection_reason else "confirmed"

    # Only add to contagion cloud if hash was confirmed by validation
    if vr.hash_confirmed and comp_hash:
        contagion_detector.mark_compromised(record.compromised_agent_id, comp_hash)
    elif not comp_hash:
        # Fallback path: no hash provided, use graph node hash (unchanged behaviour)
        node_attrs = graph.graph.nodes.get(record.compromised_agent_id, {})
        fallback_hash = node_attrs.get("content_hash", "")
        if fallback_hash:
            contagion_detector.mark_compromised(record.compromised_agent_id, fallback_hash)
        validation_status = "confirmed"

    at_risk = graph.get_at_risk_agents(record.compromised_agent_id)

    await _broadcast(app.state, {
        "type": "compromise",
        "compromised_agent_id": record.compromised_agent_id,
        "at_risk": at_risk,
    })

    return {"status": "ok", "at_risk_agents": at_risk, "validation": validation_status}


@app.post("/api/v1/reports/trust")
async def receive_trust(data: dict, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db

    event = StoredEvent(
        event_id=data.get("report_id", str(uuid.uuid4())),
        event_type="trust",
        agent_id=data.get("agent_id", ""),
        operator_id=data.get("operator_id", ""),
        timestamp=data.get("timestamp", time.time()),
        payload=data,
    )
    target_id = data.get("target_agent_id", "")
    target_node = AgentNode(
        agent_id=target_id,
        trust_tier=data.get("trust_tier", 0),
        trust_score=data.get("trust_score", 0.0),
        last_heartbeat=time.time(),
    ) if target_id else None

    def _persist_trust(tx):
        tx.execute(
            """INSERT INTO events
                   (event_id, event_type, agent_id, operator_id, timestamp, payload)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(event_id) DO UPDATE SET
                   event_type  = excluded.event_type,
                   agent_id    = excluded.agent_id,
                   operator_id = excluded.operator_id,
                   timestamp   = excluded.timestamp,
                   payload     = excluded.payload
            """,
            (
                event.event_id,
                event.event_type,
                event.agent_id,
                event.operator_id,
                event.timestamp,
                json.dumps(event.payload),
            ),
        )
        if target_node:
            tx.execute(
                """INSERT INTO agents
                       (agent_id, operator_id, trust_tier, trust_score,
                        is_compromised, is_quarantined, is_killswitched,
                        last_heartbeat, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                       operator_id     = excluded.operator_id,
                       trust_tier      = excluded.trust_tier,
                       trust_score     = excluded.trust_score,
                       is_compromised  = excluded.is_compromised,
                       is_quarantined  = excluded.is_quarantined,
                       is_killswitched = excluded.is_killswitched,
                       last_heartbeat  = excluded.last_heartbeat,
                       metadata        = excluded.metadata
                """,
                (
                    target_node.agent_id,
                    target_node.operator_id,
                    target_node.trust_tier,
                    target_node.trust_score,
                    int(target_node.is_compromised),
                    int(target_node.is_quarantined),
                    int(target_node.is_killswitched),
                    target_node.last_heartbeat,
                    json.dumps(target_node.metadata),
                ),
            )

    await run_in_transaction(db, _persist_trust)

    return {"status": "ok"}


@app.post("/api/v1/reports/threat")
async def receive_threat(data: dict, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db
    clusterer: ThreatClusterer = app.state.clusterer

    event_id = data.get("report_id", str(uuid.uuid4()))
    await run_db(db.insert_event, StoredEvent(
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

    # Extract content hash
    content_hash = data.get("content_hash", "")
    metadata: dict[str, Any] = {}
    if content_hash:
        metadata["content_hash"] = content_hash

    # Persist agent + edges in a single transaction
    from monitor.models import AgentEdge
    agent_node = AgentNode(
        agent_id=agent_id,
        operator_id=data.get("operator_id", ""),
        trust_tier=data.get("trust_tier", 0),
        trust_score=data.get("trust_score", 0.0),
        is_quarantined=data.get("is_quarantined", False),
        last_heartbeat=time.time(),
        metadata=metadata,
    )
    edge_models = [
        AgentEdge(
            source_agent_id=agent_id,
            target_agent_id=edge.get("target_agent_id", ""),
            direction=edge.get("direction", "outbound"),
            last_seen=edge.get("last_seen", time.time()),
            message_count=edge.get("message_count", 0),
        )
        for edge in edges
    ]

    def _persist_heartbeat(tx):
        tx.execute(
            """INSERT INTO agents
                   (agent_id, operator_id, trust_tier, trust_score,
                    is_compromised, is_quarantined, is_killswitched,
                    last_heartbeat, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                   operator_id     = excluded.operator_id,
                   trust_tier      = excluded.trust_tier,
                   trust_score     = excluded.trust_score,
                   is_compromised  = excluded.is_compromised,
                   is_quarantined  = excluded.is_quarantined,
                   is_killswitched = excluded.is_killswitched,
                   last_heartbeat  = excluded.last_heartbeat,
                   metadata        = excluded.metadata
            """,
            (
                agent_node.agent_id,
                agent_node.operator_id,
                agent_node.trust_tier,
                agent_node.trust_score,
                int(agent_node.is_compromised),
                int(agent_node.is_quarantined),
                int(agent_node.is_killswitched),
                agent_node.last_heartbeat,
                json.dumps(agent_node.metadata),
            ),
        )
        for e in edge_models:
            tx.execute(
                """INSERT INTO edges
                       (source_agent_id, target_agent_id, direction, last_seen, message_count)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source_agent_id, target_agent_id) DO UPDATE SET
                       direction     = excluded.direction,
                       last_seen     = excluded.last_seen,
                       message_count = excluded.message_count
                """,
                (
                    e.source_agent_id,
                    e.target_agent_id,
                    e.direction,
                    e.last_seen,
                    e.message_count,
                ),
            )

    await run_in_transaction(db, _persist_heartbeat)

    # Store hash in graph node attributes
    if content_hash:
        node_data = graph.graph.nodes.get(agent_id)
        if node_data is not None:
            node_data["content_hash"] = content_hash

    # Topic clustering and contagion detection
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    contagion_detector: ContagionDetector = app.state.contagion_detector
    hash_for_analysis = content_hash
    topic_velocity = data.get("topic_velocity", 0.0)
    if hash_for_analysis:
        topic_clusterer.update(agent_id, hash_for_analysis)

        score = contagion_detector.check_with_velocity(
            agent_id, hash_for_analysis, topic_velocity=topic_velocity,
        )
        if score >= contagion_detector._alert_threshold:
            contagion_event = StoredEvent(
                event_id=str(uuid.uuid4()),
                event_type="contagion_alert",
                agent_id=agent_id,
                operator_id=data.get("operator_id", ""),
                timestamp=time.time(),
                payload={
                    "contagion_score": score,
                    "topic_velocity": topic_velocity,
                    "hash": hash_for_analysis,
                },
            )

            # Auto-quarantine the flagged agent
            rule = QuarantineRule(
                rule_id=str(uuid.uuid4()),
                scope="agent",
                target=agent_id,
                quarantined=True,
                reason=f"Contagion alert: score={score:.3f}, velocity={topic_velocity:.3f}",
                severity="high",
                created_at=time.time(),
                created_by="contagion_detector",
            )

            def _persist_contagion_alert(tx):
                tx.execute(
                    """INSERT INTO events
                           (event_id, event_type, agent_id, operator_id, timestamp, payload)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(event_id) DO UPDATE SET
                           event_type  = excluded.event_type,
                           agent_id    = excluded.agent_id,
                           operator_id = excluded.operator_id,
                           timestamp   = excluded.timestamp,
                           payload     = excluded.payload
                    """,
                    (
                        contagion_event.event_id,
                        contagion_event.event_type,
                        contagion_event.agent_id,
                        contagion_event.operator_id,
                        contagion_event.timestamp,
                        json.dumps(contagion_event.payload),
                    ),
                )
                tx.execute(
                    """INSERT INTO quarantine_rules
                           (rule_id, scope, target, quarantined, reason, severity, created_at, created_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(rule_id) DO UPDATE SET
                           scope       = excluded.scope,
                           target      = excluded.target,
                           quarantined = excluded.quarantined,
                           reason      = excluded.reason,
                           severity    = excluded.severity,
                           created_at  = excluded.created_at,
                           created_by  = excluded.created_by
                    """,
                    (
                        rule.rule_id,
                        rule.scope,
                        rule.target,
                        int(rule.quarantined),
                        rule.reason,
                        rule.severity,
                        rule.created_at,
                        rule.created_by,
                    ),
                )
                rowcount = tx.execute(
                    "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
                    (1, agent_id),
                )
                if rowcount == 0:
                    tx.execute(
                        """INSERT INTO agents
                               (agent_id, operator_id, trust_tier, trust_score,
                                is_compromised, is_quarantined, is_killswitched,
                                last_heartbeat, metadata)
                           VALUES (?, '', 0, 0.0, 0, ?, 0, 0, '{}')
                        """,
                        (agent_id, 1),
                    )

            await run_in_transaction(db, _persist_contagion_alert)
            graph.mark_quarantined(agent_id, True)

            await _broadcast(app.state, {
                "type": "quarantine",
                "agent_id": agent_id,
                "quarantined": True,
                "reason": rule.reason,
                "source": "contagion_detector",
            })

    await _broadcast(app.state, {"type": "heartbeat", "agent_id": agent_id})

    return {"status": "ok"}


# ------------------------------------------------------------------
# Query endpoints
# ------------------------------------------------------------------

@app.get("/api/v1/graph")
async def get_graph(_key: str = Depends(verify_api_key)):
    graph: AgentGraph = app.state.graph
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    graph_data = graph.get_graph_state()

    cluster_colors = topic_clusterer.get_cluster_colors_stable()
    if not cluster_colors:
        cluster_colors = topic_clusterer.get_cluster_colors()
    for node in graph_data["nodes"]:
        node["topic_color"] = cluster_colors.get(node["id"], "")

    return graph_data


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

    await run_db(db.get_events, event_type="threat", limit=0)

    cluster_info = clusterer.get_cluster_info()
    # Filter out noise cluster
    real_clusters = [c for c in cluster_info if c["cluster_id"] >= 0]

    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    topic_centroids = topic_clusterer.get_cluster_centroids()
    topic_cluster_count = sum(1 for c in topic_centroids if c["active"])

    active_threats = await run_db(db.get_events, event_type="threat",
                                  since=time.time() - 3600)

    return {
        "r0": r0.estimate_r0(cfg.r0_window_hours),
        "r0_trend": r0.get_r0_trend(cfg.r0_window_hours),
        "active_threats": len(active_threats),
        "total_agents": len(graph_state["nodes"]),
        "compromised_agents": compromised,
        "quarantined_agents": quarantined,
        "killswitched_agents": killswitched,
        "cluster_count": len(real_clusters),
        "clusters": cluster_info,
        "topic_cluster_count": topic_cluster_count,
    }


@app.get("/api/v1/threat-intel")
async def get_threat_intel(_key: str = Depends(verify_api_key)):
    """Return threat intelligence for agent-side pre-emptive filtering."""
    graph: AgentGraph = app.state.graph
    contagion_detector: ContagionDetector = app.state.contagion_detector

    graph_state = graph.get_graph_state()

    compromised_agents = [
        n["id"] for n in graph_state["nodes"] if n["is_compromised"]
    ]
    quarantined_agents = [
        n["id"] for n in graph_state["nodes"] if n["is_quarantined"]
    ]

    # Serialize compromised hashes from contagion detector
    compromised_hashes = [
        f"{h:032x}" for h in contagion_detector._compromised.values()
    ]

    return {
        "compromised_agents": compromised_agents,
        "compromised_hashes": compromised_hashes,
        "quarantined_agents": quarantined_agents,
        "generated_at": time.time(),
    }


@app.get("/api/v1/topic-clusters")
async def get_topic_clusters(_key: str = Depends(verify_api_key)):
    """Return cluster centroid data for the dashboard."""
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    return topic_clusterer.get_cluster_centroids()


@app.get("/api/v1/embeddings")
async def get_embeddings(_key: str = Depends(verify_api_key)):
    """Return nearest-neighbor embedding data."""
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    return topic_clusterer.get_nearest_neighbors()


@app.get("/api/v1/dendrogram")
async def get_dendrogram(_key: str = Depends(verify_api_key)):
    """Return linkage data for dendrogram rendering."""
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    graph: AgentGraph = app.state.graph
    graph_state = graph.get_graph_state()

    agent_statuses: dict[str, str] = {}
    compromised_agents: set[str] = set()
    for n in graph_state["nodes"]:
        if n["is_compromised"]:
            agent_statuses[n["id"]] = "compromised"
            compromised_agents.add(n["id"])
        elif n["is_quarantined"]:
            agent_statuses[n["id"]] = "quarantined"
        else:
            agent_statuses[n["id"]] = "active"

    return topic_clusterer.get_dendrogram_data(agent_statuses, compromised_agents)


@app.get("/api/v1/trust/{agent_id}")
async def get_trust(agent_id: str, _key: str = Depends(verify_api_key)):
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph

    agent = await run_db(db.get_agent, agent_id)
    if agent is None:
        return {"agent_id": agent_id, "found": False}

    at_risk = graph.get_at_risk_agents(agent_id) if agent.is_compromised else []
    has_aegis = graph.graph.nodes.get(agent_id, {}).get("has_aegis", False)

    return {
        "agent_id": agent_id,
        "found": True,
        "trust_tier": agent.trust_tier,
        "trust_score": agent.trust_score,
        "is_compromised": agent.is_compromised,
        "is_quarantined": agent.is_quarantined,
        "is_killswitched": agent.is_killswitched,
        "has_aegis": has_aegis,
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
    blocked, reason, scope = await run_db(db.check_killswitch, agent_id, operator_id)
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
    def _persist_killswitch_create(tx):
        tx.execute(
            """INSERT INTO killswitch_rules
                   (rule_id, scope, target, blocked, reason, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(rule_id) DO UPDATE SET
                   scope      = excluded.scope,
                   target     = excluded.target,
                   blocked    = excluded.blocked,
                   reason     = excluded.reason,
                   created_at = excluded.created_at,
                   created_by = excluded.created_by
            """,
            (
                rule.rule_id,
                rule.scope,
                rule.target,
                int(rule.blocked),
                rule.reason,
                rule.created_at,
                rule.created_by,
            ),
        )
        affected_agents: list[str] = []
        if rule.blocked and rule.scope == "agent" and rule.target:
            rowcount = tx.execute(
                "UPDATE agents SET is_killswitched = ? WHERE agent_id = ?",
                (1, rule.target),
            )
            if rowcount == 0:
                tx.execute(
                    """INSERT INTO agents
                           (agent_id, operator_id, trust_tier, trust_score,
                            is_compromised, is_quarantined, is_killswitched,
                            last_heartbeat, metadata)
                       VALUES (?, '', 0, 0.0, 0, 0, ?, 0, '{}')
                    """,
                    (rule.target, 1),
                )
            affected_agents.append(rule.target)
        elif rule.blocked and rule.scope == "swarm":
            rows = tx.fetchall("SELECT * FROM agents")
            for r in rows:
                tx.execute(
                    "UPDATE agents SET is_killswitched = ? WHERE agent_id = ?",
                    (1, r["agent_id"]),
                )
                affected_agents.append(r["agent_id"])
        return affected_agents

    affected_agents = await run_in_transaction(db, _persist_killswitch_create)

    # Update graph synchronously after DB transaction
    graph: AgentGraph = app.state.graph
    for aid in affected_agents:
        graph.mark_killswitched(aid, True)

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
    rules = await run_db(db.get_killswitch_rules)
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

    def _persist_killswitch_delete(tx):
        rowcount = tx.execute(
            "DELETE FROM killswitch_rules WHERE rule_id = ?", (rule_id,)
        )
        if rowcount == 0:
            return False, []
        # Re-evaluate killswitch status for all agents
        unblocked_agents: list[str] = []
        rows = tx.fetchall("SELECT * FROM agents")
        for r in rows:
            aid = r["agent_id"]
            oid = r["operator_id"]
            is_ks = bool(r["is_killswitched"])
            # Check if still blocked by remaining rules
            swarm_row = tx.fetchone(
                "SELECT * FROM killswitch_rules WHERE scope = 'swarm' AND blocked = 1 LIMIT 1"
            )
            still_blocked = swarm_row is not None
            if not still_blocked and oid:
                op_row = tx.fetchone(
                    "SELECT * FROM killswitch_rules WHERE scope = 'operator' AND target = ? AND blocked = 1 LIMIT 1",
                    (oid,),
                )
                still_blocked = op_row is not None
            if not still_blocked and aid:
                agent_row = tx.fetchone(
                    "SELECT * FROM killswitch_rules WHERE scope = 'agent' AND target = ? AND blocked = 1 LIMIT 1",
                    (aid,),
                )
                still_blocked = agent_row is not None
            if not still_blocked and is_ks:
                tx.execute(
                    "UPDATE agents SET is_killswitched = ? WHERE agent_id = ?",
                    (0, aid),
                )
                unblocked_agents.append(aid)
        return True, unblocked_agents

    deleted, unblocked_agents = await run_in_transaction(db, _persist_killswitch_delete)

    # Update graph synchronously after DB transaction
    for aid in unblocked_agents:
        graph.mark_killswitched(aid, False)

    if deleted:
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
    quarantined, reason, scope, severity = await run_db(db.check_quarantine, agent_id, operator_id)
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
    def _persist_quarantine_create(tx):
        tx.execute(
            """INSERT INTO quarantine_rules
                   (rule_id, scope, target, quarantined, reason, severity, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(rule_id) DO UPDATE SET
                   scope       = excluded.scope,
                   target      = excluded.target,
                   quarantined = excluded.quarantined,
                   reason      = excluded.reason,
                   severity    = excluded.severity,
                   created_at  = excluded.created_at,
                   created_by  = excluded.created_by
            """,
            (
                rule.rule_id,
                rule.scope,
                rule.target,
                int(rule.quarantined),
                rule.reason,
                rule.severity,
                rule.created_at,
                rule.created_by,
            ),
        )
        affected_agents: list[str] = []
        if rule.quarantined and rule.scope == "agent" and rule.target:
            rowcount = tx.execute(
                "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
                (1, rule.target),
            )
            if rowcount == 0:
                tx.execute(
                    """INSERT INTO agents
                           (agent_id, operator_id, trust_tier, trust_score,
                            is_compromised, is_quarantined, is_killswitched,
                            last_heartbeat, metadata)
                       VALUES (?, '', 0, 0.0, 0, ?, 0, 0, '{}')
                    """,
                    (rule.target, 1),
                )
            affected_agents.append(rule.target)
        elif rule.quarantined and rule.scope == "swarm":
            rows = tx.fetchall("SELECT * FROM agents")
            for r in rows:
                tx.execute(
                    "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
                    (1, r["agent_id"]),
                )
                affected_agents.append(r["agent_id"])
        return affected_agents

    affected_agents = await run_in_transaction(db, _persist_quarantine_create)

    # Update graph synchronously after DB transaction
    graph: AgentGraph = app.state.graph
    for aid in affected_agents:
        graph.mark_quarantined(aid, True)

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
    rules = await run_db(db.get_quarantine_rules)
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

    def _persist_quarantine_delete(tx):
        rowcount = tx.execute(
            "DELETE FROM quarantine_rules WHERE rule_id = ?", (rule_id,)
        )
        if rowcount == 0:
            return False, []
        # Re-evaluate quarantine status for all agents
        unquarantined_agents: list[str] = []
        rows = tx.fetchall("SELECT * FROM agents")
        for r in rows:
            aid = r["agent_id"]
            oid = r["operator_id"]
            is_q = bool(r["is_quarantined"])
            # Check if still quarantined by remaining rules
            swarm_row = tx.fetchone(
                "SELECT * FROM quarantine_rules WHERE scope = 'swarm' AND quarantined = 1 LIMIT 1"
            )
            still_quarantined = swarm_row is not None
            if not still_quarantined and oid:
                op_row = tx.fetchone(
                    "SELECT * FROM quarantine_rules WHERE scope = 'operator' AND target = ? AND quarantined = 1 LIMIT 1",
                    (oid,),
                )
                still_quarantined = op_row is not None
            if not still_quarantined and aid:
                agent_row = tx.fetchone(
                    "SELECT * FROM quarantine_rules WHERE scope = 'agent' AND target = ? AND quarantined = 1 LIMIT 1",
                    (aid,),
                )
                still_quarantined = agent_row is not None
            if not still_quarantined and is_q:
                tx.execute(
                    "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
                    (0, aid),
                )
                unquarantined_agents.append(aid)
        return True, unquarantined_agents

    deleted, unquarantined_agents = await run_in_transaction(db, _persist_quarantine_delete)

    # Update graph synchronously after DB transaction
    for aid in unquarantined_agents:
        graph.mark_quarantined(aid, False)

    if deleted:
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
