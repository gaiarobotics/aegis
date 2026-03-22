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

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from monitor.async_db import run_db, run_in_transaction
from monitor.cache import InMemoryCache
from monitor.auth import (
    LoginRateLimiter,
    _SESSION_COOKIE_NAME,
    create_session_token,
    generate_csrf_token,
    require_role,
    verify_api_key,
    verify_session_token,
)
from monitor.clustering import ThreatClusterer
from monitor.config import MonitorConfig
from monitor.contagion import ContagionDetector, TopicClusterer as TopicHashClusterer
from monitor.db import Database
from monitor.epidemiology import R0Estimator
from monitor.graph import AgentGraph
from monitor.models import AgentNode, CompromiseRecord, KillswitchRule, QuarantineRule, StoredEvent
from monitor.validation import ReportValidator

STATIC_DIR = Path(__file__).parent / "static"

_login_limiter = LoginRateLimiter(per_minute=10, per_hour=50)


async def _periodic_background(app_state, interval: float = 30.0):
    """Periodic background work: reclustering, R0, pruning, counter sync."""
    while True:
        await asyncio.sleep(interval)
        try:
            # 1. Topic reclustering
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

            # 2. R0 computation + caching
            cfg = app_state.config
            app_state.cached_r0 = app_state.r0.estimate_r0(cfg.r0_window_hours)
            app_state.cached_r0_trend = app_state.r0.get_r0_trend(cfg.r0_window_hours)

            # 3. Prune old records
            cutoff = time.time() - cfg.r0_window_hours * 3600
            app_state.r0.prune(cutoff)

            # 4. Recompute agent counters from graph (consistency correction)
            nodes = graph_state["nodes"]
            app_state.agent_counts = {
                "total": len(nodes),
                "compromised": sum(1 for n in nodes if n["is_compromised"]),
                "quarantined": sum(1 for n in nodes if n["is_quarantined"]),
                "killswitched": sum(1 for n in nodes if n["is_killswitched"]),
            }
        except Exception:
            logging.getLogger(__name__).debug("Background task failed", exc_info=True)


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

    app.state.cached_r0 = 0.0
    app.state.cached_r0_trend = []
    app.state.agent_counts = {"total": 0, "compromised": 0, "quarantined": 0, "killswitched": 0}
    app.state.cache = InMemoryCache()

    # Warm threat-intel cache
    _ti_graph_state = app.state.graph.get_graph_state()
    _ti_result = {
        "compromised_agents": [n["id"] for n in _ti_graph_state["nodes"] if n["is_compromised"]],
        "compromised_hashes": [f"{h:032x}" for h in app.state.contagion_detector._compromised.values()],
        "quarantined_agents": [n["id"] for n in _ti_graph_state["nodes"] if n["is_quarantined"]],
        "generated_at": time.time(),
    }
    await app.state.cache.set("threat-intel", json.dumps(_ti_result).encode())

    recluster_task = asyncio.create_task(_periodic_background(app.state))
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
    """Push an event to all connected WebSocket clients in parallel."""
    clients = list(app_state.ws_clients)
    if not clients:
        return
    message = json.dumps(event)
    results = await asyncio.gather(
        *(ws.send_text(message) for ws in clients),
        return_exceptions=True,
    )
    dead = {ws for ws, r in zip(clients, results) if isinstance(r, Exception)}
    if dead:
        app_state.ws_clients -= dead


# ------------------------------------------------------------------
# Auth routes
# ------------------------------------------------------------------

@app.post("/auth/login")
async def auth_login(request: Request, data: dict):
    config: MonitorConfig = request.app.state.config

    client_ip = request.client.host if request.client else "unknown"
    if not _login_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts")

    api_key = data.get("api_key", "")

    # Open mode
    if not config.api_keys:
        secret = config.session_secret or "ephemeral"
        token = create_session_token("open", api_key, secret)
        response = JSONResponse({"role": "open"})
        response.set_cookie(
            _SESSION_COOKIE_NAME, token,
            httponly=True, samesite="lax", secure=request.url.scheme == "https",
            max_age=config.session_ttl_seconds,
        )
        return response

    # Validate the key
    import hmac as _hmac
    matched_role = None
    for configured_key, role in config.api_keys.items():
        if _hmac.compare_digest(api_key, configured_key):
            matched_role = role
            break

    if matched_role is None:
        raise HTTPException(status_code=403, detail="Invalid API key")

    if not config.session_secret:
        raise HTTPException(status_code=500, detail="Session secret not configured")

    token = create_session_token(matched_role, api_key, config.session_secret)
    response = JSONResponse({"role": matched_role})
    response.set_cookie(
        _SESSION_COOKIE_NAME, token,
        httponly=True, samesite="lax", secure=request.url.scheme == "https",
        max_age=config.session_ttl_seconds,
    )
    return response


@app.get("/auth/me")
async def auth_me(request: Request):
    config: MonitorConfig = request.app.state.config
    cookie = request.cookies.get(_SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")

    secret = config.session_secret or "ephemeral"
    payload = verify_session_token(cookie, secret, ttl=config.session_ttl_seconds)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # In non-open mode, verify key still exists
    if config.api_keys:
        import hashlib
        key_hash = payload.get("key_hash", "")
        found = any(
            hashlib.sha256(k.encode()).hexdigest() == key_hash
            for k in config.api_keys
        )
        if not found:
            raise HTTPException(status_code=401, detail="API key revoked")

    csrf = generate_csrf_token(secret) if config.session_secret else ""
    return {"role": payload["role"], "csrf_token": csrf}


@app.post("/auth/logout")
async def auth_logout(request: Request):
    config: MonitorConfig = request.app.state.config
    cookie = request.cookies.get(_SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")

    secret = config.session_secret or "ephemeral"
    payload = verify_session_token(cookie, secret, ttl=config.session_ttl_seconds)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    response = JSONResponse({"status": "logged out"})
    response.delete_cookie(_SESSION_COOKIE_NAME)
    return response


# ------------------------------------------------------------------
# Report endpoints
# ------------------------------------------------------------------

@app.post("/api/v1/reports/compromise")
async def receive_compromise(data: dict, _role: str = Depends(require_role("agent", "operator"))):
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
    app.state.agent_counts["compromised"] += 1
    await app.state.cache.invalidate("graph")
    await app.state.cache.invalidate("metrics")

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

    await app.state.cache.invalidate("threat-intel")
    await app.state.cache.invalidate("metrics")

    at_risk = graph.get_at_risk_agents(record.compromised_agent_id)

    await _broadcast(app.state, {
        "type": "compromise",
        "compromised_agent_id": record.compromised_agent_id,
        "at_risk": at_risk,
    })

    return {"status": "ok", "at_risk_agents": at_risk, "validation": validation_status}


@app.post("/api/v1/reports/trust")
async def receive_trust(data: dict, _role: str = Depends(require_role("agent", "operator"))):
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
async def receive_threat(data: dict, _role: str = Depends(require_role("agent", "operator"))):
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
    await app.state.cache.invalidate("metrics")

    await _broadcast(app.state, {
        "type": "threat",
        "agent_id": data.get("agent_id", ""),
        "threat_score": data.get("threat_score", 0.0),
    })

    return {"status": "ok"}


@app.post("/api/v1/heartbeat")
async def receive_heartbeat(data: dict, _role: str = Depends(require_role("agent", "operator"))):
    db: Database = app.state.db
    graph: AgentGraph = app.state.graph

    agent_id = data.get("agent_id", "")
    edges = data.get("edges", [])

    if agent_id not in graph.graph:
        app.state.agent_counts["total"] += 1

    graph.update_from_heartbeat(
        agent_id=agent_id,
        operator_id=data.get("operator_id", ""),
        trust_tier=data.get("trust_tier", 0),
        trust_score=data.get("trust_score", 0.0),
        is_quarantined=data.get("is_quarantined", False),
        edges=edges,
    )
    await app.state.cache.invalidate("graph")
    await app.state.cache.invalidate("metrics")

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
            await app.state.cache.invalidate("threat-intel")

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
async def get_graph(_role: str = Depends(require_role("viewer", "operator"))):
    cache = app.state.cache
    cached = await cache.get("graph")
    if cached is not None:
        return Response(content=cached, media_type="application/json")

    graph: AgentGraph = app.state.graph
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    graph_data = graph.get_graph_state()

    cluster_colors = topic_clusterer.get_cluster_colors_stable()
    if not cluster_colors:
        cluster_colors = topic_clusterer.get_cluster_colors()
    for node in graph_data["nodes"]:
        node["topic_color"] = cluster_colors.get(node["id"], "")

    await cache.set("graph", json.dumps(graph_data).encode())
    return graph_data


@app.get("/api/v1/metrics")
async def get_metrics(_role: str = Depends(require_role("viewer", "operator"))):
    cache = app.state.cache
    cached = await cache.get("metrics")
    if cached is not None:
        return Response(content=cached, media_type="application/json")

    clusterer: ThreatClusterer = app.state.clusterer
    db: Database = app.state.db

    cluster_info = clusterer.get_cluster_info()
    real_clusters = [c for c in cluster_info if c["cluster_id"] >= 0]

    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    topic_centroids = topic_clusterer.get_cluster_centroids()
    topic_cluster_count = sum(1 for c in topic_centroids if c["active"])

    active_threats = await run_db(db.get_events, event_type="threat",
                                  since=time.time() - 3600)

    counts = app.state.agent_counts
    result = {
        "r0": app.state.cached_r0,
        "r0_trend": app.state.cached_r0_trend,
        "active_threats": len(active_threats),
        "total_agents": counts["total"],
        "compromised_agents": counts["compromised"],
        "quarantined_agents": counts["quarantined"],
        "killswitched_agents": counts["killswitched"],
        "cluster_count": len(real_clusters),
        "clusters": cluster_info,
        "topic_cluster_count": topic_cluster_count,
    }
    await cache.set("metrics", json.dumps(result).encode())
    return result


@app.get("/api/v1/threat-intel")
async def get_threat_intel(_role: str = Depends(require_role("viewer", "operator"))):
    """Return threat intelligence for agent-side pre-emptive filtering."""
    cache = app.state.cache
    cached = await cache.get("threat-intel")
    if cached is not None:
        return Response(content=cached, media_type="application/json")

    graph: AgentGraph = app.state.graph
    contagion_detector: ContagionDetector = app.state.contagion_detector

    graph_state = graph.get_graph_state()
    compromised_agents = [n["id"] for n in graph_state["nodes"] if n["is_compromised"]]
    quarantined_agents = [n["id"] for n in graph_state["nodes"] if n["is_quarantined"]]
    compromised_hashes = [
        f"{h:032x}" for h in contagion_detector._compromised.values()
    ]

    result = {
        "compromised_agents": compromised_agents,
        "compromised_hashes": compromised_hashes,
        "quarantined_agents": quarantined_agents,
        "generated_at": time.time(),
    }
    await cache.set("threat-intel", json.dumps(result).encode())
    return result


@app.get("/api/v1/topic-clusters")
async def get_topic_clusters(_role: str = Depends(require_role("viewer", "operator"))):
    """Return cluster centroid data for the dashboard."""
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    return topic_clusterer.get_cluster_centroids()


@app.get("/api/v1/embeddings")
async def get_embeddings(_role: str = Depends(require_role("viewer", "operator"))):
    """Return nearest-neighbor embedding data."""
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    return topic_clusterer.get_nearest_neighbors()


@app.get("/api/v1/dendrogram")
async def get_dendrogram(_role: str = Depends(require_role("viewer", "operator"))):
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
async def get_trust(agent_id: str, _role: str = Depends(require_role("viewer", "operator"))):
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
    _role: str = Depends(require_role("viewer", "operator")),
):
    """Agent polling endpoint — returns block status."""
    db: Database = app.state.db
    blocked, reason, scope = await run_db(db.check_killswitch, agent_id, operator_id)
    return {"blocked": blocked, "reason": reason, "scope": scope}


@app.post("/api/v1/killswitch/rules")
async def create_killswitch_rule(data: dict, _role: str = Depends(require_role("operator"))):
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

    if rule.blocked and rule.scope == "agent":
        app.state.agent_counts["killswitched"] += 1
    elif rule.blocked and rule.scope == "swarm":
        app.state.agent_counts["killswitched"] = app.state.agent_counts["total"]

    await app.state.cache.invalidate("graph")
    await app.state.cache.invalidate("metrics")

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
async def list_killswitch_rules(_role: str = Depends(require_role("viewer", "operator"))):
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
async def delete_killswitch_rule(rule_id: str, _role: str = Depends(require_role("operator"))):
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

    await app.state.cache.invalidate("graph")
    await app.state.cache.invalidate("metrics")

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
    _role: str = Depends(require_role("viewer", "operator")),
):
    """Agent polling endpoint — returns quarantine status."""
    db: Database = app.state.db
    quarantined, reason, scope, severity = await run_db(db.check_quarantine, agent_id, operator_id)
    return {"quarantined": quarantined, "reason": reason, "scope": scope, "severity": severity}


@app.post("/api/v1/quarantine/rules")
async def create_quarantine_rule(data: dict, _role: str = Depends(require_role("operator"))):
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

    if rule.quarantined and rule.scope == "agent":
        app.state.agent_counts["quarantined"] += 1
    elif rule.quarantined and rule.scope == "swarm":
        app.state.agent_counts["quarantined"] = app.state.agent_counts["total"]

    await app.state.cache.invalidate("graph")
    await app.state.cache.invalidate("threat-intel")
    await app.state.cache.invalidate("metrics")

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
async def list_quarantine_rules(_role: str = Depends(require_role("viewer", "operator"))):
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
async def delete_quarantine_rule(rule_id: str, _role: str = Depends(require_role("operator"))):
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

    await app.state.cache.invalidate("graph")
    await app.state.cache.invalidate("threat-intel")
    await app.state.cache.invalidate("metrics")

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
    config: MonitorConfig = ws.app.state.config

    # In open mode, accept immediately
    if not config.api_keys:
        await ws.accept()
        app.state.ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(ws)
        return

    # Try session cookie first
    import hashlib
    cookie = ws.cookies.get(_SESSION_COOKIE_NAME)
    role = None
    if cookie and config.session_secret:
        payload = verify_session_token(cookie, config.session_secret, ttl=config.session_ttl_seconds)
        if payload and payload.get("role") in ("viewer", "operator", "open"):
            key_hash = payload.get("key_hash", "")
            for k in config.api_keys:
                if hashlib.sha256(k.encode()).hexdigest() == key_hash:
                    role = payload["role"]
                    break

    if role:
        await ws.accept()
        app.state.ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(ws)
        return

    # No valid cookie — accept and require first-message auth
    await ws.accept()
    try:
        import hmac as _hmac
        raw = await asyncio.wait_for(ws.receive_json(), timeout=10.0)
        auth_data = raw.get("auth", {})
        api_key = auth_data.get("api_key", "")
        matched_role = None
        for configured_key, r in config.api_keys.items():
            if _hmac.compare_digest(api_key, configured_key):
                matched_role = r
                break
        if matched_role not in ("viewer", "operator"):
            await ws.send_json({"authenticated": False, "error": "Insufficient permissions"})
            await ws.close(code=4003, reason="Forbidden")
            return

        await ws.send_json({"authenticated": True, "role": matched_role})
        app.state.ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(ws)
    except (asyncio.TimeoutError, Exception):
        await ws.close(code=4003, reason="Authentication required")


# ------------------------------------------------------------------
# Dashboard
# ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    index = STATIC_DIR / "index.html"
    if index.is_file():
        return HTMLResponse(content=index.read_text())
    return HTMLResponse(content="<h1>AEGIS Monitor</h1><p>Dashboard not found.</p>")
