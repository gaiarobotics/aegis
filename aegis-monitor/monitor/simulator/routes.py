"""FastAPI routes for the AEGIS epidemic simulator.

Provides two entry points:

* :func:`create_simulator_app` — standalone FastAPI app (handy for tests).
* :func:`register_routes` — mount the simulator on an existing app.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import hashlib
import hmac as _hmac

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from monitor.auth import (
    _SESSION_COOKIE_NAME,
    require_csrf,
    require_role,
    verify_session_token,
)
from monitor.config import MonitorConfig

from monitor.simulator.engine import SimulationEngine
from monitor.simulator.models import SimState
from monitor.simulator.presets import PresetManager

_STATIC_DIR = Path(__file__).parent.parent / "static"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


async def _broadcast_sim(app: FastAPI, data: dict) -> None:
    """Send *data* as JSON to every connected WebSocket client."""
    clients: set = getattr(app.state, "sim_ws_clients", set())
    dead: set[WebSocket] = set()
    message = json.dumps(data)
    for ws in clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    clients -= dead


def _get_engine(app: FastAPI) -> SimulationEngine | None:
    return getattr(app.state, "sim_engine", None)


def _require_engine(app: FastAPI) -> SimulationEngine:
    engine = _get_engine(app)
    if engine is None:
        raise HTTPException(status_code=400, detail="No simulation generated")
    return engine


# ------------------------------------------------------------------
# Route registration
# ------------------------------------------------------------------


def register_routes(app: FastAPI) -> None:
    """Register all simulator routes on *app*."""

    # Initialise state attributes if not already present
    if not hasattr(app.state, "sim_engine"):
        app.state.sim_engine = None
    if not hasattr(app.state, "preset_manager"):
        app.state.preset_manager = PresetManager()
    if not hasattr(app.state, "sim_ws_clients"):
        app.state.sim_ws_clients = set()
    if not hasattr(app.state, "sim_tick_task"):
        app.state.sim_tick_task = None

    # ------------------------------------------------------------------
    # Preset CRUD
    # ------------------------------------------------------------------

    @app.get("/api/v1/simulator/presets")
    async def list_presets(_role: str = Depends(require_role("operator"))) -> list[str]:
        return app.state.preset_manager.list_presets()

    @app.get("/api/v1/simulator/presets/{name}")
    async def load_preset(name: str, _role: str = Depends(require_role("operator"))):
        try:
            config = app.state.preset_manager.load(name)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
        return app.state.preset_manager._config_to_dict(config)

    @app.post("/api/v1/simulator/presets/{name}")
    async def save_preset(name: str, body: dict[str, Any], _role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        config = app.state.preset_manager._dict_to_config(body)
        app.state.preset_manager.save(name, config)
        return {"status": "ok"}

    @app.delete("/api/v1/simulator/presets/{name}")
    async def delete_preset(name: str, _role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        try:
            app.state.preset_manager.delete(name)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
        return {"status": "ok"}

    # ------------------------------------------------------------------
    # Simulation control
    # ------------------------------------------------------------------

    @app.post("/api/v1/simulator/generate")
    async def generate(body: dict[str, Any], _role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        config = app.state.preset_manager._dict_to_config(body)
        engine = SimulationEngine(config)
        try:
            engine.generate()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        app.state.sim_engine = engine
        return {"state": engine.state.value, "num_agents": config.num_agents}

    @app.post("/api/v1/simulator/start")
    async def start(_role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _require_engine(app)
        try:
            engine.start()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"state": engine.state.value}

    @app.post("/api/v1/simulator/pause")
    async def pause(_role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _require_engine(app)
        # Cancel auto-tick task if running
        task: asyncio.Task | None = getattr(app.state, "sim_tick_task", None)
        if task is not None and not task.done():
            task.cancel()
            app.state.sim_tick_task = None
        try:
            engine.pause()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"state": engine.state.value}

    @app.post("/api/v1/simulator/resume")
    async def resume(_role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _require_engine(app)
        try:
            engine.resume()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"state": engine.state.value}

    @app.post("/api/v1/simulator/stop")
    async def stop(_role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _require_engine(app)
        # Cancel auto-tick task if running
        task: asyncio.Task | None = getattr(app.state, "sim_tick_task", None)
        if task is not None and not task.done():
            task.cancel()
            app.state.sim_tick_task = None
        try:
            engine.stop()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"state": engine.state.value}

    @app.post("/api/v1/simulator/reset")
    async def reset(_role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _get_engine(app)
        if engine is not None:
            engine.reset()
        app.state.sim_engine = None
        return {"state": SimState.IDLE.value}

    @app.post("/api/v1/simulator/tick")
    async def tick(_role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _require_engine(app)
        try:
            snapshot = engine.tick()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        data = snapshot.to_dict()
        await _broadcast_sim(app, data)
        return data

    @app.post("/api/v1/simulator/run")
    async def run(body: dict[str, Any], _role: str = Depends(require_role("operator")), _csrf: None = Depends(require_csrf)):
        engine = _require_engine(app)
        ticks_per_second = body.get("ticks_per_second", 1)
        delay = 1.0 / max(0.1, ticks_per_second)

        async def auto_tick():
            try:
                while engine.state == SimState.RUNNING:
                    snapshot = engine.tick()
                    await _broadcast_sim(app, snapshot.to_dict())
                    await asyncio.sleep(delay)
            except asyncio.CancelledError:
                pass

        # Cancel any existing auto-tick task
        task: asyncio.Task | None = getattr(app.state, "sim_tick_task", None)
        if task is not None and not task.done():
            task.cancel()

        app.state.sim_tick_task = asyncio.create_task(auto_tick())
        return {"state": engine.state.value}

    # ------------------------------------------------------------------
    # Query endpoints
    # ------------------------------------------------------------------

    @app.get("/api/v1/simulator/status")
    async def status(_role: str = Depends(require_role("operator"))):
        engine = _get_engine(app)
        if engine is None:
            return {
                "state": SimState.IDLE.value,
                "tick": 0,
                "num_agents": 0,
                "counts": {},
            }
        agents = engine.get_agent_states()
        counts: dict[str, int] = {}
        for a in agents:
            s = a["status"]
            counts[s] = counts.get(s, 0) + 1
        return {
            "state": engine.state.value,
            "tick": engine._tick_count,
            "num_agents": len(agents),
            "counts": counts,
        }

    @app.get("/api/v1/simulator/agents")
    async def agents(_role: str = Depends(require_role("operator"))):
        engine = _require_engine(app)
        return engine.get_agent_states()

    @app.get("/api/v1/simulator/graph")
    async def graph(_role: str = Depends(require_role("operator"))):
        engine = _require_engine(app)
        if engine._graph is None:
            raise HTTPException(status_code=400, detail="No graph generated")
        graph_data = engine._graph.to_serializable()
        agent_states = {a["id"]: a for a in engine.get_agent_states()}
        for node in graph_data["nodes"]:
            agent = agent_states.get(node["id"], {})
            node.update(agent)
        return graph_data

    @app.get("/api/v1/simulator/embeddings")
    async def embeddings(_role: str = Depends(require_role("operator"))):
        engine = _require_engine(app)
        return engine.get_embedding_entries()

    @app.get("/api/v1/simulator/scatter")
    async def scatter(_role: str = Depends(require_role("operator"))):
        engine = _require_engine(app)
        return engine.get_scatter_data()

    @app.get("/api/v1/simulator/dendrogram")
    async def dendrogram(_role: str = Depends(require_role("operator"))):
        engine = _require_engine(app)
        return engine.get_dendrogram_data()

    @app.get("/api/v1/simulator/export")
    async def export(_role: str = Depends(require_role("operator"))):
        engine = _require_engine(app)
        return engine.export_results()

    # ------------------------------------------------------------------
    # WebSocket
    # ------------------------------------------------------------------

    @app.websocket("/ws/simulator")
    async def websocket_simulator(ws: WebSocket):
        config: MonitorConfig = ws.app.state.config

        # In open mode, accept immediately
        if not config.api_keys:
            await ws.accept()
            app.state.sim_ws_clients.add(ws)
            try:
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                pass
            finally:
                app.state.sim_ws_clients.discard(ws)
            return

        # Try session cookie first
        cookie = ws.cookies.get(_SESSION_COOKIE_NAME)
        role = None
        if cookie and config.session_secret:
            payload = verify_session_token(cookie, config.session_secret, ttl=config.session_ttl_seconds)
            if payload and payload.get("role") == "operator":
                key_hash = payload.get("key_hash", "")
                for k in config.api_keys:
                    if hashlib.sha256(k.encode()).hexdigest() == key_hash:
                        role = payload["role"]
                        break

        if role:
            await ws.accept()
            app.state.sim_ws_clients.add(ws)
            try:
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                pass
            finally:
                app.state.sim_ws_clients.discard(ws)
            return

        # No valid cookie — accept and require first-message auth
        await ws.accept()
        try:
            raw = await asyncio.wait_for(ws.receive_json(), timeout=10.0)
            auth_data = raw.get("auth", {})
            api_key = auth_data.get("api_key", "")
            matched_role = None
            for configured_key, r in config.api_keys.items():
                if _hmac.compare_digest(api_key, configured_key):
                    matched_role = r
                    break
            if matched_role != "operator":
                await ws.send_json({"authenticated": False, "error": "Insufficient permissions"})
                await ws.close(code=4003, reason="Forbidden")
                return

            await ws.send_json({"authenticated": True, "role": matched_role})
            app.state.sim_ws_clients.add(ws)
            try:
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                pass
            finally:
                app.state.sim_ws_clients.discard(ws)
        except (asyncio.TimeoutError, Exception):
            await ws.close(code=4003, reason="Authentication required")

    # ------------------------------------------------------------------
    # Page
    # ------------------------------------------------------------------

    @app.get("/simulator", response_class=HTMLResponse)
    async def simulator_page():
        html_path = _STATIC_DIR / "simulator.html"
        if not html_path.is_file():
            raise HTTPException(status_code=404, detail="simulator.html not found")
        return HTMLResponse(html_path.read_text())


# ------------------------------------------------------------------
# Standalone app factory
# ------------------------------------------------------------------


def create_simulator_app(preset_dir: str | None = None) -> FastAPI:
    """Create a standalone FastAPI app with all simulator routes.

    Parameters
    ----------
    preset_dir:
        Optional path to a preset directory.  Useful for tests that
        need an isolated preset storage location.
    """
    app = FastAPI(title="AEGIS Simulator")
    if preset_dir is not None:
        app.state.preset_manager = PresetManager(preset_dir=preset_dir)
    register_routes(app)
    return app
