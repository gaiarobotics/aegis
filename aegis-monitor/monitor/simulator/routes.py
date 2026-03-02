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

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

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
    async def list_presets() -> list[str]:
        return app.state.preset_manager.list_presets()

    @app.get("/api/v1/simulator/presets/{name}")
    async def load_preset(name: str):
        try:
            config = app.state.preset_manager.load(name)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
        return app.state.preset_manager._config_to_dict(config)

    @app.post("/api/v1/simulator/presets/{name}")
    async def save_preset(name: str, body: dict[str, Any]):
        config = app.state.preset_manager._dict_to_config(body)
        app.state.preset_manager.save(name, config)
        return {"status": "ok"}

    @app.delete("/api/v1/simulator/presets/{name}")
    async def delete_preset(name: str):
        try:
            app.state.preset_manager.delete(name)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
        return {"status": "ok"}

    # ------------------------------------------------------------------
    # Simulation control
    # ------------------------------------------------------------------

    @app.post("/api/v1/simulator/generate")
    async def generate(body: dict[str, Any]):
        config = app.state.preset_manager._dict_to_config(body)
        engine = SimulationEngine(config)
        try:
            engine.generate()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        app.state.sim_engine = engine
        return {"state": engine.state.value, "num_agents": config.num_agents}

    @app.post("/api/v1/simulator/start")
    async def start():
        engine = _require_engine(app)
        try:
            engine.start()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"state": engine.state.value}

    @app.post("/api/v1/simulator/pause")
    async def pause():
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
    async def resume():
        engine = _require_engine(app)
        try:
            engine.resume()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"state": engine.state.value}

    @app.post("/api/v1/simulator/stop")
    async def stop():
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
    async def reset():
        engine = _get_engine(app)
        if engine is not None:
            engine.reset()
        app.state.sim_engine = None
        return {"state": SimState.IDLE.value}

    @app.post("/api/v1/simulator/tick")
    async def tick():
        engine = _require_engine(app)
        try:
            snapshot = engine.tick()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        data = snapshot.to_dict()
        await _broadcast_sim(app, data)
        return data

    @app.post("/api/v1/simulator/run")
    async def run(body: dict[str, Any]):
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
    async def status():
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
    async def agents():
        engine = _require_engine(app)
        return engine.get_agent_states()

    @app.get("/api/v1/simulator/graph")
    async def graph():
        engine = _require_engine(app)
        if engine._graph is None:
            raise HTTPException(status_code=400, detail="No graph generated")
        graph_data = engine._graph.to_serializable()
        agent_states = {a["id"]: a for a in engine.get_agent_states()}
        for node in graph_data["nodes"]:
            agent = agent_states.get(node["id"], {})
            node.update(agent)
        return graph_data

    @app.get("/api/v1/simulator/export")
    async def export():
        engine = _require_engine(app)
        return engine.export_results()

    # ------------------------------------------------------------------
    # WebSocket
    # ------------------------------------------------------------------

    @app.websocket("/ws/simulator")
    async def websocket_simulator(ws: WebSocket):
        await ws.accept()
        app.state.sim_ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.sim_ws_clients.discard(ws)

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
