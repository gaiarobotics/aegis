"""Preset management for simulation configurations.

Provides :class:`PresetManager` which handles loading, saving, listing,
and deleting simulation presets stored as YAML files.  Builtin presets
ship in the ``presets/`` sub-package directory; an optional *user*
directory can be supplied to overlay or extend them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from monitor.simulator.models import (
    CorpusConfig,
    ModelSpec,
    ModuleToggles,
    PopulationConfig,
    ScannerToggles,
    SimConfig,
    TopologyConfig,
)

_BUILTIN_DIR = Path(__file__).parent / "presets"


class PresetManager:
    """Manage named simulation presets backed by YAML files.

    Parameters
    ----------
    preset_dir:
        Optional path to a user-managed preset directory.  When given,
        user presets take priority over builtins for :meth:`load` and
        new presets are saved here.
    """

    def __init__(self, preset_dir: str | None = None) -> None:
        self._user_dir: Path | None = Path(preset_dir) if preset_dir else None
        self._builtin_dir: Path = _BUILTIN_DIR

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_presets(self) -> list[str]:
        """Return a sorted list of available preset names.

        Names are collected from both the builtin and (optionally) user
        directories, with duplicates removed.
        """
        names: set[str] = set()
        for d in self._search_dirs():
            if d.is_dir():
                for p in d.glob("*.yaml"):
                    names.add(p.stem)
        return sorted(names)

    def load(self, name: str) -> SimConfig:
        """Load a preset by *name* and return a :class:`SimConfig`.

        The user directory is searched first (if configured), then the
        builtin directory.

        Raises
        ------
        FileNotFoundError
            If no YAML file with the given name exists in any search dir.
        """
        for d in self._search_dirs():
            path = d / f"{name}.yaml"
            if path.is_file():
                with open(path, "r") as fh:
                    data = yaml.safe_load(fh)
                return self._dict_to_config(data)
        raise FileNotFoundError(f"Preset '{name}' not found")

    def save(self, name: str, config: SimConfig) -> None:
        """Save a :class:`SimConfig` as a named preset.

        The file is written to the user directory if one was provided,
        otherwise to the builtin directory.  Parent directories are
        created as needed.
        """
        target_dir = self._user_dir if self._user_dir else self._builtin_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / f"{name}.yaml"
        with open(path, "w") as fh:
            yaml.dump(
                self._config_to_dict(config),
                fh,
                default_flow_style=False,
                sort_keys=False,
            )

    def delete(self, name: str) -> None:
        """Delete a preset by *name*.

        Searches user dir first, then builtin.

        Raises
        ------
        FileNotFoundError
            If no YAML file with the given name exists in any search dir.
        """
        for d in self._search_dirs():
            path = d / f"{name}.yaml"
            if path.is_file():
                path.unlink()
                return
        raise FileNotFoundError(f"Preset '{name}' not found")

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def _config_to_dict(self, config: SimConfig) -> dict[str, Any]:
        """Serialize a :class:`SimConfig` to a YAML-friendly dict."""
        return {
            "num_agents": config.num_agents,
            "max_ticks": config.max_ticks,
            "initial_infected_pct": config.initial_infected_pct,
            "seed_strategy": config.seed_strategy,
            "background_message_rate": config.background_message_rate,
            "recovery_ticks": config.recovery_ticks,
            **({"seed": config.seed} if config.seed is not None else {}),
            "topology": {
                "type": config.topology.type,
                "mean_degree": config.topology.mean_degree,
                "rewire_probability": config.topology.rewire_probability,
                "m": config.topology.m,
                "num_communities": config.topology.num_communities,
                "intra_probability": config.topology.intra_probability,
                "inter_probability": config.topology.inter_probability,
            },
            "population": {
                "models": [
                    {
                        "name": m.name,
                        "weight": m.weight,
                        "base_susceptibility": m.base_susceptibility,
                    }
                    for m in config.population.models
                ],
                "soul_age_mean": config.population.soul_age_mean,
                "new_agent_fraction": config.population.new_agent_fraction,
            },
            "corpus": {
                "sources": config.corpus.sources,
                "technique_probabilities": config.corpus.technique_probabilities,
            },
            "modules": {
                "scanner": config.modules.scanner,
                "broker": config.modules.broker,
                "identity": config.modules.identity,
                "behavior": config.modules.behavior,
                "recovery": config.modules.recovery,
                "sensitivity": config.modules.sensitivity,
                "confidence_threshold": config.modules.confidence_threshold,
                "scanner_toggles": {
                    "pattern_matching": config.modules.scanner_toggles.pattern_matching,
                    "semantic_analysis": config.modules.scanner_toggles.semantic_analysis,
                    "content_gate": config.modules.scanner_toggles.content_gate,
                },
            },
        }

    def _dict_to_config(self, data: dict[str, Any]) -> SimConfig:
        """Deserialize a YAML dict back to a :class:`SimConfig`."""
        topo_data = data.get("topology", {})
        pop_data = data.get("population", {})
        corpus_data = data.get("corpus", {})
        mod_data = data.get("modules", {})
        scanner_data = mod_data.get("scanner_toggles", {})

        topology = TopologyConfig(
            type=topo_data.get("type", "scale_free"),
            mean_degree=topo_data.get("mean_degree", 6),
            rewire_probability=topo_data.get("rewire_probability", 0.1),
            m=topo_data.get("m", 3),
            num_communities=topo_data.get("num_communities", 5),
            intra_probability=topo_data.get("intra_probability", 0.3),
            inter_probability=topo_data.get("inter_probability", 0.01),
        )

        models = [
            ModelSpec(
                name=m["name"],
                weight=m["weight"],
                base_susceptibility=m["base_susceptibility"],
            )
            for m in pop_data.get("models", [])
        ]
        population = PopulationConfig(
            models=models if models else PopulationConfig().models,
            soul_age_mean=pop_data.get("soul_age_mean", 50.0),
            new_agent_fraction=pop_data.get("new_agent_fraction", 0.1),
        )

        corpus = CorpusConfig(
            sources=corpus_data.get("sources", CorpusConfig().sources),
            technique_probabilities=corpus_data.get(
                "technique_probabilities",
                CorpusConfig().technique_probabilities,
            ),
        )

        scanner_toggles = ScannerToggles(
            pattern_matching=scanner_data.get("pattern_matching", True),
            semantic_analysis=scanner_data.get("semantic_analysis", True),
            content_gate=scanner_data.get("content_gate", False),
        )
        modules = ModuleToggles(
            scanner=mod_data.get("scanner", True),
            broker=mod_data.get("broker", True),
            identity=mod_data.get("identity", True),
            behavior=mod_data.get("behavior", True),
            recovery=mod_data.get("recovery", True),
            sensitivity=mod_data.get("sensitivity", 0.5),
            confidence_threshold=mod_data.get("confidence_threshold", 0.8),
            scanner_toggles=scanner_toggles,
        )

        return SimConfig(
            num_agents=data.get("num_agents", 100),
            max_ticks=data.get("max_ticks", 500),
            initial_infected_pct=data.get("initial_infected_pct", 0.02),
            seed_strategy=data.get("seed_strategy", "random"),
            background_message_rate=data.get("background_message_rate", 2.0),
            recovery_ticks=data.get("recovery_ticks", 20),
            seed=data.get("seed"),
            topology=topology,
            population=population,
            corpus=corpus,
            modules=modules,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _search_dirs(self) -> list[Path]:
        """Return directories to search, user dir first."""
        dirs: list[Path] = []
        if self._user_dir is not None:
            dirs.append(self._user_dir)
        dirs.append(self._builtin_dir)
        return dirs
