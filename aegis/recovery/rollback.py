"""Recovery rollback module for AEGIS."""

import copy
import time
import uuid
from dataclasses import dataclass
from typing import Optional


@dataclass
class SnapshotInfo:
    """Information about a saved snapshot."""

    snapshot_id: str
    timestamp: float
    description: str


class ContextRollback:
    """Manages context snapshots and rollback for the AEGIS recovery system."""

    def __init__(self, max_snapshots: int = 50) -> None:
        self._snapshots: dict[str, tuple[dict, SnapshotInfo]] = {}
        self._max_snapshots = max_snapshots
        self._snapshot_order: list[str] = []

    def save_snapshot(
        self,
        context: dict,
        snapshot_id: Optional[str] = None,
        description: str = "",
    ) -> str:
        """Save a deep copy of the context as a snapshot.

        Args:
            context: The context dictionary to snapshot.
            snapshot_id: Optional ID for the snapshot. Auto-generated if None.
            description: Optional description of the snapshot.

        Returns:
            The snapshot ID.
        """
        if snapshot_id is None:
            snapshot_id = uuid.uuid4().hex

        info = SnapshotInfo(
            snapshot_id=snapshot_id,
            timestamp=time.time(),
            description=description,
        )

        self._snapshots[snapshot_id] = (copy.deepcopy(context), info)
        self._snapshot_order.append(snapshot_id)
        while len(self._snapshots) > self._max_snapshots:
            oldest_id = self._snapshot_order.pop(0)
            self._snapshots.pop(oldest_id, None)
        return snapshot_id

    def rollback(self, snapshot_id: str) -> dict:
        """Restore a previously saved context snapshot.

        Args:
            snapshot_id: The ID of the snapshot to restore.

        Returns:
            A deep copy of the saved context.

        Raises:
            KeyError: If the snapshot_id is not found.
        """
        if snapshot_id not in self._snapshots:
            raise KeyError(f"Snapshot '{snapshot_id}' not found")

        context, _info = self._snapshots[snapshot_id]
        return copy.deepcopy(context)

    def list_snapshots(self) -> list[SnapshotInfo]:
        """List all saved snapshots.

        Returns:
            A list of SnapshotInfo objects for all saved snapshots.
        """
        return [info for _ctx, info in self._snapshots.values()]
