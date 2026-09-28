"""Per-visitor workspaces, so concurrent viewers of the hosted demo never share alerts.

Each browser session gets its own directory holding its alert DB, JSONL log and
generated captures. Stale workspaces (abandoned tabs) are pruned by age.
"""
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from typing import Optional

_ID_RE = re.compile(r"^[a-f0-9]{8,32}$")


@dataclass(frozen=True)
class Workspace:
    id: str
    root: str
    db: str
    jsonl: str
    pcap_dir: str

    @property
    def simulated_pcap(self) -> str:
        return os.path.join(self.pcap_dir, "simulated_traffic.pcap")


def new_workspace_id() -> str:
    return uuid.uuid4().hex[:16]


def open_workspace(base_dir: str, workspace_id: Optional[str] = None) -> Workspace:
    ws_id = workspace_id if workspace_id and _ID_RE.match(workspace_id) else new_workspace_id()
    root = os.path.join(base_dir, ws_id)
    pcap_dir = os.path.join(root, "pcaps")
    os.makedirs(pcap_dir, exist_ok=True)
    os.utime(root, None)  # mark as active for the stale-workspace sweep
    return Workspace(
        id=ws_id,
        root=root,
        db=os.path.join(root, "alerts.db"),
        jsonl=os.path.join(root, "alerts.jsonl"),
        pcap_dir=pcap_dir,
    )


def cleanup_stale(base_dir: str, max_age_hours: float = 12.0, keep: Optional[str] = None) -> int:
    """Delete workspaces untouched for max_age_hours; returns how many were removed."""
    if not os.path.isdir(base_dir):
        return 0
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    for name in os.listdir(base_dir):
        path = os.path.join(base_dir, name)
        if name == keep or not _ID_RE.match(name) or not os.path.isdir(path):
            continue
        try:
            if os.path.getmtime(path) < cutoff:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed
