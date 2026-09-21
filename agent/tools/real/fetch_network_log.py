"""Query network logs through the shared source/provenance adapter."""
from __future__ import annotations

from typing import Any, Dict

from ..log_source import fetch_layer_logs


def fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    return fetch_layer_logs("network", args)
