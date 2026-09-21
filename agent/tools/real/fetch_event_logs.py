"""C: resolve an incident event/window and query raw logs in that time range."""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict

from ..log_source import event_time, fetch_layer_logs, pagination, query_window
from ..time_utils import parse_iso

LAYERS = {"web": "web", "auth": "auth", "audit": "audit", "system": "audit", "network": "network"}


def resolve_window(args: Dict[str, Any]) -> tuple[str, str]:
    event = args.get("event", {})
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    window = args.get("window", event.get("window"))
    if window is not None:
        if not isinstance(window, (list, tuple)) or len(window) != 2:
            raise ValueError("window must be [start_iso, end_iso]")
        start, end = query_window(*window)
    else:
        timestamp = event.get("timestamp") or event.get("trigger_time")
        if not timestamp:
            raise ValueError("window or event.timestamp/event.trigger_time is required")
        before = args.get("before_seconds", 300)
        after = args.get("after_seconds", 300)
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (before, after)):
            raise ValueError("before_seconds/after_seconds must be non-negative integers")
        anchor = parse_iso(timestamp)
        start, end = query_window((anchor - timedelta(seconds=before)).isoformat(),
                                  (anchor + timedelta(seconds=after)).isoformat())
    return start.isoformat(), end.isoformat()


def fetch_event_logs(args: Dict[str, Any]) -> Dict[str, Any]:
    start, end = resolve_window(args)
    limit, offset = pagination(args)
    if not isinstance(args.get("host"), str) or not args["host"].strip():
        raise ValueError("host is required (collector host, not an HTTP Host header)")
    event = args.get("event", {})
    default_layers = [event["layer"]] if event.get("layer") else ["web", "auth", "audit", "network"]
    layers = args.get("layers", default_layers)
    if not isinstance(layers, list) or not layers or any(not isinstance(layer, str) or layer not in LAYERS for layer in layers):
        raise ValueError("layers must contain web/auth/audit/system/network")
    selected = list(dict.fromkeys(LAYERS[layer] for layer in layers))
    filters = args.get("filters", {})
    if not isinstance(filters, dict) or any(layer not in selected for layer in filters):
        raise ValueError("filters must be keyed by selected layers (use audit for system)")

    records, errors, totals = [], {}, {}
    for layer in selected:
        layer_filters = filters.get(layer, {})
        allowed = {"src_ip", "user", "pid", "ppid", "serial", "result", "dst_ip", "src_port",
                   "dst_port", "event_type", "method", "protocol", "path", "status_code",
                   "alert_only", "exclude_interactive", "include_user_cmd"}
        if not isinstance(layer_filters, dict) or set(layer_filters) - allowed:
            raise ValueError(f"invalid filters for {layer}")
        # Fetch at most offset+limit per layer: sufficient for a globally sorted page.
        result = fetch_layer_logs(layer, {**layer_filters, "host": args["host"],
                                  "start_time": start, "end_time": end,
                                  "limit": offset + limit, "offset": 0})
        totals[layer] = result["total_matched"]
        if result.get("error"):
            errors[layer] = result["error"]
        records.extend(result["records"])
    records.sort(key=lambda record: (event_time(record), record["layer"], record["raw_ref"]))
    page = records[offset:offset + limit]
    total = sum(totals.values())
    has_more = offset + len(page) < total
    return {"count": len(page), "records": page, "window": [start, end],
            "summary": f"사건 구간에서 총 {total}건 중 {len(page)}건 반환.",
            "total_matched": total, "has_more": has_more,
            "next_offset": offset + len(page) if has_more else None,
            "layer_counts": totals, "errors": errors, "partial": bool(errors)}
