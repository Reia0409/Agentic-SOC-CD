"""Collect seed input through the same parsers and raw references as investigation."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .tools.log_source import (LOCAL_PATH_ENV, SOURCE_TYPES, event_time,
                               normalize_documents, read_documents)


def fetch_recent_raw_logs(host: str, minutes: int = 10,
                          source_types: Optional[List[str]] = None,
                          bucket: Optional[str] = None) -> List[Dict[str, Any]]:
    if minutes <= 0:
        raise ValueError("minutes must be positive")
    source_types = list(SOURCE_TYPES) if source_types is None else source_types
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    all_records = []
    for layer in source_types:
        if layer not in SOURCE_TYPES:
            raise ValueError(f"unknown source type: {layer}")
        documents = read_documents(layer, host, start, end, bucket=bucket)
        records = normalize_documents(layer, documents, start, end)
        if os.environ.get(LOCAL_PATH_ENV[layer]):
            # Limit complete EVENTS after parsing, retaining original line numbers.
            # Keep the existing local sample replay behavior (no clock filter).
            limit = int(os.environ.get("RAW_LOG_LOCAL_MAX_LINES", "30"))
            if limit < 1:
                raise ValueError("RAW_LOG_LOCAL_MAX_LINES must be positive")
            records = records[-limit:]
        else:
            records = [r for r in records if (ts := event_time(r)) is not None and start <= ts <= end]
        for record in records:
            record["_source_type"] = layer
        all_records.extend(records)
    return all_records
