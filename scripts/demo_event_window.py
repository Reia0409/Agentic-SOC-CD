"""Offline C/D demonstration. Run: python -m scripts.demo_event_window"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

from agent.loop import InvestigationAgent
from agent.report import format_text_report
from agent.tools import build_default_registry
from agent.tools.log_source import LOCAL_PATH_ENV

ROOT = Path(__file__).resolve().parents[1]


class DemoInvestigator:
    """Deterministic decisions demonstrate data flow, not threat classification."""

    def reason(self, state, registry, **kwargs):
        if not state.tool_calls:
            return {"next_action": "call_tool", "tool_call": {
                "tool_name": "fetch_event_logs",
                "args": {"layers": ["web", "auth", "audit", "network"]},
            }}
        records = state.pending_observations[0]["result"]["records"]
        return {
            "new_evidence": [{
                "description": f"{record['layer']} 로그 관측: {record['timestamp']}",
                "layer": record["layer"], "time": record["timestamp"],
                "source_log": record["raw_ref"].rsplit(":", 1)[0],
                "raw_ref": record["raw_ref"], "confidence_contribution": 0.0,
            } for record in records],
            "next_action": "terminate", "termination_reason": "no_more_evidence",
            "final_verdict": {
                "verdict": "INCONCLUSIVE", "confidence": 0.0, "severity": "UNKNOWN",
                "attack_type": "offline_demo", "affected_systems": ["web-01"],
                "summary": "C/D 데이터 흐름 데모: 4계층 사건 조회와 원본 참조 보존을 확인했습니다.",
                "reasoning": "위협 판정용 LLM은 호출하지 않았습니다.",
            },
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "cd_demo.json")
    args = parser.parse_args()
    names = {"web": "web.jsonl", "auth": "auth.txt", "audit": "audit.txt", "network": "network.jsonl"}
    env = {LOCAL_PATH_ENV[layer]: str(ROOT / "examples" / "cd" / name) for layer, name in names.items()}
    env["LOG_LOCAL_HOST"] = "web-01"
    with patch.dict(os.environ, env):
        seed = {
            "incident_id": "INC-CD-DEMO", "host": "web-01",
            "window": ["2026-09-21T00:00:00Z", "2026-09-21T00:01:00Z"],
            "evidence_refs": [(ROOT / "examples" / "cd" / "web.jsonl").as_posix() + ":1"],
        }
        result = InvestigationAgent(DemoInvestigator(), build_default_registry()).run(seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(format_text_report(result))
    print(f"\nSaved: {args.output.resolve()}")
    return result


if __name__ == "__main__":
    main()
