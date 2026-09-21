"""D: raw input -> ingestion -> seed -> tools -> evidence -> JSON/text report."""
import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from agent.loop import InvestigationAgent
from agent.models import AgentState
from agent.prompts import build_user_prompt
from agent.provenance import references
from agent.raw_log_ingestion import fetch_recent_raw_logs
from agent.report import format_text_report
from agent.seed_generation import SeedGenerator
from agent.tools.log_source import LOCAL_PATH_ENV
from agent.tools.registry import ToolRegistry, ToolSpec, build_default_registry

from tests.test_event_window import WINDOW, local_log, query, web_line


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for name in [*LOCAL_PATH_ENV.values(), "HOST", "LOG_LOCAL_HOST", "RAW_LOG_LOCAL_MAX_LINES"]:
        monkeypatch.delenv(name, raising=False)


class ScriptedInvestigator:
    def __init__(self, decisions):
        self.decisions = iter(decisions)
        self.prompts = []

    def reason(self, state, registry, **kwargs):
        self.prompts.append(build_user_prompt(state))
        decision = next(self.decisions)
        return decision(state) if callable(decision) else deepcopy(decision)


def terminate(evidence=None):
    return {"next_action": "terminate", "termination_reason": "no_more_evidence",
            "new_evidence": evidence or [], "final_verdict": {
                "verdict": "INCONCLUSIVE", "confidence": 0.5, "severity": "LOW", "attack_type": "test"}}


def evidence(**kwargs):
    return {"description": "observed log", "layer": "web", "source_log": "web.log",
            "confidence_contribution": 0.2, **kwargs}


def test_ingestion_matches_investigation_and_does_not_renumber_tail(tmp_path, monkeypatch):
    path = local_log(tmp_path, monkeypatch, "web",
                     "\n" + web_line(WINDOW[0]) + "\nnot json\n" + web_line(WINDOW[1]))
    monkeypatch.setenv("RAW_LOG_LOCAL_MAX_LINES", "1")
    ingested = fetch_recent_raw_logs("web-01", source_types=["web"])
    fetched = query()["records"][-1]
    assert ingested[0]["raw_ref"] == f"{path}:4"
    assert {k: v for k, v in ingested[0].items() if k != "_source_type"} == fetched


@pytest.mark.parametrize("layer,text", [
    ("web", web_line(WINDOW[0])),
    ("auth", "Sep 21 00:00:00 web-01 sshd[1]: Accepted password for root from 192.0.2.10 port 22 ssh2"),
    ("network", json.dumps({"timestamp": WINDOW[0], "event_type": "alert", "src_ip": "192.0.2.10"})),
    ("audit", f'type=SYSCALL msg=audit({int(datetime(2026, 9, 21, tzinfo=timezone.utc).timestamp())}.1:1): pid=5 syscall=59'),
])
def test_same_raw_log_same_normalization_in_both_paths(tmp_path, monkeypatch, layer, text):
    # Pin ingestion's clock so yearless auth fixtures remain stable in later years.
    import importlib
    ingestion = importlib.import_module("agent.raw_log_ingestion")
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 21, tzinfo=timezone.utc)
    monkeypatch.setattr(ingestion, "datetime", Clock)
    local_log(tmp_path, monkeypatch, layer, text)
    before = ingestion.fetch_recent_raw_logs("web-01", source_types=[layer])[0]
    after = query(layers=[layer])["records"][0]
    assert {k: v for k, v in before.items() if k != "_source_type"} == after


def test_seed_and_supporting_contradicting_evidence_reach_reports(tmp_path, monkeypatch):
    path = local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    ref = f"{path}:1"
    raw = fetch_recent_raw_logs("web-01", source_types=["web"])
    class SeedLLM:
        def complete_json(self, system, user):
            assert ref in user
            return {"candidates": [{"incident_id": "INC-CD", "host": "web-01", "window": WINDOW,
                                     "layer": "web", "evidence_refs": [ref], "confidence_initial": 0.3}]}
    seed = SeedGenerator(SeedLLM()).generate(raw, "web-01")[0]
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {}}},
        terminate([evidence(raw_ref=ref), evidence(raw_refs=[ref], contradicting=True)]),
    ])
    result = InvestigationAgent(llm, build_default_registry()).run(seed)
    assert result["provenance"]["status"] == "passed"
    assert result["initial_seed"]["evidence_refs"] == [ref]
    assert result["tools_called"][0]["raw_refs"] == [ref]
    assert result["raw_refs"] == [ref]
    for name in ("evidence_chain", "contradicting_evidence"):
        assert result[name][0]["raw_ref"] == ref and result[name][0]["raw_refs"] == [ref]
    assert ref in format_text_report(result)
    assert json.loads(json.dumps(result))["raw_refs"] == [ref]
    assert '"known_raw_refs"' in llm.prompts[-1]


def test_audit_all_lines_survive_a_single_representative_citation(tmp_path, monkeypatch):
    epoch = int(datetime(2026, 9, 21, tzinfo=timezone.utc).timestamp())
    path = local_log(tmp_path, monkeypatch, "audit",
        f'type=SYSCALL msg=audit({epoch}.1:1): pid=5 syscall=59\n'
        f'type=EXECVE msg=audit({epoch}.1:1): argc=1 a0="id"\n')
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {"layers": ["system"]}}},
        terminate([evidence(raw_ref=f"{path}:1", layer="system")]),
    ])
    result = InvestigationAgent(llm, build_default_registry()).run({
        "incident_id": "AUDIT", "host": "web-01", "window": WINDOW})
    assert result["evidence_chain"][0]["raw_refs"] == [f"{path}:1", f"{path}:2"]


@pytest.mark.parametrize("citation", [{}, {"raw_refs": ["invented:1"]}, {"raw_refs": "not-a-list"},
                                      {"raw_refs": ["source:1", "invented:1"]}])
def test_missing_or_fabricated_refs_fail_validation_and_do_not_increase_confidence(citation):
    seed = {"incident_id": "BAD", "raw_ref": "source:1", "confidence_initial": 0.3}
    llm = ScriptedInvestigator([terminate([evidence(**citation)])])
    result = InvestigationAgent(llm, ToolRegistry()).run(seed)
    assert result["provenance"]["status"] == "incomplete"
    assert result["statistics"]["confidence_increase"] == 0
    assert "invented:1" not in result["raw_refs"]
    assert "invented:1" not in result["evidence_chain"][0]["raw_refs"]


def test_legacy_uncited_results_are_not_marked_validated():
    result = InvestigationAgent(ScriptedInvestigator([terminate()]), ToolRegistry()).run({"incident_id": "LEGACY"})
    assert result["provenance"]["status"] == "unavailable"


@pytest.mark.parametrize("refs", [[], ["fabricated:1"]])
def test_seed_generator_rejects_dropped_and_invented_refs(refs):
    class LLM:
        def complete_json(self, *args):
            return {"candidates": [{"incident_id": "BAD", "evidence_refs": refs}]}
    with pytest.raises(ValueError, match="evidence_refs"):
        SeedGenerator(LLM()).generate([{"raw_ref": "input:1"}], "web-01")


def test_opaque_external_seed_ref_is_not_rewritten():
    ref = "apache_access.log:88213"
    result = InvestigationAgent(ScriptedInvestigator([terminate([evidence(raw_ref=ref)])]), ToolRegistry()).run({
        "incident_id": "UPSTREAM", "evidence_refs": [ref]})
    assert result["raw_refs"] == [ref]
    assert result["evidence_chain"][0]["raw_ref"] == ref


def test_failed_tool_does_not_discard_already_observed_refs():
    registry = ToolRegistry()
    registry.register(ToolSpec("ok", "", [], handler=lambda args: {"count": 1, "records": [{"raw_ref": "input:1"}]}))
    def fail(args):
        raise OSError("offline")
    registry.register(ToolSpec("fail", "", [], handler=fail))
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "ok"}},
        {"next_action": "call_tool", "tool_call": {"tool_name": "fail"}},
        terminate([evidence(raw_ref="input:1")]),
    ])
    result = InvestigationAgent(llm, registry).run({"incident_id": "RETRY"})
    assert result["raw_refs"] == ["input:1"] and result["provenance"]["status"] == "passed"
    assert result["tools_called"][1]["error"] == "offline"


def test_process_tree_refs_and_multiline_groups(tmp_path, monkeypatch):
    epoch = int(datetime(2026, 9, 21, tzinfo=timezone.utc).timestamp())
    path = local_log(tmp_path, monkeypatch, "audit",
        f'type=SYSCALL msg=audit({epoch}.1:1): pid=5 ppid=0 syscall=59\n'
        f'type=EXECVE msg=audit({epoch}.1:1): argc=1 a0="id"\n')
    state = AgentState(incident_id="TREE", seed={})
    agent = InvestigationAgent(None, build_default_registry())
    agent._execute_tool_call(state, {"tool_name": "get_process_tree", "args": {
        "host": "web-01", "pid": 5, "start_time": WINDOW[0], "end_time": WINDOW[1]}})
    assert state.raw_refs == [f"{path}:1", f"{path}:2"]


def test_multilayer_window_tool_satisfies_existing_network_gate(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    local_log(tmp_path, monkeypatch, "network", json.dumps({
        "timestamp": WINDOW[0], "event_type": "flow", "src_ip": "192.0.2.10"}))
    decision = terminate()
    decision["termination_reason"] = "confidence_sufficient"
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {"layers": ["web", "network"]}}},
        decision,
    ])
    result = InvestigationAgent(llm, build_default_registry()).run({
        "incident_id": "MULTI", "window": WINDOW, "host": "web-01", "src_ip": "192.0.2.10", "confidence_initial": 0.9})
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
    assert not any("종료 거부" in note for note in result["investigation_notes"])
