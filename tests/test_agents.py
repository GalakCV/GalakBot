import copy
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from bounty.agents import AgentCampaign
from bounty.core import Blackboard, Breaker, Refused, RunContext
from bounty.executor import ToolLayer, validate
from bounty.llm import LLMClient, ReplayClient
from bounty.policy import InvalidArguments
from bounty.workflow import Skill
from test_kernel import ROOT, SKILLS, ctx


def reply(content=None, name=None, arguments=None, ident="call"):
    message = {"role": "assistant", "content": content, "reasoning_content": "PRIVATE_REASONING_DO_NOT_TRACE"}
    if name:
        message["tool_calls"] = [{"id": ident, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]
    return {"choices": [{"message": message}], "usage": {"prompt_tokens": 100, "prompt_cache_hit_tokens": 80,
                                                                  "prompt_cache_miss_tokens": 20, "completion_tokens": 10}}


def tool(name, args, stdin=""):
    return dict(tool=name, args=args, stdin=stdin, rationale="Observe within the approved envelope")


class Canned:
    def __init__(self, replies):
        self.replies = list(replies)
        self.payloads = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        self.payloads.append(copy.deepcopy(kwargs))
        value = self.replies.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class ParallelBrain:
    def __init__(self):
        self.chat = SimpleNamespace(completions=self)
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2)
        self.counts = {}
        self.payloads = []

    def create(self, **kwargs):
        role = kwargs["messages"][0]["content"]
        if "independent, strict" in role:
            agent = "triager"
        elif "captain" in role:
            agent = "captain"
        else:
            agent = json.loads(kwargs["messages"][2]["content"])["task"]["phase"]
        with self.lock:
            self.payloads.append(copy.deepcopy(kwargs))
            self.counts[agent] = self.counts.get(agent, 0) + 1
            turn = self.counts[agent]
        if agent in {"active-discovery", "http-probe"} and turn == 1:
            self.barrier.wait(timeout=10)  # Would fail if workers were serialized.
        if agent == "captain":
            if turn == 1:
                return reply(name="delegate", arguments=dict(tasks=[
                    dict(phase="active-discovery", host="demo.example.com", objective="Verify DNS with adaptive retry"),
                    dict(phase="http-probe", host="api.example.com", objective="Observe root response")], rationale="Independent DNS and HTTP work can run concurrently"))
            return reply(content=json.dumps(dict(action="stop", rationale="Workers completed observations and triage")))
        if agent == "active-discovery":
            if turn <= 2:
                if turn == 2:
                    assert "unreliable" in kwargs["messages"][-1]["content"]
                return reply(name="run_tool", arguments=tool("dnsx", ["-d", "demo.example.com", "-silent", "-rl", "10", "-retry", "1" if turn == 1 else "3"]), ident="dns" + str(turn))
            return reply(content=json.dumps(dict(action="stop", rationale="Lower rate and increased retry recovered resolution")))
        if agent == "http-probe":
            if turn == 1:
                return reply(name="run_tool", arguments=tool("httpx", ["-u", "api.example.com", "-json", "-rl", "10"]))
            if turn == 2:
                evidence = json.loads(kwargs["messages"][-1]["content"])["evidence"]
                return reply(name="submit_finding", arguments=dict(title="API observation requires judgment", host="api.example.com",
                    evidence=evidence, observation="A response was observed", rationale="Independent judgment required"), ident="submit")
            return reply(content=json.dumps(dict(action="stop", rationale="Observation handed to independent triager")))
        return reply(content=json.dumps(dict(state="true_positive", confidence=90, rationale="Observed response", next_step="Verify impact")))


def configure(ctx):
    ctx.config["budgets"]["cost"] = 2
    ctx.config["rates"] = dict(http=100, dns=100)
    fixture = ctx.root / "work/brain-fixture.json"
    fixture.write_text(json.dumps({"httpx": {"api.example.com": {"status_code": 403, "token": "sensitive-output"}},
                                    "dnsx_by_retry": {"1": [], "3": ["demo.example.com"]}}))
    ctx.config["fixture"] = str(fixture)
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    return skill


def test_parallel_specialists_adapt_and_independent_triage(ctx, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "opaque-never-leak")
    skill = configure(ctx)
    board = Blackboard(ctx.root)
    board.surface("old.example.com", 200, [], "test", ["token=sensitive-board"], "fake")
    board.close()
    fake = ParallelBrain()
    AgentCampaign(ctx, skill, client=fake).run()
    sent = json.dumps(fake.payloads)
    assert "sensitive-output" not in sent and "sensitive-board" not in sent and "opaque-never-leak" not in sent
    trace = (ctx.root / "traces/events.jsonl").read_text()
    assert "PRIVATE_REASONING_DO_NOT_TRACE" not in trace
    events = [json.loads(line) for line in trace.splitlines()]
    starts = [e["time"] for e in events if e["event"] == "agent.worker_start"]
    ends = [e["time"] for e in events if e["event"] == "agent.worker_end"]
    assert len(starts) == 2 and max(starts) < min(ends)
    assert fake.counts["active-discovery"] == 3
    board = Blackboard(ctx.root)
    findings = board.rows("findings")
    board.close()
    assert len(findings) == 1 and findings[0]["state"] == "needs_review"  # Fixtures cannot prove real impact.
    assert json.loads(findings[0]["details"])["verdict"]["next_step"]
    assert "Agent path" in (ctx.root / "report/report.md").read_text()


@pytest.mark.parametrize("proposed,reason", [
    (tool("httpx", ["-u", "evil.org"]), "Out-of-scope"),
    (tool("api-probe", ["https://api.example.com/admin"]), "Intrusive")])
def test_fake_model_cannot_escape_gates(ctx, proposed, reason):
    skill = configure(ctx)
    fake = Canned([reply(name="run_tool", arguments=proposed)])
    with pytest.raises(Refused, match=reason):
        AgentCampaign(ctx, skill, client=fake).run()
    assert ctx.config["status"] == "partial"
    assert (ctx.root / "breaker.json").exists()


def test_envelope_adaptive_args_and_correctable_invalid(ctx):
    configure(ctx)
    layer = ToolLayer(ctx, Breaker(ctx))
    result = layer.call({k:v for k,v in tool("dnsx", ["-d", "demo.example.com", "-rl", "10", "-retry", "3"]).items() if k != "rationale"})
    assert "demo.example.com" in result["stdout"]
    for args in (["-d", "demo.example.com", "-rl", "10001"], ["-d", "demo.example.com", "-evil"]):
        with pytest.raises(InvalidArguments):
            layer.call(dict(tool="dnsx", args=args))
        assert layer.breaker.reason is None


def test_llm_json_retry_cache_accounting_and_redaction(ctx, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "opaque-key")
    configure(ctx)
    fake = Canned([reply(content="bad JSON"), reply(content='{"state":"needs_review"}')])
    breaker = Breaker(ctx)
    llm = LLMClient(ctx, breaker, fake)
    schema = {"type":"object", "properties":{"state":{"const":"needs_review"}}, "required":["state"], "additionalProperties":False}
    result = llm.structured([{"role":"user", "content":"token=private opaque-key"}], schema)
    assert result["state"] == "needs_review"
    assert len(fake.payloads) == 2 and breaker.calls == 2 and breaker.cost > 0
    assert "opaque-key" not in json.dumps(fake.payloads) and "private" not in json.dumps(fake.payloads)
    traces = (ctx.root / "traces/events.jsonl").read_text()
    assert '"cache_hit": 80' in traces


def test_reservations_prevent_parallel_budget_overshoot(ctx):
    ctx.config["budgets"]["cost"] = 0.05
    breaker = Breaker(ctx)
    first = breaker.reserve(0.04)
    with pytest.raises(Refused, match="Cost budget"):
        breaker.reserve(0.04)
    assert first in breaker.reservations


def test_replay_client_reproduces_reply_without_key(ctx, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    configure(ctx)
    llm = LLMClient(ctx, Breaker(ctx), Canned([reply(content='{"action":"stop","rationale":"done"}')]))
    messages = [{"role":"user", "content":"Replay this observation"}]
    original = llm.complete(messages)
    replay = ReplayClient(ctx.root / "traces/events.jsonl")
    restored = LLMClient(ctx, Breaker(ctx), replay).complete(messages)
    assert restored["content"] == original["content"]
    assert "reasoning_content" not in restored


def test_whole_campaign_replay_is_offline(ctx):
    skill = configure(ctx)
    AgentCampaign(ctx, skill, client=ParallelBrain()).run()
    trace = ctx.root / "traces/events.jsonl"
    other = RunContext.init(ctx.root.parent, "replayed", ctx.config["scope"], SKILLS,
                            fixture=ctx.config["fixture"])
    other.config["budgets"]["cost"] = 2
    other.config["rates"] = dict(http=100, dns=100)
    validate(other, skill)
    AgentCampaign(other, skill, client=ReplayClient(trace)).run()
    assert other.config["status"] == "complete"
    board = Blackboard(other.root)
    assert len(board.rows("findings")) == 1
    board.close()


def test_llm_429_backoff_and_trip(ctx, monkeypatch):
    configure(ctx)
    class RateLimited(Exception):
        status_code = 429
    fake = Canned([RateLimited("never echo this secret"), reply(content="done")])
    llm = LLMClient(ctx, Breaker(ctx), fake)
    waited = []
    monkeypatch.setattr(llm, "_wait", waited.append)
    assert llm.complete([{"role":"user", "content":"Observe"}])["content"] == "done"
    assert waited == [1]
    fake = Canned([RateLimited(), RateLimited(), RateLimited()])
    llm = LLMClient(ctx, Breaker(ctx), fake)
    monkeypatch.setattr(llm, "_wait", lambda _: None)
    with pytest.raises(Refused, match="Repeated HTTP 429"):
        llm.complete([{"role":"user", "content":"Observe"}])
    assert "never echo" not in (ctx.root / "traces/events.jsonl").read_text()


def test_repeated_invalid_arguments_trip_despite_successful_llm_calls(ctx):
    configure(ctx)
    breaker = Breaker(ctx)
    layer = ToolLayer(ctx, breaker)
    for attempt in range(3):
        breaker.outcome(True)  # A successful model response must not erase argument abuse.
        with pytest.raises(Refused):
            layer.call(dict(tool="dnsx", args=["-d", "demo.example.com", "-rl", "10000"]))
    assert breaker.reason == "Repeated invalid tool arguments"


def test_authorized_explore_worker_drives_intrusive_tool(ctx):
    ctx.config.update(explore_authorized=True, selected_host="api.example.com", active_skill="api-testing")
    ctx.config["budgets"]["cost"] = 2
    skill = Skill(SKILLS, "api-testing")
    validate(ctx, skill)
    fake = Canned([
        reply(name="delegate", arguments=dict(tasks=[dict(phase="auth-enforcement", host="api.example.com", objective="Observe one approved read")], rationale="Delegate API specialist")),
        reply(name="run_tool", arguments=tool("api-probe", ["https://api.example.com/health"])),
        reply(content='{"action":"stop","rationale":"Observed response"}'),
        reply(content='{"action":"stop","rationale":"Authorized work complete"}')])
    AgentCampaign(ctx, skill, client=fake, authorized=True, host="api.example.com").run()
    assert ctx.config["status"] == "complete"
    assert '"tool": "api-probe"' in (ctx.root / "traces/events.jsonl").read_text()
