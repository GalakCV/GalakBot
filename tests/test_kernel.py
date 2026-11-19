import json
from pathlib import Path
import uuid

import pytest

from bounty.core import Blackboard, Breaker, Refused, RunContext, Scope, redact
from bounty.executor import Executor, ToolLayer, validate
from bounty.workflow import Skill

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / ".external/G-Skills"


@pytest.fixture
def ctx():
    runs = ROOT / ".test-runs" / uuid.uuid4().hex
    return RunContext.init(runs, "demo", json.loads((ROOT / "examples/scope.json").read_text()),
                           SKILLS, fixture=ROOT / "examples/fixture.json")


def test_scope(ctx):
    scope = Scope(ctx.config["scope"], SKILLS)
    assert scope.allows("HTTPS://API.Example.COM:443/path")
    assert not scope.allows("private.example.com")
    assert not scope.allows("example.com.evil.org")
    assert not scope.allows("https://api.example.com@evil.org")
    assert not scope.allows("https://name:password@api.example.com")


def test_redaction():
    value = redact({"token": "topsecret", "log": "Authorization: Bearer abc\nCookie: sid=123\npassword=hunter2",
                    "nested": [{"api_key": "key123"}], "url": "https://x.test/?access_token=sekret"})
    text = json.dumps(value)
    for secret in ("topsecret", "abc", "sid=123", "hunter2", "key123", "sekret"):
        assert secret not in text


def test_isolation_and_idempotence(ctx):
    other = RunContext.init(ctx.root.parent, "other", ctx.config["scope"], SKILLS)
    board, second = Blackboard(ctx.root), Blackboard(other.root)
    try:
        for _ in range(2):
            board.surface("api.example.com", 403, [], "test", ["gated"], "raw/test.json")
            board.finding("api-testing", "bola", "api.example.com", "Candidate", "raw/test.json", {})
        assert len(board.rows()) == len(board.rows("findings")) == 1
        assert second.rows() == []
    finally:
        board.close()
        second.close()


@pytest.mark.parametrize("mode", ["errors", "rate", "scope", "iterations", "cost", "time", "error-rate"])
def test_breaker(ctx, mode):
    breaker = Breaker(ctx)
    with pytest.raises(Refused):
        if mode == "errors":
            for _ in range(3):
                breaker.outcome(False)
        elif mode == "rate":
            for _ in range(3):
                breaker.outcome(False, 429)
        elif mode == "scope":
            Scope(ctx.config["scope"], SKILLS).require("evil.org", breaker)
        elif mode == "error-rate":
            breaker.consecutive_limit = 20
            for ok in [False, False, True, False, False, True, False, False, True, True]:
                breaker.outcome(ok)
        else:
            if mode == "iterations":
                ctx.config["budgets"][mode] = 0
            elif mode == "cost":
                breaker.cost = 1
            else:
                ctx.config["budgets"]["seconds"] = 0
            breaker.check()
    assert json.loads((ctx.root / "breaker.json").read_text())["reason"]


def test_invalid_seed_fails_validation(ctx):
    ctx.config["scope"]["seeds"] = ["evil.org"]
    with pytest.raises(Refused):
        validate(ctx, Skill(SKILLS, "recon"))
    assert ctx.config["validation"] is None


def test_tool_scope_gate_precedes_execution(ctx):
    (ctx.root / "hosts/all.txt").write_text("evil.org\n")
    layer = ToolLayer(ctx, Breaker(ctx))
    with pytest.raises(Refused, match="Out-of-scope"):
        layer.call(dict(tool="httpx", args=["-l", str(ctx.root / "hosts/all.txt"),
                                          "-o", str(ctx.root / "out/httpx.jsonl")]))
    assert not (ctx.root / "out/httpx.jsonl").exists()


def test_end_to_end_actual_skill_twice(ctx):
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    for _ in range(2):
        Executor(ctx, skill).thin_slice()
    board = Blackboard(ctx.root)
    try:
        assert len(board.rows()) == 2
        assert {r["status"] for r in board.rows()} == {"200", "403"}
        for row in board.rows():
            assert (ctx.root / row["evidence"].split("#")[0]).exists()
    finally:
        board.close()
    assert (ctx.root / "report/report.md").exists()
    assert '"tool.request"' in (ctx.root / "traces/events.jsonl").read_text()


def test_code_audit_refused():
    with pytest.raises(Refused):
        Skill(SKILLS, "code-audit")
