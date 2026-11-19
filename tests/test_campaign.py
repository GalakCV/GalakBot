import json
from pathlib import Path

import pytest

from bounty.cli import main
from bounty.core import Blackboard, Breaker, Refused, RunContext
from bounty.executor import Executor, ToolLayer, validate
from bounty.workflow import Skill
from test_kernel import ROOT, SKILLS, ctx


def test_full_recon_runs_every_script_through_broker(ctx):
    ctx.config["rates"] = {"http": 10000, "dns": 10000}
    ctx.config["scope"]["seeds"][0] = "https://DEMO.Example.COM:443/path"
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    Executor(ctx, skill).campaign_run(skill.plan())
    board = Blackboard(ctx.root)
    try:
        assert len(board.rows()) == 2
        assert {p["phase"] for p in board.rows("phases")} == set(skill.phases)
        assert all(p["state"] == "complete" for p in board.rows("phases"))
        assert all(r["state"] == "hypothesis" for r in board.rows())
    finally:
        board.close()
    traces = [json.loads(l) for l in (ctx.root / "traces/events.jsonl").read_text().splitlines()]
    tools = {r.get("tool") for r in traces if r["event"] == "tool.call"}
    assert {"subfinder", "assetfinder", "gau", "waybackurls", "curl", "dnsx", "httpx"} <= tools


def test_explore_requires_validation_authorization_and_observed_host(ctx):
    base = ["explore", "--target", "demo", "--runs", str(ctx.root.parent), "--skill", "web-testing", "--host", "api.example.com"]
    assert main(base + ["--i-am-authorized"]) == 2
    validate(ctx, Skill(SKILLS, "recon"))
    board = Blackboard(ctx.root)
    board.surface("api.example.com", 403, [], "fixture", [], "fixture")
    board.close()
    assert main(base) == 2
    assert main(base + ["--i-am-authorized"]) == 0
    saved = RunContext.load(ctx.root.parent, "demo")
    assert saved.config["status"] == "partial"
    assert not saved.config["explore_authorized"]
    board = Blackboard(ctx.root)
    assert board.rows("findings") == []
    assert all(r["state"] == "manual" for r in board.rows("phases"))
    board.close()


def test_recon_refuses_intrusive_phase(ctx):
    skill = Skill(SKILLS, "api-testing")
    validate(ctx, skill)
    with pytest.raises(Refused, match="requires explore"):
        Executor(ctx, skill).campaign_run(skill.plan())
    assert ctx.config["status"] == "partial"


def test_python_network_worker_and_tls_broker(ctx):
    ctx.config["rates"] = {"http": 10000, "dns": 10000}
    for name, selected in [("cloud", ["asset-fingerprint"]), ("infra", ["takeover", "tls"])]:
        skill = Skill(SKILLS, name)
        validate(ctx, skill)
        executor = Executor(ctx, skill)
        executor.campaign_run(skill.plan(selected), authorized=True, host="api.example.com")
    traces = (ctx.root / "traces/events.jsonl").read_text()
    assert '"tool": "dns-read"' in traces
    assert '"tool": "http-read"' in traces
    assert '"tool": "openssl"' in traces


def test_api_scripts_and_manual_dependencies(ctx):
    ctx.config.update(rates={"http": 10000, "dns": 10000}, explore_authorized=True,
                      selected_host="api.example.com", active_skill="api-testing")
    paths = ctx.root / "work/paths.txt"
    paths.write_text("/health\n")
    ctx.config["approved_paths"] = str(paths).replace("\\", "/")
    skill = Skill(SKILLS, "api-testing")
    validate(ctx, skill)
    Executor(ctx, skill).campaign_run(skill.plan(), authorized=True, host="api.example.com")
    board = Blackboard(ctx.root)
    states = {r["phase"]: r["state"] for r in board.rows("phases")}
    board.close()
    assert states["spec-recon"] == states["auth-enforcement"] == "complete"
    assert states["bola"] == "manual"


def test_unknown_tool_and_redirect_flag_trip(ctx):
    layer = ToolLayer(ctx, Breaker(ctx))
    with pytest.raises(Refused, match="Unregistered"):
        layer.call(dict(tool="evil", args=[]))
    layer = ToolLayer(ctx, Breaker(ctx))
    with pytest.raises(Refused, match="Disallowed"):
        layer.call(dict(tool="httpx", args=["-follow-redirects"]))


def test_cloud_scope_attempt_trips_hard(ctx):
    layer = ToolLayer(ctx, Breaker(ctx))
    with pytest.raises(Refused, match="Out-of-scope"):
        layer.call(dict(tool="curl", args=["-sS", "https://unowned.s3.amazonaws.com/"]))


def test_fresh_preserves_history(ctx):
    old = ctx.root / "blackboard.db"
    assert old.exists()
    RunContext.init(ctx.root.parent, "demo", ctx.config["scope"], SKILLS, fresh=True)
    archives = list(ctx.root.parent.glob("demo--archive-*/blackboard.db"))
    assert len(archives) == 1 and old.exists()


def test_manifest_cycle_and_unknown_tier(ctx):
    import yaml
    root = ctx.root / "work/skills/demo"
    root.mkdir(parents=True)
    for name in ("SKILL.md", "safety.md"):
        (root / name).write_text("Test")
    manifest = {"name": "demo", "default_tier": "passive", "phases": [
        {"id": "first", "needs": ["second"]}, {"id": "second", "needs": ["first"]}]}
    (root / "skill.yaml").write_text(yaml.safe_dump(manifest))
    with pytest.raises(Refused, match="Cyclic"):
        Skill(root.parent, "demo")
    manifest["default_tier"] = "unknown"
    (root / "skill.yaml").write_text(yaml.safe_dump(manifest))
    with pytest.raises(Refused, match="Unknown phase tier"):
        Skill(root.parent, "demo")


def test_real_script_forced_errors_write_partial_report(ctx):
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    ctx.config["scope"]["seeds"] = hosts
    (ctx.root / "scope.json").write_text(json.dumps(ctx.config["scope"]))
    fixture = ctx.root / "work/errors.json"
    fixture.write_text(json.dumps({"httpx": {h: {"error": True} for h in hosts}}))
    ctx.config.update(fixture=str(fixture), rates={"http": 10000, "dns": 10000})
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    with pytest.raises(Refused, match="Consecutive tool errors"):
        Executor(ctx, skill).thin_slice()
    assert ctx.config["status"] == "partial"
    assert "Consecutive tool errors" in (ctx.root / "report/report.md").read_text()
    assert not (ctx.root / "campaign.lock").exists()


def test_target_lock_refuses_second_campaign(ctx):
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    (ctx.root / "campaign.lock").write_text("1234")
    with pytest.raises(Refused, match="already owns"):
        Executor(ctx, skill).thin_slice()


def test_stale_validation_refused(ctx):
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    ctx.config["scope"]["out_of_scope"].append("demo.example.com")
    with pytest.raises(Refused, match="stale"):
        Executor(ctx, skill).thin_slice()


def test_dead_host_is_retained(ctx):
    ctx.config["scope"]["seeds"].append("dead.example.com")
    skill = Skill(SKILLS, "recon")
    validate(ctx, skill)
    Executor(ctx, skill).thin_slice()
    board = Blackboard(ctx.root)
    rows = {r["host"]: r for r in board.rows()}
    board.close()
    assert rows["dead.example.com"]["status"] == "dead"


def test_detector_output_is_not_confirmation():
    from bounty.observations import candidates
    from bounty.registry import Triager
    result = list(candidates("api-testing", "auth-enforcement", "200 123 /health\n401 5 /account", "api.example.com"))
    assert len(result) == 1
    assert Triager().review(result[0])["state"] == "hypothesis"


def test_passive_cannot_make_target_requests(ctx):
    layer = ToolLayer(ctx, Breaker(ctx))
    layer.tier = "passive"
    with pytest.raises(Refused, match="passive"):
        layer.call(dict(tool="http-read", args=["https://api.example.com/"]))


def test_active_safe_rejects_paths(ctx):
    layer = ToolLayer(ctx, Breaker(ctx))
    with pytest.raises(Refused, match="exceeds phase tier"):
        layer.call(dict(tool="http-read", args=["https://api.example.com/admin"]))
