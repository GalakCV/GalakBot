from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid
from functools import wraps

from .core import Blackboard, Breaker, Refused, Scope, redact, write_json
from .workflow import Skill, inside
from .portability import normalized_hash, normalized_bytes, prepare_skill


def bash_path():
    windows = Path("C:/Program Files/Git/bin/bash.exe")
    return str(windows) if os.name == "nt" and windows.exists() else shutil.which("bash")


def shell_path(path):
    return str(Path(path).resolve()).replace("\\", "/")


def bash_directory(path):
    value = shell_path(path)
    return "/" + value[0].lower() + value[2:] if os.name == "nt" else value


def signature(ctx, skill):
    data = [ctx.config["scope"], ctx.config["skills"], ctx.config.get("fixture"), skill.digest(),
            ctx.config["budgets"], ctx.config["rates"], ctx.config.get("env", {}),
            hashlib.sha256((Path(ctx.config["skills"]) / "recon/scripts/scope_filter.py").read_bytes()).hexdigest()]
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def exclusive_campaign(function):
    @wraps(function)
    def locked(self, *args, **kwargs):
        lock = self.ctx.root / "campaign.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise Refused("A campaign already owns this target (campaign.lock)") from None
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(str(os.getpid()))
            return function(self, *args, **kwargs)
        finally:
            lock.unlink(missing_ok=True)
    return locked


def validate(ctx, skill, phases=None):
    ctx.config["validation"] = None
    ctx.save()
    scope = Scope(ctx.config["scope"], ctx.config["skills"])
    phases = phases or skill.plan()
    for kind, limits in (("budget", ctx.config["budgets"]), ("rate", ctx.config["rates"])):
        for key, value in limits.items():
            if not isinstance(value, (int, float)) or value < 0 or (kind == "rate" and value == 0):
                raise Refused(f"Invalid {kind}: {key}")
    for seed in ctx.config["scope"]["seeds"]:
        scope.require(seed)
    if not bash_path():
        raise Refused("Bash required (Git Bash on Windows)")
    if ctx.config.get("fixture"):
        fixture = Path(ctx.config["fixture"])
        if not fixture.is_file():
            raise Refused("Fixture does not exist")
        json.loads(fixture.read_text(encoding="utf-8"))
        # Fixture mode only runs the audited upstream scripts, not arbitrary code.
        pins = json.loads(Path(__file__).with_name("trusted.json").read_text())
        for p in skill.root.rglob("*"):
            if p.is_file() and p.suffix in {".py", ".sh"}:
                key = str(p.relative_to(skill.root.parent)).replace("\\", "/")
                if pins.get(key) != normalized_hash(p):
                    raise Refused("Fixture runner refuses an unreviewed script: " + key)
    else:
        if sys.platform != "linux" or not shutil.which("bwrap"):
            raise Refused("Live execution requires Linux + bubblewrap network isolation; use --fixture for offline verification")
        check = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "true"],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        if check.returncode:
            raise Refused("Network sandbox self-check failed")
        import yaml
        overlays = yaml.safe_load(Path(__file__).with_name("adapters.yaml").read_text()).get(skill.name, {})
        dependencies = {dep for p in phases for dep in p.get("deps", overlays.get(p["id"], {}).get("deps", []))}
        for tool in dependencies:
            if not shutil.which(tool):
                raise Refused("Missing dependency: " + tool)
        if "httpx" in dependencies:
            check = subprocess.run([shutil.which("httpx"), "-version"], stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, timeout=10)
            if "projectdiscovery" not in (check.stdout + check.stderr).lower():
                raise Refused("httpx is not the ProjectDiscovery scanner")
        if skill.name == "recon" and any(p["id"] == "active-discovery" for p in phases):
            wordlist = ctx.config.get("env", {}).get("dns_wordlist", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
            if not Path(wordlist).is_file():
                raise Refused("DNS wordlist missing; set BOUNTY_DNS_WORDLIST before init")
            # Copy external input into the target run so workers need no extra writable mounts.
            copied = ctx.root / "work/dns-wordlist.txt"
            if Path(wordlist).resolve() != copied.resolve():
                shutil.copyfile(wordlist, copied)
            ctx.config.setdefault("env", {})["dns_wordlist"] = str(copied)
    ctx.config["validation"] = {"signature": signature(ctx, skill), "skill": skill.name, "at": time.time()}
    ctx.config["status"] = "validated"
    ctx.save()
    ctx.trace("validate", skill=skill.name, gates={"scope": True, "tools": True},
              mode="fixture" if ctx.config.get("fixture") else "live")


class ToolLayer:
    def __init__(self, ctx, breaker):
        self.ctx, self.breaker = ctx, breaker
        self.scope = Scope(ctx.config["scope"], ctx.config["skills"])
        self.fixture = json.loads(Path(ctx.config["fixture"]).read_text()) if ctx.config.get("fixture") else None
        self.next_call = 0.0
        self.tier = "active-safe"
        self.registry = {"httpx": self.httpx}
        from .plugins import register_tools
        register_tools(self)

    def call(self, request):
        from .policy import validate_request, InvalidArguments, TOOL_TIERS
        self.breaker.check()
        name = request["tool"]
        if self.tier == "passive" and name in {"httpx", "dnsx", "openssl", "http-read", "dns-read"}:
            self.breaker.trip("Active tool refused in passive phase")
        if name not in self.registry:
            self.breaker.trip("Unregistered tool: " + name)
        try:
            request = validate_request(self, request)
        except InvalidArguments as error:
            self.ctx.trace("tool.refused", tool=name, reason=str(error))
            self.breaker.invalid(str(error))
            raise
        required = TOOL_TIERS.get(name, "active-intrusive")
        if name == "curl" and any(a.startswith("https://crt.sh/?") for a in request["args"]):
            required = "passive"
        if required == "active-intrusive" and not self.ctx.config.get("explore_authorized"):
            self.breaker.trip("Intrusive tool requires explore authorization")
        if required == "active-intrusive" and self.tier != "active-intrusive":
            self.breaker.trip("Tool exceeds phase tier")
        self.ctx.trace("tool.call", tool=name, args=request["args"], gates={"registered": True})
        from .policy import options
        self.rate_override = options(request["args"]).get("-rl")
        try:
            result = self.registry[name](request["args"], request.get("stdin", ""))
        finally:
            self.rate_override = None
        for key in ("stdout", "stderr"):
            if isinstance(result.get(key), str) and len(result[key]) > 65536:
                result[key] = result[key][:65536] + "\n[output truncated]"
        return redact(result)

    def external(self, name, args, stdin="", category="http"):
        self.rate(category)
        binary = shutil.which(name)
        if not binary:
            raise Refused("Required tool missing: " + name)
        result = subprocess.run([binary, *args], input=stdin, capture_output=True, text=True,
                                timeout=min(60, max(1, self.remaining())), env=self.clean_env(), cwd=self.ctx.root)
        self.breaker.outcome(result.returncode == 0)
        return dict(code=result.returncode, stdout=redact(result.stdout), stderr=redact(result.stderr))

    def rate(self, category="http"):
        self.breaker.check()
        rate = float(self.ctx.config["rates"][category])
        if getattr(self, "rate_override", None):
            rate = min(rate, float(self.rate_override))
        if rate <= 0:
            raise Refused("Rate must be positive")
        with self.breaker.rate_lock:
            due = max(time.monotonic(), self.next_call, self.breaker.next_times.get(category, 0))
            self.breaker.next_times[category] = due + 1 / rate
        while time.monotonic() < due:
            self.breaker.check()
            time.sleep(max(0, min(0.05, due - time.monotonic())))

    def httpx(self, args, stdin):
        # The skill requests a batch; the broker gates each individual root probe.
        allowed = {"-silent", "-json", "-sc", "-title", "-td", "-location", "-cname", "-cdn", "-ip",
                   "-webserver", "-no-color"}
        options = {}
        i = 0
        while i < len(args):
            flag = args[i]
            if flag in {"-u", "-l", "-o", "-rl", "-t", "-timeout", "-retry", "-retries"} and i + 1 < len(args):
                options[flag] = args[i + 1]
                i += 2
            elif flag in allowed:
                i += 1
            else:
                self.breaker.trip("Disallowed httpx argument: " + flag)
        dest = inside(self.ctx.root, options["-o"]) if "-o" in options else None
        source = inside(self.ctx.root, options["-l"]).read_text() if "-l" in options else options["-u"]
        hosts = [self.scope.require(h, self.breaker) for h in source.splitlines() if h.strip()]
        rows = []
        failed = False
        for host in dict.fromkeys(hosts):
            self.rate()
            self.ctx.trace("tool.request", tool="httpx", host=host, gates={"scope": True, "rate": True})
            if self.fixture is not None:
                rec = self.fixture.get("httpx", {}).get(host)
                if isinstance(rec, dict) and rec.get("error"):
                    failed = True
                    self.breaker.outcome(False)
                    continue
            else:
                cmd = [shutil.which("httpx"), "-u", "https://" + host + "/", "-silent", "-json",
                       "-sc", "-title", "-td", "-location", "-webserver", "-no-color", "-no-fallback",
                       "-t", options.get("-t", "1"), "-timeout", options.get("-timeout", "10"),
                       "-retries", options.get("-retry", options.get("-retries", "1")), "-rl", options.get("-rl", "1"), "-disable-update-check"]
                result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                        timeout=min(15, max(1, self.remaining())), env=self.clean_env())
                if result.returncode:
                    failed = True
                    self.breaker.outcome(False)
                    continue
                records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
                rec = records[0] if records else None
            status = rec.get("status_code") if rec else None
            self.breaker.outcome(status != 429, status)
            if status == 429:
                self.backoff(min(2 ** self.breaker.throttles, 30))
            if rec:
                rec = dict(rec, input=host)
                if rec.get("url"):
                    self.scope.require(rec["url"], self.breaker)
                rows.append(redact(rec))
        output = "".join(json.dumps(r) + "\n" for r in rows)
        if dest:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(output, encoding="utf-8")
        return dict(stdout=output, stderr="Tool errors occurred" if failed else "", code=int(failed))

    def remaining(self):
        return self.ctx.config["budgets"]["seconds"] - (time.monotonic() - self.breaker.started)

    def backoff(self, seconds, category="http"):
        with self.breaker.rate_lock:
            self.breaker.next_times[category] = max(self.breaker.next_times.get(category, 0), time.monotonic() + seconds)

    def clean_env(self):
        return {"PATH": os.environ.get("PATH", ""), "HOME": str(self.ctx.root / "work"),
                "TMPDIR": str(self.ctx.root / "work"), "TEMP": str(self.ctx.root / "work"),
                "TMP": str(self.ctx.root / "work"), "NO_COLOR": "1"}


class Executor:
    def __init__(self, ctx, skill):
        self.ctx, self.skill = ctx, skill
        self.breaker = Breaker(ctx)
        self.tools = ToolLayer(ctx, self.breaker)
        self.campaign = uuid.uuid4().hex

    def run_script(self, phase, args):
        self.breaker.check()
        self.tools.tier = phase["tier"]
        normalized_scope = dict(self.ctx.config["scope"])
        normalized_scope["seeds"] = [self.tools.scope.require(s, self.breaker) for s in normalized_scope["seeds"]]
        write_json(self.ctx.root / "scope.json", normalized_scope)
        work = self.ctx.root / "work" / self.campaign / phase["id"]
        skill_copy = prepare_skill(self.skill.root, work / "skills")
        script = inside(skill_copy, skill_copy / (phase.get("run") or phase.get("script")))
        for value in args:
            candidate = Path(value)
            if candidate.is_absolute() and candidate.suffix == ".txt" and candidate.is_file() and candidate.resolve().is_relative_to(self.ctx.root):
                candidate.write_bytes(normalized_bytes(candidate.read_bytes()))
        spool = work / "spool"
        bin_dir = work / "bin"
        spool.mkdir(parents=True)
        bin_dir.mkdir()
        bridge = Path(__file__).with_name("bridge.py").resolve()
        # Shims contain no network implementation. Each request goes to the parent.
        import shlex
        python = shell_path(sys.executable)
        for name in self.tools.registry:
            shim = bin_dir / name
            shim.write_text("#!/bin/sh\nexec " + shlex.quote(python) + " " + shlex.quote(shell_path(bridge)) +
                            " " + shlex.quote(name) + ' "$@"\n', encoding="utf-8")
            shim.chmod(0o755)
        shim = bin_dir / "python3"
        shim.write_text("#!/bin/sh\nexec " + shlex.quote(python) + ' "$@"\n', encoding="utf-8")
        shim.chmod(0o755)
        env = self.tools.clean_env()
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        env.update(BOUNTY_SPOOL=shell_path(spool), PYTHONDONTWRITEBYTECODE="1")
        # Bash sets its own POSIX path on Windows, so prepend shims inside Bash.
        if script.suffix == ".sh":
            command = [bash_path(), "--noprofile", "--norc", "-c",
                       'export PATH="$1:$PATH"; shift; source "$0"', shell_path(script), bash_directory(bin_dir), *args]
        else:
            command = [bash_path(), "--noprofile", "--norc", "-c",
                       'export PATH="$1:$PATH"; shift; exec "$@"', "bounty", bash_directory(bin_dir),
                       sys.executable, str(Path(__file__).with_name("python_worker.py")), str(script), *args]
        if self.tools.fixture is None:
            # Scripts cannot open sockets, read operator credentials, or write outside the run directory.
            from .runtime import runtime_mounts
            mounts = runtime_mounts()
            command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", *mounts,
                       "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(self.skill.root.parent), str(self.skill.root.parent),
                       "--ro-bind", str(bridge.parent), str(bridge.parent),
                       "--bind", str(self.ctx.root), str(self.ctx.root), "--chdir", str(self.ctx.root), "--", *command]
        log = work / "process.log"
        self.ctx.trace("phase.start", campaign=self.campaign, phase=phase["id"], args=args,
                       gates={"tier": True, "validation": True, "isolated_network": self.tools.fixture is None})
        failure = None
        with log.open("wb") as output:
            process = subprocess.Popen(command, cwd=self.ctx.root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=output, start_new_session=os.name != "nt")
            try:
                while process.poll() is None:
                    self.breaker.check()
                    for request in spool.glob("*.request"):
                        try:
                            result = self.tools.call(json.loads(request.read_text()))
                            if result.get("code"):
                                failure = "Tool failed inside phase " + phase["id"]
                        except Exception as error:
                            write_json(request.with_suffix(".response"), dict(code=1, stderr=redact(str(error))))
                            raise
                        write_json(request.with_suffix(".response"), result)
                        request.rename(request.with_suffix(".handled"))
                    time.sleep(0.02)
                if process.returncode or failure:
                    self.breaker.outcome(False)
                    raise Refused(failure or f"Phase {phase['id']} exited {process.returncode}")
            finally:
                if process.poll() is None:
                    if os.name == "nt":
                        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
        log.write_text(redact(log.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
        if phase.get("out"):
            output_path = phase["out"].replace("{run_dir}", str(self.ctx.root))
            if not inside(self.ctx.root, output_path).is_file():
                raise Refused("Declared phase output is missing: " + phase["id"])
        self.breaker.outcome(True)
        self.ctx.trace("phase.complete", phase=phase["id"], evidence=str(log.relative_to(self.ctx.root)))
        return log

    @exclusive_campaign
    def thin_slice(self):
        validation = self.ctx.config.get("validation")
        if not validation or validation["signature"] != signature(self.ctx, self.skill):
            raise Refused("Validation missing or stale")
        hosts = [self.tools.scope.require(s, self.breaker) for s in self.ctx.config["scope"]["seeds"]]
        (self.ctx.root / "hosts/all.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")
        phase = self.skill.phases["http-probe"]
        if phase["tier"] not in {"passive", "active-safe"} or phase["requires_authorization"]:
            raise Refused("Intrusive phase refused by recon")
        self.ctx.config["status"] = "running"
        self.ctx.config.pop("reason", None)
        self.ctx.save()
        try:
            self.run_script(phase, [shell_path(self.ctx.root), str(min(100, self.ctx.config["rates"]["http"]))])
            self.ingest_http()
            self.ctx.config["status"] = "complete"
        except (Exception, KeyboardInterrupt) as error:
            self.ctx.config["status"] = "partial"
            self.ctx.config["reason"] = redact(str(error)) or "Interrupted"
            self.ctx.trace("campaign.stopped", reason=self.ctx.config["reason"], breaker=self.breaker.snapshot())
            raise
        finally:
            self.sanitize_logs()
            self.ctx.save()
            report(self.ctx)

    def sanitize_logs(self):
        for path in (self.ctx.root / "work" / self.campaign).rglob("*.log"):
            path.write_text(redact(path.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")

    def ingest_http(self):
        path = self.ctx.root / "out/httpx.jsonl"
        annotate = __import__("bounty.core", fromlist=["import_file"]).import_file(self.skill.root / "scripts/surface_table.py")
        board = Blackboard(self.ctx.root)
        try:
            board.db.execute("UPDATE surface SET state='hypothesis'")
            board.db.commit()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                rec = redact(json.loads(line))
                host = self.tools.scope.require(rec["input"], self.breaker)
                evidence = f"raw/{self.campaign}-httpx.jsonl#{number}"
                board.surface(host, rec["status_code"], rec.get("tech") or [],
                              "fixture" if self.tools.fixture is not None else "httpx",
                              annotate.signals(rec, host).split(";"), evidence,
                              "hypothesis" if self.tools.fixture is not None else "confirmed")
            evidence_file = self.ctx.root / "raw" / (self.campaign + "-httpx.jsonl")
            evidence_file.write_text(redact(path.read_text()), encoding="utf-8")
            dead = self.ctx.root / "out/dead.txt"
            if dead.exists():
                dead_evidence = self.ctx.root / "raw" / (self.campaign + "-dead.txt")
                dead_evidence.write_text(dead.read_text(), encoding="utf-8")
                for host in dead.read_text().splitlines():
                    if host.strip():
                        host = self.tools.scope.require(host, self.breaker)
                        board.surface(host, "dead", [], "fixture" if self.tools.fixture is not None else "httpx", [],
                                      str(dead_evidence.relative_to(self.ctx.root)),
                                      "hypothesis" if self.tools.fixture is not None else "confirmed")
        finally:
            board.close()

    @exclusive_campaign
    def campaign_run(self, phases, *, authorized=False, host=None):
        from .plugins import phase_arguments
        validation = self.ctx.config.get("validation")
        if not validation or validation["signature"] != signature(self.ctx, self.skill):
            raise Refused("Validation missing or stale")
        self.ctx.config.update(status="running")
        self.ctx.config.pop("reason", None)
        self.ctx.save()
        board = Blackboard(self.ctx.root)
        states = {}
        ident = None
        try:
            self.ctx.trace("captain.plan", campaign=self.campaign, phases=[p["id"] for p in phases],
                           rationale="Topological manifest order; one worker; no nested delegation", max_workers=1)
            for phase in phases:
                self.breaker.check()
                ident = phase["id"]
                if (phase["tier"] == "active-intrusive" or phase["requires_authorization"]) and not authorized:
                    raise Refused("Phase requires explore authorization: " + ident)
                blocked = [n for n in phase.get("needs", []) if states.get(n) != "complete"]
                args, reason = phase_arguments(self, phase, host)
                if blocked:
                    state, evidence = "blocked", "Dependencies not complete: " + ", ".join(blocked)
                elif args is None:
                    state, evidence = "manual", reason
                else:
                    self.ctx.trace("captain.delegate", worker="workflow", depth=1, phase=ident,
                                   rationale="Executable phase with satisfied dependencies")
                    log = self.run_script(phase, args)
                    state, evidence = "complete", str(log.relative_to(self.ctx.root))
                    if self.skill.name == "recon" and ident == "http-probe":
                        self.ingest_http()
                    if self.skill.name != "recon":
                        # A successful process is evidence, not a confirmed vulnerability.
                        from .registry import Registry, specialists
                        from .observations import candidates
                        parser = Registry("bounty.parsers", {"default": candidates}).get("default")
                        for observation in parser(self.skill.name, ident, redact(log.read_text()), host):
                            self.tools.scope.require(observation["host"], self.breaker)
                            review = specialists().get("triager")().review(observation)
                            board.finding(self.skill.name, ident, observation["host"], observation["title"], evidence,
                                          review, state=review["state"])
                            self.ctx.trace("triager.review", phase=ident, state=review["state"],
                                           rationale=review["rationale"])
                states[ident] = state
                board.db.execute("INSERT OR IGNORE INTO phases VALUES (?,?,?,?,?)",
                                 (self.campaign, self.skill.name, ident, state, evidence))
                board.db.commit()
                self.ctx.trace("phase.state", phase=ident, state=state, evidence=evidence)
            self.ctx.config["status"] = "complete" if all(s == "complete" for s in states.values()) else "partial"
            if self.ctx.config["status"] == "partial":
                self.ctx.config["reason"] = "Some phases require operator inputs or manual verification; see phase coverage."
        except (Exception, KeyboardInterrupt) as error:
            self.ctx.config.update(status="partial", reason=redact(str(error)) or "Interrupted")
            if ident and ident not in states:
                board.db.execute("INSERT OR IGNORE INTO phases VALUES (?,?,?,?,?)",
                                 (self.campaign, self.skill.name, ident, "failed", self.ctx.config["reason"]))
                board.db.commit()
            self.ctx.trace("campaign.stopped", reason=self.ctx.config["reason"], breaker=self.breaker.snapshot())
            raise
        finally:
            board.close()
            self.sanitize_logs()
            self.ctx.save()
            report(self.ctx)


def report(ctx, format="md"):
    from .registry import Registry
    return Registry("bounty.reports", {"md": markdown_report}).get(format)(ctx)


def markdown_report(ctx):
    board = Blackboard(ctx.root)
    try:
        lines = [f"# {ctx.config['target']}", "", f"Status: {ctx.config['status']}",
                 "Mode: " + ("OFFLINE FIXTURE — not target observations" if ctx.config.get("fixture") else "live"),
                 ctx.config.get("reason", ""), "", "| Host | Status | Tech | Source | Signals | State | Evidence |",
                 "|---|---|---|---|---|---|---|"]
        for row in board.rows():
            lines.append("| " + " | ".join(str(row[k]).replace("|", "\\|").replace("\n", " ") for k in
                         ("host", "status", "tech", "source", "signals", "state", "evidence")) + " |")
        lines.extend(["", "## Phase coverage", ""])
        for row in board.rows("phases"):
            lines.append(f"- [{row['campaign'][:8]}] {row['skill']}/{row['phase']}: {row['state']} — {row['evidence']}")
        lines.extend(["", "## Findings requiring triage", ""])
        for row in board.rows("findings"):
            lines.append(f"- {row['title']} ({row['host']}): {row['state']}; evidence: {row['evidence']}")
            verdict = json.loads(row["details"]).get("verdict")
            if verdict:
                lines.append(f"  Confidence: {verdict['confidence']}; {verdict['rationale']} Next: {verdict['next_step']}")
        trace = ctx.root / "traces/events.jsonl"
        if trace.exists():
            lines.extend(["", "## Agent path", ""])
            for line in trace.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("event") == "agent.decision":
                    lines.append(f"- {event['agent_id']}: {event['action']} — {event.get('rationale', '')}")
        dest = ctx.root / "report/report.md"
        dest.write_text(redact("\n".join(lines)) + "\n", encoding="utf-8")
        return dest
    finally:
        board.close()
