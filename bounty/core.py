from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
import threading
from functools import wraps
from dataclasses import dataclass
from pathlib import Path

_TRACE_LOCK = threading.RLock()


def synchronized(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return invoke


class Refused(RuntimeError):
    pass


def redact(value):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if re.search(
            r"authorization|cookie|password|secret|token|api[-_]?key|credential", k, re.I
        ) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                   "[REDACTED PRIVATE KEY]", value, flags=re.S)
    value = re.sub(r"(?im)((?:authorization|set-cookie|cookie)\s*:\s*)[^\r\n]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(\b(?:bearer|basic)\s+)\S+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)((?:password|secret|token|api[_-]?key|credential)[\w-]*[\"']?\s*[:=]\s*[\"']?)[^\s&\"',}]+",
                   r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[\w-]+\.[\w-]+\.[\w-]+", "[REDACTED]", value)
    return re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".new")
    temp.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temp.replace(path)


@dataclass
class RunContext:
    root: Path
    config: dict

    @classmethod
    def init(cls, runs, target, scope, skills, *, fixture=None, fresh=False):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", target) or target in {"con", "nul", "prn", "aux"}:
            raise Refused("Target must be a lowercase slug (letters, numbers, - or _).")
        root = (Path(runs) / target).resolve()
        if (root / "context.json").exists():
            old = cls.load(runs, target)
            if old.config["scope"] != scope:
                raise Refused("Existing target has a different scope; use a new target name.")
            if not fresh:
                return old
            # Preserve every historical database, including when the operator asks for fresh.
            archive = root.parent / (target + "--archive-" + uuid.uuid4().hex[:12])
            root.rename(archive)
        for name in ("raw", "traces", "findings", "report", "hosts", "out", "work"):
            (root / name).mkdir(parents=True, exist_ok=True)
        config = dict(target=target, scope=scope, skills=str(Path(skills).expanduser().resolve()),
                      fixture=str(Path(fixture).resolve()) if fixture else None,
                      budgets=dict(seconds=900, iterations=1000, cost=0.0),
                      rates=dict(http=2, dns=10), status="initialized", validation=None)
        ctx = cls(root, config)
        ctx.save()
        write_json(root / "scope.json", scope)
        Blackboard(root).close()
        return ctx

    @classmethod
    def load(cls, runs, target):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", target):
            raise Refused("Invalid target slug")
        root = (Path(runs) / target).resolve()
        try:
            return cls(root, json.loads((root / "context.json").read_text(encoding="utf-8")))
        except FileNotFoundError:
            raise Refused("Target not initialized. Supply --scope to recon or run init.") from None

    def save(self):
        write_json(self.root / "context.json", self.config)

    def trace(self, event, **data):
        with _TRACE_LOCK, (self.root / "traces/events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(redact(dict(time=time.time(), event=event, **data))) + "\n")


class Blackboard:
    def __init__(self, root):
        self.db = sqlite3.connect(Path(root) / "blackboard.db", timeout=20)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS surface (
          host TEXT PRIMARY KEY, status TEXT NOT NULL, tech TEXT NOT NULL,
          source TEXT NOT NULL, signals TEXT NOT NULL, state TEXT NOT NULL,
          evidence TEXT NOT NULL, observed REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS findings (
          natural_key TEXT PRIMARY KEY, skill TEXT, phase TEXT, host TEXT,
          title TEXT, state TEXT, evidence TEXT, details TEXT);
        CREATE TABLE IF NOT EXISTS phases (
          campaign TEXT, skill TEXT, phase TEXT, state TEXT, evidence TEXT,
          PRIMARY KEY (campaign, skill, phase));
        """)

    def surface(self, host, status, tech, source, signals, evidence, state="confirmed"):
        self.db.execute("""INSERT INTO surface VALUES (?,?,?,?,?,?,?,?)
          ON CONFLICT(host) DO UPDATE SET status=excluded.status,tech=excluded.tech,
          source=excluded.source,signals=excluded.signals,state=excluded.state,
          evidence=excluded.evidence,observed=excluded.observed""",
                        (host, str(status), ";".join(tech), source, ";".join(signals), state, evidence, time.time()))
        self.db.commit()

    def finding(self, skill, phase, host, title, evidence, details, state="hypothesis"):
        key = hashlib.sha256(json.dumps([skill, phase, host, title]).encode()).hexdigest()
        self.db.execute("""INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)
          ON CONFLICT(natural_key) DO UPDATE SET state=excluded.state,evidence=excluded.evidence,details=excluded.details""",
                        (key, skill, phase, host, redact(title), state, evidence, json.dumps(redact(details))))
        self.db.commit()

    def rows(self, table="surface"):
        if table not in {"surface", "findings", "phases"}:
            raise Refused("Unknown table")
        return [dict(r) for r in self.db.execute(f"SELECT * FROM {table}")]

    def close(self):
        self.db.close()


class Breaker:
    def __init__(self, ctx, *, consecutive=3, rate_limit=3, error_rate=0.6, window=10):
        self.lock = threading.RLock()
        self.rate_lock = threading.Lock()
        self.next_times = {}
        self.reservations = {}
        self.reservation_id = 0
        self.invalid_attempts = 0
        self.ctx, self.started = ctx, time.monotonic()
        self.consecutive_limit, self.rate_limit = consecutive, rate_limit
        self.error_rate, self.window = error_rate, window
        self.errors = self.throttles = self.calls = 0
        self.history = []
        self.status_history = []
        self.cost = 0.0
        self.reason = None

    @synchronized
    def snapshot(self):
        return dict(reason=self.reason, calls=self.calls, consecutive_errors=self.errors,
                    throttles=self.throttles, cost=self.cost, reserved_cost=sum(self.reservations.values()), elapsed=time.monotonic() - self.started)

    @synchronized
    def trip(self, reason):
        self.reason = self.reason or reason
        self.ctx.trace("breaker.trip", **self.snapshot())
        write_json(self.ctx.root / "breaker.json", self.snapshot())
        raise Refused(self.reason)

    @synchronized
    def check(self):
        if self.reason:
            raise Refused(self.reason)
        budgets = self.ctx.config["budgets"]
        if time.monotonic() - self.started >= budgets["seconds"]:
            self.trip("Time budget exceeded")
        if self.calls >= budgets["iterations"]:
            self.trip("Iteration budget exceeded")
        if self.cost > budgets["cost"]:
            self.trip("Cost budget exceeded")

    @synchronized
    def outcome(self, ok, status=None):
        self.calls += 1
        self._record(ok, status)

    @synchronized
    def reserve(self, cost=0.0):
        self.check()
        if self.cost + sum(self.reservations.values()) + cost > self.ctx.config["budgets"]["cost"]:
            self.trip("Cost budget cannot cover next LLM call; configure --cost-budget")
        self.calls += 1
        self.reservation_id += 1
        self.reservations[self.reservation_id] = cost
        return self.reservation_id

    @synchronized
    def finish(self, reservation, ok, status=None, cost=0.0):
        if reservation not in self.reservations:
            raise Refused("Unknown budget reservation")
        self.reservations.pop(reservation)
        self.cost += cost
        self._record(ok, status)
        if self.cost > self.ctx.config["budgets"]["cost"]:
            self.trip("Cost budget exceeded")

    def _record(self, ok, status=None):
        self.errors = 0 if ok else self.errors + 1
        self.history = (self.history + [not ok])[-self.window:]
        self.throttles = self.throttles + 1 if status == 429 else 0
        self.status_history = (self.status_history + [status])[-self.window:]
        self.ctx.trace("tool.outcome", ok=ok, status=status, breaker=self.snapshot())
        if self.throttles >= self.rate_limit or self.status_history.count(429) >= self.rate_limit:
            self.trip("Repeated HTTP 429")
        if self.errors >= self.consecutive_limit:
            self.trip("Consecutive tool errors")
        if len(self.history) == self.window and sum(self.history) / len(self.history) >= self.error_rate:
            self.trip("High tool error rate")

    @synchronized
    def invalid(self, reason):
        self.invalid_attempts += 1
        self.ctx.trace("gate.refused", reason=reason, invalid_attempts=self.invalid_attempts)
        self.outcome(False)
        if self.invalid_attempts >= 3:
            self.trip("Repeated invalid tool arguments")


def import_file(path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("bounty_external_" + hashlib.sha256(str(path).encode()).hexdigest(), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Scope:
    def __init__(self, config, skill_root):
        self.config = config
        self.impl = import_file(Path(skill_root) / "recon/scripts/scope_filter.py")
        for key in ("seeds", "in_scope", "out_of_scope"):
            if not isinstance(config.get(key), list) or not all(isinstance(v, str) for v in config[key]):
                raise Refused(f"scope.{key} must be a list of strings")
        if not config["seeds"] or not config["in_scope"]:
            raise Refused("Seeds and in_scope cannot be empty")
        for pattern in config["in_scope"] + config["out_of_scope"]:
            plain = pattern.removeprefix("*.")
            if not self.impl.is_valid(plain) or plain != self.impl.normalize(plain):
                raise Refused("Scope patterns must be normalized DNS names, optionally *.domain")

    def host(self, value):
        from urllib.parse import urlsplit
        raw = value.strip()
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        if parsed.username or parsed.password or "\\" in raw or any(c.isspace() for c in raw):
            raise Refused("Ambiguous host or URL credentials rejected")
        host = self.impl.normalize(raw)
        if not self.impl.is_valid(host):
            raise Refused("Invalid DNS host")
        return host

    def allows(self, value):
        try:
            host = self.host(value)
        except (Refused, ValueError):
            return False
        return (not any(self.impl.match(host, p) for p in self.config["out_of_scope"])
                and any(self.impl.match(host, p) for p in self.config["in_scope"]))

    def require(self, value, breaker=None):
        if not self.allows(value):
            if breaker:
                breaker.trip("Out-of-scope attempt: " + redact(value))
            raise Refused("Out-of-scope seed or host: " + redact(value))
        return self.host(value)
