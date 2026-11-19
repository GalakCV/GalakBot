"""Registered tool adapters. Skill-specific calling conventions are declarative overlays."""
import json
from pathlib import Path
import re
import socket
import time
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit, unquote

import yaml

from .core import Refused
from .executor import shell_path
from .workflow import inside


def register_tools(layer):
    def passive(name):
        def call(args, stdin):
            if name in {"subfinder", "assetfinder"}:
                host = args[args.index("-d") + 1] if name == "subfinder" else args[-1]
            else:
                host = stdin.strip()
            host = layer.scope.require(host, layer.breaker)
            expected = {"subfinder": ["-d", host, "-silent", "-all"],
                        "assetfinder": ["--subs-only", host], "gau": ["--subs"], "waybackurls": []}[name]
            if args != expected:
                layer.breaker.trip("Unsupported arguments for " + name)
            if layer.fixture is not None:
                layer.rate()
                layer.breaker.outcome(True)
                return dict(code=0, stdout="\n".join(layer.fixture.get("passive", {}).get(host, [host])) + "\n")
            return layer.external(name, args, stdin)
        return call

    def dnsx(args, stdin):
        permitted = {"-l", "-rl", "-retry"}
        options, i = {}, 0
        while i < len(args):
            if args[i] == "-silent":
                i += 1
            elif args[i] in permitted and i + 1 < len(args):
                options[args[i]] = args[i + 1]
                i += 2
            else:
                layer.breaker.trip("Unsupported dnsx arguments")
        data = inside(layer.ctx.root, options["-l"]).read_text() if "-l" in options else stdin
        hosts = [layer.scope.require(h, layer.breaker) for h in data.splitlines() if h.strip()]
        rows = []
        for host in dict.fromkeys(hosts):
            if layer.fixture is not None:
                layer.rate("dns")
                layer.breaker.outcome(True)
                if host in layer.fixture.get("resolved", layer.fixture.get("httpx", {})):
                    rows.append(host)
            else:
                result = layer.external("dnsx", ["-silent", "-rl", "1", "-retry", "2"], host + "\n", "dns")
                if result["code"]:
                    return result
                rows.extend(layer.scope.require(line.split()[0], layer.breaker) for line in result["stdout"].splitlines() if line)
        # Persist self-check and stop if a supposedly known-good set entirely fails.
        if "-l" not in options and hosts and not rows:
            layer.breaker.trip("DNS self-check failed; verify resolvers before continuing")
        return dict(code=0, stdout="\n".join(rows) + ("\n" if rows else ""))

    def curl(args, stdin):
        urls = [a for a in args if a.startswith(("http://", "https://"))]
        if len(urls) != 1:
            layer.breaker.trip("curl requires one explicit URL")
        url = urls[0]
        parsed = urlsplit(url)
        # The passive CT source is a fixed provider, not a target-scope exception.
        ct = parsed.scheme == "https" and parsed.netloc == "crt.sh" and parsed.path == "/"
        if ct:
            query = parse_qs(parsed.query)
            seed = query.get("q", [""])[0].removeprefix("%.")
            layer.scope.require(seed, layer.breaker)
            if query.get("output") != ["json"]:
                layer.breaker.trip("Unsupported CT request")
        else:
            layer.scope.require(url, layer.breaker)
            if not layer.ctx.config.get("explore_authorized"):
                layer.breaker.trip("Target HTTP curl requires explore")
        allowed_single = {"-sS"}
        allowed_pairs = {"-m", "-A", "-o", "-w"}
        options, i = {}, 0
        while i < len(args):
            arg = args[i]
            if arg == url or arg in allowed_single:
                i += 1
            elif arg in allowed_pairs and i + 1 < len(args):
                options[arg] = args[i + 1]
                i += 2
            else:
                layer.breaker.trip("Unsupported curl argument")
        if "-o" in options and options["-o"] not in {"/dev/null", "nul", "NUL"}:
            layer.breaker.trip("curl output path not permitted")
        record = read_http(url, ct_seed=seed if ct else None)
        output = record.get("body", "") if "-o" not in options else ""
        if "-w" in options:
            output += options["-w"].replace("%{http_code}", str(record["status"])).replace("%{size_download}", str(len(record.get("body", ""))))
        return dict(code=0, stdout=output)

    def read_http(url, ct_seed=None):
        from .core import redact
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
            layer.breaker.trip("Unsupported HTTP URL")
        if ct_seed is None:
            layer.scope.require(url, layer.breaker)
            if layer.tier == "passive" or (layer.tier == "active-safe" and (parsed.path not in {"", "/"} or parsed.query)):
                layer.breaker.trip("HTTP request exceeds phase tier")
            if any(p in unquote(parsed.path).lower() for p in ("/iam/security-credentials", "/service-accounts/", "/identity/oauth2/token")):
                layer.breaker.trip("Cloud credential retrieval is prohibited")
            selected = layer.ctx.config.get("selected_host")
            if selected and parsed.hostname != selected and layer.ctx.config.get("active_skill") != "cloud":
                layer.breaker.trip("Request is outside selected host")
        layer.rate()
        layer.ctx.trace("http.request", url=url, gates={"scope": True, "rate": True, "redirects": False})
        if layer.fixture is not None:
            record = layer.fixture.get("http", {}).get(url, {"status": 404, "body": "", "headers": {}})
            if ct_seed:
                record = {"status": 200, "body": json.dumps([{"name_value": ct_seed}]), "headers": {}}
        else:
            try:
                result = subprocess.run([sys.executable, str(Path(__file__).with_name("http_fetch.py")), url],
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                        timeout=min(12, max(0.01, layer.remaining())), env=layer.clean_env(), cwd=layer.ctx.root)
                if result.returncode:
                    raise OSError("HTTP read failed")
                record = json.loads(result.stdout)
            except (OSError, subprocess.TimeoutExpired):
                layer.breaker.outcome(False)
                layer.breaker.check()
                raise Refused("HTTP request failed") from None
        layer.breaker.outcome(record["status"] != 429, record["status"])
        if record["status"] == 429:
            layer.next_call = time.monotonic() + min(2 ** layer.breaker.throttles, 30)
        return redact(record)

    def http_read(args, stdin):
        if len(args) != 1:
            raise Refused("HTTP read requires one URL")
        return dict(code=0, stdout=json.dumps(read_http(args[0])))

    def dns_read(args, stdin):
        if len(args) != 1:
            raise Refused("DNS read requires one host")
        host = layer.scope.require(args[0], layer.breaker)
        layer.rate("dns")
        if layer.fixture is not None:
            data = layer.fixture.get("dns", {}).get(host, {"addresses": [], "aliases": []})
        else:
            # Use a subprocess with a hard deadline rather than unbounded system resolver calls.
            result = layer.external("dnsx", ["-silent", "-json", "-a", "-cname", "-rl", "1", "-retry", "2"], host + "\n", "dns")
            rows = [json.loads(line) for line in result["stdout"].splitlines() if line]
            data = {"addresses": rows[0].get("a", []) if rows else [], "aliases": rows[0].get("cname", []) if rows else []}
        layer.breaker.outcome(True)
        return dict(code=0, stdout=json.dumps(data))

    def openssl(args, stdin):
        if not args:
            raise Refused("openssl subcommand required")
        if args[0] == "x509":
            expected = ["x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"]
            if args != expected:
                layer.breaker.trip("Unsupported certificate inspection arguments")
        elif args[0] == "s_client":
            if len(args) not in {5, 6} or args[1] != "-connect" or args[3] != "-servername":
                layer.breaker.trip("Unsupported TLS arguments")
            host = layer.scope.require(args[4], layer.breaker)
            if args[2] != host + ":443" or (len(args) == 6 and args[-1] not in {"-ssl3", "-tls1", "-tls1_1"}):
                layer.breaker.trip("Unsupported TLS destination or protocol")
        else:
            layer.breaker.trip("Unsupported openssl command")
        if layer.fixture is not None:
            layer.rate()
            layer.breaker.outcome(True)
            return dict(code=0, stdout=layer.fixture.get("tls", {}).get(" ".join(args), ""))
        return layer.external("openssl", args, stdin)

    for name in ("subfinder", "assetfinder", "gau", "waybackurls"):
        layer.registry[name] = passive(name)
    layer.registry.update(dnsx=dnsx, curl=curl, openssl=openssl, **{"http-read": http_read, "dns-read": dns_read})
    # Trusted Python package plugins extend the tool layer, not agent-generated code.
    from importlib.metadata import entry_points
    for entry in entry_points(group="bounty.tools"):
        entry.load()(layer)


def phase_arguments(executor, phase, host):
    skill, ctx = executor.skill, executor.ctx
    overlay = yaml.safe_load(Path(__file__).with_name("adapters.yaml").read_text()) or {}
    local = skill.root / "harness.yaml"
    if local.exists():
        overlay.update(yaml.safe_load(local.read_text()) or {})
    settings = overlay.get(skill.name, {}).get(phase["id"], {})
    required = settings.get("requires_input")
    if required and not ctx.config.get(required):
        return None, "Operator-reviewed input required: " + required
    if settings.get("manual"):
        return None, settings["manual"]
    if not (phase.get("run") or phase.get("script")):
        return None, "Runbook only: " + str(phase.get("runbook", "no executable"))
    args = phase.get("args", settings.get("args"))
    if args is None:
        return None, "Missing executable argument contract; provide harness.yaml args"
    env = dict(skill.data.get("env", {}))
    env.update(rate_http=ctx.config["rates"]["http"], rate_dns=ctx.config["rates"]["dns"])
    env.update(ctx.config.get("env", {}))
    if executor.tools.fixture is not None:
        words = ctx.root / "work/fixture-dns.txt"
        words.write_text("api\n", encoding="utf-8")
        env["dns_wordlist"] = shell_path(words)
    values = {"run_dir": shell_path(ctx.root), "target": host or "", "base_url": "https://" + (host or ""),
              "skill_dir": shell_path(skill.root), "target_name": ctx.config["target"]}
    if ctx.config.get("approved_paths"):
        values["approved_paths"] = ctx.config["approved_paths"]
    if host:
        selected = ctx.root / "hosts/selected.txt"
        selected.write_text(host + "\n", encoding="utf-8")
        values["hosts_file"] = shell_path(selected)
    values.update({"env." + k: str(v) for k, v in env.items()})

    def expand(value):
        for _ in range(5):
            updated = re.sub(r"\$?\{([^}]+)\}", lambda m: values.get(m[1], m[0]), str(value))
            if updated == value:
                break
            value = updated
        if "{" in value:
            raise Refused("Unresolved manifest input: " + value)
        return value

    if skill.name == "recon" and phase["id"] == "active-discovery":
        wordlist = expand(env["dns_wordlist"])
        if not Path(wordlist).is_file():
            raise Refused("DNS wordlist missing; set BOUNTY_DNS_WORDLIST before init")
    for dep in phase.get("deps", settings.get("deps", [])):
        if executor.tools.fixture is None:
            import shutil
            if not shutil.which(dep):
                raise Refused("Required tool missing: " + dep)
    return [expand(a) for a in args], None
