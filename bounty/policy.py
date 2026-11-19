"""Declarative CLI envelopes. Invalid arguments are repairable; scope escapes trip."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from .core import Refused


class InvalidArguments(Refused):
    """A model may correct this refusal; the caller counts it as an error."""


@dataclass(frozen=True)
class Policy:
    switches: frozenset[str] = frozenset()
    values: dict[str, str | tuple[int, int]] = field(default_factory=dict)
    positional: str | None = None


POLICIES = {
    "subfinder": Policy(frozenset({"-silent", "-all", "-recursive"}),
                        {"-d": "host", "-rl": (1, 100), "-timeout": (1, 30), "-max-time": (1, 2), "-s": "sources"}),
    "assetfinder": Policy(frozenset({"--subs-only"}), positional="host"),
    "gau": Policy(frozenset({"--subs"}), {"--threads": (1, 4), "--timeout": (1, 30), "--retries": (1, 3), "--providers": "providers"}),
    "waybackurls": Policy(frozenset({"-no-subs", "-dates"})),
    "dnsx": Policy(frozenset({"-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-resp-only"}),
                    {"-l": "hosts_file", "-d": "host", "-rl": (1, 100), "-retry": (1, 3), "-t": (1, 20), "-timeout": (1, 30)}),
    "httpx": Policy(frozenset({"-silent", "-json", "-sc", "-title", "-td", "-location", "-cname", "-cdn", "-ip", "-webserver", "-no-color"}),
                     {"-u": "url", "-l": "hosts_file", "-o": "output", "-rl": (1, 100), "-retry": (1, 3), "-retries": (1, 3), "-t": (1, 20), "-timeout": (1, 30)}),
    "curl": Policy(frozenset({"-sS", "-s", "--silent"}),
                    {"-m": (1, 60), "--max-time": (1, 60), "-A": "user_agent", "-o": "devnull", "-w": "format"}, "curl_url"),
    "http-read": Policy(positional="url"),
    "api-probe": Policy(positional="url"),
    "dns-read": Policy(positional="host"),
    "katana": Policy(frozenset({"-silent", "-jsonl"}),
                      {"-u": "url", "-d": (0, 3), "-rl": (1, 100), "-timeout": (1, 30), "-max-pages": (1, 20)}),
}

TOOL_TIERS = {
    "subfinder": "passive", "assetfinder": "passive", "gau": "passive", "waybackurls": "passive",
    "dnsx": "active-safe", "httpx": "active-safe", "dns-read": "active-safe", "http-read": "active-safe",
    "katana": "active-safe", "openssl": "active-safe", "curl": "active-intrusive", "api-probe": "active-intrusive",
}


def options(args):
    """Read already-validated options without changing ordering or chosen values."""
    result, i = {}, 0
    while i < len(args):
        if args[i].startswith("-") and i + 1 < len(args) and not args[i + 1].startswith("-"):
            result[args[i]] = args[i + 1]
            i += 2
        else:
            i += 1
    return result


def _path(layer, value, *, output=False):
    root = layer.ctx.root.resolve()
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    allowed = ("out", "work") if output else ("hosts", "out", "work")
    if not any(path.is_relative_to(root / directory) for directory in allowed):
        raise InvalidArguments("File is outside allowed host/input/output directories")
    # Script transport and logs are not model-readable input. Restrict to data formats.
    if path.suffix.lower() not in {".txt", ".json", ".jsonl", ".tsv", ".csv"}:
        raise InvalidArguments("Only text data files are allowed")
    if any(part in {"spool", "bin"} for part in path.relative_to(root).parts):
        raise InvalidArguments("Worker control files are not tool inputs")
    if not output and (not path.is_file() or path.stat().st_size > 1048576):
        raise InvalidArguments("Input must be an existing data file no larger than 1 MiB")
    return path


def _value(layer, tool, flag, value, kind):
    if isinstance(kind, tuple):
        if not re.fullmatch(r"[0-9]+", value) or not kind[0] <= int(value) <= kind[1]:
            raise InvalidArguments(f"{flag} must be within [{kind[0]}, {kind[1]}]")
        if flag == "-rl" and layer.fixture is None:
            category = "dns" if tool == "dnsx" else "http"
            if int(value) > layer.ctx.config["rates"][category]:
                raise InvalidArguments(f"{flag} exceeds the run's {category} rate limit")
    elif kind in {"host", "url"}:
        normalized = layer.scope.require(value, layer.breaker)
        if kind == "host":
            return normalized
        if kind == "url":
            url = urlsplit(value if "://" in value else "https://" + value)
            if url.scheme not in {"http", "https"} or url.port not in {None, 80, 443}:
                raise InvalidArguments("Only HTTP(S) on ports 80/443 is allowed")
    elif kind == "curl_url":
        parsed = urlsplit(value)
        query = parse_qs(parsed.query)
        if parsed.scheme == "https" and parsed.netloc == "crt.sh" and parsed.path == "/":
            if set(query) != {"q", "output"} or query.get("output") != ["json"] or len(query["q"]) != 1:
                raise InvalidArguments("Only the fixed CT search contract is allowed")
            layer.scope.require(query["q"][0].removeprefix("%."), layer.breaker)
        else:
            _value(layer, tool, flag, value, "url")
    elif kind == "hosts_file":
        path = _path(layer, value)
        for host in path.read_text(encoding="utf-8").splitlines():
            if host.strip():
                layer.scope.require(host, layer.breaker)
        return str(path)
    elif kind == "output":
        return str(_path(layer, value, output=True))
    elif kind == "devnull":
        if value not in {"/dev/null", "nul", "NUL"}:
            raise InvalidArguments("curl output may only be discarded; results return through the broker")
    elif kind == "format":
        if value not in {"%{http_code}", "%{http_code} %{size_download}"}:
            raise InvalidArguments("Unsupported curl output format")
    elif kind == "user_agent":
        if not re.fullmatch(r"[A-Za-z0-9./_-]{1,80}", value):
            raise InvalidArguments("Invalid User-Agent")
    elif kind == "providers":
        if not set(value.split(",")) <= {"wayback", "commoncrawl", "otx", "urlscan"}:
            raise InvalidArguments("Unknown passive provider")
    elif kind == "sources":
        if not re.fullmatch(r"[a-z0-9]+(?:,[a-z0-9]+)*", value):
            raise InvalidArguments("Invalid source names")
    return value


def validate_request(layer, request):
    if not isinstance(request, dict) or not isinstance(request.get("tool"), str):
        raise InvalidArguments("Tool request must contain a tool name")
    name, args, stdin = request["tool"], request.get("args", []), request.get("stdin", "")
    if not isinstance(args, list) or len(args) > 64 or not all(isinstance(a, str) and len(a) <= 4096 for a in args):
        raise InvalidArguments("Arguments must be a bounded list of strings")
    if not isinstance(stdin, str) or len(stdin.encode()) > 1048576:
        raise InvalidArguments("stdin exceeds the 1 MiB input limit")
    for arg in args:
        # URL query separators are data, never a shell expression. No argument is passed to a shell.
        if re.search(r"[\x00-\x1f\x7f`|;<>]", arg) or "$" in arg or ("&" in arg and not arg.startswith(("http://", "https://"))):
            raise InvalidArguments("Shell metacharacters or control characters are not allowed")
    if name == "openssl":
        _openssl(layer, args)
        return dict(request, args=args, stdin=stdin)
    policy = POLICIES.get(name)
    if policy is None:
        raise InvalidArguments("No registered parameter policy for " + name)
    seen, normalized, positional, i = set(), [], [], 0
    while i < len(args):
        arg = args[i]
        if arg in policy.switches:
            if arg in seen:
                raise InvalidArguments("Duplicate flag: " + arg)
            seen.add(arg)
            normalized.append(arg)
            i += 1
        elif arg in policy.values:
            if arg in seen or i + 1 >= len(args):
                raise InvalidArguments("Missing value or duplicate flag: " + arg)
            seen.add(arg)
            normalized.extend([arg, _value(layer, name, arg, args[i + 1], policy.values[arg])])
            i += 2
        elif arg.startswith("-"):
            raise InvalidArguments("Disallowed flag for " + name + ": " + arg)
        elif policy.positional:
            positional.append(arg)
            normalized.append(_value(layer, name, "target", arg, policy.positional))
            i += 1
        else:
            raise InvalidArguments("Unexpected positional argument for " + name)
    if policy.positional and len(positional) != 1:
        raise InvalidArguments(name + " requires exactly one target")
    if name == "subfinder" and "-d" not in seen:
        raise InvalidArguments("subfinder requires -d")
    if name == "httpx" and sum(flag in seen for flag in ("-u", "-l")) != 1:
        raise InvalidArguments("httpx requires exactly one of -u or -l")
    if name == "httpx" and "-u" in seen:
        target = options(normalized)["-u"]
        url = urlsplit(target if "://" in target else "https://" + target)
        if url.path not in {"", "/"} or url.query:
            raise InvalidArguments("httpx is root-only; select an authorized path tool")
    if name == "katana" and "-u" not in seen:
        raise InvalidArguments("katana requires -u")
    if name in {"gau", "waybackurls", "dnsx"}:
        if name == "dnsx" and sum(bool(v) for v in ("-l" in seen, "-d" in seen, stdin.strip())) != 1:
            raise InvalidArguments("dnsx requires exactly one host source: -l, -d, or stdin")
        if name != "dnsx" and not stdin.strip():
            raise InvalidArguments(name + " requires an in-scope host on stdin")
        for host in stdin.splitlines():
            if host.strip():
                layer.scope.require(host, layer.breaker)
    elif stdin and name != "openssl":
        raise InvalidArguments("This tool does not accept stdin")
    return dict(request, args=normalized, stdin=stdin)


def _openssl(layer, args):
    if not args or args[0] not in {"x509", "s_client"}:
        raise InvalidArguments("Only certificate inspection is allowed")
    if args[0] == "x509":
        if set(args[1:]) - {"-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"}:
            raise InvalidArguments("Disallowed certificate inspection argument")
        if "-ext" in args and (args.index("-ext") + 1 >= len(args) or args[args.index("-ext") + 1] != "subjectAltName"):
            raise InvalidArguments("Only subjectAltName extension is allowed")
        return
    if len(args) not in {5, 6} or args[1] != "-connect" or args[3] != "-servername":
        raise InvalidArguments("TLS requires -connect host:443 -servername host")
    host = layer.scope.require(args[4], layer.breaker)
    destination = args[2].rsplit(":", 1)
    layer.scope.require(destination[0], layer.breaker)
    if args[2] != host + ":443" or (len(args) == 6 and args[-1] not in {"-ssl3", "-tls1", "-tls1_1"}):
        raise InvalidArguments("Only same-host TLS inspection on port 443 is allowed")
