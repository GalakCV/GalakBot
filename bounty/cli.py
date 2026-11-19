import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
import yaml

from .core import Blackboard, Refused, RunContext, redact
from .executor import Executor, report, validate, signature
from .workflow import Skill


def main(argv=None):
    parser = argparse.ArgumentParser(prog="bounty")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "validate", "recon", "explore", "show", "report", "targets"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--runs", default="runs")
        if name != "targets":
            cmd.add_argument("--target", required=True)
        if name in {"init", "recon"}:
            cmd.add_argument("--scope", type=Path, required=name == "init")
            cmd.add_argument("--skills", default=os.environ.get("BOUNTY_SKILLS", "~/.agents/skills"))
            cmd.add_argument("--fixture", type=Path)
            cmd.add_argument("--fresh", action="store_true")
        if name == "recon":
            cmd.add_argument("--phase", choices=["http-probe"])
        if name == "explore":
            cmd.add_argument("--skill", required=True)
            cmd.add_argument("--host", required=True)
            cmd.add_argument("--i-am-authorized", action="store_true")
            cmd.add_argument("--paths", type=Path, help="Operator-approved low-sensitivity GET paths for API auth testing")
        if name == "report":
            cmd.add_argument("--format", choices=["md"], default="md")
    args = parser.parse_args(argv)
    try:
        if args.command == "targets":
            for path in sorted(Path(args.runs).glob("*/context.json")):
                config = json.loads(path.read_text())
                print(f"{path.parent.name}\t{config['status']}")
            return 0
        if args.command == "init" or (args.command == "recon" and args.scope):
            ctx = RunContext.init(args.runs, args.target, json.loads(args.scope.read_text(encoding="utf-8-sig")),
                                  args.skills, fixture=args.fixture, fresh=args.fresh)
            if os.environ.get("BOUNTY_DNS_WORDLIST"):
                ctx.config.setdefault("env", {})["dns_wordlist"] = os.environ["BOUNTY_DNS_WORDLIST"]
                ctx.save()
        else:
            ctx = RunContext.load(args.runs, args.target)
        if args.command == "init":
            print(ctx.root)
        elif args.command in {"validate", "recon"}:
            ctx.config["explore_authorized"] = False
            ctx.config.pop("selected_host", None)
            ctx.config.pop("active_skill", None)
            skill = Skill(ctx.config["skills"], "recon")
            validate(ctx, skill, skill.plan([args.phase], dependencies=False) if args.command == "recon" and args.phase else None)
            if args.command == "recon":
                executor = Executor(ctx, skill)
                if args.phase:
                    executor.thin_slice()
                else:
                    from .registry import specialists
                    executor.campaign_run(specialists().get("captain")().plan(skill))
            print(ctx.config["status"])
        elif args.command == "explore":
            recon = Skill(ctx.config["skills"], "recon")
            previous = ctx.config.get("validation")
            if not previous or previous.get("signature") != signature(ctx, recon):
                raise Refused("Run validate before explore; validation must match current scope and skills")
            skill = Skill(ctx.config["skills"], args.skill)
            from .core import Scope
            host = Scope(ctx.config["scope"], ctx.config["skills"]).require(args.host)
            board = Blackboard(ctx.root)
            try:
                if host not in {r["host"] for r in board.rows()}:
                    raise Refused("Choose a host observed by recon first")
            finally:
                board.close()
            authorized = args.i_am_authorized
            if not authorized and sys.stdin.isatty():
                authorized = input(f"Authorize {args.skill} on {host}, target {args.target}, scope {ctx.config['scope']}? [y/N] ").lower() == "y"
            if not authorized:
                raise Refused("Explore requires explicit human authorization")
            validate(ctx, skill)
            ctx.config["explore_authorized"] = True
            ctx.config["selected_host"] = host
            ctx.config["active_skill"] = args.skill
            ctx.config.pop("approved_paths", None)
            if args.paths:
                paths = args.paths.read_text(encoding="utf-8").splitlines()
                if any(not p.startswith("/") or p.startswith("//") or any(c in p for c in "?#{}\\") or ".." in p for p in paths if p):
                    raise Refused("Approved paths must be literal absolute paths without queries, traversal, or parameters")
                dest = ctx.root / "work/approved-paths.txt"
                dest.write_text("\n".join(paths) + "\n", encoding="utf-8")
                ctx.config["approved_paths"] = str(dest).replace("\\", "/")
            ctx.trace("authorization", skill=args.skill, host=host, mechanism="flag" if args.i_am_authorized else "interactive")
            try:
                Executor(ctx, skill).campaign_run(skill.plan(), authorized=True, host=host)
            finally:
                ctx.config["explore_authorized"] = False
                ctx.config.pop("approved_paths", None)
                ctx.config.pop("selected_host", None)
                ctx.config.pop("active_skill", None)
                ctx.config["validation"] = previous
                ctx.save()
        elif args.command == "report":
            print(report(ctx, args.format))
        elif args.command == "show":
            board = Blackboard(ctx.root)
            try:
                print("host\tstatus\ttech\tsource\tsignals\tstate")
                for row in board.rows():
                    print("\t".join(row[k] for k in ("host", "status", "tech", "source", "signals", "state")))
            finally:
                board.close()
        return 0
    except KeyboardInterrupt:
        print("Interrupted; partial state preserved.", file=sys.stderr)
        return 130
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError, yaml.YAMLError) as error:
        print("Refused: " + redact(str(error)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
