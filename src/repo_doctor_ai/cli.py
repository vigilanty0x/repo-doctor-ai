"""Repo Doctor command line interface."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Sequence

from . import __version__
from .baseline import BaselineError, baseline_from_report, load_baseline
from .config import Config, ConfigError, load_config
from .diffing import ReportDataError, diff_reports, load_report, render_diff_markdown
from .journal import AuditJournal, JournalError
from .planning import build_plan, render_plan_markdown
from .registry import RegistryError
from .reporting import serialize
from .rules import RULE_HELP, build_default_registry
from .sanitization import safe_output_text
from .sbom import SbomError, build_sbom
from .scanner import Scanner


class DoctorArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ConfigError(f"invalid command arguments: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = DoctorArgumentParser(
        prog="repo-doctor",
        description="Audit a local repository and retain bounded evidence for every finding.",
    )
    parser.add_argument("--version", action="version", version=f"repo-doctor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="write a bounded example configuration")
    init.add_argument("path", nargs="?", default="repo-doctor.json")
    init.add_argument("--force", action="store_true")

    scan = sub.add_parser("scan", help="scan a local repository")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--config")
    scan.add_argument("--baseline", help="reviewed suppression baseline JSON")
    scan.add_argument("--format", choices=("text", "json", "sarif", "markdown", "html"), default="text")
    scan.add_argument("--output")
    scan.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high")
    scan.add_argument("--journal")
    scan.add_argument("--run-id")

    baseline = sub.add_parser("baseline", help="create a reviewed suppression baseline from a JSON report")
    baseline.add_argument("report")
    baseline.add_argument("--output", default="repo-doctor-baseline.json")
    baseline.add_argument("--reason", required=True)
    baseline.add_argument("--expires", help="optional YYYY-MM-DD expiry")
    baseline.add_argument("--force", action="store_true")

    diff = sub.add_parser("diff", help="compare two JSON reports by stable fingerprint")
    diff.add_argument("base")
    diff.add_argument("current")
    diff.add_argument("--format", choices=("json", "markdown"), default="markdown")
    diff.add_argument("--output")
    diff.add_argument("--fail-on-regression", action="store_true")

    plan = sub.add_parser("plan", help="build an evidence-linked remediation plan from a JSON report")
    plan.add_argument("report")
    plan.add_argument("--format", choices=("json", "markdown"), default="markdown")
    plan.add_argument("--output")

    sbom = sub.add_parser("sbom", help="build an offline CycloneDX dependency inventory")
    sbom.add_argument("path", nargs="?", default=".")
    sbom.add_argument("--config")
    sbom.add_argument("--output")

    replay = sub.add_parser("replay", help="validate an append-only audit journal")
    replay.add_argument("journal")
    replay.add_argument("--json", action="store_true", dest="json_output")

    explain = sub.add_parser("explain", help="explain a stable diagnostic code")
    explain.add_argument("code")

    rules = sub.add_parser("rules", help="list stable diagnostics and registered rule plugins")
    rules.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _emit(content: str, output: str | None) -> None:
    if output:
        _atomic_write(Path(output), content)
    else:
        print(content, end="")


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _paths_alias(first: str | Path, second: str | Path) -> bool:
    left, right = Path(first), Path(second)
    try:
        if left.exists() and right.exists() and left.samefile(right):
            return True
    except OSError:
        pass
    try:
        return left.resolve(strict=False) == right.resolve(strict=False)
    except OSError:
        return os.path.abspath(left) == os.path.abspath(right)


def _reject_output_journal_alias(output: str | None, journal: str | None) -> None:
    if not output or not journal:
        return
    journal_path = Path(journal)
    lock_path = journal_path.with_name(f".{journal_path.name}.lock")
    if _paths_alias(output, journal_path) or _paths_alias(output, lock_path):
        raise ConfigError("--output must not alias --journal or its lock file")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "init":
            path = Path(args.path)
            if path.exists() and not args.force:
                raise ConfigError(f"refusing to overwrite existing file: {path}")
            _atomic_write(path, json.dumps(Config().as_dict(), indent=2) + "\n")
            print(f"wrote {safe_output_text(str(path))}")
            return 0

        if args.command == "rules":
            registry = build_default_registry()
            if args.format == "json":
                print(_json({"diagnostics": RULE_HELP, "plugins": registry.as_dict()}), end="")
            else:
                for code in sorted(RULE_HELP):
                    print(f"{code}\t{RULE_HELP[code]}")
                print("\nPlugins:")
                for plugin in registry.plugins:
                    print(f"{plugin.name}\t{plugin.category}\t{plugin.description}")
            return 0

        if args.command == "explain":
            code = args.code.upper()
            if code not in RULE_HELP:
                raise ConfigError(f"unknown rule code: {code}")
            print(f"{code}: {RULE_HELP[code]}")
            return 0

        if args.command == "replay":
            events = AuditJournal(args.journal).replay()
            payload = {
                "valid": True,
                "events": len(events),
                "last_hash": events[-1]["hash"] if events else "0" * 64,
                "states": [event["report"].get("state") for event in events],
            }
            if args.json_output:
                print(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False))
            else:
                print(f"journal is valid ({len(events)} events)")
            return 0

        if args.command == "baseline":
            output = Path(args.output)
            if output.exists() and not args.force:
                raise BaselineError(f"refusing to overwrite existing file: {output}")
            baseline = baseline_from_report(load_report(args.report), reason=args.reason, expires=args.expires)
            _atomic_write(output, _json(baseline.as_dict()))
            print(f"wrote {safe_output_text(str(output))} ({len(baseline.entries)} entries)")
            return 0

        if args.command == "diff":
            result = diff_reports(load_report(args.base), load_report(args.current))
            content = _json(result) if args.format == "json" else render_diff_markdown(result)
            _emit(content, args.output)
            return 1 if args.fail_on_regression and result["regression"] else 0

        if args.command == "plan":
            result = build_plan(load_report(args.report))
            content = _json(result) if args.format == "json" else render_plan_markdown(result)
            _emit(content, args.output)
            return 0

        if args.command == "sbom":
            result = build_sbom(args.path, load_config(args.config))
            _emit(_json(result), args.output)
            return 0

        config = load_config(args.config)
        if bool(args.journal) != bool(args.run_id):
            raise ConfigError("--journal and --run-id must be provided together")
        _reject_output_journal_alias(args.output, args.journal)
        baseline = load_baseline(args.baseline) if args.baseline else None
        report = Scanner(config).scan(args.path, baseline=baseline)
        if args.journal:
            AuditJournal(args.journal).append(args.run_id, report.as_dict())
        _emit(serialize(report, args.format), args.output)

        if report.status != "verified":
            return 2
        if args.fail_on != "none" and report.reaches(args.fail_on):
            return 1
        return 0
    except (
        BaselineError,
        ConfigError,
        JournalError,
        OSError,
        RegistryError,
        ReportDataError,
        SbomError,
        ValueError,
    ) as exc:
        print(f"error: {safe_output_text(str(exc))}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
