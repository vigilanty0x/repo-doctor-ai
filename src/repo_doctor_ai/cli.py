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
from .config import Config, ConfigError, load_config
from .journal import AuditJournal, JournalError
from .models import Report, SEVERITY_ORDER
from .rules import RULE_HELP
from .scanner import Scanner


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-doctor", description="Audit a local repository and retain evidence for every finding.")
    parser.add_argument("--version", action="version", version=f"repo-doctor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="write a bounded example configuration")
    init.add_argument("path", nargs="?", default="repo-doctor.json")
    init.add_argument("--force", action="store_true")

    scan = sub.add_parser("scan", help="scan a local repository")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--config")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output")
    scan.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high")
    scan.add_argument("--journal")
    scan.add_argument("--run-id")

    replay = sub.add_parser("replay", help="validate an append-only audit journal")
    replay.add_argument("journal")
    replay.add_argument("--json", action="store_true", dest="json_output")

    explain = sub.add_parser("explain", help="explain a stable diagnostic code")
    explain.add_argument("code")

    sub.add_parser("rules", help="list stable rule codes")
    return parser


def _text(report: Report) -> str:
    payload = report.as_dict()
    lines = [
        f"Repo Doctor: {payload['state']} / {payload['result']} ({payload['reason_code']})",
        f"Scanned {payload['metrics']['files_scanned']} text files; {payload['summary']['total']} findings.",
    ]
    for finding in payload["findings"]:
        location = finding["location"]
        where = ""
        if location:
            where = f" {location['path']}"
            if location["line"]:
                where += f":{location['line']}"
        lines.append(f"[{finding['severity'].upper()}] {finding['code']}{where} — {finding['message']}")
        lines.append(f"  Evidence: {finding['evidence'] or 'none'}")
        lines.append(f"  Fix: {finding['remediation']}")
    return "\n".join(lines) + "\n"


def _sarif(report: Report) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    levels = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in report.findings:
        rules.setdefault(
            finding.code,
            {
                "id": finding.code,
                "shortDescription": {"text": RULE_HELP.get(finding.code, finding.message)},
                "help": {"text": finding.remediation},
            },
        )
        result: dict[str, Any] = {
            "ruleId": finding.code,
            "level": levels[finding.severity],
            "message": {"text": finding.message},
            "fingerprints": {"repoDoctor": finding.fingerprint},
            "properties": {"classification": finding.classification, "evidence": finding.evidence},
        }
        if finding.path:
            region = {"startLine": finding.line} if finding.line else None
            location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": finding.path}}}
            if region:
                location["physicalLocation"]["region"] = region
            result["locations"] = [location]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Repo Doctor AI", "version": __version__, "rules": list(rules.values())}}, "results": results}],
    }


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


def _serialize(report: Report, output_format: str) -> str:
    if output_format == "text":
        return _text(report)
    payload = report.as_dict() if output_format == "json" else _sarif(report)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            path = Path(args.path)
            if path.exists() and not args.force:
                raise ConfigError(f"refusing to overwrite existing file: {path}")
            _atomic_write(path, json.dumps(Config().as_dict(), indent=2) + "\n")
            print(f"wrote {path}")
            return 0

        if args.command == "rules":
            for code in sorted(RULE_HELP):
                print(f"{code}\t{RULE_HELP[code]}")
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
                print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            else:
                print(f"journal is valid ({len(events)} events)")
            return 0

        config = load_config(args.config)
        if bool(args.journal) != bool(args.run_id):
            raise ConfigError("--journal and --run-id must be provided together")
        report = Scanner(config).scan(args.path)
        if args.journal:
            AuditJournal(args.journal).append(args.run_id, report.as_dict())
        rendered = _serialize(report, args.format)
        if args.output:
            _atomic_write(Path(args.output), rendered)
        else:
            print(rendered, end="")

        if report.status != "verified":
            return 2
        if args.fail_on != "none" and report.reaches(args.fail_on):
            return 1
        return 0
    except (ConfigError, JournalError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

