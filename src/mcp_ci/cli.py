"""Command-line interface for local and CI use."""

from __future__ import annotations

import argparse
import asyncio
import math
from pathlib import Path
import shlex
import sys
from typing import Sequence

from . import __version__
from .baseline import apply_baseline, create_baseline, load_baseline, write_baseline
from .config import (
    Config,
    apply_policy,
    apply_rule_controls,
    apply_suppressions,
    load_config,
)
from .models import Severity
from .probe import run_http_probe, run_stdio_probe
from .reporters import render_json, render_junit, render_sarif, render_text
from .rules import build_report
from .transport import TransportError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-ci",
        description="Black-box MCP stdio and HTTP conformance/security checker.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    check = subparsers.add_parser("check", help="probe one MCP server")
    target = check.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--stdio",
        metavar="COMMAND",
        help="target command; parsed into argv and never run through a shell",
    )
    target.add_argument(
        "--http",
        metavar="URL",
        help="Streamable HTTP endpoint; remote targets must use HTTPS",
    )
    check.add_argument(
        "--protocol-version",
        default="2025-11-25",
        help="requested MCP protocol version (default: %(default)s)",
    )
    check.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="per-request timeout in seconds (default: %(default)s)",
    )
    check.add_argument(
        "--total-timeout",
        type=float,
        default=60.0,
        help="complete probe timeout in seconds (default: %(default)s)",
    )
    check.add_argument(
        "--format",
        choices=("text", "json", "junit", "sarif"),
        default="text",
        help="report format (default: %(default)s)",
    )
    check.add_argument(
        "--output",
        metavar="PATH",
        help="write the report to a UTF-8 file instead of stdout",
    )
    check.add_argument(
        "--config",
        metavar="PATH",
        help="strict JSON policy, rule controls, and finding suppressions",
    )
    baseline = check.add_mutually_exclusive_group()
    baseline.add_argument(
        "--baseline",
        metavar="PATH",
        help="compare discovered metadata with a reviewed sanitized baseline",
    )
    baseline.add_argument(
        "--write-baseline",
        metavar="PATH",
        help="atomically write a sanitized metadata baseline",
    )
    check.add_argument(
        "--fail-on",
        choices=("none", *(severity.value for severity in Severity)),
        default="medium",
        help="minimum finding severity that fails CI (default: %(default)s)",
    )
    return parser


async def _run_check(args: argparse.Namespace) -> int:
    for option, value in (
        ("--timeout", args.timeout),
        ("--total-timeout", args.total_timeout),
    ):
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{option} must be finite and greater than zero")
    threshold = None if args.fail_on == "none" else Severity.parse(args.fail_on)
    config = load_config(args.config) if args.config else Config()
    expected_baseline = load_baseline(args.baseline) if args.baseline else None
    if args.write_baseline and args.output:
        if Path(args.write_baseline).resolve() == Path(args.output).resolve():
            raise ValueError("--write-baseline and --output must use different paths")
    try:
        async with asyncio.timeout(args.total_timeout):
            if args.stdio is not None:
                command = shlex.split(args.stdio)
                if not command:
                    raise ValueError("--stdio command cannot be empty")
                evidence = await run_stdio_probe(
                    command,
                    target=args.stdio,
                    requested_protocol_version=args.protocol_version,
                    timeout=args.timeout,
                )
            else:
                evidence = await run_http_probe(
                    args.http,
                    target=args.http,
                    requested_protocol_version=args.protocol_version,
                    timeout=args.timeout,
                )
    except TimeoutError as error:
        raise TransportError(
            f"probe exceeded total timeout of {args.total_timeout:g} seconds"
        ) from error
    report = build_report(evidence)
    report.observations["limits"] = {
        "request_timeout_seconds": args.timeout,
        "total_timeout_seconds": args.total_timeout,
    }
    apply_policy(report, evidence, config.policy)
    if expected_baseline is not None:
        apply_baseline(report, evidence, expected_baseline)
    elif args.write_baseline:
        write_baseline(args.write_baseline, create_baseline(evidence))
        report.observations["baseline"] = {
            "mode": "write",
            "schema_version": 1,
            "finding_count": 0,
        }
    apply_rule_controls(report, config.rules)
    if args.config:
        apply_suppressions(report, config)
    failed = report.should_fail(threshold)
    renderers = {
        "text": render_text,
        "json": render_json,
        "junit": render_junit,
        "sarif": render_sarif,
    }
    rendered = renderers[args.format](
        report,
        threshold=threshold,
        failed=failed,
    )
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.subcommand == "check":
            return asyncio.run(_run_check(args))
    except (OSError, TransportError, ValueError) as error:
        print(f"mcp-ci: operational error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("mcp-ci: interrupted", file=sys.stderr)
        return 130
    parser.error(f"unsupported subcommand: {args.subcommand}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
