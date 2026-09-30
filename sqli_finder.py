#!/usr/bin/env python3
"""Conservative error-based SQL injection detector for authorized targets."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests


VERSION = "2.0.0"
MAX_BODY_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 10.0
DEFAULT_DELAY = 0.75

ERROR_PATTERNS = {
    "mysql": (
        r"you have an error in your sql syntax",
        r"warning.*mysql_",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysqli?::",
    ),
    "postgresql": (
        r"postgresql.*error",
        r"warning.*pg_",
        r"pg_query\(",
        r"unterminated quoted string",
    ),
    "sql_server": (
        r"microsoft sql server",
        r"sql server.*driver",
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
    ),
    "oracle": (
        r"ora-\d{5}",
        r"oracle.*driver",
        r"quoted string not properly terminated",
    ),
    "sqlite": (
        r"sqlite.*error",
        r"sqlite3\.operationalerror",
        r"unrecognized token",
    ),
    "generic_odbc": (
        r"odbc sql",
        r"sqlstate\[[0-9a-z]+\]",
    ),
}


@dataclass
class ResponseSnapshot:
    status: int
    body: str
    truncated: bool


@dataclass
class Finding:
    url: str
    parameter: str | None
    result: str
    evidence: list[str]
    baseline_status: int | None = None
    probe_status: int | None = None
    baseline_bytes: int | None = None
    probe_bytes: int | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqli-finder",
        description=(
            "Check user-supplied HTTP(S) URLs for conservative, error-based "
            "SQL injection indicators."
        ),
    )
    parser.add_argument(
        "--url",
        action="append",
        default=[],
        help="Authorized target URL. Repeat for multiple URLs.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Text file containing one authorized target URL per line.",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you are authorized to test every supplied target.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT:g}).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY:g}).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("sqli_results.jsonl"),
        help="JSON Lines result file (default: sqli_results.jsonl).",
    )
    parser.add_argument(
        "--no-output",
        action="store_true",
        help="Print results without writing a result file.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value or value.startswith("#"):
        return ""

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("credentials embedded in URLs are not supported")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def load_targets(cli_urls: Iterable[str], input_file: Path | None) -> list[str]:
    raw_targets = list(cli_urls)
    if input_file:
        raw_targets.extend(input_file.read_text(encoding="utf-8").splitlines())

    targets: list[str] = []
    seen: set[str] = set()
    for raw in raw_targets:
        target = normalize_target(raw)
        if target and target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def query_parameters(url: str) -> list[str]:
    parsed = urlsplit(url)
    return list(dict.fromkeys(key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)))


def mutate_parameter(url: str, parameter: str, suffix: str = "'") -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    changed = False
    mutated: list[tuple[str, str]] = []

    for key, value in pairs:
        if key == parameter and not changed:
            mutated.append((key, value + suffix))
            changed = True
        else:
            mutated.append((key, value))

    if not changed:
        raise ValueError(f"parameter not present: {parameter}")

    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated, doseq=True), "")
    )


def sql_error_signatures(body: str) -> set[str]:
    lowered = body.lower()
    matches: set[str] = set()
    for engine, patterns in ERROR_PATTERNS.items():
        if any(re.search(pattern, lowered, flags=re.IGNORECASE | re.DOTALL) for pattern in patterns):
            matches.add(engine)
    return matches


def read_limited_body(response: requests.Response) -> ResponseSnapshot:
    chunks: list[bytes] = []
    total = 0
    truncated = False

    for chunk in response.iter_content(chunk_size=16 * 1024):
        if not chunk:
            continue
        remaining = MAX_BODY_BYTES - total
        if remaining <= 0:
            truncated = True
            break
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if len(chunk) > remaining:
            truncated = True
            break

    raw = b"".join(chunks)
    encoding = response.encoding or "utf-8"
    return ResponseSnapshot(
        status=response.status_code,
        body=raw.decode(encoding, errors="replace"),
        truncated=truncated,
    )


def fetch(session: requests.Session, url: str, timeout: float) -> ResponseSnapshot:
    response = session.get(
        url,
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    try:
        return read_limited_body(response)
    finally:
        response.close()


def classify(baseline: ResponseSnapshot, probe: ResponseSnapshot) -> tuple[str, list[str]]:
    baseline_errors = sql_error_signatures(baseline.body)
    probe_errors = sql_error_signatures(probe.body)
    new_errors = sorted(probe_errors - baseline_errors)

    if new_errors:
        engines = ", ".join(new_errors)
        return "likely", [f"new database error signature after probe: {engines}"]

    evidence: list[str] = []
    if baseline.status < 500 <= probe.status:
        evidence.append(
            f"HTTP status changed from {baseline.status} to {probe.status}"
        )

    base_len = len(baseline.body.encode("utf-8", errors="ignore"))
    probe_len = len(probe.body.encode("utf-8", errors="ignore"))
    denominator = max(base_len, 1)
    relative_change = abs(probe_len - base_len) / denominator

    if evidence and relative_change >= 0.25:
        evidence.append(f"response size changed by {relative_change:.0%}")
        evidence.append("behavioral change is not proof of SQL injection")
        return "possible", evidence

    return "not_detected", []


def scan_target(
    session: requests.Session,
    url: str,
    timeout: float,
    delay: float,
) -> list[Finding]:
    parameters = query_parameters(url)
    if not parameters:
        return [
            Finding(
                url=url,
                parameter=None,
                result="skipped",
                evidence=["URL has no query parameters to test"],
            )
        ]

    try:
        baseline = fetch(session, url, timeout)
    except requests.RequestException as exc:
        return [
            Finding(
                url=url,
                parameter=None,
                result="error",
                evidence=[f"baseline request failed: {exc}"],
            )
        ]

    findings: list[Finding] = []
    for parameter in parameters:
        if delay > 0:
            time.sleep(delay)

        probe_url = mutate_parameter(url, parameter)
        try:
            probe = fetch(session, probe_url, timeout)
            result, evidence = classify(baseline, probe)
            findings.append(
                Finding(
                    url=url,
                    parameter=parameter,
                    result=result,
                    evidence=evidence,
                    baseline_status=baseline.status,
                    probe_status=probe.status,
                    baseline_bytes=len(baseline.body.encode("utf-8", errors="ignore")),
                    probe_bytes=len(probe.body.encode("utf-8", errors="ignore")),
                )
            )
        except requests.RequestException as exc:
            findings.append(
                Finding(
                    url=url,
                    parameter=parameter,
                    result="error",
                    evidence=[f"probe request failed: {exc}"],
                    baseline_status=baseline.status,
                )
            )

    return findings


def print_finding(finding: Finding) -> None:
    label = {
        "likely": "LIKELY",
        "possible": "POSSIBLE",
        "not_detected": "CLEAR",
        "skipped": "SKIP",
        "error": "ERROR",
    }.get(finding.result, finding.result.upper())

    parameter = f" parameter={finding.parameter}" if finding.parameter else ""
    print(f"[{label}] {finding.url}{parameter}")
    for item in finding.evidence:
        print(f"        {item}")


def append_result(path: Path, finding: Finding) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(finding), ensure_ascii=False) + "\n")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.authorized:
        parser.error(
            "--authorized is required. Only test systems you own or have explicit permission to assess."
        )
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.delay < 0:
        parser.error("--delay cannot be negative")

    try:
        targets = load_targets(args.url, args.input)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if not targets:
        parser.error("provide at least one target with --url or --input")

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                f"SQLi-Finder/{VERSION} authorized-security-test "
                "(https://github.com/emillvl/SQLi-finder)"
            ),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
        }
    )

    if not args.no_output:
        args.output.parent.mkdir(parents=True, exist_ok=True)

    summary = {"likely": 0, "possible": 0, "not_detected": 0, "skipped": 0, "error": 0}

    try:
        for target_index, target in enumerate(targets):
            if target_index and args.delay > 0:
                time.sleep(args.delay)

            for finding in scan_target(session, target, args.timeout, args.delay):
                summary[finding.result] = summary.get(finding.result, 0) + 1
                print_finding(finding)
                if not args.no_output:
                    append_result(args.output, finding)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.", file=sys.stderr)
        return 130
    finally:
        session.close()

    print(
        "\nSummary: "
        + ", ".join(f"{key}={value}" for key, value in summary.items() if value)
    )
    if not args.no_output:
        print(f"Results: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
