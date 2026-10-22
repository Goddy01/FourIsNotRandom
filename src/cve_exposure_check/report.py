from __future__ import annotations

import json
import sys
from typing import Iterable, Sequence, TextIO

from rich.console import Console
from rich.table import Table

from cve_exposure_check.models import Finding, Status


def emit_table(findings: Sequence[Finding], file: TextIO | None = None) -> None:
    console = Console(file=file or sys.stdout)
    table = Table(title="CVE Exposure Check")
    table.add_column("Status", style="bold")
    table.add_column("CVE")
    table.add_column("Target")
    table.add_column("Installed")
    table.add_column("Fixed / Expected")
    table.add_column("Detection")
    table.add_column("Remediation")

    for f in findings:
        style = {
            Status.PASS: "green",
            Status.FAIL: "red",
            Status.UNKNOWN: "yellow",
        }.get(f.status, "")
        table.add_row(
            f.status.value,
            f.cve,
            f.target,
            f.installed,
            f.fixed,
            f.detection_method or "-",
            f.remediation,
            style=style,
        )
    console.print(table)


def emit_json(findings: Sequence[Finding], file: TextIO | None = None) -> None:
    payload = [f.to_dict() for f in findings]
    print(json.dumps(payload, indent=2), file=file or sys.stdout)


def emit(findings: Sequence[Finding], fmt: str = "table", file: TextIO | None = None) -> None:
    if fmt == "json":
        emit_json(findings, file=file)
    else:
        emit_table(findings, file=file)


def exit_code(findings: Iterable[Finding], tool_error: bool = False) -> int:
    if tool_error:
        return 2
    findings = list(findings)
    if any(f.status == Status.FAIL for f in findings):
        return 1
    return 0
