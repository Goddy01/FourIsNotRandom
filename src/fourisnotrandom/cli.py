from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from fourisnotrandom import __version__
from fourisnotrandom.checks import emudhra as emudhra_checks
from fourisnotrandom.checks import gitlab as gitlab_checks
from fourisnotrandom.checks import litellm as litellm_checks
from fourisnotrandom.checks import php as php_checks
from fourisnotrandom.config_loader import (
    compromised_hash_set,
    load_compromised_hashes,
    load_fixed_versions,
    update_hashes_file,
)
from fourisnotrandom.models import Finding, Status
from fourisnotrandom.report import emit, exit_code
from fourisnotrandom.targets import TargetError, assert_not_cidr_or_range, load_targets_file

app = typer.Typer(
    name="fourisnotrandom",
    help=(
        "Detection-only CVE exposure scanner. Read-only fingerprints only - "
        "no exploit payloads. Run only against systems you own or are authorized to assess."
    ),
    no_args_is_help=True,
    add_completion=False,
)

php_app = typer.Typer(help="PHP CVE-2026-109618 / CVE-2026-109619 exposure checks.")
emudhra_app = typer.Typer(help="eMudhra compromised intermediate / toolchain checks.")
litellm_app = typer.Typer(help="LiteLLM malicious 1.107.0 pin checks.")
app.add_typer(php_app, name="php")
app.add_typer(emudhra_app, name="emudhra")
app.add_typer(litellm_app, name="litellm")


def _load_config(config: Optional[Path]) -> dict:
    return load_fixed_versions(config)


def _finish(findings: list[Finding], fmt: str, tool_error: bool = False) -> None:
    emit(findings, fmt=fmt)
    raise typer.Exit(exit_code(findings, tool_error=tool_error))


@app.callback()
def main(
    ctx: typer.Context,
    format: str = typer.Option("table", "--format", help="Output format: table or json"),
    config: Optional[Path] = typer.Option(None, "--config", help="Override fixed_versions.yaml"),
    hashes: Optional[Path] = typer.Option(
        None, "--hashes", help="Override compromised_hashes.json"
    ),
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["format"] = format if format in {"table", "json"} else "table"
    try:
        ctx.obj["config"] = _load_config(config)
        ctx.obj["hashes"] = compromised_hash_set(load_compromised_hashes(hashes) if hashes else None)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.command("version")
def version_cmd() -> None:
    """Print package version."""
    typer.echo(__version__)


@app.command("update-hashes")
def update_hashes(
    from_file: Path = typer.Option(..., "--from", help="JSON file with certificates/hashes"),
    dest: Optional[Path] = typer.Option(None, "--dest", help="Destination path (default: bundled data)"),
) -> None:
    """Refresh compromised eMudhra hash list from an external JSON file."""
    try:
        path = update_hashes_file(from_file, dest)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"Failed to update hashes: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"Updated compromised hashes at {path}")


@php_app.command("local")
def php_local(
    ctx: typer.Context,
    php_bin: str = typer.Option("php", "--php-bin", help="PHP binary path or name"),
) -> None:
    findings = php_checks.check_local(php_bin=php_bin, config=ctx.obj["config"])
    _finish(findings, ctx.obj["format"])


@php_app.command("url")
def php_url(
    ctx: typer.Context,
    url: str = typer.Argument(..., help="Explicit URL to fingerprint (no CIDR)"),
    fingerprint_url: Optional[str] = typer.Option(
        None,
        "--fingerprint-url",
        help="Optional safe banner/fingerprint path or URL (no exploit payloads)",
    ),
) -> None:
    try:
        findings = php_checks.check_remote(
            url, fingerprint_url=fingerprint_url, config=ctx.obj["config"]
        )
    except TargetError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    _finish(findings, ctx.obj["format"])


@php_app.command("fs")
def php_fs(
    ctx: typer.Context,
    path: Path = typer.Argument(..., help="Filesystem path / webroot / Dockerfile dir"),
) -> None:
    findings = php_checks.check_filesystem(path, config=ctx.obj["config"])
    _finish(findings, ctx.obj["format"])


@php_app.command("version")
def php_version(
    ctx: typer.Context,
    version: str = typer.Argument(..., help="Installed PHP version string to evaluate"),
) -> None:
    """Offline evaluation of a PHP version string (no local binary / network)."""
    finding = php_checks.evaluate_php_version(version, php_cfg=_php_cfg(ctx))
    _finish([finding], ctx.obj["format"])


def _php_cfg(ctx: typer.Context) -> dict:
    return ctx.obj["config"].get("php", {})


@emudhra_app.command("host")
def emudhra_host(
    ctx: typer.Context,
    host: str = typer.Argument(..., help="Hostname or URL (single host only)"),
) -> None:
    try:
        findings = emudhra_checks.check_host(host, hashes=ctx.obj["hashes"])
    except TargetError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    _finish(findings, ctx.obj["format"])


@emudhra_app.command("path")
def emudhra_path(
    ctx: typer.Context,
    path: Path = typer.Argument(..., help="Certificate or keystore file/directory"),
) -> None:
    findings = emudhra_checks.check_path(path, hashes=ctx.obj["hashes"])
    _finish(findings, ctx.obj["format"])


@emudhra_app.command("docker")
def emudhra_docker(
    ctx: typer.Context,
    image: str = typer.Argument(..., help="Docker image name or Dockerfile path"),
) -> None:
    findings = emudhra_checks.check_docker(image, hashes=ctx.obj["hashes"])
    _finish(findings, ctx.obj["format"])


@emudhra_app.command("toolchains")
def emudhra_toolchains(ctx: typer.Context) -> None:
    findings = emudhra_checks.check_toolchains(config=ctx.obj["config"])
    _finish(findings, ctx.obj["format"])


@emudhra_app.command("certifi-version")
def emudhra_certifi_version(
    ctx: typer.Context,
    version: str = typer.Argument(..., help="certifi version string to evaluate"),
) -> None:
    """Offline evaluation of a certifi version (e.g. 2026.10.17)."""
    finding = emudhra_checks.evaluate_certifi_version(version, config=ctx.obj["config"])
    _finish([finding], ctx.obj["format"])


@app.command("gitlab")
def gitlab_cmd(
    ctx: typer.Context,
    url: Optional[str] = typer.Option(None, "--url", help="Explicit GitLab instance URL"),
    version: Optional[str] = typer.Option(
        None,
        "--version",
        help="Offline: evaluate this GitLab version string (no network)",
    ),
) -> None:
    if version and url:
        typer.echo("Pass either --url or --version, not both.", err=True)
        raise typer.Exit(2)
    if version:
        findings = gitlab_checks.evaluate_gitlab_version(version, config=ctx.obj["config"])
        _finish(findings, ctx.obj["format"])
        return
    if not url:
        typer.echo("Provide --url or --version.", err=True)
        raise typer.Exit(2)
    try:
        findings = gitlab_checks.check_gitlab(url, config=ctx.obj["config"])
    except TargetError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    _finish(findings, ctx.obj["format"])


@litellm_app.command("env")
def litellm_env(ctx: typer.Context) -> None:
    findings = litellm_checks.check_env(config=ctx.obj["config"])
    _finish(findings, ctx.obj["format"])


@litellm_app.command("path")
def litellm_path(
    ctx: typer.Context,
    path: Path = typer.Argument(..., help="Project path with requirements/lockfiles"),
) -> None:
    findings = litellm_checks.check_path(path, config=ctx.obj["config"])
    _finish(findings, ctx.obj["format"])


@litellm_app.command("docker")
def litellm_docker(
    ctx: typer.Context,
    image: str = typer.Argument(..., help="Explicit Docker image name"),
) -> None:
    findings = litellm_checks.check_docker(image, config=ctx.obj["config"])
    _finish(findings, ctx.obj["format"])


@app.command("all")
def all_cmd(
    ctx: typer.Context,
    targets_file: Path = typer.Option(
        ..., "--targets-file", help="File with explicit hosts/URLs/paths (no CIDR)"
    ),
) -> None:
    """Run applicable checks against an explicit target list only."""
    try:
        targets = load_targets_file(targets_file)
    except TargetError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc

    findings: list[Finding] = []
    cfg = ctx.obj["config"]
    hashes = ctx.obj["hashes"]

    for t in targets:
        try:
            assert_not_cidr_or_range(t)
        except TargetError as exc:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    cve="N/A",
                    target=t,
                    installed="?",
                    fixed="",
                    remediation=str(exc),
                )
            )
            continue

        p = Path(t)
        if p.exists():
            findings.extend(php_checks.check_filesystem(p, config=cfg))
            findings.extend(emudhra_checks.check_path(p, hashes=hashes))
            findings.extend(litellm_checks.check_path(p, config=cfg))
            continue

        if t.startswith("http://") or t.startswith("https://") or "." in t:
            # Heuristic: gitlab in hostname → gitlab check; else php remote + emudhra TLS
            if "gitlab" in t.lower():
                findings.extend(gitlab_checks.check_gitlab(t, config=cfg))
            else:
                findings.extend(php_checks.check_remote(t, config=cfg))
                findings.extend(emudhra_checks.check_host(t, hashes=hashes))
        else:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    cve="N/A",
                    target=t,
                    installed="?",
                    fixed="",
                    remediation="Unrecognized target; use an existing path, URL, or hostname.",
                )
            )

    _finish(findings, ctx.obj["format"])


# Typer object is the console script entry point.
# setuptools expects a callable; Typer apps are callable.
def run() -> None:
    # Disable Click's Windows argv glob expansion so a literal "*" is rejected
    # by TargetError instead of being expanded into a directory sweep.
    app(windows_expand_args=False)


if __name__ == "__main__":
    run()
