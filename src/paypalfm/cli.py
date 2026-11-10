"""
pfm — PayPal Fraud Monitor CLI

Commands:
  pfm guard setup     Install npm wrapper (blocks fraudulent PayPal packages at install time)
  pfm audit           Audit current project's package.json / package-lock.json
  pfm scan <pkg>      Scan a specific package name@version on demand
  pfm monitor         Run the live feed monitor (prints flags to stdout)
"""
import asyncio
import json
import os
import sys

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="PayPal Package Fraud Monitor")
console = Console()

NPM_REGISTRY = "https://registry.npmjs.org"


def _fetch_package(name: str, version: str = "latest") -> tuple[dict, bytes | None]:
    with httpx.Client(timeout=20) as client:
        meta = client.get(f"{NPM_REGISTRY}/{name}/{version}").json()
        tarball_url = meta.get("dist", {}).get("tarball")
        tarball = client.get(tarball_url).content if tarball_url else None
    return meta, tarball


@app.command()
def scan(package: str = typer.Argument(..., help="package@version or just package name")):
    """Scan a specific npm package for PayPal fraud patterns."""
    from paypalfm.triage import triage
    from paypalfm.investigate import investigate

    name, _, version = package.partition("@")
    version = version or "latest"

    console.print(f"[bold]Fetching[/bold] {name}@{version}…")
    pkg, tarball = _fetch_package(name, version)
    actual_version = pkg.get("version", version)

    console.print("[bold]Triaging…[/bold]")
    result = triage(name, actual_version, pkg, tarball)

    console.print(f"Triage score: [yellow]{result.score:.2f}[/yellow]")
    for r in result.reasons:
        color = "red" if r.startswith("critical") else "yellow"
        console.print(f"  [{color}]{r}[/{color}]")

    if result.send_to_model:
        console.print("[bold]Sending to Claude…[/bold]")
        verdict = investigate(name, actual_version, pkg, tarball)
        _print_verdict(verdict)

        if verdict.malicious and verdict.confidence >= 0.7:
            console.print("\n[bold red]Running PayPal Sandbox verification…[/bold red]")
            from paypalfm.paypal_verify import verify
            sandbox = verify(name, actual_version)
            _print_sandbox(sandbox)
    else:
        console.print("[green]Clean — below model threshold.[/green]")


@app.command()
def audit(path: str = typer.Argument(".", help="Path to project root")):
    """Audit a project's package.json for fraudulent PayPal dependencies."""
    import pathlib
    pkg_json = pathlib.Path(path) / "package.json"
    if not pkg_json.exists():
        console.print("[red]No package.json found.[/red]")
        raise typer.Exit(1)

    data = json.loads(pkg_json.read_text())
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    paypal_deps = {k: v for k, v in deps.items()
                   if any(kw in k.lower() for kw in ("paypal", "braintree", "venmo"))}

    if not paypal_deps:
        console.print("[green]No PayPal-related dependencies found.[/green]")
        return

    console.print(f"Found [bold]{len(paypal_deps)}[/bold] PayPal-related dependencies. Scanning…")
    for name, ver_spec in paypal_deps.items():
        version = ver_spec.lstrip("^~>=<") or "latest"
        typer.echo(f"\n→ {name}@{version}")
        scan(f"{name}@{version}")


@app.command()
def monitor():
    """Run the live npm feed monitor."""
    from paypalfm.monitor import run_forever
    from paypalfm.triage import triage
    from paypalfm.investigate import investigate
    from paypalfm import ledger

    async def on_package(name, version, pkg):
        result = triage(name, version, pkg)
        if not result.send_to_model:
            return
        verdict = investigate(name, version, pkg)
        if verdict.label in ("suspicious", "malicious"):
            ledger.record(name, version, verdict.label, verdict.model_dump_json())
            console.print(
                f"[red]FLAG[/red] {name}@{version} "
                f"confidence={verdict.confidence:.2f} label={verdict.label}\n"
                f"  {verdict.summary}"
            )

    console.print("[bold green]PayPal Fraud Monitor running…[/bold green]")
    asyncio.run(run_forever(on_package))


def _print_verdict(v):
    color = "red" if v.malicious else "yellow" if v.label == "suspicious" else "green"
    console.print(f"\n[bold {color}]Verdict: {v.label.upper()}[/bold {color}] "
                  f"(confidence={v.confidence:.2f})")
    console.print(f"  {v.summary}")
    if v.persuasion_detected:
        console.print("  [red bold]⚠ Persuasion detected — package text argued it was safe[/red bold]")
    if v.cited_lines:
        console.print("  Cited evidence:")
        for c in v.cited_lines[:5]:
            console.print(f"    [{c.ref}] {c.file}: {c.line[:80]}")


def _print_sandbox(s):
    console.print("\n[bold]Sandbox Results:[/bold]")
    console.print(f"  Credential exfiltrated: {'[red]YES[/red]' if s.credential_exfiltrated else '[green]no[/green]'}")
    console.print(f"  Merchant ID swapped:    {'[red]YES[/red]' if s.merchant_id_swapped else '[green]no[/green]'}")
    console.print(f"  Confirmed fraud:        {'[red bold]YES[/red bold]' if s.confirmed_fraud else '[green]no[/green]'}")
    if s.captured_requests:
        console.print("  Outbound requests:")
        for req in s.captured_requests[:5]:
            console.print(f"    {req}")


if __name__ == "__main__":
    app()
