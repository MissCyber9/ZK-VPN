"""``zkvpn zk`` (toolchain, keys, ceremony) and ``zkvpn doctor``."""

from pathlib import Path

import click

from zkvpn import diagnostics
from zkvpn.cli.utils import console, print_error, print_info, print_success, print_warning
from zkvpn.zk import ceremony as ceremony_mod
from zkvpn.zk import toolchain


def _guard(func):
    """Turn toolchain errors into a clean message and a non-zero exit code."""
    import functools

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except toolchain.ToolchainError as e:
            print_error(str(e))
            raise SystemExit(1)
    return wrapper


@click.group(name="zk")
def zk():
    """ZK toolchain: build the proving keys, run the trusted-setup ceremony."""


@zk.command(name="setup")
@click.option("--dir", "zk_dir", type=click.Path(file_okay=False), help="Workspace (default: per-user data dir)")
@click.option("--ptau-power", default=12, show_default=True, help="Powers-of-tau size (2^N constraints)")
@_guard
def zk_setup(zk_dir, ptau_power):
    """Build the circuit and DEVELOPMENT keys (single-party setup)."""
    print_info("Installing the pinned toolchain and building the circuit (about a minute)...")
    build = toolchain.build_dev_keys(Path(zk_dir) if zk_dir else None, ptau_power)
    print_success(f"Keys built in {build}")
    print_warning("Single-party setup: anyone who kept its entropy can forge proofs. "
                  "For production run `zkvpn zk ceremony`.")


@zk.command(name="status")
def zk_status():
    """Say whether the proving keys are present."""
    ws = toolchain.default_workspace()
    if toolchain.is_built():
        marker = ws / "build" / "CEREMONY.txt"
        kind = "multi-party ceremony" if marker.exists() else "single-party DEVELOPMENT setup"
        print_success(f"Keys present in {ws / 'build'} ({kind})")
    else:
        print_error(f"No keys in {ws / 'build'}. Run: zkvpn zk setup")
        raise SystemExit(1)


@zk.group(name="ceremony")
def ceremony():
    """Multi-party trusted setup (see `zkvpn zk ceremony --help` and the README)."""


_dir_opt = click.option("--ceremony-dir", type=click.Path(file_okay=False), default="ceremony",
                        show_default=True)


@ceremony.command(name="init")
@click.argument("ptau", required=False, type=click.Path(dir_okay=False))
@click.option("--dev", is_flag=True, help="Local single-party phase 1 (tests only!)")
@_dir_opt
@_guard
def ceremony_init(ptau, dev, ceremony_dir):
    """Start: verify a PUBLIC phase-1 file and create the first key."""
    if dev:
        print_warning("--dev builds a SINGLE-PARTY phase 1: tests only, never production.")
    out = ceremony_mod.init(Path(ceremony_dir), Path(ptau) if ptau else None, dev)
    print_success(f"Initialised {out}. Send zkey_0000.zkey to the first participant.")


@ceremony.command(name="contribute")
@click.argument("zkey_in", type=click.Path(dir_okay=False))
@click.argument("zkey_out", type=click.Path(dir_okay=False))
@click.argument("name")
@_guard
def ceremony_contribute(zkey_in, zkey_out, name):
    """Add YOUR entropy. Send only ZKEY_OUT to the next participant; keep nothing."""
    digest = ceremony_mod.contribute(Path(zkey_in), Path(zkey_out), name)
    print_success(f"Contribution done. Send ONLY {zkey_out} to the next participant.")
    console.print(f"Output sha256 (publish it): {digest}")


@ceremony.command(name="beacon")
@click.argument("zkey_in", type=click.Path(dir_okay=False))
@click.argument("zkey_out", type=click.Path(dir_okay=False))
@click.argument("public_hex")
@_guard
def ceremony_beacon(zkey_in, zkey_out, public_hex):
    """Final step: apply a public random beacon (e.g. a later Bitcoin block hash)."""
    console.print(f"Beacon applied. sha256: {ceremony_mod.beacon(Path(zkey_in), Path(zkey_out), public_hex)}")


@ceremony.command(name="verify")
@click.argument("zkey", type=click.Path(dir_okay=False))
@_dir_opt
@_guard
def ceremony_verify(zkey, ceremony_dir):
    """Recompile the circuit and verify the WHOLE contribution chain."""
    console.print(ceremony_mod.verify(Path(zkey), Path(ceremony_dir)))
    print_success("OK: the key is the product of a valid ceremony for this circuit.")


@ceremony.command(name="finalize")
@click.argument("zkey", type=click.Path(dir_okay=False))
@_dir_opt
@_guard
def ceremony_finalize(zkey, ceremony_dir):
    """Verify, then install the ceremony keys for use."""
    build = ceremony_mod.finalize(Path(zkey), Path(ceremony_dir))
    print_success(f"Ceremony keys installed in {build}")


@click.command(name="doctor")
def doctor():
    """Check that this machine can run ZK-VPN (any operating system)."""
    marks = {diagnostics.OK: "[green]✓[/green]", diagnostics.WARN: "[yellow]![/yellow]",
             diagnostics.FAIL: "[red]✗[/red]"}
    failed = False
    for check in diagnostics.run_checks():
        console.print(f" {marks[check.status]} [bold]{check.name}[/bold]: {check.detail}")
        if check.hint:
            console.print(f"     [dim]{check.hint}[/dim]")
        failed |= check.status == diagnostics.FAIL
    raise SystemExit(1 if failed else 0)
