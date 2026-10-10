"""ZK-VPN CLI main entry point.

This module provides the main CLI interface using Click.
All commands are organized in groups for better usability.
"""

import asyncio
import sys
import os
import functools
import inspect
from pathlib import Path

import click
from dotenv import load_dotenv

# Load environment variables
env_file = Path("/etc/zkvpn/.env")
if env_file.exists():
    load_dotenv(env_file)
else:
    load_dotenv()  # Try local .env

from zkvpn.cli.commands import (
    connect, disconnect, serve, status, identity, config,
    peer, test, version, help
)
from zkvpn.cli.utils import console, print_error


def _run_sync(callback):
    """Wrap a coroutine function so click can call it synchronously."""
    @functools.wraps(callback)
    def wrapper(*args, **kwargs):
        try:
            return asyncio.run(callback(*args, **kwargs))
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/yellow]")
            raise SystemExit(130)
        except (click.ClickException, click.exceptions.Exit, SystemExit):
            raise
        except Exception as e:
            print_error(f"Command failed: {e}")
            raise SystemExit(1)
    return wrapper


def async_command(cmd):
    """Make every coroutine callback of a click command (or group tree) synchronous."""
    if inspect.iscoroutinefunction(cmd.callback):
        cmd.callback = _run_sync(cmd.callback)
    for sub in getattr(cmd, "commands", {}).values():
        async_command(sub)
    return cmd


@click.group()
@click.version_option(version="0.1.0", prog_name="zkvpn")
@click.option('--debug', is_flag=True, help='Enable debug logging')
def cli(debug):
    """ZK-VPN - Zero-Knowledge VPN with privacy guarantees.
    
    A WireGuard-based VPN prototype that authenticates clients with
    zero-knowledge (Groth16) session proofs. It does not, and cannot,
    prove that a server keeps no logs.
    """
    if debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        console.print("[dim]Debug mode enabled[/dim]")


# Add commands with async wrapper
cli.add_command(async_command(connect))
cli.add_command(async_command(disconnect))
cli.add_command(async_command(serve))
cli.add_command(async_command(status))
cli.add_command(async_command(identity))
cli.add_command(async_command(config))
cli.add_command(async_command(peer))
cli.add_command(async_command(test))
cli.add_command(version)
cli.add_command(help)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
