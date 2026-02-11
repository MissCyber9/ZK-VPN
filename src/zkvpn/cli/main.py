"""ZK-VPN CLI main entry point.

This module provides the main CLI interface using Click.
All commands are organized in groups for better usability.
"""

import asyncio
import sys
import os
import functools
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
    connect, disconnect, status, proofs, config,
    peer, test, version, help
)
from zkvpn.cli.utils import console, print_error


def async_command(func):
    """Decorator to run async commands synchronously."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return asyncio.run(func(*args, **kwargs))
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/yellow]")
            return 130
        except Exception as e:
            print_error(f"Command failed: {e}")
            return 1
    return wrapper


@click.group()
@click.version_option(version="0.1.0", prog_name="zkvpn")
@click.option('--debug', is_flag=True, help='Enable debug logging')
def cli(debug):
    """ZK-VPN - Zero-Knowledge VPN with privacy guarantees.
    
    A lightweight VPN that uses zero-knowledge proofs to ensure
    no logs are kept. All proofs are generated and verified in RAM,
    never written to disk.
    """
    if debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        console.print("[dim]Debug mode enabled[/dim]")


# Add commands with async wrapper
cli.add_command(async_command(connect))
cli.add_command(async_command(disconnect))
cli.add_command(async_command(status))
cli.add_command(proofs)  # Group commands don't need async wrapper
cli.add_command(config)   # Group commands don't need async wrapper
cli.add_command(peer)     # Group commands don't need async wrapper
cli.add_command(test)     # Group commands don't need async wrapper
cli.add_command(version)
cli.add_command(help)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
