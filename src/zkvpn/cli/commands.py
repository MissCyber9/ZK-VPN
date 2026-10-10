"""ZK-VPN CLI commands.

All commands are organized by functionality:
- connect/disconnect: Tunnel management
- status: System status
- identity: ZK identity management
- config: Configuration
- test: Diagnostics
- peer: Peer management
"""

import asyncio
import os
import sys
import json
from typing import Optional, List, Dict, Any
from pathlib import Path

import click
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from zkvpn.core.config import settings, get_settings
from zkvpn.core.memory import session_manager, key_store
from zkvpn.zk import (SessionProver, SessionVerifier, generate_identity, load_identity,
                      public_identity, save_identity)
from zkvpn.protocol.tunnel import tunnel, TunnelConfig
from zkvpn.protocol.wireguard import wg_interface, WireGuardPeer
from zkvpn.protocol.dns import dns_protector
from zkvpn.cli.utils import (
    console, print_success, print_error, print_warning, print_info,
    print_table, print_json, format_bytes, format_duration,
    format_timestamp, run_with_spinner, generate_qr_code,
    copy_to_clipboard, StatusColors
)

# ============================================================================
# CONNECT / DISCONNECT COMMANDS
# ============================================================================

@click.command()
@click.argument('peer', required=False)
@click.option('--endpoint', '-e', help='Server endpoint (ip:port)')
@click.option('--pubkey', '-k', help="Server's public key")
@click.option('--config', '-c', help='Config file path')
@click.option('--identity', '-i', 'identity_file', type=click.Path(exists=True, dir_okay=False),
              help='ZK identity file (see `zkvpn identity new`); required by servers enforcing proofs')
async def connect(peer: Optional[str], endpoint: Optional[str], 
                  pubkey: Optional[str], config: Optional[str],
                  identity_file: Optional[str]):
    """Connect to a VPN peer or start server.
    
    If no arguments provided, starts in server mode.
    If peer name provided, connects to that peer.
    """
    try:
        if not peer and not endpoint:
            # Server mode
            print_info("Starting ZK-VPN server...")
            
            success = await run_with_spinner(
                tunnel.start_server(),
                "Initializing WireGuard interface..."
            )
            
            if success:
                # Generate QR code for easy client config
                wg_status = await wg_interface.get_status()
                pubkey = wg_status.get('public_key')
                endpoint_ip = await _get_public_ip()
                
                if pubkey and endpoint_ip:
                    qr_data = f"{endpoint_ip}:{settings.port}:{pubkey}"
                    qr = generate_qr_code(qr_data)
                    
                    console.print("\n[bold cyan]📱 Client Configuration QR Code:[/bold cyan]")
                    console.print(qr)
                    
                    print_success(f"Server started on {settings.host}:{settings.port}")
                    print_info(f"Public key: {pubkey}")
                    
                    if copy_to_clipboard(pubkey):
                        print_info("Public key copied to clipboard!")
            else:
                print_error("Failed to start server")
                raise SystemExit(1)
                
        else:
            # Client mode
            if not endpoint:
                print_error("Endpoint required for client mode (--endpoint)")
                raise SystemExit(2)
            
            if not pubkey:
                print_error("Server public key required (--pubkey)")
                raise SystemExit(2)
            
            print_info(f"Connecting to {endpoint}...")
            
            sk = load_identity(identity_file) if identity_file else None
            if sk is None:
                print_warning("No --identity: only works with servers that do not require ZK proofs")
            else:
                print_info("Proving identity to the server (Groth16)...")
            success = await tunnel.connect(endpoint, pubkey, identity_sk=sk)
            
            if success:
                print_success(f"Connected to {endpoint}")
                
                # Test connection
                status = tunnel.get_status()
                console.print(f"[cyan]Interface:[/cyan] {status['interface']}")
                console.print(f"[cyan]IP Address:[/cyan] {status['address']}")
                console.print(f"[cyan]Kill-switch:[/cyan] {'on' if status['killswitch'] else 'off'}")
                
                if settings.dns_protection_enabled:
                    await dns_protector.enable_protection()
                    print_success("DNS leak protection enabled")
            else:
                print_error("Connection failed")
                raise SystemExit(1)
                
    except Exception as e:
        print_error(f"Connection error: {e}")
        raise SystemExit(1)


@click.command()
async def serve():
    """Run the VPN server in the foreground until SIGTERM/SIGINT (systemd entry point)."""
    import signal

    if not await tunnel.start_server():
        print_error("Failed to start server")
        raise SystemExit(1)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    print_info("ZK-VPN server running (Ctrl+C to stop)")
    await stop.wait()
    await tunnel.disconnect()


@click.command()
async def disconnect():
    """Disconnect from VPN."""
    try:
        print_info("Disconnecting...")
        
        if settings.dns_protection_enabled:
            await dns_protector.disable_protection()
        
        # Disconnect tunnel
        success = await tunnel.disconnect()
        
        if success:
            print_success("Disconnected")
        else:
            print_error("Failed to disconnect")
            
    except Exception as e:
        print_error(f"Disconnect error: {e}")


# ============================================================================
# STATUS COMMANDS
# ============================================================================

@click.command()
@click.option('--watch', '-w', is_flag=True, help='Live status updates')
@click.option('--json', '-j', 'json_output', is_flag=True, help='JSON output')
async def status(watch: bool, json_output: bool):
    """Show VPN status."""
    if json_output:
        status_data = {
            "tunnel": tunnel.get_status(),
            "wireguard": await wg_interface.get_status(),
            "dns": {
                "protected": dns_protector.is_protected,
                "servers": await dns_protector._get_current_dns_servers()
            }
        }
        print_json(status_data)
        return
    
    if watch:
        await _watch_status()
    else:
        await _show_status()


async def _show_status():
    """Show single status view."""
    # Tunnel status
    tunnel_status = tunnel.get_status()
    wg_status = await wg_interface.get_status()
    
    # Header
    console.rule("[bold cyan]ZK-VPN Status[/bold cyan]")
    
    # Connection status
    status_symbol = StatusColors.status_symbol(tunnel_status['connected'])
    console.print(f"\n{status_symbol} [bold]Connection:[/bold] ", end="")
    if tunnel_status['connected']:
        console.print("[green]Connected[/green]")
    else:
        console.print("[red]Disconnected[/red]")
    
    # Interface info
    if tunnel_status['connected']:
        table = Table(box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        
        table.add_row("Interface", tunnel_status['interface'])
        table.add_row("Address", tunnel_status['address'])
        table.add_row("Public Key", tunnel_status['public_key'][:32] + "...")
        table.add_row("Listen Port", str(wg_status.get('listen_port', '-')))
        
        console.print(table)
    
    # Peer info
    if wg_status.get('peers'):
        peer_table = Table(title="Peers", box=box.SIMPLE)
        peer_table.add_column("Public Key", style="cyan")
        peer_table.add_column("Endpoint")
        peer_table.add_column("Handshake")
        peer_table.add_column("Transfer")
        
        for peer in wg_status['peers']:
            peer_table.add_row(
                peer['public_key'][:16] + "...",
                peer.get('endpoint') or '-',
                peer.get('latest_handshake') or '-',
                f"↓{format_bytes(peer['transfer']['rx'])} ↑{format_bytes(peer['transfer']['tx'])}"
            )
        
        console.print(peer_table)
    
    # DNS status
    console.print("\n[bold cyan]🌐 DNS Protection[/bold cyan]")
    if dns_protector.is_protected:
        console.print("  Status: [green]Protected[/green]")
        dns_servers = await dns_protector._get_current_dns_servers()
        console.print(f"  DNS Servers: {', '.join(dns_servers)}")
    else:
        console.print("  Status: [red]Not Protected[/red]")


async def _watch_status():
    """Live status updates."""
    with Live(refresh_per_second=2, screen=True) as live:
        while True:
            layout = Layout()
            layout.split_column(
                Layout(name="header"),
                Layout(name="body"),
                Layout(name="footer")
            )
            
            # Header
            header_text = Text("ZK-VPN Live Status", style="bold cyan")
            header_text.append(" (Ctrl+C to exit)", style="dim")
            layout["header"].update(Panel(header_text))
            
            # Body
            tunnel_status = tunnel.get_status()
            wg_status = await wg_interface.get_status()
            
            status_table = Table(box=box.SIMPLE)
            status_table.add_column("Component", style="cyan")
            status_table.add_column("Status", style="bold")
            status_table.add_column("Details")
            
            # Connection
            status_symbol = StatusColors.status_symbol(tunnel_status['connected'])
            status_table.add_row(
                "Connection",
                f"{status_symbol} {'Connected' if tunnel_status['connected'] else 'Disconnected'}",
                f"Interface: {tunnel_status['interface']}"
            )
            
            # WireGuard
            if tunnel_status['connected']:
                status_table.add_row(
                    "WireGuard",
                    f"[green]Active[/green]",
                    f"Port: {wg_status.get('listen_port', '-')}"
                )
            
            # DNS
            status_table.add_row(
                "DNS",
                f"[{'green' if dns_protector.is_protected else 'red'}]{'Protected' if dns_protector.is_protected else 'Leaking'}[/]",
                f"Servers: {', '.join(await dns_protector._get_current_dns_servers())[:30]}..."
            )
            
            layout["body"].update(Panel(status_table, title="System Status"))
            
            # Footer
            if wg_status.get('peers'):
                peer_text = f"Peers: {len(wg_status['peers'])} connected"
                if wg_status['peers']:
                    rx_total = sum(p['transfer']['rx'] for p in wg_status['peers'])
                    tx_total = sum(p['transfer']['tx'] for p in wg_status['peers'])
                    peer_text += f" | ↓{format_bytes(rx_total)} ↑{format_bytes(tx_total)}"
                layout["footer"].update(Panel(peer_text))
            
            live.update(layout)
            await asyncio.sleep(0.5)


# ============================================================================
# IDENTITY COMMANDS
# ============================================================================

@click.group()
def identity():
    """Manage your zero-knowledge identity."""
    pass


@identity.command(name="new")
@click.argument('path', type=click.Path(dir_okay=False))
async def identity_new(path: str):
    """Create a new secret identity at PATH (mode 0600, never overwritten).

    Prints the public identity: give it to the server operator, who lists it in
    ZKVPN_AUTHORIZED_IDENTITIES. Back the file up: it cannot be recovered.
    """
    try:
        sk = save_identity(path)
    except FileExistsError:
        print_error(f"{path} already exists; refusing to overwrite an identity")
        raise SystemExit(1)
    print_success(f"Identity saved to {path} (keep it secret)")
    console.print(f"Public identity: [cyan]{await public_identity(sk)}[/cyan]")


@identity.command(name="show")
@click.argument('path', type=click.Path(exists=True, dir_okay=False))
async def identity_show(path: str):
    """Print the public identity for the secret identity file PATH."""
    console.print(await public_identity(load_identity(path)))


# ============================================================================
# CONFIG COMMANDS
# ============================================================================

@click.group()
def config():
    """Manage configuration."""
    pass


@config.command(name="show")
@click.option('--secrets', is_flag=True, help='Show secrets (dangerous!)')
def config_show(secrets: bool):
    """Show current configuration."""
    settings_dict = settings.model_dump()
    
    if not secrets:
        # Redact secrets
        settings_dict['private_key'] = '***REDACTED***'
    
    print_json(settings_dict)


@config.command(name="set")
@click.argument('key')
@click.argument('value')
def config_set(key: str, value: str):
    """Set a (non-secret) configuration value."""
    from zkvpn.core.config import validate_setting

    try:
        var = validate_setting(key, value)
    except ValueError as e:
        print_error(str(e))
        raise SystemExit(1)

    env_file = Path("/etc/zkvpn/.env")
    env_file.parent.mkdir(parents=True, exist_ok=True)
    lines = env_file.read_text().splitlines() if env_file.exists() else []

    entry = f"{var}={value}"
    for i, line in enumerate(lines):
        if line.startswith(f"{var}="):
            lines[i] = entry
            break
    else:
        lines.append(entry)

    # Atomic write, owner-only permissions (the file may hold secrets)
    tmp = env_file.with_name(env_file.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, env_file)

    print_success(f"Configuration updated: {var}")
    print_warning("Restart service to apply changes")


@config.command(name="reset")
@click.confirmation_option(prompt='Reset all configuration?')
def config_reset():
    """Reset configuration to defaults."""
    env_file = Path("/etc/zkvpn/.env")
    if env_file.exists():
        env_file.unlink()
    
    print_success("Configuration reset to defaults")


@config.command(name="export")
@click.option('--format', '-f', type=click.Choice(['json', 'env', 'qr']), default='env')
def config_export(format: str):
    """Export configuration."""
    settings_dict = settings.model_dump()
    
    if format == 'json':
        print_json(settings_dict)
    
    elif format == 'env':
        for key, value in settings_dict.items():
            if value is not None and key != 'private_key':
                print(f"ZKVPN_{key.upper()}={value}")
    
    elif format == 'qr':
        # Generate QR code with connection info
        wg_status = asyncio.run(wg_interface.get_status())
        pubkey = wg_status.get('public_key')
        if pubkey:
            qr_data = f"{settings.host}:{settings.port}:{pubkey}"
            console.print(generate_qr_code(qr_data))
            print_info(f"Connection string: {qr_data}")


# ============================================================================
# PEER COMMANDS
# ============================================================================

@click.group()
def peer():
    """Manage WireGuard peers."""
    pass


@peer.command(name="add")
@click.argument('public_key')
@click.option('--ip', '-i', help='Assigned IP address')
@click.option('--endpoint', '-e', help='Peer endpoint')
async def peer_add(public_key: str, ip: Optional[str], endpoint: Optional[str]):
    """Add a new peer."""
    if not tunnel._is_connected:
        print_error("Not connected")
        return
    
    try:
        peer = WireGuardPeer(
            public_key=public_key,
            endpoint=endpoint,
            allowed_ips=[f"{ip}/32"] if ip else None
        )
        
        success = await wg_interface.add_peer(peer)
        
        if success:
            print_success(f"Added peer {public_key[:16]}...")
            if ip:
                print_info(f"Assigned IP: {ip}")
        else:
            print_error("Failed to add peer")
            
    except Exception as e:
        print_error(f"Failed to add peer: {e}")


@peer.command(name="remove")
@click.argument('public_key')
async def peer_remove(public_key: str):
    """Remove a peer."""
    success = await wg_interface.remove_peer(public_key)
    
    if success:
        print_success(f"Removed peer {public_key[:16]}...")
    else:
        print_error("Failed to remove peer")


@peer.command(name="list")
async def peer_list():
    """List all peers."""
    status = await wg_interface.get_status()
    
    if not status.get('peers'):
        print_info("No peers connected")
        return
    
    table = Table(title="WireGuard Peers")
    table.add_column("Public Key", style="cyan")
    table.add_column("Endpoint")
    table.add_column("Handshake", justify="right")
    table.add_column("Transfer", justify="right")
    table.add_column("Allowed IPs")
    
    for peer in status['peers']:
        table.add_row(
            peer['public_key'][:16] + "...",
            peer.get('endpoint') or '-',
            peer.get('latest_handshake') or '-',
            f"↓{format_bytes(peer['transfer']['rx'])} ↑{format_bytes(peer['transfer']['tx'])}",
            ", ".join(peer.get('allowed_ips', []))
        )
    
    console.print(table)


# ============================================================================
# TEST COMMANDS
# ============================================================================

@click.group()
def test():
    """Run diagnostics and tests."""
    pass


@test.command(name="leak")
async def test_leak():
    """Test for DNS/IPv6 leaks."""
    print_info("Testing for leaks...")
    
    with console.status("[bold cyan]Running leak tests...") as status:
        results = await dns_protector.test_leaks()
    
    console.print("\n[bold cyan]📊 Leak Test Results[/bold cyan]")
    
    # DNS Leak
    dns_status = "✅ No DNS leak" if not results['dns_leak'] else "❌ DNS LEAK DETECTED"
    dns_color = "green" if not results['dns_leak'] else "red"
    console.print(f"\n  DNS: [{dns_color}]{dns_status}[/{dns_color}]")
    
    if results['dns_servers']:
        console.print(f"  DNS Servers: {', '.join(results['dns_servers'])}")
    
    # IPv6 Leak
    ipv6_status = "✅ IPv6 disabled" if not results['ipv6_leak'] else "❌ IPv6 ENABLED"
    ipv6_color = "green" if not results['ipv6_leak'] else "yellow"
    console.print(f"\n  IPv6: [{ipv6_color}]{ipv6_status}[/{ipv6_color}]")
    
    # Public IP
    if results['public_ip']:
        console.print(f"\n  Public IP: {results['public_ip']}")
    
    # Summary
    if results['dns_leak'] or results['ipv6_leak']:
        print_warning("\nLeaks detected! Run 'zkvpn connect' to enable protection.")
    else:
        print_success("\nNo leaks detected - you are secure!")


@test.command(name="speed")
@click.option('--duration', '-d', default=10, help='Test duration in seconds')
async def test_speed(duration: int):
    """Test VPN speed."""
    if not tunnel._is_connected:
        print_error("Not connected to VPN")
        return
    
    print_info(f"Running speed test for {duration} seconds...")
    
    # Get initial stats
    status = await wg_interface.get_status()
    initial_rx = 0
    initial_tx = 0
    
    for peer in status.get('peers', []):
        initial_rx += peer['transfer']['rx']
        initial_tx += peer['transfer']['tx']
    
    # Wait
    with console.status("[bold cyan]Measuring speed...") as status:
        await asyncio.sleep(duration)
    
    # Get final stats
    status = await wg_interface.get_status()
    final_rx = 0
    final_tx = 0
    
    for peer in status.get('peers', []):
        final_rx += peer['transfer']['rx']
        final_tx += peer['transfer']['tx']
    
    # Calculate speeds
    rx_speed = (final_rx - initial_rx) / duration
    tx_speed = (final_tx - initial_tx) / duration
    
    console.print("\n[bold cyan]📈 Speed Test Results[/bold cyan]")
    console.print(f"\n  Download: {format_bytes(rx_speed)}/s")
    console.print(f"  Upload:   {format_bytes(tx_speed)}/s")
    console.print(f"  Duration: {duration} seconds")


@test.command(name="zk")
async def test_zk():
    """Round-trip a real Groth16 session proof (prove + verify)."""
    print_info("Testing ZK proof system...")
    prover_, verifier_ = SessionProver(), SessionVerifier()
    if not prover_.backend.available:
        print_error("ZK artifacts missing: run scripts/setup_circuits.sh")
        return

    wg_key = "A" * 43 + "="
    nonce = verifier_.issue_challenge()

    loop = asyncio.get_running_loop()
    start = loop.time()
    proof = await prover_.prove(generate_identity(), nonce, wg_key)
    gen_ms = (loop.time() - start) * 1000
    start = loop.time()
    result = await verifier_.verify(proof, nonce, wg_key)
    verify_ms = (loop.time() - start) * 1000

    console.print("\n[bold cyan]🔐 ZK System Test[/bold cyan]")
    console.print(f"  Generation: {gen_ms:.0f}ms")
    console.print(f"  Verification: {verify_ms:.0f}ms")
    console.print(f"  Valid: {'✓' if result.valid else '✗'}")
    if result.valid:
        print_success("ZK system is functioning correctly")
    else:
        print_error(f"ZK system test failed: {result.error}")


@test.command(name="all")
async def test_all():
    """Run all diagnostic tests."""
    console.rule("[bold cyan]ZK-VPN Full Diagnostics[/bold cyan]")
    
    # Connection test
    console.print("\n[bold]1. Connection Status[/bold]")
    if tunnel._is_connected:
        console.print("   ✅ Connected")
    else:
        console.print("   ⚠️  Not connected")
    
    # ZK test
    console.print("\n[bold]2. ZK Proof System[/bold]")
    await test_zk.callback()
    
    # Leak test
    console.print("\n[bold]3. Security Tests[/bold]")
    await test_leak.callback()
    
    # Performance
    if tunnel._is_connected:
        console.print("\n[bold]4. Quick Speed Test[/bold]")
        await test_speed.callback(5)
    
    console.rule("[bold cyan]Diagnostics Complete[/bold cyan]")


# ============================================================================
# UTILITY COMMANDS
# ============================================================================

@click.command()
def version():
    """Show version information."""
    from zkvpn import __version__, __author__
    
    console.print(f"[bold cyan]ZK-VPN[/bold cyan] [green]v{__version__}[/green]")
    console.print(f"Author: {__author__}")
    console.print(f"Python: {sys.version.split()[0]}")
    
    # Check WireGuard
    try:
        import subprocess
        result = subprocess.run(["wg", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"WireGuard: {result.stdout.strip()}")
    except:
        console.print("WireGuard: [red]Not installed[/red]")


@click.command()
@click.argument('command', required=False)
def help(command: Optional[str]):
    """Show help for commands."""
    if command:
        ctx = click.get_current_context()
        ctx.info_name = command
        click.echo(ctx.command.get_help(ctx))
    else:
        click.echo(ctx.parent.get_help())


# ============================================================================
# PRIVATE HELPERS
# ============================================================================

async def _get_public_ip() -> Optional[str]:
    """Get public IP address."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "https://api.ipify.org",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except:
        return None
