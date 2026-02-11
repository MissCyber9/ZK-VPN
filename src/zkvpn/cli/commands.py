"""ZK-VPN CLI commands.

All commands are organized by functionality:
- connect/disconnect: Tunnel management
- status: System status
- proofs: ZK proof management
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
from zkvpn.core.memory import proof_store, session_manager, key_store
from zkvpn.circuits.prover import prover, Proof
from zkvpn.circuits.verifier import verifier
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
async def connect(peer: Optional[str], endpoint: Optional[str], 
                  pubkey: Optional[str], config: Optional[str]):
    """Connect to a VPN peer or start server.
    
    If no arguments provided, starts in server mode.
    If peer name provided, connects to that peer.
    """
    try:
        if not peer and not endpoint:
            # Server mode
            print_info("Starting ZK-VPN server...")
            
            async with run_with_spinner(
                tunnel.start_server(),
                "Initializing WireGuard interface..."
            ):
                success = await tunnel.start_server()
            
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
                
        else:
            # Client mode
            if not endpoint:
                print_error("Endpoint required for client mode (--endpoint)")
                return
            
            if not pubkey:
                print_error("Server public key required (--pubkey)")
                return
            
            print_info(f"Connecting to {endpoint}...")
            
            success = await tunnel.connect(endpoint, pubkey)
            
            if success:
                print_success(f"Connected to {endpoint}")
                
                # Test connection
                status = tunnel.get_status()
                console.print(f"[cyan]Interface:[/cyan] {status['interface']}")
                console.print(f"[cyan]IP Address:[/cyan] {status['address']}")
                console.print(f"[cyan]Proof:[/cyan] {status['last_proof'][:16]}...")
                
                # Enable DNS protection
                await dns_protector.enable_protection()
                print_success("DNS leak protection enabled")
            else:
                print_error("Connection failed")
                
    except Exception as e:
        print_error(f"Connection error: {e}")


@click.command()
async def disconnect():
    """Disconnect from VPN."""
    try:
        print_info("Disconnecting...")
        
        # Disable DNS protection
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
            },
            "zk": {
                "proofs_generated": prover.get_stats()["proofs_generated"],
                "verifications": verifier.get_stats()["verifications"],
                "cached_proofs": len(prover._proof_cache)
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
                peer.get('endpoint', '-'),
                peer.get('latest handshake', '-'),
                f"↓{format_bytes(peer['transfer']['rx'])} ↑{format_bytes(peer['transfer']['tx'])}"
            )
        
        console.print(peer_table)
    
    # ZK Proof status
    console.print("\n[bold cyan]🔐 Zero-Knowledge Proofs[/bold cyan]")
    
    last_proof = tunnel._last_proof
    if last_proof:
        age_color = StatusColors.health_color(last_proof.age_seconds)
        console.print(
            f"  Last Proof: {last_proof.proof_hash[:16]}... "
            f"[{age_color}]({format_duration(last_proof.age_seconds)} old)[/{age_color}]"
        )
        console.print(f"  Valid: [green]✓[/green]" if last_proof.public_inputs.get('is_valid') else "[red]✗[/red]")
    
    # DNS status
    console.print("\n[bold cyan]🌐 DNS Protection[/bold cyan]")
    if dns_protector.is_protected:
        console.print("  Status: [green]Protected[/green]")
        dns_servers = await dns_protector._get_current_dns_servers()
        console.print(f"  DNS Servers: {', '.join(dns_servers)}")
    else:
        console.print("  Status: [red]Not Protected[/red]")
    
    # Performance stats
    console.print("\n[bold cyan]📊 Performance[/bold cyan]")
    prover_stats = prover.get_stats()
    verifier_stats = verifier.get_stats()
    
    console.print(f"  Proofs Generated: {prover_stats['proofs_generated']}")
    console.print(f"  Avg Generation: {prover_stats['avg_generation_time']*1000:.1f}ms")
    console.print(f"  Verifications: {verifier_stats['verifications']}")
    console.print(f"  Avg Verification: {verifier_stats['avg_verification_time_ms']:.2f}ms")
    console.print(f"  Cache Hits: {verifier_stats['cached_verifications']}")
    console.print(f"  Success Rate: {verifier_stats['success_rate']*100:.1f}%")


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
            
            # ZK Proofs
            if tunnel._last_proof:
                age = tunnel._last_proof.age_seconds
                age_color = StatusColors.health_color(age)
                status_table.add_row(
                    "ZK Proof",
                    f"[{age_color[5:]}]{format_duration(age)} old[/{age_color[5:]}]",
                    f"Hash: {tunnel._last_proof.proof_hash[:16]}..."
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
# PROOF COMMANDS
# ============================================================================

@click.group()
def proofs():
    """Manage zero-knowledge proofs."""
    pass


@proofs.command(name="list")
async def proofs_list():
    """List recent proofs."""
    stats = prover.get_stats()
    proofs_list = list(prover._proof_cache.values())[-10:]  # Last 10
    
    if not proofs_list:
        print_info("No proofs in cache")
        return
    
    table = Table(title=f"Recent Proofs ({len(proofs_list)} in cache)")
    table.add_column("Hash", style="cyan")
    table.add_column("Age", justify="right")
    table.add_column("Valid", justify="center")
    table.add_column("Size", justify="right")
    
    for proof in reversed(proofs_list):
        age_color = StatusColors.health_color(proof.age_seconds)
        table.add_row(
            proof.proof_hash[:16] + "...",
            f"[{age_color[5:]}]{format_duration(proof.age_seconds)}[/{age_color[5:]}]",
            "✓" if proof.public_inputs.get('is_valid') else "✗",
            format_bytes(proof.size_bytes)
        )
    
    console.print(table)
    
    # Summary
    console.print(f"\n[cyan]Total Generated:[/cyan] {stats['proofs_generated']}")
    console.print(f"[cyan]Avg Generation:[/cyan] {stats['avg_generation_time']*1000:.1f}ms")
    console.print(f"[cyan]Avg Size:[/cyan] {format_bytes(stats['avg_proof_size_bytes'])}")


@proofs.command(name="verify")
@click.argument('proof_hash', required=False)
async def proofs_verify(proof_hash: Optional[str]):
    """Verify a specific proof."""
    if not proof_hash:
        # Verify last proof
        proof = tunnel._last_proof
        if not proof:
            print_error("No proof available")
            return
    else:
        # Find proof by hash prefix
        proof = None
        for p in prover._proof_cache.values():
            if p.proof_hash.startswith(proof_hash):
                proof = p
                break
        
        if not proof:
            print_error(f"Proof not found: {proof_hash}")
            return
    
    print_info(f"Verifying proof {proof.proof_hash[:16]}...")
    
    result = await verifier.verify(proof, use_cache=False)
    
    if result.valid:
        print_success(f"Proof is valid (verified in {result.verification_time_ms:.2f}ms)")
    else:
        print_error(f"Proof is invalid: {result.error}")


@proofs.command(name="generate")
async def proofs_generate():
    """Generate a new proof."""
    print_info("Generating new proof...")
    
    proof = await prover.generate_proof()
    
    print_success(f"Proof generated in {prover.get_stats()['avg_generation_time']*1000:.1f}ms")
    console.print(f"  Hash: {proof.proof_hash}")
    console.print(f"  Size: {format_bytes(proof.size_bytes)}")
    console.print(f"  Valid: {'✓' if proof.public_inputs.get('is_valid') else '✗'}")


@proofs.command(name="clear")
async def proofs_clear():
    """Clear proof cache."""
    await prover.clear_cache()
    await verifier.clear_cache()
    print_success("Proof cache cleared")


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
    """Set configuration value."""
    env_file = Path("/etc/zkvpn/.env")
    
    if not env_file.exists():
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.touch()
    
    # Read existing
    content = env_file.read_text() if env_file.exists() else ""
    lines = content.splitlines()
    
    # Update or add
    found = False
    for i, line in enumerate(lines):
        if line.startswith(f"ZKVPN_{key.upper()}="):
            lines[i] = f"ZKVPN_{key.upper()}={value}"
            found = True
            break
    
    if not found:
        lines.append(f"ZKVPN_{key.upper()}={value}")
    
    # Write back
    env_file.write_text("\n".join(lines))
    
    print_success(f"Configuration updated: {key}={value}")
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
            peer.get('endpoint', '-'),
            peer.get('latest handshake', '-'),
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
    """Test ZK proof system."""
    print_info("Testing ZK proof system...")
    
    # Generate proof
    start = asyncio.get_event_loop().time()
    proof = await prover.generate_proof(deterministic=True)
    gen_time = (asyncio.get_event_loop().time() - start) * 1000
    
    # Verify proof
    start = asyncio.get_event_loop().time()
    result = await verifier.verify(proof, use_cache=False)
    verify_time = (asyncio.get_event_loop().time() - start) * 1000
    
    console.print("\n[bold cyan]🔐 ZK System Test[/bold cyan]")
    console.print(f"\n  Generation: {gen_time:.1f}ms [green]✓[/green]" if gen_time < 500 else "[red]✗[/red]")
    console.print(f"  Verification: {verify_time:.2f}ms [green]✓[/green]" if verify_time < 50 else "[red]✗[/red]")
    console.print(f"  Proof Size: {format_bytes(proof.size_bytes)} [green]✓[/green]" if proof.size_bytes < 1024 else "[red]✗[/red]")
    console.print(f"  Valid: {'✓' if result.valid else '✗'}")
    
    if result.valid:
        print_success("ZK system is functioning correctly")
    else:
        print_error("ZK system test failed")


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
