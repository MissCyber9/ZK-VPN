"""
CLI principale ZK-VPN
"""

import click
import json
import sys
from pathlib import Path
from datetime import datetime

# Import des modules ZK-VPN
try:
    from ..circuits.prover import ZKProver
    from ..protocol.wireguard import WireGuardManager, check_wireguard_availability
    ZK_MODULES_AVAILABLE = True
except ImportError:
    ZK_MODULES_AVAILABLE = False
    print("⚠️  Modules ZK-VPN non disponibles, mode limité")

@click.group()
@click.option('--debug', is_flag=True, help='Mode debug')
@click.pass_context
def cli(ctx, debug):
    """ZK-VPN - VPN Zero-Knowledge avec preuves ZK-SNARKs"""
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    ctx.obj['start_time'] = datetime.now()
    
    if debug:
        click.echo(f"🔧 Debug mode activé")
        click.echo(f"Python: {sys.version}")

@cli.command()
def version():
    """Affiche la version de ZK-VPN"""
    from .. import __version__
    click.echo(f"ZK-VPN v{__version__}")
    click.echo("Prototype avec preuves ZK no-logging")

@cli.command()
@click.pass_context
def status(ctx):
    """Affiche le statut complet du système"""
    click.echo("🔍 STATUT ZK-VPN")
    click.echo("=" * 50)
    
    # Version
    from .. import __version__
    click.echo(f"Version: {__version__}")
    
    # WireGuard
    if check_wireguard_availability():
        click.echo("🌐 WireGuard: ✅ Disponible")
    else:
        click.echo("🌐 WireGuard: ❌ Non disponible")
    
    # Modules ZK
    if ZK_MODULES_AVAILABLE:
        click.echo("🔐 Modules ZK: ✅ Chargés")
    else:
        click.echo("🔐 Modules ZK: ❌ Manquants")
    
    # Temps d'exécution
    runtime = datetime.now() - ctx.obj['start_time']
    click.echo(f"⏱️  Runtime: {runtime.total_seconds():.1f}s")
    
    # Dossier de configuration
    config_dir = Path.home() / ".zkvpn"
    config_dir.mkdir(exist_ok=True)
    click.echo(f"📁 Config: {config_dir}")

@cli.command()
@click.option('--count', default=1, help='Nombre de preuves à générer')
@click.pass_context
def test_proofs(ctx, count):
    """Génère des preuves ZK de test"""
    if not ZK_MODULES_AVAILABLE:
        click.echo("❌ Modules ZK non disponibles")
        return
    
    from ..circuits.prover import ZKProver
    
    prover = ZKProver()
    
    with click.progressbar(range(count), label='Génération des preuves') as bar:
        proofs = []
        for i in bar:
            proof = prover.prove_no_logging({
                "test_id": i,
                "action": "test_proof",
                "timestamp": datetime.now().isoformat()
            })
            proofs.append(proof)
    
    click.echo(f"✅ {len(proofs)} preuve(s) générée(s)")
    
    if ctx.obj['debug'] and proofs:
        click.echo("
📄 Dernière preuve:")
        click.echo(json.dumps(proofs[-1], indent=2))

@cli.command()
def check_wg():
    """Vérifie l'installation WireGuard"""
    if check_wireguard_availability():
        click.echo("✅ WireGuard est installé et disponible")
        
        # Tenter de générer des clés
        from ..protocol.wireguard import generate_wireguard_keys
        keys = generate_wireguard_keys()
        
        if keys.get("status") == "success":
            click.echo("✅ Clés WireGuard générables")
            click.echo(f"   Clé publique: {keys['public_key'][:16]}...")
        else:
            click.echo(f"⚠️  Erreur génération clés: {keys.get('error', 'inconnue')}")
    else:
        click.echo("❌ WireGuard n'est pas disponible")
        click.echo("   Installation: sudo apt install wireguard wireguard-tools")

@cli.command()
@click.option('--name', default='default', help='Nom de la configuration')
def init_config(name):
    """Initialise une configuration ZK-VPN"""
    config_dir = Path.home() / ".zkvpn"
    config_dir.mkdir(exist_ok=True)
    
    config_file = config_dir / f"{name}.json"
    
    config = {
        "version": "0.1.0",
        "name": name,
        "created": datetime.now().isoformat(),
        "wireguard_interface": "zkvpn0",
        "zk_proofs_enabled": True,
        "no_logging_enforced": True
    }
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    click.echo(f"✅ Configuration créée: {config_file}")
    click.echo(f"   WireGuard interface: {config['wireguard_interface']}")
    click.echo(f"   Preuves ZK: {'activées' if config['zk_proofs_enabled'] else 'désactivées'}")

if __name__ == "__main__":
    cli(obj={})
