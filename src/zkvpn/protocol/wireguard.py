"""
Gestion WireGuard pour ZK-VPN
Version: 0.1.0 (interface Python)
"""

import subprocess
import json
import tempfile
import os
from pathlib import Path
from typing import Dict, Optional, List
import shutil

class WireGuardManager:
    """Gestionnaire WireGuard via commandes système"""
    
    def __init__(self, interface: str = "zkvpn0"):
        self.interface = interface
        self.wg_path = shutil.which("wg")
        self.ip_path = shutil.which("ip")
    
    def is_available(self) -> bool:
        """Vérifie si WireGuard est disponible"""
        return self.wg_path is not None and self.ip_path is not None
    
    def generate_keys(self) -> Dict[str, str]:
        """Génère une paire de clés WireGuard"""
        if not self.is_available():
            return {"error": "WireGuard non disponible"}
        
        try:
            # Générer clé privée
            priv_result = subprocess.run(
                [self.wg_path, "genkey"],
                capture_output=True,
                text=True,
                check=True
            )
            private_key = priv_result.stdout.strip()
            
            # Générer clé publique
            pub_result = subprocess.run(
                [self.wg_path, "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True
            )
            public_key = pub_result.stdout.strip()
            
            return {
                "private_key": private_key,
                "public_key": public_key,
                "status": "success"
            }
        except subprocess.CalledProcessError as e:
            return {
                "error": f"Erreur génération clés: {e.stderr}",
                "status": "error"
            }
    
    def create_interface(self) -> Dict[str, any]:
        """Crée l'interface WireGuard"""
        if not self.is_available():
            return {"error": "Commandes système non disponibles"}
        
        try:
            # Créer interface
            subprocess.run(
                [self.ip_path, "link", "add", "dev", self.interface, "type", "wireguard"],
                capture_output=True,
                check=True
            )
            
            # Assigner adresse IP
            subprocess.run(
                [self.ip_path, "address", "add", "10.0.0.1/24", "dev", self.interface],
                capture_output=True,
                check=True
            )
            
            # Activer interface
            subprocess.run(
                [self.ip_path, "link", "set", self.interface, "up"],
                capture_output=True,
                check=True
            )
            
            return {
                "status": "success",
                "interface": self.interface,
                "ip_address": "10.0.0.1/24"
            }
        except subprocess.CalledProcessError as e:
            return {
                "status": "error",
                "error": f"Erreur création interface: {e.stderr[:200]}"
            }
    
    def get_status(self) -> Dict[str, any]:
        """Récupère le statut WireGuard"""
        if not self.is_available():
            return {"error": "WireGuard non disponible"}
        
        try:
            result = subprocess.run(
                [self.wg_path, "show", self.interface],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "status": "active",
                    "output": result.stdout,
                    "interface": self.interface
                }
            else:
                return {
                    "status": "inactive",
                    "error": result.stderr[:200] if result.stderr else "Interface non trouvée"
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def create_config(self, private_key: str, peers: List[Dict] = None) -> str:
        """Crée une configuration WireGuard"""
        config = f"[Interface]
"
        config += f"PrivateKey = {private_key}
"
        config += f"Address = 10.0.0.1/24
"
        config += f"ListenPort = 51820
"
        
        if peers:
            for i, peer in enumerate(peers):
                config += f"
[Peer] #{i+1}
"
                config += f"PublicKey = {peer.get('public_key', '')}
"
                config += f"AllowedIPs = {peer.get('allowed_ips', '10.0.0.2/32')}
"
                if 'endpoint' in peer:
                    config += f"Endpoint = {peer['endpoint']}
"
        
        return config

# Instance par défaut
default_wg_manager = WireGuardManager()

def check_wireguard_availability() -> bool:
    """Vérifie si WireGuard est disponible"""
    return default_wg_manager.is_available()

def generate_wireguard_keys() -> Dict[str, str]:
    """Génère des clés WireGuard"""
    return default_wg_manager.generate_keys()

if __name__ == "__main__":
    print("🧪 Test WireGuard Manager")
    print(f"Disponible: {check_wireguard_availability()}")
    
    if check_wireguard_availability():
        keys = generate_wireguard_keys()
        print(f"Clés générées: {keys.get('status', 'error')}")
        
        if keys.get("status") == "success":
            config = default_wg_manager.create_config(keys["private_key"])
            print(f"Config: {len(config)} caractères")
