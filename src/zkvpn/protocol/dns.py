"""DNS leak protection for ZK-VPN.

This module ensures all DNS queries are routed through the VPN tunnel
and prevents DNS leaks on IPv4 and IPv6.
"""

import asyncio
import subprocess
import re
from typing import List, Optional
import logging
from pathlib import Path

from zkvpn.core.config import settings

logger = logging.getLogger(__name__)


class DNSProtector:
    """DNS leak protection manager."""
    
    def __init__(self, interface: str = None):
        """Initialize DNS protector.
        
        Args:
            interface: VPN interface name
        """
        self.interface = interface or settings.wireguard_interface
        self._original_resolv_conf: Optional[str] = None
        self._dns_servers = ["1.1.1.1", "1.0.0.1"]  # Cloudflare DNS
        self._protected = False
    
    async def enable_protection(self) -> bool:
        """Enable DNS leak protection.
        
        Forces all DNS queries through the VPN tunnel.
        
        Returns:
            bool: True if successful
        """
        try:
            # Backup original resolv.conf
            await self._backup_resolv_conf()
            
            # Set DNS servers via resolvconf
            await self._set_dns_resolvconf()
            
            # Block DNS on other interfaces (IPv4 & IPv6)
            await self._block_dns_leaks()
            
            self._protected = True
            logger.info(f"DNS leak protection enabled with servers: {self._dns_servers}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable DNS protection: {e}")
            return False
    
    async def disable_protection(self) -> bool:
        """Disable DNS leak protection.
        
        Returns:
            bool: True if successful
        """
        try:
            # Restore original resolv.conf
            await self._restore_resolv_conf()
            
            # Remove DNS blocking rules
            await self._remove_dns_blocks()
            
            self._protected = False
            logger.info("DNS leak protection disabled")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable DNS protection: {e}")
            return False
    
    async def test_leaks(self) -> dict:
        """Test for DNS/IPv6 leaks.
        
        Returns:
            dict: Test results
        """
        results = {
            "dns_leak": False,
            "ipv6_leak": False,
            "dns_servers": [],
            "public_ip": None
        }
        
        try:
            # Test DNS servers currently in use
            dns_servers = await self._get_current_dns_servers()
            results["dns_servers"] = dns_servers
            
            # Check if any DNS server is not our VPN DNS
            for server in dns_servers:
                if server not in self._dns_servers and not server.startswith("10."):
                    results["dns_leak"] = True
                    logger.warning(f"DNS leak detected: {server}")
            
            # Test IPv6 connectivity
            ipv6_enabled = await self._check_ipv6()
            results["ipv6_leak"] = ipv6_enabled
            
            # Get public IP
            results["public_ip"] = await self._get_public_ip()
            
        except Exception as e:
            logger.error(f"Leak test failed: {e}")
        
        return results
    
    async def _backup_resolv_conf(self):
        """Backup the current resolv.conf."""
        resolv_conf = Path("/etc/resolv.conf")
        if resolv_conf.exists():
            self._original_resolv_conf = resolv_conf.read_text()
            logger.debug("Backed up resolv.conf")
    
    async def _restore_resolv_conf(self):
        """Restore original resolv.conf."""
        if self._original_resolv_conf:
            resolv_conf = Path("/etc/resolv.conf")
            resolv_conf.write_text(self._original_resolv_conf)
            logger.debug("Restored resolv.conf")
    
    async def _set_dns_resolvconf(self):
        """Set DNS servers using resolvconf."""
        try:
            # Create resolvconf head
            head_content = "# ZK-VPN DNS\n"
            for dns in self._dns_servers:
                head_content += f"nameserver {dns}\n"
            
            # Write to resolvconf head
            proc = await asyncio.create_subprocess_exec(
                "tee", "/etc/resolvconf/head",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate(input=head_content.encode())
            
            # Update resolv.conf
            await asyncio.create_subprocess_exec(
                "resolvconf", "-u"
            )
            
            logger.debug(f"DNS servers set via resolvconf: {self._dns_servers}")
            
        except Exception as e:
            # Fallback to direct /etc/resolv.conf modification
            logger.warning(f"resolvconf failed, using direct modification: {e}")
            resolv_conf = Path("/etc/resolv.conf")
            content = "# Generated by ZK-VPN\n"
            for dns in self._dns_servers:
                content += f"nameserver {dns}\n"
            resolv_conf.write_text(content)
    
    async def _block_dns_leaks(self):
        """Block DNS on all interfaces except VPN."""
        try:
            # IPv4 DNS leak prevention
            # Block port 53 on all interfaces except VPN
            cmd = [
                "iptables", "-I", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "udp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            cmd = [
                "iptables", "-I", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "tcp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            # IPv6 DNS leak prevention
            cmd = [
                "ip6tables", "-I", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "udp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            cmd = [
                "ip6tables", "-I", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "tcp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            logger.debug("DNS leak blocking rules added")
            
        except Exception as e:
            logger.warning(f"Failed to add DNS blocking rules: {e}")
    
    async def _remove_dns_blocks(self):
        """Remove DNS blocking rules."""
        try:
            # Remove IPv4 rules
            cmd = [
                "iptables", "-D", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "udp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            cmd = [
                "iptables", "-D", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "tcp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            # Remove IPv6 rules
            cmd = [
                "ip6tables", "-D", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "udp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
            cmd = [
                "ip6tables", "-D", "OUTPUT", "!",
                "-o", self.interface,
                "-p", "tcp",
                "--dport", "53",
                "-j", "DROP"
            ]
            await asyncio.create_subprocess_exec(*cmd)
            
        except Exception as e:
            logger.debug(f"Failed to remove DNS blocking rules: {e}")
    
    async def _get_current_dns_servers(self) -> List[str]:
        """Get currently configured DNS servers."""
        servers = []
        
        try:
            resolv_conf = Path("/etc/resolv.conf")
            if resolv_conf.exists():
                content = resolv_conf.read_text()
                for line in content.split('\n'):
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except Exception as e:
            logger.debug(f"Failed to read DNS servers: {e}")
        
        return servers
    
    async def _check_ipv6(self) -> bool:
        """Check if IPv6 is enabled and might leak."""
        try:
            # Check if IPv6 is enabled on non-VPN interfaces
            result = subprocess.run(
                ["ip", "-6", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Check for non-tunnel IPv6 addresses
            for line in result.stdout.split('\n'):
                if 'inet6' in line and self.interface not in line:
                    if not line.startswith('inet6 ::1'):  # Ignore localhost
                        return True
            
            return False
            
        except Exception:
            return False
    
    async def _get_public_ip(self) -> Optional[str]:
        """Get current public IP address."""
        try:
            # Try multiple services
            services = [
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ifconfig.me"
            ]
            
            for service in services:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-m", "5", service,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate()
                    if stdout:
                        ip = stdout.decode().strip()
                        if ip:
                            return ip
                except:
                    continue
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to get public IP: {e}")
            return None
    
    @property
    def is_protected(self) -> bool:
        """Check if DNS protection is enabled."""
        return self._protected


# Global DNS protector instance
dns_protector = DNSProtector()


__all__ = ["DNSProtector", "dns_protector"]
