"""Tests for WireGuard integration."""

import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from zkvpn.protocol.wireguard import WireGuardInterface, WireGuardPeer, wg_interface
from zkvpn.protocol.tunnel import ZKTunnel, tunnel
from zkvpn.protocol.dns import DNSProtector, dns_protector


@pytest.mark.asyncio
class TestWireGuardInterface:
    """Test WireGuard interface management."""
    
    @patch('subprocess.run')
    def test_generate_keypair(self, mock_run):
        """Test keypair generation."""
        mock_run.return_value.stdout = "test_private_key\n"
        
        wg = WireGuardInterface("test0")
        
        # Mock second call for pubkey
        def side_effect(*args, **kwargs):
            result = MagicMock()
            result.stdout = "test_private_key\n" if "genkey" in args[0] else "test_public_key\n"
            return result
        
        mock_run.side_effect = side_effect
        
        private, public = wg.generate_keypair()
        
        assert private == "test_private_key"
        assert public == "test_public_key"
    
    @patch('subprocess.run')
    @patch('asyncio.create_subprocess_exec')
    async def test_configure_interface(self, mock_subproc, mock_run):
        """Test interface configuration."""
        mock_subproc.return_value.communicate.return_value = (b"", b"")
        mock_subproc.return_value.returncode = 0
        
        wg = WireGuardInterface("test0")
        
        with patch.object(wg, 'generate_keypair') as mock_gen:
            mock_gen.return_value = ("priv", "pub")
            
            result = await wg.configure_interface()
            
            assert result is True
            assert wg._initialized is True
    
    @patch('subprocess.run')
    async def test_add_peer(self, mock_run):
        """Test adding a peer."""
        mock_run.return_value.returncode = 0
        
        wg = WireGuardInterface("test0")
        peer = WireGuardPeer(
            public_key="test_pubkey",
            endpoint="10.0.0.2:51820",
            allowed_ips=["10.0.0.2/32"]
        )
        
        result = await wg.add_peer(peer)
        
        assert result is True
        assert "test_pubkey" in wg.peers
    
    @patch('subprocess.run')
    async def test_get_status(self, mock_run):
        """Test status retrieval."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = """
interface: test0
  public key: test_public_key
  listening port: 51820

peer: peer1_pubkey
  endpoint: 10.0.0.2:51820
  allowed ips: 10.0.0.2/32
  latest handshake: 1 second ago
  transfer: 1.23 KiB received, 4.56 KiB sent
"""
        
        wg = WireGuardInterface("test0")
        status = await wg.get_status()
        
        assert status["interface"] == "test0"
        assert status["public_key"] == "test_public_key"
        assert status["listen_port"] == 51820
        assert len(status["peers"]) == 1
        assert status["peers"][0]["public_key"] == "peer1_pubkey"
    
    @patch('subprocess.run')
    async def test_set_address(self, mock_run):
        """Test setting interface address."""
        mock_run.return_value.returncode = 0
        
        wg = WireGuardInterface("test0")
        result = await wg.set_address("10.0.0.1/24")
        
        assert result is True
        assert wg.address == "10.0.0.1/24"
    
    @patch('subprocess.run')
    async def test_delete_interface(self, mock_run):
        """Test interface deletion."""
        mock_run.return_value.returncode = 0
        
        wg = WireGuardInterface("test0")
        wg._initialized = True
        
        result = await wg.delete_interface()
        
        assert result is True
        assert wg._initialized is False


@pytest.mark.asyncio
class TestZKTunnel:
    """Test VPN tunnel with ZK proofs."""
    
    @patch.object(WireGuardInterface, 'configure_interface')
    @patch.object(WireGuardInterface, 'set_address')
    async def test_start_server(self, mock_set_addr, mock_configure):
        """Test starting VPN server."""
        mock_configure.return_value = True
        mock_set_addr.return_value = True
        
        tunnel = ZKTunnel()
        
        with patch.object(tunnel, '_enable_ip_forwarding') as mock_forward:
            mock_forward.return_value = None
            
            result = await tunnel.start_server()
            
            assert result is True
            assert tunnel._is_connected is True
    
    @patch.object(WireGuardInterface, 'configure_interface')
    @patch.object(WireGuardInterface, 'set_address')
    @patch.object(WireGuardInterface, 'add_peer')
    async def test_connect(self, mock_add_peer, mock_set_addr, mock_configure):
        """Test connecting to VPN server."""
        mock_configure.return_value = True
        mock_set_addr.return_value = True
        mock_add_peer.return_value = True
        
        tunnel = ZKTunnel()
        
        result = await tunnel.connect("10.0.0.1:51820", "server_pubkey")
        
        assert result is True
        assert tunnel._is_connected is True
        assert tunnel._current_session is not None
    
    @patch.object(WireGuardInterface, 'delete_interface')
    async def test_disconnect(self, mock_delete):
        """Test disconnection."""
        mock_delete.return_value = True
        
        tunnel = ZKTunnel()
        tunnel._is_connected = True
        tunnel._proof_task = asyncio.create_task(asyncio.sleep(1))
        tunnel._health_check_task = asyncio.create_task(asyncio.sleep(1))
        
        result = await tunnel.disconnect()
        
        assert result is True
        assert tunnel._is_connected is False
    
    @patch.object(WireGuardInterface, 'add_peer')
    async def test_add_client(self, mock_add_peer):
        """Test adding client to server."""
        mock_add_peer.return_value = True
        
        tunnel = ZKTunnel()
        
        with patch.object(tunnel, '_assign_client_ip') as mock_assign:
            mock_assign.return_value = "10.0.0.10"
            
            result = await tunnel.add_client("client_pubkey")
            
            assert result is True


@pytest.mark.asyncio
class TestDNSProtector:
    """Test DNS leak protection."""
    
    @patch('pathlib.Path.read_text')
    @patch('pathlib.Path.write_text')
    @patch('asyncio.create_subprocess_exec')
    async def test_enable_protection(self, mock_subproc, mock_write, mock_read):
        """Test enabling DNS protection."""
        mock_read.return_value = "original config"
        mock_subproc.return_value.communicate.return_value = (b"", b"")
        
        dns = DNSProtector("test0")
        result = await dns.enable_protection()
        
        assert result is True
        assert dns._protected is True
    
    @patch('subprocess.run')
    async def test_test_leaks(self, mock_run):
        """Test leak detection."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        
        dns = DNSProtector("test0")
        results = await dns.test_leaks()
        
        assert "dns_leak" in results
        assert "ipv6_leak" in results
        assert "dns_servers" in results
    
    @patch('asyncio.create_subprocess_exec')
    async def test_disable_protection(self, mock_subproc):
        """Test disabling DNS protection."""
        mock_subproc.return_value.communicate.return_value = (b"", b"")
        
        dns = DNSProtector("test0")
        dns._protected = True
        dns._original_resolv_conf = "original"
        
        with patch('pathlib.Path.write_text'):
            result = await dns.disable_protection()
            
            assert result is True
            assert dns._protected is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
