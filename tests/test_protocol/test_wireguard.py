"""Tests for WireGuard integration."""

import asyncio
import subprocess
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from zkvpn.protocol.wireguard import WireGuardInterface, WireGuardPeer, wg_interface, parse_wg_show
from zkvpn.protocol.tunnel import ZKTunnel, tunnel
from zkvpn.protocol.dns import DNSProtector, dns_protector

# Valid 44-char base64 WireGuard-style keys
PUB1 = "A" * 43 + "="
PUB2 = "B" * 43 + "="
PUB3 = "C" * 43 + "="


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
        """Test interface configuration (independent of which WireGuard tools are installed)."""
        mock_subproc.return_value.communicate.return_value = (b"", b"")
        mock_subproc.return_value.returncode = 0

        def fake_run(cmd, **kwargs):
            result = MagicMock()
            result.stdout = ""
            # `ip link show` -> interface absent; everything else (incl. `ip link add ... wireguard`) works
            result.returncode = 1 if cmd[:3] == ["ip", "link", "show"] else 0
            return result

        mock_run.side_effect = fake_run
        wg = WireGuardInterface("test0")

        def fake_keypair():
            wg.private_key, wg.public_key = "priv", "pub"
            return "priv", "pub"

        with patch.object(wg, 'generate_keypair', side_effect=fake_keypair):
            result = await wg.configure_interface()

            assert result is True
            assert wg._initialized is True

    @patch('shutil.which', return_value=None)
    @patch('subprocess.run')
    @patch('asyncio.create_subprocess_exec')
    async def test_no_kernel_module_and_no_wireguard_go_is_a_clear_error(self, mock_subproc, mock_run, _which):
        mock_subproc.return_value.communicate.return_value = (b"", b"")

        def fake_run(cmd, **kwargs):
            result = MagicMock()
            result.stdout = ""
            result.returncode = 1 if cmd[:3] in (["ip", "link", "show"], ["ip", "link", "add"]) else 0
            return result

        mock_run.side_effect = fake_run
        wg = WireGuardInterface("test0")
        wg.private_key, wg.public_key = "priv", "pub"
        assert await wg.configure_interface("priv") is False       # logged, not a crash

    @patch('subprocess.run')
    async def test_add_peer(self, mock_run):
        """Test adding a peer."""
        mock_run.return_value.returncode = 0
        
        wg = WireGuardInterface("test0")
        peer = WireGuardPeer(
            public_key=PUB1,
            endpoint="10.0.0.2:51820",
            allowed_ips=["10.0.0.2/32"]
        )
        
        result = await wg.add_peer(peer)
        
        assert result is True
        assert PUB1 in wg.peers
    
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
        
        with patch.object(tunnel, '_enable_ip_forwarding') as mock_forward, \
             patch('zkvpn.protocol.tunnel.AdmissionServer.start', AsyncMock()) as admission, \
             patch.object(tunnel.nat, 'enable', AsyncMock(return_value=True)):
            mock_forward.return_value = None
            
            result = await tunnel.start_server()
            
            assert result is True
            assert tunnel._is_connected is True
            admission.assert_awaited_once()
        if tunnel._health_check_task:
            tunnel._health_check_task.cancel()
    
    @patch.object(WireGuardInterface, 'configure_interface')
    @patch.object(WireGuardInterface, 'set_address')
    @patch.object(WireGuardInterface, 'add_peer')
    async def test_connect(self, mock_add_peer, mock_set_addr, mock_configure):
        """Test connecting to VPN server."""
        mock_configure.return_value = True
        mock_set_addr.return_value = True
        mock_add_peer.return_value = True
        
        tunnel = ZKTunnel()
        
        with patch.object(tunnel.killswitch, 'enable', AsyncMock(return_value=True)) as ks, \
             patch.object(tunnel.routes, 'enable', AsyncMock(return_value=True)), \
             patch.object(tunnel, '_bring_up', AsyncMock()):
            result = await tunnel.connect("10.0.0.1:51820", PUB2)
        ks.assert_awaited_once_with(["10.0.0.1:51820"])
        
        assert result is True
        assert tunnel._is_connected is True
        assert tunnel._current_session is not None
    
    @patch.object(WireGuardInterface, 'delete_interface')
    async def test_disconnect(self, mock_delete):
        """Test disconnection."""
        mock_delete.return_value = True
        
        tunnel = ZKTunnel()
        tunnel._is_connected = True
        tunnel._health_check_task = asyncio.create_task(asyncio.sleep(1))
        
        result = await tunnel.disconnect()
        
        assert result is True
        assert tunnel._is_connected is False
    
    @patch.object(WireGuardInterface, 'add_peer')
    async def test_add_client_requires_proof(self, mock_add_peer):
        """By default a client without a ZK session proof is refused."""
        mock_add_peer.return_value = True
        tunnel = ZKTunnel()

        assert await tunnel.add_client(PUB3) is False
        mock_add_peer.assert_not_called()

    @patch.object(WireGuardInterface, 'add_peer')
    async def test_add_client_rejects_invalid_proof(self, mock_add_peer):
        from zkvpn.zk import SessionProof, VerifyResult
        mock_add_peer.return_value = True
        tunnel = ZKTunnel()
        proof = SessionProof({}, [])

        with patch.object(tunnel.auth, 'verify',
                          AsyncMock(return_value=VerifyResult(False, "invalid proof"))):
            assert await tunnel.add_client(PUB3, nonce="n", proof=proof) is False
        mock_add_peer.assert_not_called()

    @patch.object(WireGuardInterface, 'add_peer')
    async def test_add_client_with_valid_proof(self, mock_add_peer):
        from zkvpn.zk import SessionProof, VerifyResult
        mock_add_peer.return_value = True
        tunnel = ZKTunnel()
        proof = SessionProof({}, [])

        with patch.object(tunnel.auth, 'verify',
                          AsyncMock(return_value=VerifyResult(True, pk="1"))), \
             patch.object(tunnel, '_assign_client_ip', AsyncMock(return_value="10.0.0.10")):
            assert await tunnel.add_client(PUB3, nonce="n", proof=proof) is True
        mock_add_peer.assert_called_once()

    @patch.object(WireGuardInterface, 'add_peer')
    async def test_add_client_proof_optional_when_disabled(self, mock_add_peer):
        mock_add_peer.return_value = True
        tunnel = ZKTunnel()

        with patch('zkvpn.protocol.tunnel.settings.require_client_proof', False), \
             patch.object(tunnel, '_assign_client_ip', AsyncMock(return_value="10.0.0.10")):
            assert await tunnel.add_client(PUB3) is True


@pytest.mark.asyncio
class TestDNSProtector:
    """DNS leak protection (resolver backends, persisted state, firewall rules)."""

    @pytest.fixture(autouse=True)
    def sandbox(self, tmp_path, monkeypatch):
        import zkvpn.protocol.dns as dnsmod
        self.resolv = tmp_path / "resolv.conf"
        self.resolv.write_text("nameserver 192.168.1.1\n")
        monkeypatch.setattr(dnsmod, "RESOLV_CONF", self.resolv)
        monkeypatch.setattr(dnsmod.settings, "state_dir", str(tmp_path / "state"))
        monkeypatch.setattr(dnsmod.settings, "dns_backend", "file")
        monkeypatch.setattr(dnsmod.settings, "dns_servers", "10.0.0.1,10.0.0.2")
        self.calls = []

        async def fake_run(self_, cmd, stdin=None):
            self.calls.append((tuple(cmd), stdin))
            return 0

        monkeypatch.setattr(DNSProtector, "_run", fake_run)

    async def test_file_backend_writes_and_restores_across_processes(self):
        dns = DNSProtector("test0")
        assert await dns.enable_protection() is True
        assert "nameserver 10.0.0.1" in self.resolv.read_text()
        assert dns.is_protected

        other_process = DNSProtector("test0")          # `disconnect` is a different process
        assert other_process.is_protected              # state survived (not just in memory)
        assert await other_process.disable_protection() is True
        assert self.resolv.read_text() == "nameserver 192.168.1.1\n"
        assert not other_process.is_protected

    async def test_does_not_clobber_resolv_conf_changed_by_someone_else(self):
        dns = DNSProtector("test0")
        await dns.enable_protection()
        self.resolv.write_text("nameserver 9.9.9.9\n")   # network manager rewrote it meanwhile
        await dns.disable_protection()
        assert self.resolv.read_text() == "nameserver 9.9.9.9\n"

    async def test_enable_twice_does_not_lose_the_original(self):
        dns = DNSProtector("test0")
        await dns.enable_protection()
        await dns.enable_protection()
        await dns.disable_protection()
        assert self.resolv.read_text() == "nameserver 192.168.1.1\n"

    async def test_resolved_backend_commands(self, monkeypatch):
        import zkvpn.protocol.dns as dnsmod
        monkeypatch.setattr(dnsmod.settings, "dns_backend", "resolved")
        dns = DNSProtector("test0")
        assert await dns.enable_protection() is True
        cmds = [c for c, _ in self.calls if c[0] == "resolvectl"]
        assert ("resolvectl", "dns", "test0", "10.0.0.1", "10.0.0.2") in cmds
        assert ("resolvectl", "domain", "test0", "~.") in cmds
        assert self.resolv.read_text() == "nameserver 192.168.1.1\n"   # file untouched
        await dns.disable_protection()
        assert ("resolvectl", "revert", "test0") in [c for c, _ in self.calls]

    async def test_resolvconf_backend_commands(self, monkeypatch):
        import zkvpn.protocol.dns as dnsmod
        monkeypatch.setattr(dnsmod.settings, "dns_backend", "resolvconf")
        dns = DNSProtector("test0")
        await dns.enable_protection()
        assert (("resolvconf", "-a", "test0"), "# Generated by ZK-VPN\nnameserver 10.0.0.1\nnameserver 10.0.0.2\n") in self.calls
        await dns.disable_protection()
        assert ("resolvconf", "-d", "test0") in [c for c, _ in self.calls]

    async def test_failure_rolls_back(self, monkeypatch):
        dns = DNSProtector("test0")

        async def failing(self_, cmd, stdin=None):
            return 1 if cmd[0] in ("iptables", "ip6tables") and cmd[1] == "-A" else 0

        monkeypatch.setattr(DNSProtector, "_run", failing)
        assert await dns.enable_protection() is False
        assert self.resolv.read_text() == "nameserver 192.168.1.1\n"
        assert not dns.is_protected

    def test_firewall_rules_block_plain_dns_and_dot_outside_tunnel(self):
        from zkvpn.protocol.dns import dns_rules
        flat = [" ".join(c) for c in dns_rules("test0")]
        assert "iptables -A ZKVPN_DNS -o test0 -j RETURN" in flat
        assert "iptables -A ZKVPN_DNS -p udp --dport 53 -j DROP" in flat
        assert "ip6tables -A ZKVPN_DNS -p tcp --dport 853 -j DROP" in flat
        assert flat[8] == "iptables -I OUTPUT 1 -j ZKVPN_DNS"       # activated after the chain is complete

    async def test_leak_report_flags_foreign_servers(self):
        dns = DNSProtector("test0")
        results = await dns.test_leaks()
        assert results["dns_leak"] is True                          # 192.168.1.1 is not ours
        assert results["dns_servers"] == ["192.168.1.1"]


class TestInputValidation:
    """Peer inputs are validated before reaching `wg set`."""

    def test_rejects_option_like_key(self):
        with pytest.raises(ValueError):
            WireGuardPeer(public_key="--help")

    def test_rejects_bad_endpoint(self):
        with pytest.raises(ValueError):
            WireGuardPeer(public_key=PUB1, endpoint="-evil:51820")
        with pytest.raises(ValueError):
            WireGuardPeer(public_key=PUB1, endpoint="1.2.3.4:99999")

    def test_rejects_bad_allowed_ips(self):
        with pytest.raises(ValueError):
            WireGuardPeer(public_key=PUB1, allowed_ips=["not-an-ip"])

    def test_accepts_valid_peer(self):
        WireGuardPeer(public_key=PUB1, endpoint="[::1]:51820", allowed_ips=["10.0.0.2/32"])


async def test_memory_guard_covers_async_body():
    """memory_guard must stay active until the coroutine finishes."""
    from zkvpn.core.memory import memory_guard

    @memory_guard("t")
    async def boom():
        await asyncio.sleep(0)
        raise MemoryError

    assert asyncio.iscoroutinefunction(boom)
    with pytest.raises(MemoryError):
        await boom()


class TestWgShowParser:
    OUTPUT = """interface: wg0
  public key: PUBKEY
  private key: (hidden)
  listening port: 51820

peer: PEER1
  endpoint: [2001:db8::1]:51820
  allowed ips: 10.0.0.2/32, fd00::2/128
  latest handshake: 1 minute, 5 seconds ago
  transfer: 92 B received, 1.50 KiB sent

peer: PEER2
  allowed ips: (none)
"""

    def test_parses_peer_fields_ipv6_and_units(self):
        status = parse_wg_show(self.OUTPUT)
        assert status["public_key"] == "PUBKEY"
        assert status["listen_port"] == 51820
        p1, p2 = status["peers"]
        assert p1["endpoint"] == "[2001:db8::1]:51820"
        assert p1["allowed_ips"] == ["10.0.0.2/32", "fd00::2/128"]
        assert p1["latest_handshake"] == "1 minute, 5 seconds ago"
        assert p1["transfer"] == {"rx": 92, "tx": 1536}
        assert p2["allowed_ips"] == [] and p2["endpoint"] is None


class TestKillSwitch:
    def test_rules_allow_only_tunnel_loopback_and_server(self):
        from zkvpn.protocol.killswitch import build_rules, CHAIN
        rules = build_rules("zkvpn0", ["203.0.113.5:51820", "[2001:db8::1]:51820"])
        v4 = [r for r in rules if r[0] == "iptables" and r[1:3] == ("-A", CHAIN)]
        v6 = [r for r in rules if r[0] == "ip6tables" and r[1:3] == ("-A", CHAIN)]
        assert ("iptables", "-A", CHAIN, "-o", "zkvpn0", "-j", "ACCEPT") in v4
        assert any("203.0.113.5" in r for r in v4) and not any("2001:db8::1" in r for r in v4)
        assert any("2001:db8::1" in r for r in v6) and not any("203.0.113.5" in r for r in v6)
        assert v4[-1][-1] == "DROP" and v6[-1][-1] == "DROP"
        # the OUTPUT jump is installed last, once the chain is complete
        assert rules[-1][:4] == ("ip6tables", "-I", "OUTPUT", "1")

    def test_hostname_endpoint_rejected(self):
        from zkvpn.protocol.killswitch import build_rules
        with pytest.raises(ValueError):
            build_rules("zkvpn0", ["vpn.example.com:51820"])

    async def test_enable_rolls_back_on_failure(self):
        from zkvpn.protocol.killswitch import KillSwitch
        ks = KillSwitch("zkvpn0")
        calls = []

        async def fake_run(cmd):
            calls.append(cmd)
            return 1 if cmd[:2] == ("iptables", "-A") and cmd[-1] == "DROP" else 0

        ks._run = fake_run
        assert await ks.enable(["203.0.113.5:51820"]) is False
        assert ks.active is False
        assert ("iptables", "-X", "ZKVPN_KILLSWITCH") in calls   # rolled back

    async def test_enable_and_disable(self):
        from zkvpn.protocol.killswitch import KillSwitch
        ks = KillSwitch("zkvpn0")

        async def ok(cmd):
            return 0

        ks._run = ok
        assert await ks.enable(["203.0.113.5:51820"]) is True and ks.active
        await ks.disable()
        assert ks.active is False


class TestRemoveClient:
    async def test_remove_client_keeps_server_running(self):
        tunnel = ZKTunnel()
        tunnel._client_sessions[PUB3] = "sess"
        with patch.object(WireGuardInterface, 'remove_peer', AsyncMock(return_value=True)), \
             patch.object(WireGuardInterface, 'delete_interface', AsyncMock()) as delete:
            assert await tunnel.remove_client(PUB3) is True
        delete.assert_not_called()
        assert PUB3 not in tunnel._client_sessions


class TestRouting:
    def test_parse_route_get(self):
        from zkvpn.protocol.routing import parse_route_get
        assert parse_route_get("203.0.113.5 via 10.9.0.254 dev eth0 src 10.9.0.2") == ("10.9.0.254", "eth0")
        assert parse_route_get("10.9.0.1 dev eth0 src 10.9.0.2") == (None, "eth0")

    def test_pin_command_v4_and_v6(self):
        from zkvpn.protocol.routing import pin_command
        assert pin_command("203.0.113.5", "10.9.0.254", "eth0") == [
            "ip", "route", "replace", "203.0.113.5/32", "via", "10.9.0.254", "dev", "eth0", "proto", "252"]
        assert pin_command("2001:db8::1", None, "eth0")[:5] == ["ip", "-6", "route", "replace", "2001:db8::1/128"]

    async def test_hostname_endpoint_refused(self):
        from zkvpn.protocol.routing import RouteManager
        assert await RouteManager("zkvpn0").enable("vpn.example.com") is False

    def test_nat_rules_isolate_clients_and_masquerade(self):
        from zkvpn.protocol.routing import nat_rules
        rules = nat_rules("zkvpn0", "10.0.0.0/24")
        flat = [" ".join(r) for r in rules]
        assert any("-s 10.0.0.0/24 ! -o zkvpn0 -j MASQUERADE" in r for r in flat)
        drop = next(i for i, r in enumerate(flat) if "-i zkvpn0 -o zkvpn0 -j DROP" in r)
        accept = next(i for i, r in enumerate(flat) if "-A ZKVPN_FWD -i zkvpn0 -j ACCEPT" in r)
        assert drop < accept            # client-to-client dropped before the generic accept
        assert flat[-1].startswith("iptables -I FORWARD 1")   # activated last


class TestErrorMessages:
    def test_wireguard_go_banner_is_reduced_to_the_real_error(self):
        from zkvpn.protocol.wireguard import _stderr_text
        banner = ("┌────────────┐\n│ WARNING    │\n└────────────┘\n"
                  "ERROR: (zkvpn0) 2026/10/10 Failed to create TUN device: permission denied\n")
        err = subprocess.CalledProcessError(1, "wireguard-go", stderr=banner.encode())   # bytes!
        assert _stderr_text(err) == "ERROR: (zkvpn0) 2026/10/10 Failed to create TUN device: permission denied"

    def test_error_reported_on_stdout_is_found(self):
        from zkvpn.protocol.wireguard import _stderr_text
        err = subprocess.CalledProcessError(1, "wireguard-go", output=b"ERROR: tun denied\n",
                                            stderr=b"\xe2\x94\x94\xe2\x94\x80\n")
        assert _stderr_text(err) == "ERROR: tun denied"

    def test_empty_stderr(self):
        from zkvpn.protocol.wireguard import _stderr_text
        assert _stderr_text(subprocess.CalledProcessError(1, "x", stderr=None)) == "no output"


class TestKeyHandling:
    """A client must never inherit the server's configured private key."""

    async def test_client_generates_its_own_key_even_if_a_server_key_is_configured(self, monkeypatch):
        from pydantic import SecretStr
        from zkvpn.core.config import settings
        monkeypatch.setattr(settings, "private_key", SecretStr("SERVERKEY" + "A" * 35))
        wg = WireGuardInterface("test0")
        generated = []

        def fake_keypair():
            generated.append(True)
            wg.private_key, wg.public_key = "fresh-priv", "fresh-pub"
            return "fresh-priv", "fresh-pub"

        with patch.object(wg, "generate_keypair", side_effect=fake_keypair), \
             patch("subprocess.run") as run, \
             patch("asyncio.create_subprocess_exec") as proc:
            run.return_value.returncode = 0
            proc.return_value.communicate = AsyncMock(return_value=(b"", b""))
            proc.return_value.returncode = 0
            await wg.configure_interface()
        assert generated and wg.private_key == "fresh-priv"

    async def test_server_uses_the_configured_key(self, monkeypatch):
        from pydantic import SecretStr
        key = "S" * 43 + "="
        from zkvpn.core.config import settings
        monkeypatch.setattr(settings, "private_key", SecretStr(key))
        tunnel = ZKTunnel(WireGuardInterface("test0"))      # not the shared global interface
        with patch.object(WireGuardInterface, "configure_interface", AsyncMock(return_value=True)) as cfg, \
             patch.object(WireGuardInterface, "set_address", AsyncMock(return_value=True)), \
             patch.object(tunnel, "_enable_ip_forwarding", AsyncMock()), \
             patch.object(tunnel.nat, "enable", AsyncMock(return_value=True)), \
             patch("zkvpn.protocol.tunnel.AdmissionServer.start", AsyncMock()):
            assert await tunnel.start_server() is True
        cfg.assert_awaited_once_with(key)
        tunnel._health_check_task.cancel()
