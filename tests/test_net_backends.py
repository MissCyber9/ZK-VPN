"""macOS and Windows network backends, and backend selection.

Command construction and output parsing are pure functions, so they are verified here on every
operating system. Behaviour (ordering, rollback, name propagation) is tested with fake runners.
"""

import json
from unittest.mock import AsyncMock

import pytest

from zkvpn.platform import UnsupportedPlatform
from zkvpn.platform.net import CLIENT, DNS, KILLSWITCH, ROUTES, SERVER, get_backend
from zkvpn.platform.net import macos, windows
from zkvpn.platform.net._exec import check_name, ps_quote
from zkvpn.platform.net.base import NetBackend

SERVER_KEY = "S" * 43 + "="


class TestBackendSelection:
    def test_linux_has_every_feature(self):
        be = get_backend("linux")
        assert be.name == "Linux" and be.features == {CLIENT, ROUTES, KILLSWITCH, DNS, SERVER}

    @pytest.mark.parametrize("name,label", [("darwin", "macOS"), ("win32", "Windows")])
    def test_other_systems_are_clients_only(self, name, label):
        be = get_backend(name)
        assert be.name == label
        assert be.features == {CLIENT, ROUTES, KILLSWITCH, DNS}
        assert not be.supports(SERVER)
        with pytest.raises(UnsupportedPlatform, match="server"):
            be.make_nat("zkvpn0", "10.0.0.0/24")

    def test_unknown_system_degrades_instead_of_crashing(self):
        be = get_backend("freebsd14")
        assert be.features == frozenset()
        with pytest.raises(UnsupportedPlatform):
            be.make_interface("zkvpn0")

    def test_every_backend_builds_its_components_without_touching_the_os(self):
        for name in ("linux", "darwin", "win32"):
            be = get_backend(name)
            for make in (be.make_interface, be.make_routes, be.make_killswitch, be.make_dns):
                assert make("zkvpn0") is not None


class TestInjectionSafety:
    @pytest.mark.parametrize("bad", ["x'; Remove-Item C:\\ -Recurse; '", "a$(calc)", "name\nnext", "", "a" * 65])
    def test_unsafe_names_are_refused(self, bad):
        with pytest.raises(ValueError):
            check_name(bad)

    def test_quotes_are_doubled(self):
        assert ps_quote("it's") == "'it''s'"

    def test_windows_scripts_refuse_hostile_input(self):
        with pytest.raises(ValueError):
            windows.new_route_script("0.0.0.0/1", "0.0.0.0", alias="zk'; calc; '")
        with pytest.raises(ValueError):
            windows.new_route_script("not-a-prefix", "0.0.0.0", alias="zkvpn0")
        with pytest.raises(ValueError):
            windows.killswitch_enable_script("zkvpn0", ["1.2.3.4:51820; calc"])
        with pytest.raises(ValueError):
            windows.killswitch_enable_script("zkvpn0", ["vpn.example.com:51820"])


class TestMacOSParsing:
    ROUTE_GET = """   route to: 203.0.113.5
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
"""

    def test_route_get(self):
        assert macos.parse_route_get(self.ROUTE_GET) == ("192.168.1.1", "en0")
        assert macos.parse_route_get("  interface: en0\n") == (None, "en0")      # on-link

    def test_pf_rules_pass_before_the_final_block(self):
        rules = macos.pf_rules("utun7", ["203.0.113.5:51820", "[2001:db8::1]:51820"]).splitlines()
        assert rules[0] == "pass out quick on lo0 all"
        assert "pass out quick on utun7 all" in rules
        assert "pass out quick inet proto udp to 203.0.113.5 port 51820" in rules
        assert "pass out quick inet6 proto udp to 2001:db8::1 port 51820" in rules
        assert rules[-1] == "block drop out all"                     # nothing after the catch-all

    def test_pf_rules_reject_hostnames_and_garbage(self):
        for bad in ("vpn.example.com:51820", "1.2.3.4", "1.2.3.4:abc"):
            with pytest.raises(ValueError):
                macos.pf_rules("utun7", [bad])

    def test_pf_dns_rules(self):
        rules = macos.pf_dns_rules("utun7")
        assert rules.index("pass out quick on utun7") < rules.index("block drop out quick")
        assert "53 853" in rules

    def test_pf_token(self):
        assert macos.parse_pf_token("pf enabled\nToken : 12345678901234\n") == "12345678901234"
        assert macos.parse_pf_token("nothing") is None

    def test_network_services_skip_the_note_and_disabled_ones(self):
        out = ("An asterisk (*) denotes that a network service is disabled.\n"
               "Wi-Fi\nThunderbolt Bridge\n*USB 10/100 LAN\n")
        assert macos.parse_network_services(out) == ["Wi-Fi", "Thunderbolt Bridge"]

    def test_dns_servers(self):
        assert macos.parse_dns_servers("1.1.1.1\n8.8.8.8\n") == ["1.1.1.1", "8.8.8.8"]
        assert macos.parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n") == []

    def test_scutil_dns(self):
        out = "  nameserver[0] : 192.168.1.1\n  nameserver[1] : 8.8.8.8\n  nameserver[0] : 192.168.1.1\n"
        assert macos.parse_scutil_dns(out) == ["192.168.1.1", "8.8.8.8"]

    def test_ipv6_leak_detection_ignores_the_tunnel_and_link_local(self):
        ifconfig = ("lo0: flags=8049<UP>\n\tinet6 ::1 prefixlen 128\n"
                    "en0: flags=8863<UP>\n\tinet6 fe80::1%en0 prefixlen 64\n"
                    "utun7: flags=8051<UP>\n\tinet6 2001:db8::5 prefixlen 64\n")
        assert macos.has_global_ipv6(ifconfig, "utun7") is False
        assert macos.has_global_ipv6(ifconfig + "en0: flags=8863<UP>\n\tinet6 2001:db8::9 prefixlen 64\n",
                                     "utun7") is True


class TestWindowsParsing:
    def test_tunnel_config(self):
        cfg = windows.tunnel_config(SERVER_KEY, 51820)
        assert cfg.startswith("[Interface]\n") and f"PrivateKey = {SERVER_KEY}" in cfg and "ListenPort = 51820" in cfg
        assert "[Peer]" not in cfg

    def test_find_netroute(self):
        assert windows.parse_find_netroute('{"InterfaceIndex":12,"NextHop":"192.168.1.1"}') == (12, "192.168.1.1")
        assert windows.parse_find_netroute('[{"InterfaceIndex":7,"NextHop":"0.0.0.0"}]') == (7, "0.0.0.0")
        assert windows.parse_find_netroute("garbage") == (None, None)

    def test_route_scripts(self):
        assert windows.new_route_script("0.0.0.0/1", "0.0.0.0", alias="zkvpn0") == (
            "New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'zkvpn0' -NextHop '0.0.0.0' "
            "-RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null")
        assert "-InterfaceIndex 12" in windows.new_route_script("203.0.113.5/32", "192.168.1.1", index=12)
        assert "Remove-NetRoute" in windows.remove_route_script("0.0.0.0/1")

    def test_killswitch_allows_first_and_blocks_last(self):
        script = windows.killswitch_enable_script("zkvpn0", ["203.0.113.5:51820"])
        steps = script.split("; ")
        assert steps[-1] == "Set-NetFirewallProfile -All -DefaultOutboundAction Block"
        assert all("Set-NetFirewallProfile" not in s for s in steps[:-1])
        assert any("-InterfaceAlias 'zkvpn0'" in s for s in steps)
        assert any("-RemoteAddress '203.0.113.5' -RemotePort 51820" in s for s in steps)

    def test_killswitch_restore_uses_the_saved_policy(self):
        previous = windows.parse_firewall_profiles(json.dumps([
            {"Name": "Domain", "DefaultOutboundAction": 0}, {"Name": "Public", "DefaultOutboundAction": 2}]))
        script = windows.killswitch_disable_script(previous)
        assert "-Name 'Domain' -DefaultOutboundAction Allow" in script
        assert "-Name 'Public' -DefaultOutboundAction Block" in script
        assert script.endswith("-ErrorAction SilentlyContinue")        # rules removed last
        # nothing saved (crash before the snapshot): fail open rather than leave the user offline
        assert "-All -DefaultOutboundAction Allow" in windows.killswitch_disable_script({})

    def test_dns_block_covers_other_adapters_only(self):
        script = windows.dns_block_script("zkvpn0", ["Ethernet", "Wi-Fi"])
        assert script.count("-InterfaceAlias 'Ethernet','Wi-Fi'") == 2          # udp and tcp
        assert "zkvpn0" not in script
        assert windows.dns_block_script("zkvpn0", []) == "$null"


class FakeRun:
    """Records commands; answers from a script of (prefix -> result)."""

    def __init__(self, answers=None, fail=()):
        self.calls, self.answers, self.fail = [], answers or {}, fail

    async def __call__(self, *cmd, **kw):
        self.calls.append(cmd)
        for prefix, result in self.answers.items():
            if cmd[:len(prefix)] == prefix:
                return result
        return (1, "", "boom") if any(cmd[:len(f)] == f for f in self.fail) else (0, "", "")


@pytest.fixture
def state(tmp_path, monkeypatch):
    from zkvpn.core.config import settings
    monkeypatch.setattr(settings, "state_dir", str(tmp_path / "state"))
    return tmp_path / "state"


class TestMacRoutes:
    ROUTE = ("route", "-n", "get", "203.0.113.5")

    async def test_pins_the_server_before_capturing_everything(self, monkeypatch, state):
        fake = FakeRun({self.ROUTE: (0, TestMacOSParsing.ROUTE_GET, "")})
        monkeypatch.setattr(macos, "run", fake)
        assert await macos.MacRouteManager("utun7").enable("203.0.113.5") is True
        cmds = [" ".join(c) for c in fake.calls]
        pin = next(i for i, c in enumerate(cmds) if "-host 203.0.113.5 192.168.1.1" in c)
        first_half = next(i for i, c in enumerate(cmds) if "0.0.0.0/1 -interface utun7" in c)
        assert pin < first_half                        # the WireGuard packets must not loop into the tunnel
        assert any("-inet6 ::/1" in c for c in cmds)   # IPv6 cannot bypass the tunnel

    async def test_rolls_back_when_a_route_fails(self, monkeypatch, state):
        fake = FakeRun({self.ROUTE: (0, TestMacOSParsing.ROUTE_GET, "")},
                       fail=[("route", "-q", "-n", "add", "-inet", "128.0.0.0/1")])
        monkeypatch.setattr(macos, "run", fake)
        assert await macos.MacRouteManager("utun7").enable("203.0.113.5") is False
        assert any(c[:4] == ("route", "-n", "delete", "-host") for c in fake.calls)   # pinned route removed

    async def test_refuses_hostnames(self, monkeypatch, state):
        monkeypatch.setattr(macos, "run", FakeRun())
        assert await macos.MacRouteManager("utun7").enable("vpn.example.com") is False

    async def test_disable_works_from_another_process(self, monkeypatch, state):
        fake = FakeRun({self.ROUTE: (0, TestMacOSParsing.ROUTE_GET, "")})
        monkeypatch.setattr(macos, "run", fake)
        await macos.MacRouteManager("utun7").enable("203.0.113.5")
        fake.calls.clear()
        await macos.MacRouteManager("utun7").disable()                  # a fresh object, as in `disconnect`
        assert any(c[:5] == ("route", "-n", "delete", "-host", "203.0.113.5") for c in fake.calls)


class TestMacKillSwitch:
    async def test_pf_is_enabled_loaded_and_fully_undone(self, monkeypatch, state):
        fake = FakeRun({("pfctl", "-E"): (0, "", "pf enabled\nToken : 42\n")})
        monkeypatch.setattr(macos, "run", fake)
        ks = macos.MacKillSwitch("utun7")
        assert await ks.enable(["203.0.113.5:51820"]) is True and ks.active
        loaded = [c for c in fake.calls if c[:3] == ("pfctl", "-a", macos.PF_ANCHOR) and "-f" in c]
        assert loaded
        await macos.MacKillSwitch("utun7").disable()                    # separate process
        assert ("pfctl", "-X", "42") in fake.calls                      # the pf token we took is released
        assert any(c[:5] == ("pfctl", "-a", macos.PF_ANCHOR, "-F", "all") for c in fake.calls)

    async def test_failed_load_does_not_leave_pf_on(self, monkeypatch, state):
        fake = FakeRun({("pfctl", "-E"): (0, "", "Token : 7\n")}, fail=[("pfctl", "-a")])
        monkeypatch.setattr(macos, "run", fake)
        ks = macos.MacKillSwitch("utun7")
        assert await ks.enable(["203.0.113.5:51820"]) is False and not ks.active
        assert ("pfctl", "-X", "7") in fake.calls


class TestWindowsKillSwitch:
    async def test_snapshot_before_changing_and_rollback_on_failure(self, monkeypatch, state):
        calls = []

        async def fake_ps(script, timeout=60.0):
            calls.append(script)
            if script.startswith("Get-NetFirewallProfile"):
                return 0, json.dumps([{"Name": "Public", "DefaultOutboundAction": 0}]), ""
            if "DefaultOutboundAction Block" in script:
                return 1, "", "access denied"
            return 0, "", ""

        monkeypatch.setattr(windows, "powershell", fake_ps)
        ks = windows.WindowsKillSwitch("zkvpn0")
        assert await ks.enable(["203.0.113.5:51820"]) is False and not ks.active
        assert calls[0].startswith("Get-NetFirewallProfile")            # snapshot first
        assert "-Name 'Public' -DefaultOutboundAction Allow" in calls[-1]  # policy restored

    async def test_state_survives_for_a_separate_disconnect(self, monkeypatch, state):
        seen = []

        async def fake_ps(script, timeout=60.0):
            seen.append(script)
            if script.startswith("Get-NetFirewallProfile"):
                return 0, json.dumps({"Name": "Private", "DefaultOutboundAction": 2}), ""
            return 0, "", ""

        monkeypatch.setattr(windows, "powershell", fake_ps)
        await windows.WindowsKillSwitch("zkvpn0").enable(["203.0.113.5:51820"])
        await windows.WindowsKillSwitch("zkvpn0").disable()
        assert "-Name 'Private' -DefaultOutboundAction Block" in seen[-1]


class TestWindowsRoutes:
    async def test_order_and_cleanup(self, monkeypatch, state):
        scripts = []

        async def fake_ps(script, timeout=60.0):
            scripts.append(script)
            if script.startswith("Find-NetRoute"):
                return 0, '{"InterfaceIndex":12,"NextHop":"192.168.1.1"}', ""
            return 0, "", ""

        monkeypatch.setattr(windows, "powershell", fake_ps)
        assert await windows.WindowsRouteManager("zkvpn0").enable("203.0.113.5") is True
        main = next(s for s in scripts if "New-NetRoute" in s)
        assert main.index("203.0.113.5/32") < main.index("0.0.0.0/1") < main.index("128.0.0.0/1")
        await windows.WindowsRouteManager("zkvpn0").disable()
        assert "203.0.113.5/32" in scripts[-1] and "0.0.0.0/1" in scripts[-1]


class TestTunnelWithAnyBackend:
    """The tunnel only talks to the backend interface, so a fake one exercises the macOS-style flow."""

    def make_backend(self, features, interface):
        from types import SimpleNamespace as NS
        made = NS(killswitch=NS(interface="zkvpn0", enable=AsyncMock(return_value=True),
                                disable=AsyncMock(), active=False),
                  routes=NS(interface="zkvpn0", enable=AsyncMock(return_value=True), disable=AsyncMock()),
                  dns=NS(interface="zkvpn0"))
        return made, NetBackend(
            name="Fake", features=frozenset(features),
            make_interface=lambda name: interface,
            make_routes=lambda name: made.routes, make_killswitch=lambda name: made.killswitch,
            make_dns=lambda name: made.dns, make_nat=lambda name, cidr: None)

    def fake_interface(self, renamed_to):
        from types import SimpleNamespace as NS
        iface = NS(interface="zkvpn0", is_initialized=False, public_key=SERVER_KEY, address="0.0.0.0")

        async def configure(private_key=None):
            iface.interface, iface.is_initialized = renamed_to, True      # the OS picks the name
            return True

        iface.configure_interface = configure
        iface.set_address = AsyncMock(return_value=True)
        iface.add_peer = AsyncMock(return_value=True)
        iface.bring_up = AsyncMock()
        iface.get_status = AsyncMock(return_value={"peers": []})
        return iface

    async def test_os_chosen_interface_name_reaches_every_component(self):
        from zkvpn.protocol.tunnel import ZKTunnel
        iface = self.fake_interface("utun7")
        made, be = self.make_backend({CLIENT, ROUTES, KILLSWITCH, DNS}, iface)
        tunnel = ZKTunnel(backend=be)
        assert await tunnel.connect("203.0.113.5:51820", SERVER_KEY) is True
        assert made.killswitch.interface == made.routes.interface == made.dns.interface == "utun7"
        made.killswitch.enable.assert_awaited_once_with(["203.0.113.5:51820"])
        made.routes.enable.assert_awaited_once_with("203.0.113.5")
        tunnel._health_check_task.cancel()

    async def test_a_client_only_backend_refuses_to_serve(self):
        from zkvpn.protocol.tunnel import ZKTunnel
        _, be = self.make_backend({CLIENT, ROUTES, KILLSWITCH, DNS}, self.fake_interface("utun7"))
        assert await ZKTunnel(backend=be).start_server() is False

    async def test_connect_fails_closed_if_routing_cannot_be_installed(self):
        from zkvpn.protocol.tunnel import ZKTunnel
        made, be = self.make_backend({CLIENT, ROUTES, KILLSWITCH, DNS}, self.fake_interface("utun7"))
        made.routes.enable = AsyncMock(return_value=False)
        assert await ZKTunnel(backend=be).connect("203.0.113.5:51820", SERVER_KEY) is False
