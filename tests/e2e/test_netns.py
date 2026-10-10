"""End-to-end tests on a real (virtual) network: Linux network namespaces.

    zk-cli  10.9.0.2 ──┐
                       ├── zk-isp (router 10.9.0.254 / 10.8.0.254 / 192.0.2.254)
    zk-srv  10.8.0.1 ──┤
                       │
    zk-web  192.0.2.10 ┘   (TCP service that answers with the address it sees)

Real `zkvpn serve` / `zkvpn connect` processes, real WireGuard (kernel module or
wireguard-go), real iptables, real Groth16 proofs. They verify the *behaviour*:
the web site sees the VPN server's address instead of the client's, unauthorised
clients are refused, the kill-switch really stops leaks, disconnect restores
everything.

Needs root, `ip`, `wg`, `iptables`, WireGuard (kernel or wireguard-go) and the
built ZK circuit. Run:  sudo -E env PATH=$PATH pytest -m e2e tests/e2e
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import time

import pytest

from zkvpn.zk import SnarkBackend

pytestmark = pytest.mark.e2e

CLI, SRV, ISP, WEB = "zk-cli", "zk-srv", "zk-isp", "zk-web"
CLI_IP, SRV_IP, WEB_IP = "10.9.0.2", "10.8.0.1", "192.0.2.10"
WEB_PORT = 9000
SRV_IF, CLI_IF = "zksrv0", "zkcli0"


def _have_wireguard() -> bool:
    if shutil.which("wireguard-go"):
        return True
    r = subprocess.run(["ip", "link", "add", "zkprobe0", "type", "wireguard"],
                       capture_output=True)
    subprocess.run(["ip", "link", "del", "zkprobe0"], capture_output=True)
    return r.returncode == 0


def _can_netns() -> bool:
    if os.geteuid() != 0 or not shutil.which("ip"):
        return False
    r = subprocess.run(["ip", "netns", "add", "zkprobe"], capture_output=True)
    subprocess.run(["ip", "netns", "del", "zkprobe"], capture_output=True)
    return r.returncode == 0


_SKIP = None
if not _can_netns():
    _SKIP = "needs root and network namespaces"
elif not (shutil.which("wg") and shutil.which("iptables")):
    _SKIP = "needs wg and iptables"
elif not _have_wireguard():
    _SKIP = "needs kernel WireGuard or wireguard-go"
elif not SnarkBackend().available:
    _SKIP = "run scripts/setup_circuits.sh first"
if _SKIP:
    pytestmark = [pytest.mark.e2e, pytest.mark.skip(reason=_SKIP)]


# --------------------------------------------------------------------------- helpers

def sh(*args, ns=None, check=True, timeout=60, env=None, input=None, **kw):
    cmd = list(args)
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.run(cmd, capture_output=True, text=True, check=check,
                          timeout=timeout, env=env, input=input, **kw)


def zkvpn(*args, ns, env_extra=None, check=False, timeout=90):
    env = {**os.environ, "ZKVPN_DNS_PROTECTION_ENABLED": "false", **(env_extra or {})}
    return sh(sys.executable, "-m", "zkvpn.cli.main", *args, ns=ns, env=env,
              check=check, timeout=timeout, cwd="/tmp")


def ns_kill_all(ns):
    for pid in sh("ip", "netns", "pids", ns, check=False).stdout.split():
        try:
            os.kill(int(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def probe(timeout=3):
    """From the client namespace, ask the web site who it sees. None = unreachable."""
    code = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(%d)\n"
        "try:\n s.connect(('%s',%d)); print(s.makefile().readline().strip())\n"
        "except Exception: print('FAIL')\n" % (timeout, WEB_IP, WEB_PORT))
    out = sh(sys.executable, "-c", code, ns=CLI, check=False, timeout=timeout + 5).stdout.strip()
    return None if out in ("", "FAIL") else out


def isp_leak_packets():
    """Packets the client sent straight to the web site through the ISP router."""
    out = sh("iptables", "-L", "FORWARD", "-v", "-n", "-x", ns=ISP).stdout
    for line in out.splitlines():
        if CLI_IP in line and WEB_IP in line:
            return int(line.split()[0])
    raise AssertionError("ISP counter rule missing")


def chains(ns):
    return sh("iptables-save", ns=ns, check=False).stdout


def wait_for(cond, timeout=30, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.3)
    raise AssertionError(f"timeout waiting for {what}")


# --------------------------------------------------------------------------- topology

@pytest.fixture(scope="module")
def topology():
    procs = []
    for ns in (CLI, SRV, ISP, WEB):
        sh("ip", "netns", "del", ns, check=False)
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)
    links = [  # (ns_a, if_a, ip_a, ns_b, if_b, ip_b)
        (CLI, "c0", CLI_IP + "/24", ISP, "i-c", "10.9.0.254/24"),
        (SRV, "s0", SRV_IP + "/24", ISP, "i-s", "10.8.0.254/24"),
        (WEB, "w0", WEB_IP + "/24", ISP, "i-w", "192.0.2.254/24"),
    ]
    for na, ia, ipa, nb, ib, ipb in links:
        sh("ip", "link", "add", ia, "type", "veth", "peer", "name", ib)
        sh("ip", "link", "set", ia, "netns", na)
        sh("ip", "link", "set", ib, "netns", nb)
        for ns, ifn, ip in ((na, ia, ipa), (nb, ib, ipb)):
            sh("ip", "addr", "add", ip, "dev", ifn, ns=ns)
            sh("ip", "link", "set", ifn, "up", ns=ns)
    sh("ip", "route", "add", "default", "via", "10.9.0.254", ns=CLI)
    sh("ip", "route", "add", "default", "via", "10.8.0.254", ns=SRV)
    sh("ip", "route", "add", "default", "via", "192.0.2.254", ns=WEB)
    sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=ISP)
    # counts anything the client sends directly to the web site (= a leak)
    sh("iptables", "-A", "FORWARD", "-s", CLI_IP, "-d", WEB_IP, "-j", "ACCEPT", ns=ISP)

    web_code = (
        "import socketserver\n"
        "class H(socketserver.StreamRequestHandler):\n"
        " def handle(self): self.wfile.write(('you_are=%%s\\n' %% self.client_address[0]).encode())\n"
        "socketserver.ThreadingTCPServer.allow_reuse_address=True\n"
        "socketserver.ThreadingTCPServer(('%s',%d),H).serve_forever()\n" % (WEB_IP, WEB_PORT))
    procs.append(subprocess.Popen(
        ["ip", "netns", "exec", WEB, sys.executable, "-c", web_code],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    wait_for(lambda: probe(1) is not None, 15, "direct path to web site")
    yield
    for p in procs:
        p.kill()
    for ns in (CLI, SRV, ISP, WEB):
        ns_kill_all(ns)
        sh("ip", "netns", "del", ns, check=False)


@pytest.fixture(scope="module")
def identities(tmp_path_factory):
    import asyncio
    from zkvpn.zk import public_identity, save_identity
    d = tmp_path_factory.mktemp("ids")
    out = {}
    for name in ("alice", "mallory"):
        path = str(d / name)
        sk = save_identity(path)
        out[name] = (path, asyncio.run(public_identity(sk)))
    return out


@pytest.fixture(scope="module")
def server(topology, identities):
    private = sh("wg", "genkey").stdout.strip()
    public = sh("wg", "pubkey", input=private).stdout.strip()
    env = {**os.environ,
           "ZKVPN_PRIVATE_KEY": private,
           "ZKVPN_WIREGUARD_INTERFACE": SRV_IF,
           "ZKVPN_AUTHORIZED_IDENTITIES": identities["alice"][1],   # mallory is NOT listed
           "ZKVPN_LOG_LEVEL": "DEBUG"}
    proc = subprocess.Popen(
        ["ip", "netns", "exec", SRV, sys.executable, "-m", "zkvpn.cli.main", "serve"],
        env=env, cwd="/tmp", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        wait_for(lambda: ":51821" in sh("ss", "-ltn", ns=SRV, check=False).stdout, 40,
                 "admission server")
    except AssertionError:
        proc.kill()
        raise AssertionError("server did not start:\n" + (proc.stdout.read() or ""))
    yield {"public": public, "proc": proc}
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(20)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise AssertionError("server did not stop on SIGTERM")
    leftovers = chains(SRV)
    assert "ZKVPN" not in leftovers, "server left firewall rules behind:\n" + leftovers


@pytest.fixture
def clean_client(server):
    """Each test starts from a pristine client and leaves nothing behind."""
    def reset():
        ns_kill_all(CLI)                      # only processes inside the client namespace
        zkvpn("disconnect", ns=CLI, env_extra={"ZKVPN_WIREGUARD_INTERFACE": CLI_IF})
        sh("ip", "route", "flush", "proto", "252", ns=CLI, check=False)
        sh("ip", "link", "del", CLI_IF, ns=CLI, check=False)
    reset()
    yield
    reset()


def connect(server, identity=None, env_extra=None):
    args = ["connect", "-e", f"{SRV_IP}:51820", "-k", server["public"]]
    if identity:
        args += ["-i", identity]
    return zkvpn(*args, ns=CLI, env_extra={"ZKVPN_WIREGUARD_INTERFACE": CLI_IF,
                                            **(env_extra or {})})


# --------------------------------------------------------------------------- scenarios

def test_baseline_client_reaches_web_directly(topology):
    assert probe() == f"you_are={CLI_IP}"


def test_vpn_hides_client_address_behind_server(server, identities, clean_client):
    before = isp_leak_packets()
    r = connect(server, identities["alice"][0])
    assert r.returncode == 0, r.stdout + r.stderr
    # NAT + routing + admission + WireGuard handshake all have to work for this:
    assert probe(8) == f"you_are={SRV_IP}"
    assert isp_leak_packets() == before, "traffic must go through the tunnel, not around it"


def test_client_without_proof_is_refused_and_nothing_changes(server, clean_client):
    before = isp_leak_packets()
    r = connect(server, identity=None)
    assert r.returncode == 0, r.stdout + r.stderr   # client side has nothing to object to
    # ...but the server never admitted it (no peer), so nothing flows, and nothing leaks
    assert probe(3) is None
    assert isp_leak_packets() == before


def test_unlisted_identity_is_refused(server, identities, clean_client):
    r = connect(server, identities["mallory"][0])
    assert r.returncode != 0, "an identity absent from the allow-list must not connect"
    assert "ZKVPN_KILLSWITCH" not in chains(CLI)          # nothing half-configured
    assert "proto 252" not in sh("ip", "route", ns=CLI).stdout
    assert probe() == f"you_are={CLI_IP}"                   # client keeps its normal path


def test_killswitch_stops_leak_when_tunnel_dies(server, identities, clean_client):
    assert connect(server, identities["alice"][0]).returncode == 0
    assert probe(8) == f"you_are={SRV_IP}"
    before = isp_leak_packets()
    # the tunnel dies abruptly (WireGuard process killed -> interface and routes vanish)
    ns_kill_all(CLI)
    wait_for(lambda: sh("ip", "link", "show", CLI_IF, ns=CLI, check=False).returncode != 0,
             10, "tunnel interface to vanish")
    assert "dev zkcli0" not in sh("ip", "route", ns=CLI).stdout, "routes should be gone with the link"
    assert probe(3) is None, "kill-switch must block the direct path"
    assert isp_leak_packets() == before, "no packet may reach the web site outside the tunnel"


def test_without_killswitch_the_same_failure_leaks(server, identities, clean_client):
    """Control experiment: proves the previous test can actually detect a leak."""
    r = connect(server, identities["alice"][0], {"ZKVPN_KILLSWITCH_ENABLED": "false"})
    assert r.returncode == 0, r.stdout + r.stderr
    before = isp_leak_packets()
    ns_kill_all(CLI)
    wait_for(lambda: sh("ip", "link", "show", CLI_IF, ns=CLI, check=False).returncode != 0,
             10, "tunnel interface to vanish")
    assert probe(5) == f"you_are={CLI_IP}"                  # traffic escaped in clear
    assert isp_leak_packets() > before


def test_disconnect_restores_everything(server, identities, clean_client):
    assert connect(server, identities["alice"][0]).returncode == 0
    assert probe(8) == f"you_are={SRV_IP}"
    r = zkvpn("disconnect", ns=CLI, env_extra={"ZKVPN_WIREGUARD_INTERFACE": CLI_IF})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ZKVPN" not in chains(CLI)
    assert "proto 252" not in sh("ip", "route", ns=CLI).stdout
    assert sh("ip", "link", "show", CLI_IF, ns=CLI, check=False).returncode != 0
    assert probe() == f"you_are={CLI_IP}"


def test_server_installs_nat_and_isolation_rules(server):
    rules = chains(SRV)
    assert "ZKVPN_NAT" in rules and "ZKVPN_FWD" in rules      # present while running
    assert "-i zksrv0 -o zksrv0 -j DROP" in rules             # clients isolated from each other
