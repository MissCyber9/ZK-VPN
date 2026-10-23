"""End-to-end tests on a real (virtual) network: Linux network namespaces.

    zk-cli   10.9.0.2   ──┐
    zk-cli2  10.9.1.2   ──┤
                          ├── zk-isp (router; also routes IPv6 fd00:9::/64 <-> fd00:2::/64)
    zk-srv   10.8.0.1   ──┤
    zk-web   192.0.2.10 ──┘   TCP service answering with the address it sees (+ DNS server)

Real `zkvpn serve` / `zkvpn connect` processes, real WireGuard (kernel module or
wireguard-go), real iptables, real Groth16 proofs. They verify the *behaviour*:
the web site sees the VPN server's address instead of the client's, unauthorised
clients are refused, the kill-switch really stops leaks, DNS goes through the tunnel
and is restored, clients cannot reach each other, IPv6 does not leak, disconnect
restores everything.

Needs root, `ip`, `wg`, `iptables`, WireGuard (kernel or wireguard-go) and the
built ZK circuit. Run:  sudo -E env PATH=$PATH pytest -m e2e tests/e2e
"""

import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

from zkvpn.zk import SnarkBackend

pytestmark = pytest.mark.e2e

CLI, CLI2, SRV, ISP, WEB = "zk-cli", "zk-cli2", "zk-srv", "zk-isp", "zk-web"
ALL_NS = (CLI, CLI2, SRV, ISP, WEB)
CLI_IP, CLI2_IP, SRV_IP, WEB_IP = "10.9.0.2", "10.9.1.2", "10.8.0.1", "192.0.2.10"
CLI_IP6, WEB_IP6 = "fd00:9::2", "fd00:2::10"
WEB_PORT = 9000
SRV_IF, CLI_IF, CLI2_IF = "zksrv0", "zkcli0", "zkcli1"
DNS_LOG = "/tmp/zk-e2e-dns.log"
STATE_DIR = "/tmp/zk-e2e-state"


HAVE_V6 = os.path.exists("/proc/net/if_inet6")        # some kernels/sandboxes have no IPv6 at all
needs_v6 = pytest.mark.skipif(not HAVE_V6, reason="this kernel has no IPv6 support")


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
elif not (shutil.which("wg") and shutil.which("iptables") and shutil.which("ip6tables")):
    _SKIP = "needs wg, iptables and ip6tables"
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
    env = {**os.environ, "ZKVPN_DNS_PROTECTION_ENABLED": "false",
           "ZKVPN_STATE_DIR": f"{STATE_DIR}-{ns}", **(env_extra or {})}
    return sh(sys.executable, "-m", "zkvpn.cli.main", *args, ns=ns, env=env,
              check=check, timeout=timeout, cwd="/tmp")


def ns_kill_all(ns):
    for pid in sh("ip", "netns", "pids", ns, check=False).stdout.split():
        try:
            os.kill(int(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def probe(timeout=3, ns=CLI, v6=False):
    """From `ns`, ask the web site who it sees. None = unreachable."""
    family, addr = ("AF_INET6", WEB_IP6) if v6 else ("AF_INET", WEB_IP)
    code = (
        "import socket\n"
        "s=socket.socket(socket.%s); s.settimeout(%d)\n"
        "try:\n s.connect(('%s',%d)); print(s.makefile().readline().strip())\n"
        "except Exception: print('FAIL')\n" % (family, timeout, addr, WEB_PORT))
    out = sh(sys.executable, "-c", code, ns=ns, check=False, timeout=timeout + 5).stdout.strip()
    return None if out in ("", "FAIL") else out


def _counter(tool, src, dst):
    out = sh(tool, "-L", "FORWARD", "-v", "-n", "-x", ns=ISP).stdout
    for line in out.splitlines():
        if src in line and dst in line:
            return int(line.split()[0])
    raise AssertionError("ISP counter rule missing")


def isp_leak_packets():
    """IPv4 packets the client sent straight to the web site through the ISP router."""
    return _counter("iptables", CLI_IP, WEB_IP)


def isp_leak_packets6():
    return _counter("ip6tables", CLI_IP6, WEB_IP6)


def chains(ns):
    return sh("iptables-save", ns=ns, check=False).stdout + \
        sh("ip6tables-save", ns=ns, check=False).stdout


def tunnel_ip(ns, iface):
    out = sh("ip", "-4", "-o", "addr", "show", iface, ns=ns).stdout.split()
    return out[out.index("inet") + 1].split("/")[0]


def wait_for(cond, timeout=30, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.3)
    raise AssertionError(f"timeout waiting for {what}")


def iface_gone(ns, iface):
    return sh("ip", "link", "show", iface, ns=ns, check=False).returncode != 0


# --------------------------------------------------------------------------- topology

WEB_SERVER = """
import socket, socketserver, threading
class H(socketserver.StreamRequestHandler):
    def handle(self): self.wfile.write(('you_are=%%s\\n' %% self.client_address[0]).encode())
class V6(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
socketserver.ThreadingTCPServer.allow_reuse_address = True
if %(have_v6)s:
    try:
        threading.Thread(target=V6(('%(v6)s', %(port)d), H).serve_forever, daemon=True).start()
    except OSError as e:
        print('IPv6 listener failed:', e, flush=True)
socketserver.ThreadingTCPServer(('%(v4)s', %(port)d), H).serve_forever()
""" % {"v4": WEB_IP, "v6": WEB_IP6, "port": WEB_PORT, "have_v6": HAVE_V6}

DNS_SERVER = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('%s', 53))
while True:
    data, addr = s.recvfrom(512)
    open('%s', 'a').write(addr[0] + '\\n')
    end = 12
    while data[end] != 0: end += data[end] + 1
    question = data[12:end + 5]
    s.sendto(data[:2] + b'\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00' + question +
             b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04' + bytes([192, 0, 2, 10]), addr)
""" % (WEB_IP, DNS_LOG)


@pytest.fixture(scope="module")
def topology():
    procs = []
    try:
        yield from _build_topology(procs)
    finally:                      # never leave namespaces behind, even if setup failed halfway
        for p in procs:
            p.kill()
        for ns in ALL_NS:
            ns_kill_all(ns)
            sh("ip", "netns", "del", ns, check=False)
        shutil.rmtree(f"/etc/netns/{CLI}", ignore_errors=True)
        for ns in (CLI, CLI2):
            shutil.rmtree(f"{STATE_DIR}-{ns}", ignore_errors=True)


def _build_topology(procs):
    for ns in ALL_NS:
        sh("ip", "netns", "del", ns, check=False)
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)
    links = [  # (ns_a, if_a, ip_a, ns_b, if_b, ip_b) -- IPv6 addresses added below
        (CLI, "c0", CLI_IP + "/24", ISP, "i-c", "10.9.0.254/24"),
        (CLI2, "c0", CLI2_IP + "/24", ISP, "i-c2", "10.9.1.254/24"),
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
    sh("ip", "route", "add", "default", "via", "10.9.1.254", ns=CLI2)
    sh("ip", "route", "add", "default", "via", "10.8.0.254", ns=SRV)
    sh("ip", "route", "add", "default", "via", "192.0.2.254", ns=WEB)
    sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=ISP)
    # counters: anything the client sends straight to the web site (= a leak)
    sh("iptables", "-A", "FORWARD", "-s", CLI_IP, "-d", WEB_IP, "-j", "ACCEPT", ns=ISP)
    if HAVE_V6:   # IPv6 world: client <-> ISP <-> web (the server has none: the tunnel is IPv4-only)
        for ns, ifn, addr in ((CLI, "c0", CLI_IP6 + "/64"), (ISP, "i-c", "fd00:9::254/64"),
                              (WEB, "w0", WEB_IP6 + "/64"), (ISP, "i-w", "fd00:2::254/64")):
            # nodad: skip duplicate-address detection, otherwise the address stays "tentative"
            # for ~1s and binding a server to it fails
            sh("ip", "-6", "addr", "add", addr, "dev", ifn, "nodad", ns=ns)
        sh("ip", "-6", "route", "add", "default", "via", "fd00:9::254", ns=CLI)
        sh("ip", "-6", "route", "add", "default", "via", "fd00:2::254", ns=WEB)
        sh("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", ns=ISP)
        sh("ip6tables", "-A", "FORWARD", "-s", CLI_IP6, "-d", WEB_IP6, "-j", "ACCEPT", ns=ISP)
    # `ip netns exec` bind-mounts /etc/netns/<ns>/resolv.conf: DNS tests never touch the host's
    os.makedirs(f"/etc/netns/{CLI}", exist_ok=True)
    with open(f"/etc/netns/{CLI}/resolv.conf", "w") as f:
        f.write("nameserver 10.9.0.254\n")

    for code, ns in ((WEB_SERVER, WEB), (DNS_SERVER, WEB)):
        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", ns, sys.executable, "-c", code],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    try:
        wait_for(lambda: probe(1) is not None, 15, "direct IPv4 path to the web site")
        if HAVE_V6:
            wait_for(lambda: probe(1, v6=True) is not None, 15, "direct IPv6 path to the web site")
    except AssertionError as e:
        diag = [sh("ip", "-6", "addr", ns=WEB, check=False).stdout,
                sh("ip", "-6", "route", ns=CLI, check=False).stdout,
                sh("ss", "-ltn", ns=WEB, check=False).stdout]
        raise AssertionError(f"{e}\n--- web v6 addrs / client v6 routes / web listeners ---\n" + "\n".join(diag))
    yield


@pytest.fixture(scope="module")
def identities(tmp_path_factory):
    import asyncio
    from zkvpn.zk import public_identity, save_identity
    d = tmp_path_factory.mktemp("ids")
    out = {}
    for name in ("alice", "bob", "mallory"):
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
           # alice and bob are authorised, mallory is NOT listed
           "ZKVPN_AUTHORIZED_IDENTITIES": f"{identities['alice'][1]},{identities['bob'][1]}",
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


CLIENTS = {CLI: CLI_IF, CLI2: CLI2_IF}


@pytest.fixture
def clean_client(server):
    """Each test starts from pristine clients and leaves nothing behind."""
    def reset():
        for ns, iface in CLIENTS.items():
            ns_kill_all(ns)                   # only processes inside that client's namespace
            zkvpn("disconnect", ns=ns, env_extra={"ZKVPN_WIREGUARD_INTERFACE": iface,
                                                  "ZKVPN_DNS_PROTECTION_ENABLED": "true"})
            sh("ip", "route", "flush", "proto", "252", ns=ns, check=False)
            sh("ip", "link", "del", iface, ns=ns, check=False)
        with open(f"/etc/netns/{CLI}/resolv.conf", "w") as f:
            f.write("nameserver 10.9.0.254\n")
        open(DNS_LOG, "w").close()
    reset()
    yield
    reset()


def connect(server, identity=None, env_extra=None, ns=CLI):
    args = ["connect", "-e", f"{SRV_IP}:51820", "-k", server["public"]]
    if identity:
        args += ["-i", identity]
    return zkvpn(*args, ns=ns, env_extra={"ZKVPN_WIREGUARD_INTERFACE": CLIENTS[ns],
                                          **(env_extra or {})})


DNS_ENV = {"ZKVPN_DNS_PROTECTION_ENABLED": "true", "ZKVPN_DNS_SERVERS": WEB_IP,
           "ZKVPN_DNS_BACKEND": "file"}


def resolv(ns=CLI):
    return sh("cat", "/etc/resolv.conf", ns=ns).stdout


def resolve_from_client():
    out = sh(sys.executable, "-c",
             "import socket; print(socket.gethostbyname('some-name.test'))",
             ns=CLI, check=False, timeout=30)
    return out.stdout.strip() or None


# --------------------------------------------------------------------------- scenarios

def test_baseline_client_reaches_web_directly(topology):
    assert probe() == f"you_are={CLI_IP}"
    if HAVE_V6:
        assert probe(v6=True) == f"you_are={CLI_IP6}"


def test_vpn_hides_client_address_behind_server(server, identities, clean_client):
    before = isp_leak_packets()
    r = connect(server, identities["alice"][0])
    assert r.returncode == 0, r.stdout + r.stderr
    # NAT + routing + admission + WireGuard handshake all have to work for this:
    assert probe(8) == f"you_are={SRV_IP}"
    assert isp_leak_packets() == before, "traffic must go through the tunnel, not around it"


def test_client_without_proof_is_refused_and_nothing_leaks(server, clean_client):
    before = isp_leak_packets()
    r = connect(server, identity=None)
    assert r.returncode == 0, r.stdout + r.stderr   # client side has nothing to object to
    # ...but the server never admitted it (no peer), so nothing flows, and nothing leaks
    assert probe(3) is None
    assert isp_leak_packets() == before


def test_unlisted_identity_is_refused(server, identities, clean_client):
    r = connect(server, identities["mallory"][0])
    assert r.returncode != 0, "an identity absent from the allow-list must not connect"
    assert "ZKVPN" not in chains(CLI)                       # nothing half-configured
    assert "proto 252" not in sh("ip", "route", ns=CLI).stdout
    assert probe() == f"you_are={CLI_IP}"                   # client keeps its normal path


def test_killswitch_stops_leak_when_tunnel_dies(server, identities, clean_client):
    assert connect(server, identities["alice"][0]).returncode == 0
    assert probe(8) == f"you_are={SRV_IP}"
    before = isp_leak_packets()
    # the tunnel dies abruptly (WireGuard process killed -> interface and routes vanish)
    ns_kill_all(CLI)
    wait_for(lambda: iface_gone(CLI, CLI_IF), 10, "tunnel interface to vanish")
    assert "dev zkcli0" not in sh("ip", "route", ns=CLI).stdout, "routes should be gone with the link"
    assert probe(3) is None, "kill-switch must block the direct path"
    assert isp_leak_packets() == before, "no packet may reach the web site outside the tunnel"


def test_without_killswitch_the_same_failure_leaks(server, identities, clean_client):
    """Control experiment: proves the previous test can actually detect a leak."""
    r = connect(server, identities["alice"][0], {"ZKVPN_KILLSWITCH_ENABLED": "false"})
    assert r.returncode == 0, r.stdout + r.stderr
    before = isp_leak_packets()
    ns_kill_all(CLI)
    wait_for(lambda: iface_gone(CLI, CLI_IF), 10, "tunnel interface to vanish")
    assert probe(5) == f"you_are={CLI_IP}"                  # traffic escaped in clear
    assert isp_leak_packets() > before


def test_disconnect_restores_everything(server, identities, clean_client):
    assert connect(server, identities["alice"][0]).returncode == 0
    assert probe(8) == f"you_are={SRV_IP}"
    r = zkvpn("disconnect", ns=CLI, env_extra={"ZKVPN_WIREGUARD_INTERFACE": CLI_IF})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ZKVPN" not in chains(CLI)
    assert "proto 252" not in sh("ip", "route", ns=CLI).stdout
    assert iface_gone(CLI, CLI_IF)
    assert probe() == f"you_are={CLI_IP}"


def test_server_installs_nat_and_isolation_rules(server):
    rules = chains(SRV)
    assert "ZKVPN_NAT" in rules and "ZKVPN_FWD" in rules      # present while running
    assert "-i zksrv0 -o zksrv0 -j DROP" in rules             # clients isolated from each other


# ----- DNS -------------------------------------------------------------------------

def test_dns_goes_through_the_tunnel_and_is_restored(server, identities, clean_client):
    original = resolv()
    assert "10.9.0.254" in original
    r = connect(server, identities["alice"][0], DNS_ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"nameserver {WEB_IP}" in resolv() and "10.9.0.254" not in resolv()
    assert resolve_from_client() == "192.0.2.10"
    asked_from = open(DNS_LOG).read().split()
    assert asked_from, "the DNS server never received the query"
    # the resolver saw the VPN server's address: the query travelled through the tunnel
    assert set(asked_from) == {SRV_IP}, asked_from

    # `disconnect` is a different process: it must restore the original from persisted state
    r = zkvpn("disconnect", ns=CLI, env_extra={**DNS_ENV, "ZKVPN_WIREGUARD_INTERFACE": CLI_IF})
    assert r.returncode == 0, r.stdout + r.stderr
    assert resolv() == original
    assert "ZKVPN_DNS" not in chains(CLI)
    assert not os.path.exists(f"{STATE_DIR}-{CLI}/dns.json")


def test_plain_dns_is_blocked_outside_the_tunnel(server, identities, clean_client):
    """DNS protection alone (kill-switch off) must stop plain DNS if the tunnel dies."""
    env = {**DNS_ENV, "ZKVPN_KILLSWITCH_ENABLED": "false"}
    assert connect(server, identities["alice"][0], env).returncode == 0
    ns_kill_all(CLI)
    wait_for(lambda: iface_gone(CLI, CLI_IF), 10, "tunnel interface to vanish")
    open(DNS_LOG, "w").close()
    assert probe(4) == f"you_are={CLI_IP}"       # non-DNS traffic escapes (kill-switch is off)...
    assert resolve_from_client() is None          # ...but DNS does not
    assert open(DNS_LOG).read().strip() == "", "a DNS query leaked to the resolver"


# ----- several clients ----------------------------------------------------------------

def test_two_clients_work_together_but_cannot_reach_each_other(server, identities, clean_client):
    assert connect(server, identities["alice"][0], ns=CLI).returncode == 0
    assert connect(server, identities["bob"][0], ns=CLI2).returncode == 0
    assert probe(8, ns=CLI) == f"you_are={SRV_IP}"
    assert probe(8, ns=CLI2) == f"you_are={SRV_IP}"
    alice, bob = tunnel_ip(CLI, CLI_IF), tunnel_ip(CLI2, CLI2_IF)
    assert alice != bob, "each client must get its own address"

    ping = lambda ns, ip: sh("ping", "-c", "2", "-W", "2", ip, ns=ns, check=False).returncode == 0
    assert ping(SRV, alice) and ping(SRV, bob), "the server reaches both (tunnels are up)"
    assert not ping(CLI, bob), "client-to-client traffic through the server must be dropped"
    assert not ping(CLI2, alice)


# ----- IPv6 ---------------------------------------------------------------------------

@needs_v6
def test_ipv6_does_not_leak_around_the_tunnel(server, identities, clean_client):
    before6 = isp_leak_packets6()
    assert connect(server, identities["alice"][0]).returncode == 0
    assert probe(8) == f"you_are={SRV_IP}"                   # IPv4 works through the tunnel
    assert probe(3, v6=True) is None, "IPv6 must not reach the site outside the tunnel"
    assert isp_leak_packets6() == before6


@needs_v6
def test_ipv6_does_not_leak_even_without_killswitch_while_tunnel_is_up(server, identities, clean_client):
    before6 = isp_leak_packets6()
    r = connect(server, identities["alice"][0], {"ZKVPN_KILLSWITCH_ENABLED": "false"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert probe(3, v6=True) is None                          # the ::/1 routes swallow it
    assert isp_leak_packets6() == before6
