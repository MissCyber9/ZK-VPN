#!/usr/bin/env bash
# Runs INSIDE the systemd container (see run.sh): install, real service, real client.
set -euo pipefail
step() { echo; echo "=== $*"; }
fail() { echo "FAIL: $*" >&2; journalctl -u zkvpn --no-pager 2>/dev/null | tail -40 >&2 || true; exit 1; }
wait_service() {
    for _ in $(seq 60); do
        systemctl is-active -q zkvpn && ss -ltn | grep -q ':51821' && return 0
        sleep 1
    done
    fail "service not active / admission port not listening"
}

step "install.sh on $(. /etc/os-release; echo "$PRETTY_NAME")"
ZKVPN_SOURCE_DIR=/src bash /src/scripts/install.sh

step "installed layout"
[[ "$(stat -c '%a %U' /etc/zkvpn/.env)" == "600 root" ]] || fail ".env must be 0600 root"
id zkvpn >/dev/null
[[ -f /etc/zkvpn/public.key ]]
runuser -u zkvpn -- /opt/zkvpn/venv/bin/zkvpn --version >/dev/null || fail "service user cannot run the CLI"

step "start the real systemd service"
systemctl start zkvpn
wait_service
MAINPID="$(systemctl show -p MainPID --value zkvpn)"
[[ "$(ps -o user= -p "$MAINPID" | tr -d ' ')" == "zkvpn" ]] || fail "service must not run as root"
iptables -t nat -S | grep -q ZKVPN_NAT || fail "NAT chain missing"
iptables -S | grep -q ZKVPN_FWD || fail "forward chain missing"
! journalctl -u zkvpn --no-pager | grep -q Traceback || fail "traceback in the service log"
echo "service up as user zkvpn, rules installed"

step "a client in a namespace connects to the installed service"
ip netns add cli
ip link add v-root type veth peer name v-cli
ip link set v-cli netns cli
ip addr add 10.7.0.1/24 dev v-root; ip link set v-root up
ip netns exec cli ip addr add 10.7.0.2/24 dev v-cli
ip netns exec cli ip link set v-cli up; ip netns exec cli ip link set lo up
ip netns exec cli ip route add default via 10.7.0.1

zkvpn identity new /root/id >/dev/null
PK="$(zkvpn identity show /root/id | tail -1 | tr -d ' ')"
[[ "$PK" =~ ^[0-9]+$ ]] || fail "could not read the public identity (got '$PK')"
sed -i "s/^ZKVPN_AUTHORIZED_IDENTITIES=.*/ZKVPN_AUTHORIZED_IDENTITIES=${PK}/" /etc/zkvpn/.env
systemctl restart zkvpn
wait_service

export ZKVPN_DNS_PROTECTION_ENABLED=false ZKVPN_WIREGUARD_INTERFACE=zkcli0 ZKVPN_STATE_DIR=/tmp/zkstate
ip netns exec cli zkvpn connect -e 10.7.0.1:51820 -k "$(cat /etc/zkvpn/public.key)" -i /root/id \
    || fail "client could not connect"
ip netns exec cli ping -c 2 -W 3 10.0.0.1 >/dev/null || fail "no connectivity through the tunnel"
echo "tunnel works: the namespace client reaches the server's tunnel address"

step "an identity that is not authorised is refused"
zkvpn identity new /root/id2 >/dev/null
ip netns exec cli zkvpn disconnect >/dev/null || true
ip netns exec cli ip link del zkcli0 2>/dev/null || true
! ip netns exec cli zkvpn connect -e 10.7.0.1:51820 -k "$(cat /etc/zkvpn/public.key)" -i /root/id2 >/dev/null 2>&1 \
    || fail "unauthorised identity was admitted"
echo "refused as expected"
ip netns exec cli zkvpn disconnect >/dev/null || true

step "stopping the service leaves nothing behind"
systemctl stop zkvpn
sleep 2
! iptables-save | grep -q ZKVPN || fail "firewall rules left behind"
! ip link show zkvpn0 >/dev/null 2>&1 || fail "interface left behind"
echo "clean"

if [[ "${1:-}" == "--e2e" ]]; then
    step "full network-namespace suite on this distribution"
    ip netns del cli 2>/dev/null || true
    /opt/zkvpn/venv/bin/pip install --quiet -r /src/requirements-dev.txt
    cd /src && /opt/zkvpn/venv/bin/python -m pytest -m e2e tests/e2e -p no:cacheprovider -q
fi
