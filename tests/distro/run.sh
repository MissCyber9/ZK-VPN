#!/usr/bin/env bash
# Test the installer, the systemd unit and the real service on a given distribution image.
#
#   tests/distro/run.sh ubuntu:24.04            # install + service + client end to end
#   tests/distro/run.sh debian:12 --e2e         # ... plus the full network-namespace suite
#
# The container has its OWN network namespace (default Docker bridge): firewall rules the
# service installs never touch the host. Needs Docker and --privileged (systemd, netns, iptables).
set -euo pipefail

IMG="${1:?usage: run.sh <docker-image> [--e2e]}"
E2E="${2:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE="$(echo "$IMG" | tr ':/' '--')"
BASE="zkvpn-prep-${SAFE}"
NAME="zkvpn-test-${SAFE}"
RELAY_PID=""

cleanup() {
    if [[ -n "${KEEP:-}" ]]; then echo ">>> KEEP set: container $NAME left running (docker exec -it $NAME bash)"
    else docker rm -f "$NAME" "${BASE}-c" >/dev/null 2>&1 || true; fi
    [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
}
trap cleanup EXIT

# --- optional outbound proxy (cloud sandboxes): relay it onto the Docker bridge
PROXY_ENV=()
CA_MOUNT=()
if [[ -n "${HTTPS_PROXY:-}" ]]; then
    GW="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
    HP="${HTTPS_PROXY#*://}"; HP="${HP%%/*}"
    python3 "$ROOT/tests/distro/proxy_forward.py" "$GW" 42638 "${HP%:*}" "${HP##*:}" &
    RELAY_PID=$!
    sleep 1
    CT_PROXY="http://${GW}:42638"
    CA="${SSL_CERT_FILE:-/root/.ccr/ca-bundle.crt}"
    CA_MOUNT=(-v "${CA}:/etc/ssl/certs/ccr.crt:ro")
    PROXY_ENV=(-e "HTTPS_PROXY=$CT_PROXY" -e "https_proxy=$CT_PROXY" -e "HTTP_PROXY=$CT_PROXY"
               -e "SSL_CERT_FILE=/etc/ssl/certs/ccr.crt" -e "REQUESTS_CA_BUNDLE=/etc/ssl/certs/ccr.crt"
               -e "PIP_CERT=/etc/ssl/certs/ccr.crt" -e "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ccr.crt"
               -e "CURL_CA_BUNDLE=/etc/ssl/certs/ccr.crt" -e "GIT_SSL_CAINFO=/etc/ssl/certs/ccr.crt")
fi

FAMILY="$(docker run --rm "$IMG" sh -c '. /etc/os-release; echo " $ID $ID_LIKE "')"
echo ">>> image $IMG (os-release:${FAMILY})"

# --- 1. prepare an image that can boot systemd (commit, because PID 1 cannot be swapped)
docker rm -f "${BASE}-c" >/dev/null 2>&1 || true
docker run -d --name "${BASE}-c" "${CA_MOUNT[@]}" "$IMG" sleep infinity >/dev/null
prep() { docker exec "${PROXY_ENV[@]}" "${BASE}-c" sh -c "$1"; }
if [[ "$FAMILY" == *" debian "* || "$FAMILY" == *" ubuntu "* ]]; then
    [[ -n "${CT_PROXY:-}" ]] && prep "printf 'Acquire::https::Proxy \"$CT_PROXY\";\nAcquire::http::Proxy \"$CT_PROXY\";\nAcquire::https::CaInfo \"/etc/ssl/certs/ccr.crt\";\n' > /etc/apt/apt.conf.d/99proxy; for f in /etc/apt/sources.list.d/*.sources /etc/apt/sources.list; do [ -f \$f ] && sed -i 's|http://|https://|g' \$f; done"
    prep "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus iproute2 procps iputils-ping ca-certificates >/dev/null"
else
    [[ -n "${CT_PROXY:-}" ]] && prep "echo 'proxy=$CT_PROXY' >> /etc/dnf/dnf.conf; echo 'sslcacert=/etc/ssl/certs/ccr.crt' >> /etc/dnf/dnf.conf"
    prep "dnf install -y -q systemd iproute procps-ng iputils >/dev/null"
fi
docker commit "${BASE}-c" "$BASE" >/dev/null
docker rm -f "${BASE}-c" >/dev/null

# --- 2. boot it with systemd as PID 1
docker run -d --name "$NAME" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    -v "$ROOT:/src:ro" "${CA_MOUNT[@]}" -e container=docker --stop-signal SIGRTMIN+3 \
    "$BASE" /sbin/init >/dev/null
for _ in $(seq 60); do
    state="$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)"
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done
[[ "$state" == running || "$state" == degraded ]] || { echo "systemd did not boot (state: ${state:-none})"; docker logs "$NAME" | tail -20; exit 1; }
echo ">>> systemd up ($state)"

# --- 3. run the checks inside
docker exec "${PROXY_ENV[@]}" "$NAME" bash /src/tests/distro/checks.sh $E2E
echo ">>> ${IMG}: ALL CHECKS PASSED"
