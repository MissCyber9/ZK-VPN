#!/usr/bin/env bash
# Build the image, start a server container and connect a client container to it:
# admission (real Groth16 proof), real WireGuard, real routes, over a Docker network.
#
#   tests/docker/smoke.sh                  # uses the local Docker daemon
# In a sandbox with an outbound proxy it is relayed automatically (see tests/distro/run.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="zkvpn:smoke"
NET="zkvpn-smoke-net"
SERVER="zkvpn-smoke-server"
RELAY_PID=""
BUILD_ARGS=()

cleanup() {
    docker rm -f "$SERVER" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n "${HTTPS_PROXY:-}" ]]; then   # cloud sandboxes: give the build the proxy through a relay
    GW="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
    HP="${HTTPS_PROXY#*://}"; HP="${HP%%/*}"
    python3 "$ROOT/tests/distro/proxy_forward.py" "$GW" 42639 "${HP%:*}" "${HP##*:}" &
    RELAY_PID=$!; sleep 1
    CA="${SSL_CERT_FILE:-/root/.ccr/ca-bundle.crt}"
    docker rm -f zkvpn-smoke-base-c >/dev/null 2>&1 || true
    docker run -d --name zkvpn-smoke-base-c -v "$CA:/mnt/ca.crt:ro" ubuntu:24.04 sleep 600 >/dev/null
    docker exec zkvpn-smoke-base-c sh -ec "
        mkdir -p /etc/ssl/certs && cp /mnt/ca.crt /etc/ssl/certs/ccr.crt
        printf 'Acquire::https::Proxy \"http://$GW:42639\";\nAcquire::http::Proxy \"http://$GW:42639\";\nAcquire::https::CaInfo \"/etc/ssl/certs/ccr.crt\";\n' > /etc/apt/apt.conf.d/99proxy
        sed -i 's|http://|https://|g' /etc/apt/sources.list.d/*.sources 2>/dev/null || true"
    docker commit \
        --change "ENV HTTPS_PROXY=http://$GW:42639 HTTP_PROXY=http://$GW:42639 SSL_CERT_FILE=/etc/ssl/certs/ccr.crt PIP_CERT=/etc/ssl/certs/ccr.crt NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ccr.crt REQUESTS_CA_BUNDLE=/etc/ssl/certs/ccr.crt" \
        zkvpn-smoke-base-c zkvpn-smoke-base >/dev/null
    docker rm -f zkvpn-smoke-base-c >/dev/null
    BUILD_ARGS=(--build-arg BASE=zkvpn-smoke-base)
fi

echo "=== build"
docker build "${BUILD_ARGS[@]}" -t "$IMAGE" "$ROOT"

echo "=== the image contains no secret"
! docker run --rm --entrypoint sh "$IMAGE" -c 'find / -xdev \( -name ".env" -o -name "*.pem" -o -name "id_rsa*" \) -not -path "*/node_modules/*" -not -path "/usr/*" -not -path "/etc/ssl/*" -not -name cacert.pem 2>/dev/null | grep .' \
    || { echo "FAIL: secret-like file in the image"; exit 1; }

echo "=== server"
docker network create "$NET" >/dev/null
PRIV="$(docker run --rm --entrypoint wg "$IMAGE" genkey)"
docker run -d --name "$SERVER" --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e ZKVPN_PRIVATE_KEY="$PRIV" "$IMAGE" >/dev/null
for _ in $(seq 60); do
    docker logs "$SERVER" 2>&1 | grep -qE '[A-Za-z0-9+/]{43}=' && break
    [[ "$(docker inspect -f '{{.State.Running}}' "$SERVER")" == true ]] || { docker logs "$SERVER"; echo "FAIL: server stopped"; exit 1; }
    sleep 1
done
# the key may be wrapped onto its own line by the console
PUB="$(docker logs "$SERVER" 2>&1 | grep -oE '[A-Za-z0-9+/]{43}=' | head -1)"
[[ "$PUB" == "$(echo "$PRIV" | docker run --rm -i --entrypoint wg "$IMAGE" pubkey)" ]] \
    || { echo "FAIL: the server does not use the configured key"; exit 1; }
echo "server up, public key $PUB"
SERVER_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SERVER")"

echo "=== client container connects through the tunnel"
docker run --rm --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun --entrypoint sh "$IMAGE" -c "
    set -e
    zkvpn identity new /tmp/id >/dev/null
    ZKVPN_DNS_PROTECTION_ENABLED=false zkvpn connect -e $SERVER_IP:51820 -k '$PUB' -i /tmp/id
    # 10.0.0.1 is the server's TUNNEL address: reachable only through WireGuard
    python3 -c \"import socket; socket.create_connection(('10.0.0.1', 51821), 10); print('reached the server through the tunnel')\"
"
echo ">>> docker smoke test PASSED"
