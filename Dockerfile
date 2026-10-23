# ZK-VPN server image: runs the same on any host that can run Linux containers
# (Linux, macOS and Windows via Docker Desktop, cloud container services).
#
#   docker build -t zkvpn .
#   docker run -d --name zkvpn --cap-add NET_ADMIN --device /dev/net/tun \
#       --sysctl net.ipv4.ip_forward=1 -p 51820:51820/udp -p 51821:51821/tcp \
#       --env-file .env zkvpn
#
# No secret is baked into the image: the WireGuard key and the allow-list come from the
# environment at run time (see .env.example). The proving keys built here come from a
# single-party DEVELOPMENT setup; mount your own ceremony keys with
#   -v /path/to/keys:/data/zk -e ZKVPN_ZK_DIR=/data/zk
ARG BASE=ubuntu:24.04
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

# wireguard-go: used automatically when the host kernel has no WireGuard module
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip nodejs npm \
        wireguard-tools wireguard-go iproute2 iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/zkvpn
COPY requirements.txt setup.py README.md LICENSE ./
COPY src ./src
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt . \
 && /opt/venv/bin/zkvpn zk setup --dir /opt/zkvpn/zk \
 && rm -rf /root/.npm /root/.cache

ENV PATH="/opt/venv/bin:${PATH}" \
    ZKVPN_ZK_DIR=/opt/zkvpn/zk \
    ZKVPN_STATE_DIR=/run/zkvpn

EXPOSE 51820/udp 51821/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python3 -c "import socket; socket.create_connection(('127.0.0.1', 51821), 3)" || exit 1

ENTRYPOINT ["zkvpn"]
CMD ["serve"]
