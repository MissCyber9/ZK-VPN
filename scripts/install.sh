#!/usr/bin/env bash
# ZK-VPN installer (Linux server, systemd)
#
# Supported distribution families (detected from /etc/os-release):
#   debian : Debian, Ubuntu and derivatives          (apt)
#   rhel   : Fedora, RHEL, Rocky, AlmaLinux, CentOS  (dnf)
# Anything else: the script stops and lists what to install by hand.
#
# Environment overrides (mainly for tests / offline installs):
#   ZKVPN_SOURCE_DIR  install from this local checkout instead of cloning GitHub
#   ZKVPN_REPO / ZKVPN_BRANCH   repository (default MissCyber9/ZK-VPN) and branch (default main)
#   ZKVPN_INSTALL_DIR / ZKVPN_CONFIG_DIR   default /opt/zkvpn and /etc/zkvpn
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

REPO="${ZKVPN_REPO:-MissCyber9/ZK-VPN}"
BRANCH="${ZKVPN_BRANCH:-main}"
SOURCE_DIR="${ZKVPN_SOURCE_DIR:-}"
INSTALL_DIR="${ZKVPN_INSTALL_DIR:-/opt/zkvpn}"
CONFIG_DIR="${ZKVPN_CONFIG_DIR:-/etc/zkvpn}"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_USER="zkvpn"
LOG_FILE="/var/log/zkvpn-install.log"
WG_PORT=51820
ADMISSION_PORT=51821

mkdir -p "$(dirname "$LOG_FILE")"
log()     { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"; exit 1; }
warn()    { echo -e "${YELLOW}[WARN] $1${NC}" | tee -a "$LOG_FILE"; }
info()    { echo -e "${BLUE}[INFO] $1${NC}" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS] $1${NC}" | tee -a "$LOG_FILE"; }

FAMILY=""
check_root() {
    [[ $EUID -eq 0 ]] || error "This installer must be run as root (sudo)."
}

detect_distro() {
    [[ -f /etc/os-release ]] || error "Cannot detect the distribution (no /etc/os-release)."
    # shellcheck disable=SC1091
    . /etc/os-release
    local ids=" ${ID:-} ${ID_LIKE:-} "
    if   [[ "$ids" == *" debian "* || "$ids" == *" ubuntu "* ]]; then FAMILY=debian
    elif [[ "$ids" == *" fedora "* || "$ids" == *" rhel "* || "$ids" == *" centos "* ]]; then FAMILY=rhel
    else
        error "Unsupported distribution '${PRETTY_NAME:-$ID}'. Install by hand: wireguard-tools, iproute2, iptables, python3 (>=3.9) with venv, nodejs (>=18), npm, git, then run scripts/setup_circuits.sh and 'zkvpn serve'."
    fi
    info "Detected ${PRETTY_NAME:-$ID} (family: $FAMILY)"
}

pkg_install() {
    case "$FAMILY" in
        debian) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >> "$LOG_FILE" 2>&1 ;;
        rhel)   dnf install -y -q "$@" >> "$LOG_FILE" 2>&1 ;;
    esac
}

check_requirements() {
    info "Checking system requirements..."
    [[ -d /run/systemd/system ]] || warn "systemd is not running: the service unit will be written but cannot be started here"
    local mem; mem=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    [[ $mem -ge 256 ]] || warn "Low memory (${mem}MB); 256MB recommended"
}

install_dependencies() {
    info "Installing system dependencies..."
    case "$FAMILY" in
        debian)
            apt-get update -qq >> "$LOG_FILE" 2>&1
            pkg_install wireguard-tools iproute2 iptables python3 python3-venv python3-pip \
                        nodejs npm git curl ca-certificates ;;
        rhel)
            pkg_install wireguard-tools iproute iptables-nft python3 python3-pip \
                        nodejs npm git curl ca-certificates ;;
    esac

    local pyok nodemajor
    pyok=$(python3 -c 'import sys; print(int(sys.version_info >= (3, 9)))')
    [[ "$pyok" == 1 ]] || error "Python 3.9+ required (found $(python3 -V))"
    nodemajor=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
    [[ "$nodemajor" -ge 18 ]] || error "Node.js 18+ required (found $(node -v 2>/dev/null || echo none)). See https://github.com/nodesource/distributions"
    command -v wg >/dev/null || error "WireGuard tools installation failed"

    # Kernel WireGuard if available, wireguard-go (userspace) otherwise (containers, old kernels)
    if ip link add zkvpn-probe type wireguard 2>/dev/null; then
        ip link del zkvpn-probe
        info "Kernel WireGuard available"
    else
        warn "Kernel WireGuard unavailable; installing wireguard-go (userspace)"
        pkg_install wireguard-go || warn "wireguard-go is not packaged here: install a kernel with WireGuard or build wireguard-go"
    fi
    success "System dependencies installed"
}

create_user_and_directories() {
    info "Creating service user and directories..."
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" /var/log/zkvpn
    chmod 755 "$INSTALL_DIR"
    chown root:"$SERVICE_USER" "$CONFIG_DIR"; chmod 750 "$CONFIG_DIR"
    chown "$SERVICE_USER":"$SERVICE_USER" /var/log/zkvpn; chmod 750 /var/log/zkvpn
    # secrets live here: root-only (systemd reads it as root, the service never opens it)
    touch "${CONFIG_DIR}/.env"; chmod 600 "${CONFIG_DIR}/.env"; chown root:root "${CONFIG_DIR}/.env"
}

get_code() {
    info "Fetching ZK-VPN code..."
    if [[ -n "$SOURCE_DIR" ]]; then
        [[ -d "${SOURCE_DIR}/src" ]] || error "ZKVPN_SOURCE_DIR=${SOURCE_DIR} has no src/"
        # copy the tree (no .git, no build output, no caches)
        tar -C "$SOURCE_DIR" --exclude=.git --exclude=node_modules --exclude=__pycache__ \
            --exclude='*.egg-info' --exclude=zk/build -cf - . | tar -C "$INSTALL_DIR" -xf -
    elif [[ -d "${INSTALL_DIR}/.git" ]]; then
        git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH" >> "$LOG_FILE" 2>&1 \
            || warn "git pull failed, continuing with existing code"
    else
        git clone --depth 1 --branch "$BRANCH" "https://github.com/${REPO}.git" "$INSTALL_DIR" >> "$LOG_FILE" 2>&1 \
            || error "Failed to clone repository"
    fi
    [[ -d "${INSTALL_DIR}/src" ]] || error "Failed to fetch source code"
    success "Code fetched"
}

setup_venv() {
    info "Setting up Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip setuptools wheel >> "$LOG_FILE" 2>&1
    "${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt" >> "$LOG_FILE" 2>&1 \
        || error "pip install of requirements failed (see $LOG_FILE)"
    "${VENV_DIR}/bin/pip" install --quiet -e "$INSTALL_DIR" >> "$LOG_FILE" 2>&1 \
        || error "pip install of zkvpn failed (see $LOG_FILE)"
    success "Virtual environment created"
}

build_circuits() {
    info "Building ZK circuit (about a minute)..."
    "${INSTALL_DIR}/scripts/setup_circuits.sh" >> "$LOG_FILE" 2>&1 \
        || error "ZK circuit build failed (run ${INSTALL_DIR}/scripts/setup_circuits.sh to see why)"
    warn "ZK keys come from a SINGLE-PARTY development setup; use scripts/ceremony.sh for production"
    chmod -R a+rX "${INSTALL_DIR}/zk"
    success "ZK circuit built"
}

generate_config() {
    info "Generating configuration..."
    if grep -q '^ZKVPN_PRIVATE_KEY=' "${CONFIG_DIR}/.env" 2>/dev/null; then
        warn "Existing configuration kept (${CONFIG_DIR}/.env)"
        return
    fi
    local priv pub
    priv=$(wg genkey); pub=$(echo "$priv" | wg pubkey)
    cat > "${CONFIG_DIR}/.env" << ENVFILE
# ZK-VPN configuration -- DO NOT SHARE (contains the WireGuard private key)
ZKVPN_NODE_ID=node-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
ZKVPN_PORT=${WG_PORT}
ZKVPN_ADMISSION_PORT=${ADMISSION_PORT}
ZKVPN_HOST=0.0.0.0
ZKVPN_LOG_LEVEL=INFO
ZKVPN_WIREGUARD_INTERFACE=zkvpn0
ZKVPN_NETWORK_CIDR=10.0.0.0/24
ZKVPN_PRIVATE_KEY=${priv}
ZKVPN_ZK_DIR=${INSTALL_DIR}/zk
ZKVPN_STATE_DIR=/run/zkvpn
ZKVPN_REQUIRE_CLIENT_PROOF=true
# Comma-separated client identities allowed to connect (EMPTY = ANY valid identity!):
ZKVPN_AUTHORIZED_IDENTITIES=
ENVFILE
    chmod 600 "${CONFIG_DIR}/.env"
    echo "$pub" > "${CONFIG_DIR}/public.key"; chmod 644 "${CONFIG_DIR}/public.key"
    success "Configuration generated"
    info "Server WireGuard public key: ${pub}"
}

setup_systemd() {
    info "Writing systemd unit..."
    cat > /etc/systemd/system/zkvpn.service << UNIT
[Unit]
Description=ZK-VPN server
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
EnvironmentFile=${CONFIG_DIR}/.env
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/zkvpn serve
Restart=on-failure
RestartSec=5
# /run/zkvpn: state that must survive a restart of the process but not a reboot
RuntimeDirectory=zkvpn
RuntimeDirectoryMode=0700

# wireguard-go (used when the kernel has no WireGuard) needs /dev/net/tun; the standard mode is
# 0666, but some containers create it 0600. Fix it only when it is not already usable.
ExecStartPre=-+/usr/bin/find /dev/net/tun -maxdepth 0 ! -perm -0666 -exec chmod 0666 {} +

# Network administration without root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

# Hardening. /run stays writable: iptables needs /run/xtables.lock and
# wireguard-go its control socket in /run/wireguard.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run /var/log/zkvpn
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
MemoryMax=300M

[Install]
WantedBy=multi-user.target
UNIT
    if [[ -d /run/systemd/system ]]; then systemctl daemon-reload; fi
    success "Systemd unit written"
}

setup_network() {
    info "Configuring network (IP forwarding, firewall)..."
    # The only system-wide change: let the host route packets. Everything else
    # (NAT, forwarding rules, client isolation) is added and removed by the service itself.
    printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-zkvpn.conf
    sysctl -q -p /etc/sysctl.d/99-zkvpn.conf >> "$LOG_FILE" 2>&1 || warn "Could not apply ip_forward now (it will apply at next boot)"

    # Open the ports only in a firewall that is already active; never enable or reset one.
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow ${WG_PORT}/udp >/dev/null; ufw allow ${ADMISSION_PORT}/tcp >/dev/null
        info "Opened ${WG_PORT}/udp and ${ADMISSION_PORT}/tcp in ufw"
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=${WG_PORT}/udp --add-port=${ADMISSION_PORT}/tcp >/dev/null
        firewall-cmd --reload >/dev/null
        info "Opened ${WG_PORT}/udp and ${ADMISSION_PORT}/tcp in firewalld"
    else
        warn "No active ufw/firewalld: make sure ${WG_PORT}/udp and ${ADMISSION_PORT}/tcp are reachable"
    fi
}

create_symlink() {
    ln -sf "${VENV_DIR}/bin/zkvpn" /usr/local/bin/zkvpn
    success "CLI installed at /usr/local/bin/zkvpn"
}

test_installation() {
    info "Testing installation..."
    "${VENV_DIR}/bin/python" -c "import zkvpn" || error "Python import test failed"
    /usr/local/bin/zkvpn --version >/dev/null || error "CLI test failed"
    # the service user must be able to read everything it needs
    if command -v runuser >/dev/null; then
        runuser -u "$SERVICE_USER" -- "${VENV_DIR}/bin/zkvpn" --version >/dev/null \
            || error "CLI does not work as user ${SERVICE_USER}"
    fi
    success "Installation test passed"
}

main() {
    log "${GREEN}Installing ZK-VPN${NC}"
    check_root
    detect_distro
    check_requirements
    install_dependencies
    create_user_and_directories
    get_code
    setup_venv
    build_circuits
    generate_config
    setup_systemd
    setup_network
    create_symlink
    test_installation

    echo
    success "ZK-VPN installed."
    cat << NEXT
Next steps:
  1. Create a client identity (on the client):   zkvpn identity new ~/.zkvpn-identity
  2. Put its public identity in ${CONFIG_DIR}/.env  (ZKVPN_AUTHORIZED_IDENTITIES=...)
  3. Start:   systemctl enable --now zkvpn      Logs: journalctl -u zkvpn
  4. Give clients this server key: $(cat "${CONFIG_DIR}/public.key")
NEXT
}

main "$@"
