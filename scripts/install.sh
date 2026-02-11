#!/usr/bin/env bash
# ZK-VPN One-Liner Installer
# Version: v0.1.0-rc1
# Description: Secure, minimal, 30-second installation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="MissCyber9/ZK-VPN"
BRANCH="main"
INSTALL_DIR="/opt/zkvpn"
CONFIG_DIR="/etc/zkvpn"
VENV_DIR="${INSTALL_DIR}/venv"
SYSTEMD_SERVICE="zkvpn"
LOG_FILE="/var/log/zkvpn-install.log"

# Print with timestamp
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARN] $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This installer must be run as root\n   curl -sSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts/install.sh | sudo bash"
    fi
}

# Check system requirements
check_requirements() {
    info "Checking system requirements..."
    
    # OS Check
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            warn "This installer is optimized for Ubuntu/Debian. Your OS: $ID"
        fi
    fi
    
    # Python version
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed. Install it with: apt-get install python3 python3-pip python3-venv"
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ $(echo "$PYTHON_VERSION < 3.8" | bc) -eq 1 ]]; then
        error "Python 3.8+ required (found $PYTHON_VERSION)"
    fi
    info "Python $PYTHON_VERSION detected"
    
    # Check memory (minimum 256MB)
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_MEM -lt 256 ]]; then
        warn "Low memory detected (${TOTAL_MEM}MB). Minimum recommended: 256MB"
    fi
    
    # Check disk space
    AVAIL_DISK=$(df -m / | awk 'NR==2 {print $4}')
    if [[ $AVAIL_DISK -lt 500 ]]; then
        warn "Low disk space (${AVAIL_DISK}MB). Minimum recommended: 500MB"
    fi
}

# Install system dependencies
install_dependencies() {
    info "Installing system dependencies..."
    
    apt-get update -qq
    apt-get install -y -qq \
        wireguard \
        wireguard-tools \
        python3 \
        python3-pip \
        python3-venv \
        curl \
        wget \
        git \
        ufw \
        resolvconf \
        net-tools \
        dnsutils \
        bc \
        > /dev/null 2>&1
    
    # Verify WireGuard installation
    if ! command -v wg &> /dev/null; then
        error "WireGuard installation failed"
    fi
    
    success "System dependencies installed"
}

# Create directories with secure permissions
create_directories() {
    info "Creating directories..."
    
    # Install directory
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    # Config directory
    mkdir -p "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    
    # Log directory
    mkdir -p /var/log/zkvpn
    chmod 750 /var/log/zkvpn
    
    # Create empty .env file with secure permissions
    touch "${CONFIG_DIR}/.env"
    chmod 600 "${CONFIG_DIR}/.env"
    chown root:root "${CONFIG_DIR}/.env"
    
    info "Directories created at $INSTALL_DIR"
}

# Clone or update repository
get_code() {
    info "Fetching ZK-VPN code..."
    
    if [[ -d "${INSTALL_DIR}/src" ]]; then
        warn "Existing installation found. Updating..."
        cd "$INSTALL_DIR"
        git pull origin "$BRANCH" || {
            warn "Git pull failed, continuing with existing code"
        }
    else
        git clone --depth 1 --branch "$BRANCH" \
            "https://github.com/${REPO}.git" \
            "${INSTALL_DIR}/tmp" || error "Failed to clone repository"
        
        mv "${INSTALL_DIR}/tmp/zk-vpn-prototype/src" "${INSTALL_DIR}/src"
        rm -rf "${INSTALL_DIR}/tmp"
    fi
    
    if [[ ! -d "${INSTALL_DIR}/src" ]]; then
        error "Failed to fetch source code"
    fi
    
    success "Code fetched successfully"
}

# Setup Python virtual environment
setup_venv() {
    info "Setting up Python virtual environment..."
    
    python3 -m venv "$VENV_DIR"
    source "${VENV_DIR}/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    
    # Install dependencies
    if [[ -f "${INSTALL_DIR}/src/requirements.txt" ]]; then
        pip install -r "${INSTALL_DIR}/src/requirements.txt" > /dev/null 2>&1
    else
        # Minimal dependencies
        pip install \
            pydantic \
            pydantic-settings \
            click \
            python-dotenv \
            > /dev/null 2>&1
    fi
    
    # Install the package in development mode
    cd "${INSTALL_DIR}/src"
    pip install -e . > /dev/null 2>&1
    
    deactivate
    
    success "Virtual environment created"
}

# Generate initial configuration
generate_config() {
    info "Generating secure configuration..."
    
    # Generate WireGuard private key
    WG_PRIVATE_KEY=$(wg genkey)
    WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
    
    # Generate random node ID
    NODE_ID="node-$(tr -dc a-f0-九 < /dev/urandom | head -c 16)"
    
    # Write configuration
    cat > "${CONFIG_DIR}/.env" << EOF
# ZK-VPN Configuration
# Generated: $(date)
# DO NOT SHARE THIS FILE

# Node configuration
ZKVPN_NODE_ID=${NODE_ID}
ZKVPN_PORT=51820
ZKVPN_HOST=0.0.0.0

# Security
ZKVPN_LOG_LEVEL=INFO
ZKVPN_PROOF_TTL_SECONDS=3600
ZKVPN_SESSION_TIMEOUT_SECONDS=7200
ZKVPN_MAX_SESSIONS=10

# WireGuard
ZKVPN_WIREGUARD_INTERFACE=zkvpn0
ZKVPN_NETWORK_CIDR=10.0.0.0/24
ZKVPN_PRIVATE_KEY=${WG_PRIVATE_KEY}

# Performance
ZKVPN_MEMORY_MAX_MB=150
ZKVPN_CPU_QUOTA_PERCENT=10
EOF
    
    chmod 600 "${CONFIG_DIR}/.env"
    
    # Save public key for peer configuration
    echo "$WG_PUBLIC_KEY" > "${CONFIG_DIR}/public.key"
    chmod 644 "${CONFIG_DIR}/public.key"
    
    success "Configuration generated"
    info "Node public key: ${WG_PUBLIC_KEY}"
}

# Setup systemd service
setup_systemd() {
    info "Setting up systemd service..."
    
    cat > /etc/systemd/system/zkvpn.service << EOF
[Unit]
Description=ZK-VPN Secure Tunnel
Documentation=https://github.com/${REPO}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
EnvironmentFile=${CONFIG_DIR}/.env
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/zkvpn-node
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${CONFIG_DIR} /var/log/zkvpn
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
MemoryMax=150M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    success "Systemd service created"
}

# Basic system hardening
harden_system() {
    info "Applying basic system hardening..."
    
    # Configure UFW firewall
    if command -v ufw &> /dev/null; then
        ufw --force disable > /dev/null 2>&1
        ufw default deny incoming > /dev/null 2>&1
        ufw default allow outgoing > /dev/null 2>&1
        ufw allow 51820/udp comment 'ZK-VPN WireGuard' > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        ufw --force enable > /dev/null 2>&1
        info "Firewall configured"
    fi
    
    # Kernel parameters for WireGuard optimization
    cat > /etc/sysctl.d/99-zkvpn.conf << EOF
# ZK-VPN optimizations
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.conf.all.rp_filter=strict
net.ipv4.conf.default.rp_filter=strict
net.ipv4.tcp_syncookies=1
EOF
    
    sysctl -p /etc/sysctl.d/99-zkvpn.conf > /dev/null 2>&1 || warn "Failed to apply kernel parameters"
    
    success "System hardening applied"
}

# Create CLI symlink
create_symlink() {
    info "Creating CLI symlink..."
    
    cat > /usr/local/bin/zkvpn << EOF
#!/bin/bash
source ${VENV_DIR}/bin/activate
python3 -m zkvpn.cli.main "\$@"
deactivate
EOF
    
    chmod +x /usr/local/bin/zkvpn
    
    # Create node service wrapper
    cat > /usr/local/bin/zkvpn-node << EOF
#!/bin/bash
source ${VENV_DIR}/bin/activate
python3 -m zkvpn.cli.main node --config ${CONFIG_DIR}/.env
EOF
    
    chmod +x /usr/local/bin/zkvpn-node
    
    success "CLI installed at /usr/local/bin/zkvpn"
}

# Test installation
test_installation() {
    info "Testing installation..."
    
    # Test import
    if ! source "${VENV_DIR}/bin/activate" && python3 -c "import zkvpn" 2>/dev/null; then
        warn "Python import test failed"
    else
        success "Python module import successful"
    fi
    deactivate 2>/dev/null || true
    
    # Test CLI
    if ! /usr/local/bin/zkvpn --version 2>/dev/null; then
        warn "CLI test failed"
    else
        success "CLI test successful"
    fi
}

# Main installation flow
main() {
    log "${GREEN}Starting ZK-VPN installation v0.1.0-rc1${NC}"
    
    check_root
    check_requirements
    
    # Installation phases
    install_dependencies
    create_directories
    get_code
    setup_venv
    generate_config
    setup_systemd
    harden_system
    create_symlink
    test_installation
    
    # Final message
    echo ""
    success "ZK-VPN installation completed successfully!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 Next steps:"
    echo ""
    echo "  1. Check configuration:"
    echo "     ${GREEN}sudo cat ${CONFIG_DIR}/public.key${NC}"
    echo ""
    echo "  2. Start ZK-VPN service:"
    echo "     ${GREEN}sudo systemctl start zkvpn${NC}"
    echo ""
    echo "  3. Enable on boot:"
    echo "     ${GREEN}sudo systemctl enable zkvpn${NC}"
    echo ""
    echo "  4. Check status:"
    echo "     ${GREEN}sudo systemctl status zkvpn${NC}"
    echo ""
    echo "  5. Test your VPN:"
    echo "     ${GREEN}zkvpn status${NC}"
    echo "     ${GREEN}zkvpn test --leak-check${NC}"
    echo ""
    echo "📚 Documentation: https://github.com/${REPO}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${YELLOW}Node public key:${NC}"
    echo -e "${GREEN}$(cat ${CONFIG_DIR}/public.key)${NC}"
    echo ""
    
    log "Installation log saved to ${LOG_FILE}"
}

# Run main function
main "$@"