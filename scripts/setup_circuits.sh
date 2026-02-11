#!/usr/bin/env bash
# Setup Circom and dependencies for ZK-VPN
# Run: ./setup_circuits.sh

set -euo pipefail

echo "🔧 Setting up Circom for ZK-VPN..."

# Install system dependencies
apt-get update
apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    libgmp-dev \
    libsodium-dev \
    nasm \
    nlohmann-json3-dev

# Install Rust (required for circom)
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install circom
if ! command -v circom &> /dev/null; then
    echo "Installing circom..."
    git clone https://github.com/iden3/circom.git
    cd circom
    cargo build --release
    cargo install --path circom
    cd ..
    rm -rf circom
fi

# Install snarkjs
if ! command -v snarkjs &> /dev/null; then
    echo "Installing snarkjs..."
    npm install -g snarkjs
fi

# Install circomlib
echo "Installing circomlib..."
mkdir -p node_modules
npm install circomlib

# Verify installations
echo "✅ Verification:"
circom --version
snarkjs --version

echo "✅ Circuit setup complete!"