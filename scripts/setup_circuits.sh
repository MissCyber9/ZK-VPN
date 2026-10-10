#!/usr/bin/env bash
# Build the ZK-VPN session_auth Groth16 circuit.
#
# Needs only Node.js (>= 18) and npm: circom is provided by the pinned
# `circom2` package (WASM build of circom 2), proving by snarkjs.
#
# Outputs (in zk/build/):
#   session_auth.wasm  witness generator
#   session_auth.zkey  proving key
#   vkey.json          verification key
#
# WARNING: the powers-of-tau and the phase-2 contribution below are produced by
# a SINGLE local party. That is fine for development and tests, but anyone who
# kept that entropy could forge proofs. For production, replace them with a
# multi-party ceremony (e.g. the public Hermez/Perpetual Powers of Tau files
# plus a phase-2 ceremony) and distribute only the final zkey/vkey.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZK="${ROOT}/zk"
CIRCUIT="${ROOT}/src/zkvpn/circuits/session_auth.circom"
BUILD="${ZK}/build"
PTAU_POWER="${PTAU_POWER:-12}"

command -v node >/dev/null || { echo "node is required" >&2; exit 1; }
command -v npm  >/dev/null || { echo "npm is required"  >&2; exit 1; }

cd "$ZK"
npm install --no-audit --no-fund --silent
BIN="${ZK}/node_modules/.bin"

rm -rf "$BUILD"; mkdir -p "$BUILD"
"${BIN}/circom2" "$CIRCUIT" --r1cs --wasm -l node_modules -o "$BUILD"
mv "${BUILD}/session_auth_js/session_auth.wasm" "${BUILD}/session_auth.wasm"
rm -rf "${BUILD}/session_auth_js"

ENTROPY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
"${BIN}/snarkjs" powersoftau new bn128 "$PTAU_POWER" "${BUILD}/pot_0.ptau" >/dev/null
"${BIN}/snarkjs" powersoftau contribute "${BUILD}/pot_0.ptau" "${BUILD}/pot_1.ptau" \
    --name="zkvpn-dev" -e="$ENTROPY" >/dev/null
"${BIN}/snarkjs" powersoftau prepare phase2 "${BUILD}/pot_1.ptau" "${BUILD}/pot_final.ptau" >/dev/null
"${BIN}/snarkjs" groth16 setup "${BUILD}/session_auth.r1cs" "${BUILD}/pot_final.ptau" "${BUILD}/s_0.zkey" >/dev/null
ENTROPY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
"${BIN}/snarkjs" zkey contribute "${BUILD}/s_0.zkey" "${BUILD}/session_auth.zkey" \
    --name="zkvpn-dev" -e="$ENTROPY" >/dev/null
"${BIN}/snarkjs" zkey export verificationkey "${BUILD}/session_auth.zkey" "${BUILD}/vkey.json" >/dev/null

# Keep only what is needed at runtime.
rm -f "${BUILD}"/pot_*.ptau "${BUILD}/s_0.zkey" "${BUILD}/session_auth.r1cs"
echo "Built ${BUILD}: session_auth.wasm session_auth.zkey vkey.json"
