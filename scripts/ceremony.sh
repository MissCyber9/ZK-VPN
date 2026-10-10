#!/usr/bin/env bash
# Multi-party trusted-setup ceremony for the ZK-VPN session_auth circuit (Groth16).
#
# Why: with a single-party setup (scripts/setup_circuits.sh), whoever kept the
# setup entropy ("toxic waste") can forge proofs. In a ceremony every participant
# adds their own entropy; the keys are safe as long as AT LEAST ONE participant
# destroyed theirs. Nobody needs to trust anybody else, only that someone honest
# took part.
#
#   Phase 1 (circuit independent)  Use a PUBLIC Powers-of-Tau file made by a large ceremony,
#                                  e.g. Hermez "powersOfTau28_hez_final_12.ptau".
#   Phase 2 (this circuit)         The steps below.
#
# Flow (coordinator = whoever runs init/finalize; participants run only `contribute`):
#
#   coordinator$ scripts/ceremony.sh init  powersOfTau28_hez_final_12.ptau
#                -> ceremony/ptau.ptau, ceremony/session_auth.r1cs, ceremony/zkey_0000.zkey
#   participant1$ scripts/ceremony.sh contribute ceremony/zkey_0000.zkey ceremony/zkey_0001.zkey "Alice"
#   participant2$ scripts/ceremony.sh contribute ceremony/zkey_0001.zkey ceremony/zkey_0002.zkey "Bob"
#   ...          (each passes ONLY the .zkey file to the next; keep nothing, delete the entropy)
#   coordinator$ scripts/ceremony.sh beacon ceremony/zkey_0002.zkey ceremony/zkey_final.zkey <hex>
#                (<hex>: a public value unpredictable before the last contribution, e.g. the hash
#                 of a Bitcoin block mined after the contributions closed; publish which one)
#   anyone$      scripts/ceremony.sh verify ceremony/zkey_final.zkey      # recompiles, checks the WHOLE chain
#   coordinator$ scripts/ceremony.sh finalize ceremony/zkey_final.zkey    # installs into zk/build
#
# `init --dev` generates a LOCAL single-party phase 1 for tests. Never use it in production.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZK="${ROOT}/zk"
CIRCUIT="${ROOT}/src/zkvpn/circuits/session_auth.circom"
CEREMONY="${CEREMONY_DIR:-${ROOT}/ceremony}"
BIN="${ZK}/node_modules/.bin"
SNARKJS="${BIN}/snarkjs"
PTAU_POWER="${PTAU_POWER:-12}"
BUILD="${ZK_BUILD_DIR:-${ZK}/build}"

die() { echo "ceremony: $*" >&2; exit 1; }
need_tools() {
    command -v node >/dev/null || die "node is required"
    [[ -x "$SNARKJS" ]] || (cd "$ZK" && npm install --no-audit --no-fund --silent)
    [[ -x "$SNARKJS" ]] || die "snarkjs not installed in ${ZK}"
}
sha() { sha256sum "$1" | cut -d' ' -f1; }
entropy() { head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

compile() {  # compile the circuit deterministically into $1
    mkdir -p "$1"
    "${BIN}/circom2" "$CIRCUIT" --r1cs --wasm -l "${ZK}/node_modules" -o "$1" >/dev/null
}

cmd_init() {
    need_tools
    local ptau="" dev=0
    for a in "$@"; do [[ "$a" == "--dev" ]] && dev=1 || ptau="$a"; done
    mkdir -p "$CEREMONY"
    [[ -e "${CEREMONY}/zkey_0000.zkey" ]] && die "${CEREMONY} already initialised (remove it to restart)"

    if [[ -n "$ptau" ]]; then
        [[ -f "$ptau" ]] || die "no such file: $ptau"
        echo "Verifying the phase-1 file (this can take a while)..."
        "$SNARKJS" powersoftau verify "$ptau" >/dev/null || die "phase-1 file failed verification"
        cp "$ptau" "${CEREMONY}/ptau.ptau"
    elif [[ $dev -eq 1 ]]; then
        echo "WARNING: --dev builds a SINGLE-PARTY phase 1. Tests only, never production." >&2
        "$SNARKJS" powersoftau new bn128 "$PTAU_POWER" "${CEREMONY}/p0.ptau" >/dev/null
        "$SNARKJS" powersoftau contribute "${CEREMONY}/p0.ptau" "${CEREMONY}/p1.ptau" \
            --name="dev" -e="$(entropy)" >/dev/null
        "$SNARKJS" powersoftau prepare phase2 "${CEREMONY}/p1.ptau" "${CEREMONY}/ptau.ptau" >/dev/null
        rm -f "${CEREMONY}"/p0.ptau "${CEREMONY}"/p1.ptau
    else
        die "usage: init <public-phase1.ptau> | init --dev"
    fi

    compile "${CEREMONY}/build"
    cp "${CEREMONY}/build/session_auth.r1cs" "${CEREMONY}/session_auth.r1cs"
    "$SNARKJS" groth16 setup "${CEREMONY}/session_auth.r1cs" "${CEREMONY}/ptau.ptau" \
        "${CEREMONY}/zkey_0000.zkey" >/dev/null
    {
        echo "circuit_sha256=$(sha "$CIRCUIT")"
        echo "r1cs_sha256=$(sha "${CEREMONY}/session_auth.r1cs")"
        echo "ptau_sha256=$(sha "${CEREMONY}/ptau.ptau")"
    } > "${CEREMONY}/MANIFEST.txt"
    echo "Initialised ${CEREMONY}. Send zkey_0000.zkey to the first participant."
    cat "${CEREMONY}/MANIFEST.txt"
}

cmd_contribute() {
    need_tools
    [[ $# -ge 3 ]] || die "usage: contribute <in.zkey> <out.zkey> <your name>"
    local in="$1" out="$2" name="$3"
    [[ -f "$in" ]] || die "no such file: $in"
    [[ ! -e "$out" ]] || die "$out exists"
    # fresh entropy from the OS; nothing is stored, nothing to destroy afterwards
    "$SNARKJS" zkey contribute "$in" "$out" --name="$name" -e="$(entropy)"
    echo "Contribution done. Send ONLY ${out} to the next participant."
    echo "Output sha256: $(sha "$out")  (publish it so others can check what you produced)"
}

cmd_beacon() {
    need_tools
    [[ $# -eq 3 ]] || die "usage: beacon <in.zkey> <out.zkey> <public-hex>"
    [[ "$3" =~ ^[0-9a-fA-F]{16,}$ ]] || die "beacon must be a hex string of at least 16 digits"
    "$SNARKJS" zkey beacon "$1" "$2" "$3" 10 -n="Final beacon" >/dev/null
    echo "Beacon applied. sha256: $(sha "$2")"
}

cmd_verify() {
    need_tools
    [[ $# -eq 1 ]] || die "usage: verify <final.zkey>"
    local zkey="$1"
    [[ -f "${CEREMONY}/ptau.ptau" ]] || die "missing ${CEREMONY}/ptau.ptau (the phase-1 file used by init)"
    (   # subshell: its EXIT trap cleans the temp dir without leaking into the caller
        tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
        # Recompile from source: we verify against THIS circuit, not a file someone sent us.
        compile "$tmp"
        if [[ -f "${CEREMONY}/MANIFEST.txt" ]]; then
            grep -q "^r1cs_sha256=$(sha "${tmp}/session_auth.r1cs")$" "${CEREMONY}/MANIFEST.txt" \
                || die "circuit source does not match the ceremony manifest"
        fi
        echo "Verifying the whole contribution chain against ptau + circuit..."
        "$SNARKJS" zkey verify "${tmp}/session_auth.r1cs" "${CEREMONY}/ptau.ptau" "$zkey" \
            || die "ZKEY VERIFICATION FAILED"
        echo "OK: zkey is the product of a valid ceremony for this circuit."
    )
}

cmd_finalize() {
    need_tools
    [[ $# -eq 1 ]] || die "usage: finalize <final.zkey>"
    cmd_verify "$1"
    local build="$BUILD"
    rm -rf "$build"; mkdir -p "$build"
    compile "${build}/c"
    mv "${build}/c/session_auth_js/session_auth.wasm" "${build}/session_auth.wasm"
    rm -rf "${build}/c"
    cp "$1" "${build}/session_auth.zkey"
    "$SNARKJS" zkey export verificationkey "$1" "${build}/vkey.json" >/dev/null
    {
        echo "ceremony=multi-party"
        cat "${CEREMONY}/MANIFEST.txt"
        echo "zkey_sha256=$(sha "$1")"
        echo "vkey_sha256=$(sha "${build}/vkey.json")"
    } > "${build}/CEREMONY.txt"
    echo "Installed ceremony keys into ${build}"
}

case "${1:-}" in
    init) shift; cmd_init "$@" ;;
    contribute) shift; cmd_contribute "$@" ;;
    beacon) shift; cmd_beacon "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    finalize) shift; cmd_finalize "$@" ;;
    *) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
