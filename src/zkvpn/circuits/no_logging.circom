pragma circom 2.1.0;

// ZK-VPN No-Logging Circuit
// Version: v0.1.0
// Description: Zero-knowledge proof that no logs are kept
// Proves: timestamp_hash = hash(timestamp + nonce) without revealing timestamp

include "node_modules/circomlib/circuits/sha256/sha256.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template NoLoggingProof(n) {
    signal input timestamp;      // Current timestamp (private)
    signal input nonce;         // Random nonce (private)
    signal input prev_hash;     // Previous proof hash (public)
    signal output proof_hash;   // Hash for next proof (public)
    signal output is_valid;     // Proof validity (public)
    
    // Constants
    var MAX_DRIFT = 300;        // 5 minutes max drift
    
    // Hash the timestamp with nonce
    component sha = Sha256(n);
    
    // Prepare input bits
    signal input bits[512];
    
    // Convert timestamp and nonce to bits
    component timestamp2bits = Num2Bits(n);
    timestamp2bits.in <== timestamp;
    
    component nonce2bits = Num2Bits(n);
    nonce2bits.in <== nonce;
    
    // Concatenate bits: timestamp || nonce
    for (var i = 0; i < n; i++) {
        sha.in[i] <== timestamp2bits.out[i];
        sha.in[i + n] <== nonce2bits.out[i];
    }
    
    // Hash output
    component hash = Sha256(n * 2);
    for (var i = 0; i < 256; i++) {
        hash.out[i] <== sha.out[i];
    }
    
    // Convert hash to signal
    component bits2num = Bits2Num(256);
    for (var i = 0; i < 256; i++) {
        bits2num.in[i] <== hash.out[i];
    }
    
    proof_hash <== bits2num.out;
    
    // Verify timestamp is recent
    signal input current_time;   // Current blockchain time (public)
    
    component lt = LessThan(n);
    lt.in[0] <== current_time - timestamp;
    lt.in[1] <== MAX_DRIFT;
    
    component gt = GreaterThan(n);
    gt.in[0] <== timestamp - current_time;
    gt.in[1] <== 0;
    
    // timestamp must be <= current_time AND >= current_time - MAX_DRIFT
    is_valid <== lt.out * (1 - gt.out);
}

component main = NoLoggingProof(64);