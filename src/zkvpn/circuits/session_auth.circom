pragma circom 2.1.0;

// ZK-VPN session authentication circuit (Groth16 / bn128).
//
// Proves, without revealing `sk`:
//   1. the prover knows the secret key behind the public identity `pk`
//      (pk = Poseidon(sk));
//   2. the proof is bound to a verifier-chosen `challenge` and to the
//      previous proof `prev_tag` (tag = Poseidon(sk, challenge, prev_tag)),
//      which prevents replay and links successive proofs into a chain;
//   3. `timestamp` is not in the future and at most MAX_DRIFT seconds older
//      than `current_time` (both are public: the verifier checks them against
//      its own clock).
//
// It does NOT prove that a server keeps no logs: no zero-knowledge proof can.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template SessionAuth(MAX_DRIFT) {
    signal input sk;            // private
    signal input challenge;     // public
    signal input timestamp;     // public
    signal input current_time;  // public
    signal input prev_tag;      // public
    signal output pk;           // public identity
    signal output tag;          // public proof tag

    component idHash = Poseidon(1);
    idHash.inputs[0] <== sk;
    pk <== idHash.out;

    component tagHash = Poseidon(3);
    tagHash.inputs[0] <== sk;
    tagHash.inputs[1] <== challenge;
    tagHash.inputs[2] <== prev_tag;
    tag <== tagHash.out;

    // timestamp <= current_time (32-bit unix seconds)
    component notFuture = LessEqThan(32);
    notFuture.in[0] <== timestamp;
    notFuture.in[1] <== current_time;
    notFuture.out === 1;

    // current_time - timestamp <= MAX_DRIFT
    component fresh = LessEqThan(32);
    fresh.in[0] <== current_time - timestamp;
    fresh.in[1] <== MAX_DRIFT;
    fresh.out === 1;
}

component main {public [challenge, timestamp, current_time, prev_tag]} = SessionAuth(300);
