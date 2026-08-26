pragma circom 2.2.0;

include "sha256.circom";

template Sha256Bytes(N_BYTES) {
    signal input in[8 * N_BYTES];
    signal output out[256];

    component sha = Sha256(8 * N_BYTES);

    for (var i = 0; i < 8 * N_BYTES; i++) {
        sha.in[i] <== in[i];
    }

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}
