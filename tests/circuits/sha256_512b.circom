pragma circom 2.2.0;

include "circomlib-sha256/sha256.circom";

template Sha256512Bytes() {
    signal input in[4096];
    signal output out[256];

    component sha = Sha256(4096);

    for (var i = 0; i < 4096; i++) {
        sha.in[i] <== in[i];
    }

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}

component main = Sha256512Bytes();
