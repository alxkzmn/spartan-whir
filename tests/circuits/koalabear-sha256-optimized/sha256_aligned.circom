pragma circom 2.0.0;

include "../koalabear-sha256/constants.circom";
include "sha256compression.circom";
include "paddingcompression.circom";

template Sha2562048Bytes() {
    signal input in[16384];
    signal output out[256];

    var nDataBlocks = 32;

    component initial[8];
    for (var i = 0; i < 8; i++) {
        initial[i] = H(i);
    }

    // The optimized XOR and majority rows are determined on Boolean inputs.
    for (var i = 0; i < 16384; i++) {
        in[i] * (in[i] - 1) === 0;
    }

    component dataCompression[nDataBlocks];
    for (var i = 0; i < nDataBlocks; i++) {
        dataCompression[i] = Sha256compression();

        for (var k = 0; k < 256; k++) {
            if (i == 0) {
                dataCompression[i].hin[k] <== initial[k \ 32].out[k % 32];
            } else {
                var word = k \ 32;
                var bit = k % 32;
                dataCompression[i].hin[k] <== dataCompression[i - 1].out[32 * word + 31 - bit];
            }
        }

        for (var k = 0; k < 512; k++) {
            dataCompression[i].inp[k] <== in[512 * i + k];
        }
    }

    component paddingCompression = Sha2562048PaddingCompression();
    for (var k = 0; k < 256; k++) {
        var word = k \ 32;
        var bit = k % 32;
        paddingCompression.hin[k] <==
            dataCompression[nDataBlocks - 1].out[32 * word + 31 - bit];
    }
    for (var k = 0; k < 256; k++) {
        out[k] <== paddingCompression.out[k];
    }
}
