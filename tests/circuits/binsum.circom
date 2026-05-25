/*
    Copyright 2018 0KIMS association.

    This file is adapted from circomlib's BinSum template and remains subject
    to the GNU General Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at your option) any later
    version.

    This KoalaBear-specific variant avoids packing a 32-bit word into one field
    element and constrains carry values bit by bit.
*/
pragma circom 2.0.0;

template CarryBits(n) {
    signal input in;
    signal bit[n];
    var acc = 0;

    if (n == 2) {
        bit[0] <-- in & 1;
        bit[0] * (bit[0] - 1) === 0;
        (in - bit[0]) * (in - bit[0] - 2) === 0;
    } else {
        for (var i = 0; i < n; i++) {
            bit[i] <-- (in >> i) & 1;
            bit[i] * (bit[i] - 1) === 0;
            acc += (1 << i) * bit[i];
        }
        in === acc;
    }
}

template BinSum(n, ops) {
    signal input in[ops][n];
    signal output out[n];
    signal carry[n + 1];

    component carry_bits[n];

    carry[0] <== 0;

    for (var k = 0; k < n; k++) {
        var carry_width = 1;
        var bit_sum = 0;
        for (var j = 0; j < ops; j++) {
            bit_sum += in[j][k];
        }
        if (ops > 2) {
            carry_width = 2;
        }
        if ((ops > 4) && (k > 1)) {
            carry_width = 3;
        }

        out[k] <-- (carry[k] + bit_sum) & 1;
        carry[k + 1] <-- (carry[k] + bit_sum) >> 1;

        out[k] * (out[k] - 1) === 0;
        carry[k] + bit_sum === out[k] + 2 * carry[k + 1];

        carry_bits[k] = CarryBits(carry_width);
        carry_bits[k].in <== carry[k + 1];
    }
}
