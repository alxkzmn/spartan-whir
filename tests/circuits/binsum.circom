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

template Carry3Bits() {
    signal input in;
    signal bit[3];

    bit[0] <-- in & 1;
    bit[1] <-- (in >> 1) & 1;
    bit[2] <-- (in >> 2) & 1;

    bit[0] * (bit[0] - 1) === 0;
    bit[1] * (bit[1] - 1) === 0;
    bit[2] * (bit[2] - 1) === 0;
    in === bit[0] + 2 * bit[1] + 4 * bit[2];
}

template BinSum(n, ops) {
    signal input in[ops][n];
    signal output out[n];
    signal carry[n + 1];

    component carry_bits[n + 1];

    carry[0] <== 0;
    carry_bits[0] = Carry3Bits();
    carry_bits[0].in <== carry[0];

    for (var k = 0; k < n; k++) {
        var bit_sum = 0;
        for (var j = 0; j < ops; j++) {
            bit_sum += in[j][k];
        }

        out[k] <-- (carry[k] + bit_sum) & 1;
        carry[k + 1] <-- (carry[k] + bit_sum) >> 1;

        out[k] * (out[k] - 1) === 0;
        carry[k] + bit_sum === out[k] + 2 * carry[k + 1];

        carry_bits[k + 1] = Carry3Bits();
        carry_bits[k + 1].in <== carry[k + 1];
    }
}
