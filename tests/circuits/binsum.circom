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
    var acc = 0;

    if (n == 1) {
        in * (in - 1) === 0;
    } else if (n == 2) {
        signal bit;
        bit <-- in & 1;
        bit * (bit - 1) === 0;
        (in - bit) * (in - bit - 2) === 0;
    } else {
        signal bit[n];
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

    if ((n == 32) && (ops <= 7)) {
        signal carry[3];
        component carry_bits[2];

        carry[0] <== 0;

        var max_carry = 0;
        var segment_start;
        var segment_width;
        var segment_base;
        var segment_sum;
        var output_sum;
        var carry_width;

        for (var segment = 0; segment < 2; segment++) {
            // Use 27+5 when 3-bit carries are possible, so segment equations stay below the field modulus.
            if (ops > 4) {
                segment_start = 27 * segment;
                segment_width = 27 - 22 * segment;
            } else {
                segment_start = 28 * segment;
                segment_width = 28 - 24 * segment;
            }
            segment_base = 1 << segment_width;
            segment_sum = carry[segment];
            output_sum = 0;

            for (var bit = 0; bit < segment_width; bit++) {
                for (var j = 0; j < ops; j++) {
                    segment_sum += (1 << bit) * in[j][segment_start + bit];
                }
                out[segment_start + bit] <-- (segment_sum >> bit) & 1;
                out[segment_start + bit] * (out[segment_start + bit] - 1) === 0;
                output_sum += (1 << bit) * out[segment_start + bit];
            }

            carry[segment + 1] <-- segment_sum >> segment_width;
            segment_sum === output_sum + segment_base * carry[segment + 1];

            max_carry = (max_carry + ops * (segment_base - 1)) \ segment_base;
            carry_width = 1;
            if (max_carry > 1) {
                carry_width = 2;
            }
            if (max_carry > 3) {
                carry_width = 3;
            }

            carry_bits[segment] = CarryBits(carry_width);
            carry_bits[segment].in <== carry[segment + 1];
        }
    } else {
        signal carry[n + 1];
        component carry_bits[n];

        carry[0] <== 0;

        var max_carry = 0;
        for (var k = 0; k < n; k++) {
            var carry_width;
            var carry_bound;
            var bit_sum = 0;
            for (var j = 0; j < ops; j++) {
                bit_sum += in[j][k];
            }

            max_carry = (max_carry + ops) \ 2;
            carry_width = 1;
            carry_bound = 2;
            while (max_carry >= carry_bound) {
                carry_width++;
                carry_bound *= 2;
            }

            out[k] <-- (carry[k] + bit_sum) & 1;
            carry[k + 1] <-- (carry[k] + bit_sum) >> 1;

            out[k] * (out[k] - 1) === 0;
            carry[k] + bit_sum === out[k] + 2 * carry[k + 1];

            carry_bits[k] = CarryBits(carry_width);
            carry_bits[k].in <== carry[k + 1];
        }
    }
}
