/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

include "../binsum.circom";
include "constants.circom";
include "sigma.circom";
include "ch.circom";
include "maj.circom";

template BinSum32RoundConstantWide(round, ops) {
    signal input in[ops][32];
    signal output out[32];

    if (ops <= 6) {
        signal carry[3];
        component carry_bits[2];

        carry[0] <== 0;

        var max_carry = 0;
        var carry_width;
        var segment_start;
        var segment_width;
        var segment_base;
        var segment_sum;
        var output_sum;
        var kbit;

        for (var segment = 0; segment < 2; segment++) {
            // 27+5 keeps 3-bit carry equations below the KoalaBear modulus.
            segment_start = 27 * segment;
            segment_width = 27 - 22 * segment;
            segment_base = 1 << segment_width;
            segment_sum = carry[segment];
            output_sum = 0;

            for (var bit = 0; bit < segment_width; bit++) {
                kbit = Kbit(round, segment_start + bit);
                segment_sum += (1 << bit) * kbit;
                for (var j = 0; j < ops; j++) {
                    segment_sum += (1 << bit) * in[j][segment_start + bit];
                }
                out[segment_start + bit] <-- (segment_sum >> bit) & 1;
                out[segment_start + bit] * (out[segment_start + bit] - 1) === 0;
                output_sum += (1 << bit) * out[segment_start + bit];
            }

            carry[segment + 1] <-- segment_sum >> segment_width;
            segment_sum === output_sum + segment_base * carry[segment + 1];

            max_carry = (max_carry + (ops + 1) * (segment_base - 1)) \ segment_base;
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
        signal carry[33];
        component carry_bits[32];

        var max_carry = 0;
        var carry_width;
        var bit_sum;
        var kbit;

        carry[0] <== 0;

        for (var k = 0; k < 32; k++) {
            kbit = Kbit(round, k);
            bit_sum = kbit;
            for (var j = 0; j < ops; j++) {
                bit_sum += in[j][k];
            }

            max_carry = (max_carry + ops + kbit) \ 2;
            carry_width = 1;
            if (max_carry > 1) {
                carry_width = 2;
            }
            if (max_carry > 3) {
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
}

template Sha256Round(round) {
    signal input a[32];
    signal input b[32];
    signal input c[32];
    signal input d[32];
    signal input e[32];
    signal input f[32];
    signal input g[32];
    signal input h[32];
    signal input w[32];
    signal output next_a[32];
    signal output next_e[32];

    component ch = Ch_t(32);
    component maj = Maj_t(32);
    component bigsigma0 = BigSigma(2, 13, 22);
    component bigsigma1 = BigSigma(6, 11, 25);
    component sum_e = BinSum32RoundConstantWide(round, 5);
    component sum_a = BinSum32RoundConstantWide(round, 6);

    for (var k = 0; k < 32; k++) {
        bigsigma0.in[k] <== a[k];
        bigsigma1.in[k] <== e[k];

        ch.a[k] <== e[k];
        ch.b[k] <== f[k];
        ch.c[k] <== g[k];

        maj.a[k] <== a[k];
        maj.b[k] <== b[k];
        maj.c[k] <== c[k];
    }

    for (var k = 0; k < 32; k++) {
        sum_e.in[0][k] <== d[k];
        sum_e.in[1][k] <== h[k];
        sum_e.in[2][k] <== bigsigma1.out[k];
        sum_e.in[3][k] <== ch.out[k];
        sum_e.in[4][k] <== w[k];

        sum_a.in[0][k] <== h[k];
        sum_a.in[1][k] <== bigsigma1.out[k];
        sum_a.in[2][k] <== ch.out[k];
        sum_a.in[3][k] <== w[k];
        sum_a.in[4][k] <== bigsigma0.out[k];
        sum_a.in[5][k] <== maj.out[k];
    }

    for (var k = 0; k < 32; k++) {
        next_a[k] <== sum_a.out[k];
        next_e[k] <== sum_e.out[k];
    }
}
