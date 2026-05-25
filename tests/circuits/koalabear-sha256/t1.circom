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

template BinSum32RoundConstant(round) {
    signal input in[4][32];
    signal output out[32];
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
        for (var j = 0; j < 4; j++) {
            bit_sum += in[j][k];
        }

        max_carry = (max_carry + 4 + kbit) \ 2;
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

template T1(round) {
    signal input h[32];
    signal input e[32];
    signal input f[32];
    signal input g[32];
    signal input w[32];
    signal output out[32];

    var ki;

    component ch = Ch_t(32);
    component bigsigma1 = BigSigma(6, 11, 25);

    for (ki=0; ki<32; ki++) {
        bigsigma1.in[ki] <== e[ki];
        ch.a[ki] <== e[ki];
        ch.b[ki] <== f[ki];
        ch.c[ki] <== g[ki];
    }

    component sum = BinSum32RoundConstant(round);
    for (ki=0; ki<32; ki++) {
        sum.in[0][ki] <== h[ki];
        sum.in[1][ki] <== bigsigma1.out[ki];
        sum.in[2][ki] <== ch.out[ki];
        sum.in[3][ki] <== w[ki];
    }

    for (ki=0; ki<32; ki++) {
        out[ki] <== sum.out[ki];
    }
}
