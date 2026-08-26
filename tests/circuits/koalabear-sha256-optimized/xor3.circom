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

/*
 * For Boolean a, b, and c, the multiplier in this row is always one of
 * +/-1, +/-2, or +/-3. The row therefore uniquely determines out as the
 * Boolean three-input XOR without a separate intermediate product.
 */
pragma circom 2.0.0;

template Xor3(n) {
    signal input a[n];
    signal input b[n];
    signal input c[n];
    signal output out[n];

    for (var k=0; k<n; k++) {
        out[k] <-- (a[k] + b[k] + c[k]) & 1;
        6*a[k] + 6*b[k] - 24*c[k] ===
            (out[k] + 2*a[k] + 2*b[k] + 7*c[k]) * (a[k] + b[k] - 4*c[k] + 1);
    }
}

/*
 * The shifted operand of a lower sigma is zero in its high lanes. There the
 * three-input row reduces to the standard determined two-input XOR row,
 * which has three fewer matrix entries. For Boolean a and b,
 * 2ab = a + b - out uniquely determines out as their XOR.
 */
template Xor3ZeroTail(n, live) {
    signal input a[n];
    signal input b[n];
    signal input c[n];
    signal output out[n];

    for (var k=0; k<n; k++) {
        if (k < live) {
            out[k] <-- (a[k] + b[k] + c[k]) & 1;
            6*a[k] + 6*b[k] - 24*c[k] ===
                (out[k] + 2*a[k] + 2*b[k] + 7*c[k]) *
                    (a[k] + b[k] - 4*c[k] + 1);
        } else {
            c[k] === 0;
            out[k] <-- (a[k] + b[k]) & 1;
            2*a[k]*b[k] === a[k] + b[k] - out[k];
        }
    }
}
