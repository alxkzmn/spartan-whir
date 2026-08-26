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
 * +/-2, +/-3, or +/-4. The row uniquely determines the majority bit.
 */
pragma circom 2.0.0;

template Maj_t(n) {
    signal input a[n];
    signal input b[n];
    signal input c[n];
    signal output out[n];

    for (var k=0; k<n; k++) {
        out[k] <-- (a[k] & b[k]) | (a[k] & c[k]) | (b[k] & c[k]);
        12 + (out[k] + a[k] + b[k] - 9*c[k] + 3) *
            (a[k] + b[k] + 6*c[k] - 4) === 0;
    }
}
