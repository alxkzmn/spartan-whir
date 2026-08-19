pragma circom 2.0.0;

include "round.circom";
include "../binsum.circom";

// The final block contains 0x80, zeros, and the big-endian bit length 16384.
// Split schedule words into 16-bit halves so every constant is canonical in
// KoalaBear while the round interface remains a 32-element bit vector.
function Sha2562048PaddingScheduleBit(index, bit) {
    var lo[64] = [
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x4000,
        0x0000, 0x0010, 0x5000, 0x1100, 0x0800, 0x0004, 0xd542, 0x2c04,
        0x0020, 0x200b, 0x6e05, 0x2351, 0x2c88, 0xff0a, 0x3f1a, 0x5de1,
        0xfa98, 0x740c, 0xef38, 0x2eb8, 0x88f5, 0x70df, 0xa60e, 0xf587,
        0x8410, 0x0e0e, 0xeb57, 0x0a18, 0x57a5, 0x13d7, 0xad3d, 0x039f,
        0xf2e4, 0xf02a, 0x555c, 0x38b4, 0x8760, 0x31d8, 0xdc09, 0x57dd,
        0x0b31, 0x4c8b, 0x6bb2, 0xb7d7, 0xb350, 0xe1d1, 0xa75a, 0xe86a
    ];
    var hi[64] = [
        0x8000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x8000, 0x2800, 0x0020, 0x0000, 0x2200, 0x0aa0, 0x0508, 0x8000,
        0x9808, 0x13c3, 0x0032, 0x1600, 0x8562, 0x1acf, 0xe3f4, 0xa96b,
        0x516d, 0x019d, 0x5c6b, 0x9fee, 0xd07c, 0x733c, 0x95c5, 0xda0f,
        0xdde6, 0x05fc, 0xdb15, 0xf7c9, 0x2a45, 0x7b88, 0xc038, 0xd70b,
        0xdfa6, 0x3f38, 0xe4ba, 0x03e5, 0x58f7, 0xd4d2, 0x89ae, 0xb39c,
        0xf1ff, 0x59f1, 0xb14e, 0xfb78, 0x9d0e, 0x9b2e, 0xe962, 0xe4f0
    ];

    if (bit < 16) {
        return (lo[index] >> bit) & 1;
    }
    return (hi[index] >> (bit - 16)) & 1;
}

template Sha2562048PaddingCompression() {
    signal input hin[256];
    signal output out[256];

    signal a[65][32];
    signal b[65][32];
    signal c[65][32];
    signal d[65][32];
    signal e[65][32];
    signal f[65][32];
    signal g[65][32];
    signal h[65][32];

    component round[64];
    component fsum[8];

    for (var i = 0; i < 64; i++) {
        round[i] = Sha256Round(i);
    }
    for (var i = 0; i < 8; i++) {
        fsum[i] = BinSum(32, 2);
    }

    for (var k = 0; k < 32; k++) {
        a[0][k] <== hin[k];
        b[0][k] <== hin[32 + k];
        c[0][k] <== hin[64 + k];
        d[0][k] <== hin[96 + k];
        e[0][k] <== hin[128 + k];
        f[0][k] <== hin[160 + k];
        g[0][k] <== hin[192 + k];
        h[0][k] <== hin[224 + k];
    }

    for (var t = 0; t < 64; t++) {
        for (var k = 0; k < 32; k++) {
            round[t].a[k] <== a[t][k];
            round[t].b[k] <== b[t][k];
            round[t].c[k] <== c[t][k];
            round[t].d[k] <== d[t][k];
            round[t].e[k] <== e[t][k];
            round[t].f[k] <== f[t][k];
            round[t].g[k] <== g[t][k];
            round[t].h[k] <== h[t][k];
            round[t].w[k] <== Sha2562048PaddingScheduleBit(t, k);
        }

        for (var k = 0; k < 32; k++) {
            a[t + 1][k] <== round[t].next_a[k];
            b[t + 1][k] <== a[t][k];
            c[t + 1][k] <== b[t][k];
            d[t + 1][k] <== c[t][k];
            e[t + 1][k] <== round[t].next_e[k];
            f[t + 1][k] <== e[t][k];
            g[t + 1][k] <== f[t][k];
            h[t + 1][k] <== g[t][k];
        }
    }

    for (var k = 0; k < 32; k++) {
        fsum[0].in[0][k] <== hin[k];
        fsum[0].in[1][k] <== a[64][k];
        fsum[1].in[0][k] <== hin[32 + k];
        fsum[1].in[1][k] <== b[64][k];
        fsum[2].in[0][k] <== hin[64 + k];
        fsum[2].in[1][k] <== c[64][k];
        fsum[3].in[0][k] <== hin[96 + k];
        fsum[3].in[1][k] <== d[64][k];
        fsum[4].in[0][k] <== hin[128 + k];
        fsum[4].in[1][k] <== e[64][k];
        fsum[5].in[0][k] <== hin[160 + k];
        fsum[5].in[1][k] <== f[64][k];
        fsum[6].in[0][k] <== hin[192 + k];
        fsum[6].in[1][k] <== g[64][k];
        fsum[7].in[0][k] <== hin[224 + k];
        fsum[7].in[1][k] <== h[64][k];
    }

    for (var k = 0; k < 32; k++) {
        out[31 - k] <== fsum[0].out[k];
        out[63 - k] <== fsum[1].out[k];
        out[95 - k] <== fsum[2].out[k];
        out[127 - k] <== fsum[3].out[k];
        out[159 - k] <== fsum[4].out[k];
        out[191 - k] <== fsum[5].out[k];
        out[223 - k] <== fsum[6].out[k];
        out[255 - k] <== fsum[7].out[k];
    }
}
