pragma circom 2.2.0;

template SumOfSquares(N) {
    signal input xs[N];
    signal output out;
    signal partial[N + 1];

    partial[0] <== 0;
    for (var i = 0; i < N; i++) {
        partial[i + 1] <== partial[i] + xs[i] * xs[i];
    }
    out <== partial[N];
}

component main { public [xs] } = SumOfSquares(65536);
