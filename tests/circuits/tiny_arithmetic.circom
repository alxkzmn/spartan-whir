pragma circom 2.2.0;

template TinyArithmetic() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b + a + 7;
}

component main { public [a] } = TinyArithmetic();
