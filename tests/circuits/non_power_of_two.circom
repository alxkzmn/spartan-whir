pragma circom 2.2.0;

template NonPowerOfTwo() {
    signal input x;
    signal output y;
    signal t0;
    signal t1;
    signal t2;

    t0 <== x * x;
    t1 <== t0 + x;
    t2 <== t1 * t1;
    y <== t2 + 3;
}

component main { public [x] } = NonPowerOfTwo();
