# Poseidon1 full-ZK DirectSparse client comparison

#### Result

On the fixed 2,048-byte SHA-256 full-ZK DirectSparse workload, Poseidon1 `witness_and_prove` is 20.222% slower than Poseidon2. Criterion's 95% confidence interval for the regression is 19.769% to 20.682%. This exceeds the recommended 5% client target. The recommendation does not reject Poseidon1; selection also uses the verified LeanVM root-proof measurements and implementation surface.

| Profile | Mean `witness_and_prove` | 95% confidence interval | Proof bytes, min / median / max | Mean native verification | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poseidon2 | 63.258 ms | 63.082–63.457 ms | 1,223,812 / 1,225,764 / 1,228,036 | 46.356 ms | 931,840,000 bytes |
| Poseidon1 | 76.050 ms | 75.886–76.219 ms | 1,223,236 / 1,226,372 / 1,228,740 | 56.380 ms | 935,919,616 bytes |

The Criterion result uses 30 flat samples, a four-second warm-up, a twelve-second measurement period, and the same 16-input corpus. Poseidon2 used seven iterations per sample and Poseidon1 used six. Proof size and native verification use one deterministic proof per corpus input. Peak RSS is the maximum resident set size of the already-built benchmark process for that 16-proof diagnostic corpus; compilation is excluded.

#### Fixed workload

- Spartan-WHIR source base: `411849a2826ad734b18c461c3c47fb45e0561166`, with the uncommitted Poseidon1 profile implementation in this worktree.
- Plonky3 revision: `f64ae15da3807388b1a4e0a89a4fde8fdcdff515`.
- Circom KoalaBear compiler revision: `bb7ae6d406debbfe8afc68305cbd6106fda945bc`.
- R1CS: optimized 2,048-byte SHA-256, 605,424 nonlinear constraints, SHA-256 `1f1c6beae387e938d86b5ca433abc024945f14c2763db0c29638613ebb206627`.
- Linked witness library SHA-256: `e238e0960d2b8236e1a051bdba17a15f36909ae34f5b7d7e2ef2dbcbbfbe6601`.
- Protocol: full-ZK, DirectSparse, quintic extension, 116-bit Johnson-bound target, selected full-ZK WHIR schedule, default masking parameters.
- Corpus: 16 fixed 2,048-byte inputs with deterministic per-sample proof randomness.
- Build flags: `--release --features parallel` with `RUSTFLAGS='-C target-cpu=native -C debuginfo=0'`; Poseidon1 adds the `poseidon1` feature.
- Machine: Apple M4 Pro, 12 physical and 12 logical cores, 48 GiB memory; the default Rayon pool used 12 threads.
- Rust: `rustc 1.96.0-nightly (d9563937f 2026-03-03)`, LLVM 22.1.0.

#### Criterion commands

Poseidon2 baseline:

```bash
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' SHA256_BENCH_WORKDIR=target/sha256-optimized-cache SHA256_ZK_BENCH_PROVING_ONLY=1 SHA256_ZK_BENCH_SINGLE_PROVING_VARIANT=full_zk_direct SHA256_ZK_BENCH_SECURITY_BITS=116 SHA256_ZK_BENCH_EXTENSION=selected SHA256_ZK_BENCH_CORPUS_SIZE=16 cargo bench --features parallel --bench sha256_full_zk -- --save-baseline poseidon2
```

Poseidon1 comparison:

```bash
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' SHA256_BENCH_WORKDIR=target/sha256-optimized-cache SHA256_ZK_BENCH_PROVING_ONLY=1 SHA256_ZK_BENCH_SINGLE_PROVING_VARIANT=full_zk_direct SHA256_ZK_BENCH_SECURITY_BITS=116 SHA256_ZK_BENCH_EXTENSION=selected SHA256_ZK_BENCH_CORPUS_SIZE=16 cargo bench --features parallel,poseidon1 --bench sha256_full_zk -- --baseline poseidon2
```

The raw Criterion benchmark metadata, samples, estimates, and comparison estimates are under `criterion/` in this directory.

#### Artifact preparation

The stock Circom 2.2.3 binary does not recognize `--prime koalabear`. The current KoalaBear branch includes the linked witness-generator ABI used by this benchmark. Build the compiler at the recorded revision and pass its binary to:

```bash
tests/circuits/build_sha256_optimized_fixture.sh /path/to/circom/target/release/circom
```

The fixture builder links GMP explicitly and searches `/opt/homebrew` and `/usr/local` for its headers and library.
