# Poseidon full-ZK DirectSparse LeanVM comparison

#### Result

The Poseidon1 profile is selected for the LeanVM verifier guest. On the matched four-constraint synthetic full-ZK DirectSparse fixture, Poseidon1 reduced LeanVM execution from 8,497,653 to 868,295 cycles and root proving from 17.106 seconds to 1.110 seconds. Both root proofs passed LeanVM's native verifier. This comparison establishes the recursive cost ratio for the synthetic verifier fixture; it is not a production-shaped recursive measurement.

The client benchmark on the production 2,048-byte SHA-256 workload measured a 20.222% Poseidon1 `witness_and_prove` regression, with a 95% confidence interval of 19.769% to 20.682%. This is above the recommended 5% target. The recommendation is not a rejection gate. The measured synthetic recursive cost, the production Poseidon1 SPARK guest measurement, the existing Poseidon1 LeanVM table, and the absence of a new Poseidon2 AIR and terminal-verifier table justify selecting Poseidon1.

#### LeanVM measurements

These are single release-profile measurements on the same Apple M4 Pro with 12 effective threads. Each command compiled the fixed guest, executed it, generated a LeanVM root proof with `log_inv_rate = 2`, and verified that root proof.

| Metric | Poseidon1 | Poseidon2 |
| --- | ---: | ---: |
| Canonical guest input | 53,716 bytes | 53,460 bytes |
| Compiled instructions | 138,300 | 146,859 |
| Padded instructions | 262,144 | 262,144 |
| Encoded bytecode | 16,777,216 bytes | 16,777,216 bytes |
| Compile time | 1,444.834 ms | 1,356.573 ms |
| Compiler peak RSS | 384,876,544 bytes | 395,067,392 bytes |
| Execution cycles | 868,295 | 8,497,653 |
| Allocated memory cells | 1,035,529 | 8,622,368 |
| Padded memory cells | 1,048,576 | 16,777,216 |
| Execution table | 868,295 rows, padded to `2^20` | 8,497,653 rows, padded to `2^24` |
| Extension-operation table | 19,878 rows, padded to `2^15` | 19,878 rows, padded to `2^15` |
| Poseidon1 table | 2,405 calls, padded to `2^12` | 0 calls, padded to `2^8` |
| Execution peak RSS | 514,342,912 bytes | 2,511,945,728 bytes |
| Root proving time | 1,109.811 ms | 17,106.066 ms |
| Root verification time | 34.471 ms | 39.549 ms |
| Serialized root proof | 336,367 bytes | 350,420 bytes |
| Process peak RSS through root verification | 3,226,124,288 bytes | 34,751,479,808 bytes |

Poseidon2 used 9.787 times as many guest cycles, 16 times the padded execution rows, 16 times the padded memory, and 15.413 times the root proving time. Its ordinary-instruction verifier remained within the current VM table limits, but used 98.73% of its allocated memory region.

The production Poseidon1 SPARK guest later measured 33,485,006 execution cycles, only 69,426 below `2^25`. Using the synthetic fixture's 9.787-times cycle ratio predicts that a production Poseidon2 guest implemented with ordinary instructions would exceed the current `2^26` execution-table ceiling by a wide margin. This is an extrapolation from the four-constraint comparison, not a measured production Poseidon2 SPARK result.

The Poseidon2 precompile candidate was not implemented or measured. It would require new width-16 and width-24 execution semantics, trace generation, AIR tables, native and Python verification support, recursive-proof support, and terminal AIR checks. The current decision keeps that larger change out of the LeanVM fork. Reopen the candidate if Poseidon1 cannot meet an explicit application budget or if compatible Poseidon2 precompile support becomes available.

#### Commands

Poseidon1:

```bash
cargo run -p spartan_whir_guest --release --bin leanvm-full-zk-direct-poseidon1 -- prove
cargo test -p spartan_whir_guest --release --test full_zk_direct_poseidon1 -- --nocapture
```

Poseidon2:

```bash
cargo run -p spartan_whir_guest --release --bin leanvm-full-zk-direct-poseidon2 -- prove
cargo test -p spartan_whir_guest --release --test full_zk_direct_poseidon2 -- --nocapture
```

The two mutation suites change the application public input, witness commitment, application mask commitment, outer sumcheck, inner sumcheck, and hiding-WHIR base claim. Every mutation rejects, and both decoders reject trailing words.
