# spartan-whir — Agent Instructions

## Project Intent

`spartan-whir` is part of the client-side proving work on a proof system that is:

- directly verifiable on Ethereum-like EVMs without a SNARK wrapper,
- post-quantum and transparent,
- still competitive for client-side proving,
- suitable for comparison benchmarks against other WHIR-based systems.

When making changes, optimize for the eventual verifier that can exist on today's EVM, not for abstract elegance or generic cryptographic flexibility.

Proof size and verifier-facing calldata size are the primary optimization targets inside that EVM-oriented goal. When tradeoffs exist, prefer the path that keeps proofs and encoded blobs smaller unless there is a clear soundness, compatibility, or benchmark-representativeness reason not to.

## Default Path Invariants

- Keep the default concrete proving/verification path aligned with efficient EVM verification.
- Preserve EVM-friendly transcript and commitment choices in the default path. In practice, this means the default transcript and Merkle hashing should stay Keccak-aligned unless explicitly asked to explore a different design.
- Do not switch the default challenger to a field-native or algebraic challenger as a refactor convenience. That may simplify Rust code, but it moves the protocol away from the intended EVM verifier model.
- Do not replace the default hash/commitment path with primitives that lack a clear EVM verification story.
- Treat transcript ordering, proof encoding, digest layout, and other verifier-facing details as protocol surface, not incidental implementation details.

## What Is Flexible

- Field choices, extension choices, proof-system tuning, and internal structure may evolve when supported by benchmarks and verifier-cost reasoning.
- Additive experimental paths are welcome when they are clearly separated from the default path.
- If you want to try a non-EVM-oriented primitive or alternative challenger, add it as an explicit experiment, feature, or separate API instead of silently changing the default.

## Refactoring Rules

- Do not broaden abstractions around cryptographic backends unless there is a concrete need in this crate.
- Do not make "cleanups" that change verifier-relevant behavior without calling that out explicitly.
- If a change can affect verifier gas, calldata size, proof size, transcript compatibility, or benchmark comparability, state that impact in your summary.
- When changing extension choices or adding a new extension, document extension-specific algebraic limits and support level explicitly. This includes `TWO_ADICITY`-dependent behavior, skip-path feasibility, and which paths are currently exercised by tests or benchmarks.
- Prefer changes that keep `spartan-whir` representative for future client-side proving comparison benchmarks.

## Docs and Benchmarks

- When you add, rename, or materially change a benchmark target, profiling flow, or tracing/proof-size output, update `README.md` in the same change.
- Keep benchmark commands, benchmark target names, environment knobs, and output examples in the docs aligned with the actual code.
- Benchmark/profiling output intended for direct human inspection should be stable and human-readable. Prefer labeled `key: value` fields and clear tree/group structure over raw debug dumps.
- If a benchmark fixture is only shape-similar to a real circuit, document that approximation explicitly instead of describing it as the real circuit.
- Keep `README.md` focused on the current codebase state rather than changelog-style history; describe the format and behavior that exist now.

## Decision Heuristic

If a change improves software neatness but makes direct EVM verification less realistic or less efficient, reject it by default.
