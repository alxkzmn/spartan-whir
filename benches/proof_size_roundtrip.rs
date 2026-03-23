use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use spartan_whir::engine::OcticBinExtension;
use spartan_whir::{
    encode_spartan_blob_v1_with_report, generate_satisfiable_fixture, new_keccak_challenger,
    KeccakEngine, ProofCodecConfig, SecurityConfig, SoundnessAssumption, SpartanProtocol,
    SumcheckStrategy, SyntheticR1csConfig, WhirParams, WhirPcs, WhirPcsConfig,
};

mod proof_size_tracing;

const DEFAULT_K: usize = 19;
const DEFAULT_NUM_IO: usize = 256;
const DEFAULT_A_TERMS: usize = 2;
const DEFAULT_B_TERMS: usize = 1;
const DEFAULT_SEED: u64 = 0x5A5A_2026_0310_0001;

fn phase3_security() -> SecurityConfig {
    SecurityConfig {
        security_level_bits: 80,
        merkle_security_bits: 80,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    }
}

fn phase3_whir_params() -> WhirParams {
    WhirParams {
        pow_bits: 20,
        folding_factor: 4,
        starting_log_inv_rate: 6,
        rs_domain_initial_reduction_factor: 3,
    }
}

fn phase3_pcs_config() -> WhirPcsConfig {
    WhirPcsConfig {
        num_variables: 0,
        security: phase3_security(),
        whir: phase3_whir_params(),
        sumcheck_strategy: SumcheckStrategy::Svo,
    }
}

fn read_env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn read_env_u64(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn bench_proof_size_roundtrip(c: &mut Criterion) {
    let k = read_env_usize("SPARTAN_WHIR_BENCH_K", DEFAULT_K);
    let num_constraints_default = 1usize
        .checked_shl(k as u32)
        .expect("k must be small enough for usize");
    let num_constraints = read_env_usize(
        "SPARTAN_WHIR_BENCH_NUM_CONSTRAINTS",
        num_constraints_default,
    );
    let num_io = read_env_usize("SPARTAN_WHIR_BENCH_NUM_IO", DEFAULT_NUM_IO);
    let a_terms = read_env_usize("SPARTAN_WHIR_BENCH_A_TERMS", DEFAULT_A_TERMS);
    let b_terms = read_env_usize("SPARTAN_WHIR_BENCH_B_TERMS", DEFAULT_B_TERMS);
    let seed = read_env_u64("SPARTAN_WHIR_BENCH_SEED", DEFAULT_SEED);

    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: k,
        num_constraints,
        num_io,
        a_terms_per_constraint: a_terms,
        b_terms_per_constraint: b_terms,
        seed,
    })
    .expect("fixture generation succeeds");

    let (pk, vk) = SpartanProtocol::<KeccakEngine<OcticBinExtension>, WhirPcs>::setup(
        &fixture.shape,
        &phase3_security(),
        &phase3_whir_params(),
        &phase3_pcs_config(),
    )
    .expect("setup succeeds");

    let mut challenger = new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine<OcticBinExtension>, WhirPcs>::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut challenger,
    )
    .expect("prove succeeds");

    let codec = ProofCodecConfig::default();
    let (_blob, report) =
        encode_spartan_blob_v1_with_report(&codec, &vk.pcs_config, &instance, &proof)
            .expect("encoding succeeds");
    proof_size_tracing::emit_proof_size_roundtrip_trace(
        k,
        num_constraints,
        num_io,
        a_terms,
        b_terms,
        seed,
        &report,
    );

    let mut prove_group = c.benchmark_group("proof_size_roundtrip");
    prove_group.sample_size(10);
    prove_group.throughput(Throughput::Elements(num_constraints as u64));
    prove_group.bench_with_input(
        BenchmarkId::new("prove", format!("k{k}_a{a_terms}_b{b_terms}")),
        &(),
        |b, _| {
            b.iter(|| {
                let mut prover_challenger = new_keccak_challenger();
                let (_instance, _proof) =
                    SpartanProtocol::<KeccakEngine<OcticBinExtension>, WhirPcs>::prove(
                        &pk,
                        &fixture.public_inputs,
                        &fixture.witness,
                        &mut prover_challenger,
                    )
                    .expect("prove succeeds");
            });
        },
    );
    prove_group.finish();

    let mut verify_group = c.benchmark_group("proof_size_roundtrip");
    verify_group.sample_size(10);
    verify_group.throughput(Throughput::Elements(num_constraints as u64));
    verify_group.bench_with_input(
        BenchmarkId::new("verify", format!("k{k}_a{a_terms}_b{b_terms}")),
        &(),
        |b, _| {
            b.iter(|| {
                let mut verifier_challenger = new_keccak_challenger();
                SpartanProtocol::<KeccakEngine<OcticBinExtension>, WhirPcs>::verify(
                    &vk,
                    &instance,
                    &proof,
                    &mut verifier_challenger,
                )
                .expect("verify succeeds");
            });
        },
    );
    verify_group.finish();
}

criterion_group!(benches, bench_proof_size_roundtrip);
criterion_main!(benches);
