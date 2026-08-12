#[path = "support/sha256_circom.rs"]
mod sha256_circom;

use std::{env, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use sha256_circom::{input_binary, message, Sha256CircomFixture};
use spartan_whir::{
    engine::F, recommended_octic_zk_whir_params, MatrixClosingMode, MlePcs, OcticBinExtension,
    Plonky3WhirPcs, PoseidonEngine, PoseidonSpartanProtocol, PoseidonZkProvingKey,
    PoseidonZkSetupConfig, PoseidonZkSpartanProtocol, PoseidonZkVerifyingKey, ProvingKey,
    R1csInstance, SecurityConfig, SoundnessAssumption, SpartanProofKind, SpartanSnarkConfig,
    VerifyingKey, ZkSpartanProof,
};

const SHA256_SIZE: usize = 2048;
const DEFAULT_CORPUS_SIZE: usize = 16;
const FULL_ZK_SEED: u64 = 0x5A25_6B32_4655_4C4C;

type PlainProtocol = PoseidonSpartanProtocol<OcticBinExtension>;
type FullZkProtocol = PoseidonZkSpartanProtocol<OcticBinExtension>;
type Engine = PoseidonEngine<OcticBinExtension>;
type PlainProvingKey = ProvingKey<Engine, Plonky3WhirPcs>;
type PlainVerifyingKey = VerifyingKey<Engine, Plonky3WhirPcs>;
type FullZkProvingKey = PoseidonZkProvingKey<OcticBinExtension>;
type FullZkVerifyingKey = PoseidonZkVerifyingKey<OcticBinExtension>;
type Commitment = <Plonky3WhirPcs as MlePcs<Engine>>::Commitment;
type Instance = R1csInstance<F, Commitment>;
type PlainProof = SpartanProofKind<Engine, Plonky3WhirPcs>;
type FullZkProof = ZkSpartanProof<OcticBinExtension>;

fn benchmark_sha256_full_zk(c: &mut Criterion) {
    let fixture = Sha256CircomFixture::load(SHA256_SIZE)
        .unwrap_or_else(|error| panic!("failed to load SHA-256 benchmark fixture: {error}"));
    let corpus_size = env_usize("SHA256_ZK_BENCH_CORPUS_SIZE", DEFAULT_CORPUS_SIZE);
    assert!(
        corpus_size > 1,
        "SHA256_ZK_BENCH_CORPUS_SIZE must exceed one"
    );
    let messages = (0..corpus_size)
        .map(|sample| message(SHA256_SIZE, sample))
        .collect::<Vec<_>>();
    let inputs = messages
        .iter()
        .map(|message| input_binary(message))
        .collect::<Vec<_>>();
    fixture
        .validate_input(&messages[0], &inputs[0])
        .expect("cached linked witness generator matches SHA-256");

    let num_variables = fixture.shape.num_vars.next_power_of_two().ilog2() as usize;
    let (plain_config, full_zk_config) = benchmark_configs(num_variables);
    let (plain_pk, plain_vk) = PlainProtocol::setup_with_config(&fixture.shape, &plain_config)
        .expect("plain-WHIR setup succeeds");
    let (full_zk_pk, full_zk_vk) =
        FullZkProvingKey::setup(fixture.shape.clone(), full_zk_config.clone())
            .expect("full-ZK setup succeeds");

    benchmark_setup(c, &fixture, &plain_config, &full_zk_config);
    benchmark_proving(c, &fixture, &plain_config, &plain_pk, &full_zk_pk);

    let (plain_proofs, full_zk_proofs) = build_proof_corpus(
        &fixture,
        &messages,
        &inputs,
        &plain_config,
        &plain_pk,
        &plain_vk,
        &full_zk_pk,
        &full_zk_vk,
    );
    report_proof_sizes(&plain_proofs, &full_zk_proofs);
    benchmark_verification(c, &plain_vk, &plain_proofs, &full_zk_vk, &full_zk_proofs);
}

fn benchmark_setup(
    c: &mut Criterion,
    fixture: &Sha256CircomFixture,
    plain_config: &SpartanSnarkConfig,
    full_zk_config: &PoseidonZkSetupConfig,
) {
    let mut group = c.benchmark_group(format!("sha256_{SHA256_SIZE}b/setup"));
    group.bench_function(BenchmarkId::from_parameter("no_zk"), |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                PlainProtocol::setup_with_config(&fixture.shape, plain_config)
                    .expect("plain-WHIR setup succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_function(BenchmarkId::from_parameter("full_zk"), |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                FullZkProvingKey::setup(fixture.shape.clone(), full_zk_config.clone())
                    .expect("full-ZK setup succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn benchmark_proving(
    c: &mut Criterion,
    fixture: &Sha256CircomFixture,
    config: &SpartanSnarkConfig,
    plain_pk: &PlainProvingKey,
    full_zk_pk: &FullZkProvingKey,
) {
    let mut group = c.benchmark_group(format!("sha256_{SHA256_SIZE}b/witness_and_prove"));
    let mut plain_sample = 0usize;
    group.bench_function(BenchmarkId::from_parameter("no_zk"), |bencher| {
        bencher.iter_batched(
            || {
                let input = input_binary(&message(SHA256_SIZE, plain_sample));
                plain_sample += 1;
                input
            },
            |input| {
                let (witness, public_inputs) = fixture
                    .generator
                    .generate_witness(&input, fixture.shape.num_vars, fixture.shape.num_io)
                    .expect("plain-WHIR witness generation succeeds");
                let mut challenger = spartan_whir::poseidon_challenger();
                PlainProtocol::prove_with_mode(
                    plain_pk,
                    &public_inputs,
                    &witness,
                    config.matrix_closing,
                    &mut challenger,
                )
                .expect("plain-WHIR proving succeeds")
            },
            BatchSize::PerIteration,
        );
    });

    let mut full_zk_sample = 0usize;
    group.bench_function(BenchmarkId::from_parameter("full_zk"), |bencher| {
        bencher.iter_batched(
            || {
                let sample = full_zk_sample;
                full_zk_sample += 1;
                let input = input_binary(&message(SHA256_SIZE, sample));
                (input, sample_rng(sample))
            },
            |(input, mut rng)| {
                let (witness, public_inputs) = fixture
                    .generator
                    .generate_witness(&input, fixture.shape.num_vars, fixture.shape.num_io)
                    .expect("full-ZK witness generation succeeds");
                let mut challenger = spartan_whir::poseidon_challenger();
                FullZkProtocol::prove_with_rng(
                    full_zk_pk,
                    &public_inputs,
                    &witness,
                    &mut challenger,
                    &mut rng,
                )
                .expect("full-ZK proving succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn build_proof_corpus(
    fixture: &Sha256CircomFixture,
    messages: &[Vec<u8>],
    inputs: &[Vec<u8>],
    config: &SpartanSnarkConfig,
    plain_pk: &PlainProvingKey,
    plain_vk: &PlainVerifyingKey,
    full_zk_pk: &FullZkProvingKey,
    full_zk_vk: &FullZkVerifyingKey,
) -> (Vec<(Instance, PlainProof)>, Vec<(Instance, FullZkProof)>) {
    let mut plain_proofs = Vec::with_capacity(inputs.len());
    let mut full_zk_proofs = Vec::with_capacity(inputs.len());
    for (sample, input) in inputs.iter().enumerate() {
        let (witness, public_inputs) = fixture
            .generator
            .generate_witness(input, fixture.shape.num_vars, fixture.shape.num_io)
            .expect("verification-corpus witness generation succeeds");
        fixture
            .validate_input(&messages[sample], input)
            .expect("verification-corpus input matches SHA-256");

        let mut plain_prover = spartan_whir::poseidon_challenger();
        let plain = PlainProtocol::prove_with_mode(
            plain_pk,
            &public_inputs,
            &witness,
            config.matrix_closing,
            &mut plain_prover,
        )
        .expect("verification-corpus plain-WHIR proof succeeds");
        let mut plain_verifier = spartan_whir::poseidon_challenger();
        PlainProtocol::verify_with_mode(plain_vk, &plain.0, &plain.1, &mut plain_verifier)
            .expect("verification-corpus plain-WHIR proof verifies");
        plain_proofs.push(plain);

        let mut rng = sample_rng(sample);
        let mut full_zk_prover = spartan_whir::poseidon_challenger();
        let full_zk = FullZkProtocol::prove_with_rng(
            full_zk_pk,
            &public_inputs,
            &witness,
            &mut full_zk_prover,
            &mut rng,
        )
        .expect("verification-corpus full-ZK proof succeeds");
        let mut full_zk_verifier = spartan_whir::poseidon_challenger();
        FullZkProtocol::verify(full_zk_vk, &full_zk.0, &full_zk.1, &mut full_zk_verifier)
            .expect("verification-corpus full-ZK proof verifies");
        full_zk_proofs.push(full_zk);
    }
    (plain_proofs, full_zk_proofs)
}

fn benchmark_verification(
    c: &mut Criterion,
    plain_vk: &PlainVerifyingKey,
    plain_proofs: &[(Instance, PlainProof)],
    full_zk_vk: &FullZkVerifyingKey,
    full_zk_proofs: &[(Instance, FullZkProof)],
) {
    let mut group = c.benchmark_group(format!("sha256_{SHA256_SIZE}b/verify"));
    let mut plain_sample = 0usize;
    group.bench_function(BenchmarkId::from_parameter("no_zk"), |bencher| {
        bencher.iter_batched(
            || {
                let (instance, proof) = &plain_proofs[plain_sample % plain_proofs.len()];
                plain_sample += 1;
                (instance, proof)
            },
            |(instance, proof)| {
                let mut challenger = spartan_whir::poseidon_challenger();
                PlainProtocol::verify_with_mode(plain_vk, instance, proof, &mut challenger)
                    .expect("plain-WHIR verification succeeds")
            },
            BatchSize::PerIteration,
        );
    });

    let mut full_zk_sample = 0usize;
    group.bench_function(BenchmarkId::from_parameter("full_zk"), |bencher| {
        bencher.iter_batched(
            || {
                let (instance, proof) = &full_zk_proofs[full_zk_sample % full_zk_proofs.len()];
                full_zk_sample += 1;
                (instance, proof)
            },
            |(instance, proof)| {
                let mut challenger = spartan_whir::poseidon_challenger();
                FullZkProtocol::verify(full_zk_vk, instance, proof, &mut challenger)
                    .expect("full-ZK verification succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn report_proof_sizes(
    plain_proofs: &[(Instance, PlainProof)],
    full_zk_proofs: &[(Instance, FullZkProof)],
) {
    let plain = size_stats(plain_proofs.iter().map(|(_, proof)| {
        bincode::serialize(proof)
            .expect("plain proof serializes")
            .len()
    }));
    let full_zk = size_stats(full_zk_proofs.iter().map(|(_, proof)| {
        bincode::serialize(proof)
            .expect("full-ZK proof serializes")
            .len()
    }));
    println!(
        "proof_size_bytes: variant=no_zk min={} median={} max={}",
        plain.min, plain.median, plain.max
    );
    println!(
        "proof_size_bytes: variant=full_zk min={} median={} max={}",
        full_zk.min, full_zk.median, full_zk.max
    );

    let application_masks = size_stats(full_zk_proofs.iter().map(|(_, proof)| {
        bincode::serialize(&(
            proof.inner_mask_commitment.clone(),
            proof.outer_mask_commitment.clone(),
        ))
        .expect("application-mask commitments serialize")
        .len()
    }));
    let outer_iop = size_stats(full_zk_proofs.iter().map(|(_, proof)| {
        bincode::serialize(&(
            &proof.outer_sumcheck,
            proof.outer_claims,
            &proof.outer_mask_evals,
        ))
        .expect("outer IOP proof serializes")
        .len()
    }));
    let inner_iop = size_stats(full_zk_proofs.iter().map(|(_, proof)| {
        bincode::serialize(&(
            &proof.inner_sumcheck,
            proof.inner_sumcheck_mask_commitment.clone(),
        ))
        .expect("inner IOP proof serializes")
        .len()
    }));
    let pcs_relation = size_stats(full_zk_proofs.iter().map(|(_, proof)| {
        bincode::serialize(&proof.pcs_proof)
            .expect("PCS relation proof serializes")
            .len()
    }));
    println!(
        "full_zk_proof_sections_median_bytes: application_mask_commitments={} outer_iop={} inner_iop={} pcs_relation={}",
        application_masks.median, outer_iop.median, inner_iop.median, pcs_relation.median
    );
}

struct SizeStats {
    min: usize,
    median: usize,
    max: usize,
}

fn size_stats(values: impl IntoIterator<Item = usize>) -> SizeStats {
    let mut values = values.into_iter().collect::<Vec<_>>();
    assert!(!values.is_empty(), "proof-size corpus must not be empty");
    values.sort_unstable();
    let median = if values.len().is_multiple_of(2) {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2
    } else {
        values[values.len() / 2]
    };
    SizeStats {
        min: values[0],
        median,
        max: values[values.len() - 1],
    }
}

fn sample_rng(sample: usize) -> StdRng {
    StdRng::seed_from_u64(FULL_ZK_SEED.wrapping_add(sample as u64))
}

fn env_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|error| panic!("{name} must be a usize: {error}")),
        Err(env::VarError::NotPresent) => default,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

fn benchmark_configs(num_variables: usize) -> (SpartanSnarkConfig, PoseidonZkSetupConfig) {
    let security = SecurityConfig {
        security_level_bits: 123,
        merkle_security_bits: 123,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    let whir = recommended_octic_zk_whir_params(num_variables);
    let plain = SpartanSnarkConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security,
        whir_params: whir.clone(),
        spark_whir_params: None,
    };
    let full_zk = PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security,
        whir_params: whir,
        ell_zk: env_usize("SHA256_BENCH_ZK_ELL", spartan_whir::DEFAULT_ZK_ELL),
        mask_log_inv_rate: env_usize(
            "SHA256_BENCH_ZK_MASK_LOG_INV_RATE",
            spartan_whir::DEFAULT_ZK_MASK_LOG_INV_RATE,
        ),
    };
    (plain, full_zk)
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_secs(4))
        .measurement_time(Duration::from_secs(12));
    targets = benchmark_sha256_full_zk
}
criterion_main!(benches);
