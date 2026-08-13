#[path = "support/sha256.rs"]
mod sha256;

use std::{env, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use rand::{
    distr::{Distribution, StandardUniform},
    rngs::StdRng,
    SeedableRng,
};
use serde::{Deserialize, Serialize};
use sha256::{input_binary, message, Sha256Fixture};
use spartan_whir::{
    engine::{ExtField, F},
    recommended_octic_zk_whir_params, MatrixClosingMode, MlePcs, OcticBinExtension, Plonky3WhirPcs,
    PoseidonChallenger, PoseidonEngine, PoseidonSpartanProtocol, PoseidonZkProvingKey,
    PoseidonZkSetupConfig, PoseidonZkSpartanProtocol, PoseidonZkVerifyingKey, ProvingKey,
    QuinticExtension, R1csInstance, SecurityConfig, SoundnessAssumption, SpartanProofKind,
    SpartanSnarkConfig, VerifyingKey, WhirFoldingSchedule, WhirParams, ZkSpartanProof,
};

const DEFAULT_SHA256_SIZE: usize = 2048;
const DEFAULT_CORPUS_SIZE: usize = 16;
const FULL_ZK_SEED: u64 = 0x5A25_6B32_4655_4C4C;

type PlainProtocol<Ext> = PoseidonSpartanProtocol<Ext>;
type FullZkProtocol<Ext> = PoseidonZkSpartanProtocol<Ext>;
type Engine<Ext> = PoseidonEngine<Ext>;
type PlainProvingKey<Ext> = ProvingKey<Engine<Ext>, Plonky3WhirPcs>;
type PlainVerifyingKey<Ext> = VerifyingKey<Engine<Ext>, Plonky3WhirPcs>;
type FullZkProvingKey<Ext> = PoseidonZkProvingKey<Ext>;
type FullZkVerifyingKey<Ext> = PoseidonZkVerifyingKey<Ext>;
type Commitment<Ext> = <Plonky3WhirPcs as MlePcs<Engine<Ext>>>::Commitment;
type Instance<Ext> = R1csInstance<F, Commitment<Ext>>;
type PlainProof<Ext> = SpartanProofKind<Engine<Ext>, Plonky3WhirPcs>;
type FullZkProof<Ext> = ZkSpartanProof<Ext>;

fn benchmark_sha256_full_zk(c: &mut Criterion) {
    let sha256_size = env_usize("SHA256_ZK_BENCH_SIZE", DEFAULT_SHA256_SIZE);
    match env_string("SHA256_ZK_BENCH_EXTENSION", "octic").as_str() {
        "octic" => benchmark_extension::<OcticBinExtension>(c, sha256_size, "octic"),
        "quintic" => benchmark_extension::<QuinticExtension>(c, sha256_size, "quintic"),
        extension => panic!("SHA256_ZK_BENCH_EXTENSION must be octic or quintic, got {extension}"),
    }
}

fn benchmark_extension<Ext>(c: &mut Criterion, sha256_size: usize, extension: &str)
where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<Commitment<Ext>>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
    let fixture = Sha256Fixture::load(sha256_size)
        .unwrap_or_else(|error| panic!("failed to load SHA-256 benchmark fixture: {error}"));
    let corpus_size = env_usize("SHA256_ZK_BENCH_CORPUS_SIZE", DEFAULT_CORPUS_SIZE);
    assert!(
        corpus_size > 1,
        "SHA256_ZK_BENCH_CORPUS_SIZE must exceed one"
    );
    let messages = (0..corpus_size)
        .map(|sample| message(sha256_size, sample))
        .collect::<Vec<_>>();
    let inputs = messages
        .iter()
        .map(|message| input_binary(message))
        .collect::<Vec<_>>();
    fixture
        .validate_input(&messages[0], &inputs[0])
        .expect("cached linked witness generator matches SHA-256");

    let num_variables = fixture.shape.num_vars.next_power_of_two().ilog2() as usize;
    let (plain_config, full_zk_config) = benchmark_configs(num_variables, extension);
    let (plain_pk, plain_vk) =
        PlainProtocol::<Ext>::setup_with_config(&fixture.shape, &plain_config)
            .expect("plain-WHIR setup succeeds");
    let (full_zk_pk, full_zk_vk) =
        FullZkProvingKey::<Ext>::setup(fixture.shape.clone(), full_zk_config.clone())
            .expect("full-ZK setup succeeds");

    benchmark_setup::<Ext>(
        c,
        sha256_size,
        extension,
        &fixture,
        &plain_config,
        &full_zk_config,
    );
    benchmark_proving::<Ext>(
        c,
        sha256_size,
        extension,
        &fixture,
        &plain_config,
        &plain_pk,
        &full_zk_pk,
    );

    let (plain_proofs, full_zk_proofs) = build_proof_corpus::<Ext>(
        &fixture,
        &messages,
        &inputs,
        &plain_config,
        &plain_pk,
        &plain_vk,
        &full_zk_pk,
        &full_zk_vk,
    );
    report_proof_sizes::<Ext>(&plain_proofs, &full_zk_proofs);
    benchmark_verification::<Ext>(
        c,
        sha256_size,
        extension,
        &plain_vk,
        &plain_proofs,
        &full_zk_vk,
        &full_zk_proofs,
    );
}

fn benchmark_setup<Ext>(
    c: &mut Criterion,
    sha256_size: usize,
    extension: &str,
    fixture: &Sha256Fixture,
    plain_config: &SpartanSnarkConfig,
    full_zk_config: &PoseidonZkSetupConfig,
) where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<Commitment<Ext>>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
    let mut group = c.benchmark_group(format!("sha256_{sha256_size}b_{extension}/setup"));
    group.bench_function(BenchmarkId::from_parameter("no_zk"), |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                PlainProtocol::<Ext>::setup_with_config(&fixture.shape, plain_config)
                    .expect("plain-WHIR setup succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_function(BenchmarkId::from_parameter("full_zk"), |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                FullZkProvingKey::<Ext>::setup(fixture.shape.clone(), full_zk_config.clone())
                    .expect("full-ZK setup succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn benchmark_proving<Ext>(
    c: &mut Criterion,
    sha256_size: usize,
    extension: &str,
    fixture: &Sha256Fixture,
    config: &SpartanSnarkConfig,
    plain_pk: &PlainProvingKey<Ext>,
    full_zk_pk: &FullZkProvingKey<Ext>,
) where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<Commitment<Ext>>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
    let mut group = c.benchmark_group(format!(
        "sha256_{sha256_size}b_{extension}/witness_and_prove"
    ));
    let mut plain_sample = 0usize;
    group.bench_function(BenchmarkId::from_parameter("no_zk"), |bencher| {
        bencher.iter_batched(
            || {
                let input = input_binary(&message(sha256_size, plain_sample));
                plain_sample += 1;
                input
            },
            |input| {
                let (witness, public_inputs) = fixture
                    .generator
                    .generate_witness(&input, fixture.shape.num_vars, fixture.shape.num_io)
                    .expect("plain-WHIR witness generation succeeds");
                let mut challenger = spartan_whir::poseidon_challenger();
                PlainProtocol::<Ext>::prove_with_mode(
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
                let input = input_binary(&message(sha256_size, sample));
                (input, sample_rng(sample))
            },
            |(input, mut rng)| {
                let (witness, public_inputs) = fixture
                    .generator
                    .generate_witness(&input, fixture.shape.num_vars, fixture.shape.num_io)
                    .expect("full-ZK witness generation succeeds");
                let mut challenger = spartan_whir::poseidon_challenger();
                FullZkProtocol::<Ext>::prove_with_rng(
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

fn build_proof_corpus<Ext>(
    fixture: &Sha256Fixture,
    messages: &[Vec<u8>],
    inputs: &[Vec<u8>],
    config: &SpartanSnarkConfig,
    plain_pk: &PlainProvingKey<Ext>,
    plain_vk: &PlainVerifyingKey<Ext>,
    full_zk_pk: &FullZkProvingKey<Ext>,
    full_zk_vk: &FullZkVerifyingKey<Ext>,
) -> (
    Vec<(Instance<Ext>, PlainProof<Ext>)>,
    Vec<(Instance<Ext>, FullZkProof<Ext>)>,
)
where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<Commitment<Ext>>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
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
        let plain = PlainProtocol::<Ext>::prove_with_mode(
            plain_pk,
            &public_inputs,
            &witness,
            config.matrix_closing,
            &mut plain_prover,
        )
        .expect("verification-corpus plain-WHIR proof succeeds");
        let mut plain_verifier = spartan_whir::poseidon_challenger();
        PlainProtocol::<Ext>::verify_with_mode(plain_vk, &plain.0, &plain.1, &mut plain_verifier)
            .expect("verification-corpus plain-WHIR proof verifies");
        plain_proofs.push(plain);

        let mut rng = sample_rng(sample);
        let mut full_zk_prover = spartan_whir::poseidon_challenger();
        let full_zk = FullZkProtocol::<Ext>::prove_with_rng(
            full_zk_pk,
            &public_inputs,
            &witness,
            &mut full_zk_prover,
            &mut rng,
        )
        .expect("verification-corpus full-ZK proof succeeds");
        let mut full_zk_verifier = spartan_whir::poseidon_challenger();
        FullZkProtocol::<Ext>::verify(full_zk_vk, &full_zk.0, &full_zk.1, &mut full_zk_verifier)
            .expect("verification-corpus full-ZK proof verifies");
        full_zk_proofs.push(full_zk);
    }
    (plain_proofs, full_zk_proofs)
}

fn benchmark_verification<Ext>(
    c: &mut Criterion,
    sha256_size: usize,
    extension: &str,
    plain_vk: &PlainVerifyingKey<Ext>,
    plain_proofs: &[(Instance<Ext>, PlainProof<Ext>)],
    full_zk_vk: &FullZkVerifyingKey<Ext>,
    full_zk_proofs: &[(Instance<Ext>, FullZkProof<Ext>)],
) where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<Commitment<Ext>>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
    let mut group = c.benchmark_group(format!("sha256_{sha256_size}b_{extension}/verify"));
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
                PlainProtocol::<Ext>::verify_with_mode(plain_vk, instance, proof, &mut challenger)
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
                FullZkProtocol::<Ext>::verify(full_zk_vk, instance, proof, &mut challenger)
                    .expect("full-ZK verification succeeds")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn report_proof_sizes<Ext>(
    plain_proofs: &[(Instance<Ext>, PlainProof<Ext>)],
    full_zk_proofs: &[(Instance<Ext>, FullZkProof<Ext>)],
) where
    Ext: ExtField + Serialize,
    StandardUniform: Distribution<Ext>,
{
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
        bincode::serialize(&(proof.application_mask_commitment.clone(),))
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

fn env_string(name: &str, default: &str) -> String {
    match env::var(name) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => default.to_owned(),
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

fn benchmark_configs(
    num_variables: usize,
    extension: &str,
) -> (SpartanSnarkConfig, PoseidonZkSetupConfig) {
    let security = SecurityConfig {
        security_level_bits: 123,
        merkle_security_bits: 123,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    let whir = benchmark_whir_params(num_variables, extension);
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

fn benchmark_whir_params(num_variables: usize, extension: &str) -> WhirParams {
    let Some(raw) = env::var_os("SHA256_ZK_BENCH_SCHEDULE") else {
        assert_eq!(
            extension, "octic",
            "SHA256_ZK_BENCH_SCHEDULE is required for non-octic extensions"
        );
        return recommended_octic_zk_whir_params(num_variables);
    };
    let label = raw
        .into_string()
        .unwrap_or_else(|_| panic!("SHA256_ZK_BENCH_SCHEDULE must be valid UTF-8"));
    let parts = label.split('_').collect::<Vec<_>>();
    assert!(
        parts.len() == 7 && parts[0] == extension && parts[1] == "cfsr",
        "unsupported SHA256_ZK_BENCH_SCHEDULE: {label}"
    );

    let pow_bits = parse_schedule_component(parts[2], "pow") as u32;
    let first = parse_schedule_component(parts[3], "ff");
    let rest = parse_schedule_component(parts[4], "rest");
    let starting_log_inv_rate = parse_schedule_component(parts[5], "lir");
    let rs_domain_initial_reduction_factor = parse_schedule_component(parts[6], "rsv");
    let schedule = WhirFoldingSchedule::ConstantFromSecondRound { first, rest };
    let round_log_inv_rates = benchmark_round_log_inv_rates(
        num_variables,
        &schedule,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    );

    WhirParams {
        pow_bits,
        folding_factor: first,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
        folding_schedule: Some(schedule),
        round_log_inv_rates,
    }
}

fn parse_schedule_component(component: &str, prefix: &str) -> usize {
    component
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("expected {prefix} component, got {component}"))
        .parse()
        .unwrap_or_else(|error| panic!("invalid {prefix} component {component}: {error}"))
}

fn benchmark_round_log_inv_rates(
    num_variables: usize,
    schedule: &WhirFoldingSchedule,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> Vec<usize> {
    let mut rate = starting_log_inv_rate;
    let num_rounds = folding_schedule_rounds(num_variables, schedule).saturating_sub(1);
    (0..num_rounds)
        .map(|round| {
            let folding = schedule.at_round(round).expect("schedule round exists");
            let reduction = if round == 0 {
                rs_domain_initial_reduction_factor
            } else {
                1
            };
            rate = rate
                .checked_add(folding)
                .and_then(|value| value.checked_sub(reduction))
                .unwrap_or_else(|| panic!("invalid log inverse rate at round {round}"));
            rate
        })
        .collect()
}

fn folding_schedule_rounds(num_variables: usize, schedule: &WhirFoldingSchedule) -> usize {
    let mut remaining = num_variables;
    for round in 0.. {
        let folding = schedule.at_round(round).expect("schedule round exists");
        assert!(folding <= remaining, "invalid folding schedule");
        remaining -= folding;
        if remaining <= spartan_whir::FINAL_SUMCHECK_MAX_VARIABLES {
            return round + 1;
        }
    }
    unreachable!()
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
