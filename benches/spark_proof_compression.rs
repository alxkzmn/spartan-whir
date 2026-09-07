#[path = "support/sha256.rs"]
mod sha256;

use std::{env, fs, hint::black_box, path::PathBuf, time::Duration};

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use p3_challenger::FieldChallenger;
use p3_field::PrimeField32;
use rand::{rngs::StdRng, SeedableRng};
use serde_json::json;
use sha256::{input_binary, message, Sha256Fixture};
use spartan_whir::{
    engine::F,
    poseidon1_challenger, preprocess_spark_tables,
    proof_compression::{CompressedZkProofFor, ProofCompressionOptions},
    recommended_quintic_spark_fixed_whir_params, recommended_quintic_spark_read_whir_params,
    recommended_quintic_spark_zk_whir_params, MatrixClosingMode, Poseidon1Challenger,
    Poseidon1Engine, Poseidon1ZkCommitment, Poseidon1ZkProvingKey, Poseidon1ZkSpartanProof,
    Poseidon1ZkSpartanProtocol, Poseidon1ZkVerifyingKey, PoseidonZkSetupConfig, QuinticExtension,
    R1csInstance, SecurityConfig, SoundnessAssumption, SparkWhirParams,
};

const MESSAGE_BYTES: usize = 2048;
const SECURITY_BITS: u32 = 116;
const RNG_SEED: u64 = 0x5A25_6B32_4655_4C4C;
type Protocol = Poseidon1ZkSpartanProtocol<QuinticExtension>;
type ProvingKey = Poseidon1ZkProvingKey<QuinticExtension>;
type VerifyingKey = Poseidon1ZkVerifyingKey<QuinticExtension>;
type Proof = Poseidon1ZkSpartanProof<QuinticExtension>;
type CompressedProof = CompressedZkProofFor<Poseidon1Engine<QuinticExtension>>;
type Instance = R1csInstance<F, Poseidon1ZkCommitment>;

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    options: Option<ProofCompressionOptions>,
}

impl Variant {
    fn all() -> Vec<Self> {
        let rows = ProofCompressionOptions {
            structured_rows: true,
            ..ProofCompressionOptions::default()
        };
        let fresh = ProofCompressionOptions {
            fresh_rows: true,
            ..rows
        };
        let packed = ProofCompressionOptions {
            packed_fields: true,
            ..fresh
        };
        let metadata = ProofCompressionOptions {
            compact_integers: true,
            ..packed
        };
        let factored = ProofCompressionOptions {
            factored_rounds: true,
            ..metadata
        };
        let final_rows = ProofCompressionOptions {
            final_rows: true,
            ..factored
        };
        let derived_products = ProofCompressionOptions {
            derived_products: true,
            ..final_rows
        };
        let refined_metadata = ProofCompressionOptions {
            refined_metadata: true,
            ..derived_products
        };
        let duplicate_columns = ProofCompressionOptions {
            duplicate_columns: true,
            ..refined_metadata
        };
        vec![
            Self {
                name: "baseline",
                options: None,
            },
            Self {
                name: "rows",
                options: Some(rows),
            },
            Self {
                name: "rows_fresh",
                options: Some(fresh),
            },
            Self {
                name: "rows_fresh_packed",
                options: Some(packed),
            },
            Self {
                name: "rows_fresh_packed_metadata",
                options: Some(metadata),
            },
            Self {
                name: "rows_fresh_packed_metadata_factored",
                options: Some(factored),
            },
            Self {
                name: "final_rows",
                options: Some(final_rows),
            },
            Self {
                name: "derived_products",
                options: Some(derived_products),
            },
            Self {
                name: "refined_metadata",
                options: Some(refined_metadata),
            },
            Self {
                name: "duplicate_columns",
                options: Some(duplicate_columns),
            },
        ]
    }
}

enum PreparedProof {
    Baseline(Proof),
    Compressed(CompressedProof),
}

impl PreparedProof {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Baseline(proof) => bincode::serialize(proof).expect("baseline encodes"),
            Self::Compressed(proof) => proof.to_bytes().expect("compressed proof encodes"),
        }
    }
}

struct Sample {
    instance: Instance,
    proof: PreparedProof,
    bytes: Vec<u8>,
}

struct Corpus {
    variant: Variant,
    samples: Vec<Sample>,
}

fn selected_names(name: &str, allowed: &[&str]) -> Vec<String> {
    let value = env::var(name).unwrap_or_else(|_| String::from("all"));
    let selected = if value == "all" {
        allowed
            .iter()
            .map(|name| String::from(*name))
            .collect::<Vec<_>>()
    } else {
        value
            .split(',')
            .map(|value| value.trim().to_owned())
            .collect::<Vec<_>>()
    };
    assert!(!selected.is_empty(), "{name} must not be empty");
    for item in &selected {
        assert!(
            allowed.contains(&item.as_str()),
            "unknown {name} value {item}; expected {allowed:?}"
        );
    }
    selected
}

fn env_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be an integer")),
        Err(env::VarError::NotPresent) => default,
        Err(error) => panic!("invalid {name}: {error}"),
    }
}

fn config(fixture: &Sha256Fixture) -> PoseidonZkSetupConfig {
    let witness_variables = fixture.shape.num_vars.next_power_of_two().ilog2() as usize;
    let tables = preprocess_spark_tables(&fixture.shape).expect("SPARK tables preprocess");
    let value_variables = tables.value_domain_size.ilog2() as usize;
    let fixed_variables = value_variables + spartan_whir::protocol::fixed_value_column_bits();
    let audit_variables = tables.row_memory_size.max(tables.col_memory_size).ilog2() as usize
        + spartan_whir::protocol::fixed_audit_column_bits();
    let read_variables =
        value_variables + spartan_whir::protocol::read_table_column_bits::<QuinticExtension>();
    let mut read = recommended_quintic_spark_read_whir_params(read_variables);
    // The same read schedule serves both power-of-two coordinate groups.
    read.round_log_inv_rates.clear();
    PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::Spark,
        security: SecurityConfig {
            security_level_bits: SECURITY_BITS,
            merkle_security_bits: SECURITY_BITS,
            soundness_assumption: SoundnessAssumption::JohnsonBound,
        },
        whir_params: recommended_quintic_spark_zk_whir_params(witness_variables),
        spark_whir_params: Some(SparkWhirParams {
            fixed_value: recommended_quintic_spark_fixed_whir_params(fixed_variables),
            fixed_audit: recommended_quintic_spark_fixed_whir_params(audit_variables),
            read,
        }),
        ell_zk: spartan_whir::DEFAULT_ZK_ELL,
        mask_log_inv_rate: spartan_whir::DEFAULT_ZK_MASK_LOG_INV_RATE,
    }
}

fn sample_rng(sample: usize) -> StdRng {
    StdRng::seed_from_u64(RNG_SEED.wrapping_add(sample as u64))
}

fn challenge_sample(mut challenger: Poseidon1Challenger) -> Vec<QuinticExtension> {
    (0..16)
        .map(|_| challenger.sample_algebra_element())
        .collect()
}

fn decode_and_verify(vk: &VerifyingKey, sample: &Sample, variant: Variant) {
    let mut challenger = poseidon1_challenger();
    if variant.options.is_some() {
        let proof = CompressedProof::from_bytes(black_box(&sample.bytes)).expect("proof decodes");
        Protocol::verify_compressed(vk, black_box(&sample.instance), proof, &mut challenger)
            .expect("compressed proof verifies");
    } else {
        let proof: Proof = bincode::deserialize(black_box(&sample.bytes)).expect("proof decodes");
        Protocol::verify(vk, black_box(&sample.instance), &proof, &mut challenger)
            .expect("baseline proof verifies");
    }
}

fn build_corpora(
    witnesses: &[(spartan_whir::R1csWitness<F>, Vec<F>)],
    pk: &ProvingKey,
    vk: &VerifyingKey,
    variants: &[Variant],
) -> Vec<Corpus> {
    // Baseline proofs are always present for matched size and challenge checks,
    // even when their timing is excluded by the variant filter.
    let mut corpora = vec![Corpus {
        variant: Variant::all()[0],
        samples: Vec::new(),
    }];
    corpora.extend(
        variants
            .iter()
            .filter(|variant| variant.options.is_some())
            .map(|&variant| Corpus {
                variant,
                samples: Vec::new(),
            }),
    );
    for (sample_index, (witness, public_inputs)) in witnesses.iter().enumerate() {
        let mut prover = poseidon1_challenger();
        let (instance, proof) = Protocol::prove_with_rng(
            pk,
            public_inputs,
            witness,
            &mut prover,
            &mut sample_rng(sample_index),
        )
        .expect("baseline corpus proving succeeds");
        let expected_challenges = challenge_sample(prover);
        let expected_instance = bincode::serialize(&instance).expect("instance serializes");
        let mut verifier = poseidon1_challenger();
        Protocol::verify(vk, &instance, &proof, &mut verifier).expect("baseline corpus verifies");
        assert_eq!(
            challenge_sample(verifier),
            expected_challenges,
            "baseline prover/verifier challenge samples match"
        );
        let proof = PreparedProof::Baseline(proof);
        let bytes = proof.encode();
        corpora[0].samples.push(Sample {
            instance,
            proof,
            bytes,
        });

        for corpus in &mut corpora[1..] {
            let mut prover = poseidon1_challenger();
            let (instance, proof) = Protocol::prove_compressed_with_rng(
                pk,
                public_inputs,
                witness,
                &mut prover,
                &mut sample_rng(sample_index),
                corpus.variant.options.expect("compressed variant"),
            )
            .expect("compressed corpus proving succeeds");
            assert_eq!(
                bincode::serialize(&instance).unwrap(),
                expected_instance,
                "matched proof instances agree"
            );
            assert_eq!(
                challenge_sample(prover),
                expected_challenges,
                "compressed and baseline prover challenge samples match"
            );
            let bytes = proof.to_bytes().expect("compressed proof encodes");
            let decoded = CompressedProof::from_bytes(&bytes).expect("compressed proof decodes");
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "compressed encoding is canonical"
            );
            let mut verifier = poseidon1_challenger();
            Protocol::verify_compressed(vk, &instance, decoded, &mut verifier)
                .expect("compressed corpus verifies");
            assert_eq!(
                challenge_sample(verifier),
                expected_challenges,
                "compressed verifier challenge samples match"
            );
            corpus.samples.push(Sample {
                instance,
                proof: PreparedProof::Compressed(proof),
                bytes,
            });
        }
        println!("corpus_sample_verified: {}", sample_index + 1);
    }
    for corpus in &corpora {
        for sample in &corpus.samples {
            decode_and_verify(vk, sample, corpus.variant);
        }
    }
    corpora
}

fn write_size_report(
    fixture: &Sha256Fixture,
    setup: &PoseidonZkSetupConfig,
    corpora: &[Corpus],
    selected: &[Variant],
    phases: &[String],
) {
    let baseline = &corpora[0].samples;
    let variants = corpora.iter().map(|corpus| {
        let bytes = corpus.samples.iter().map(|sample| sample.bytes.len()).collect::<Vec<_>>();
        let saved = bytes.iter().zip(baseline).map(|(size, baseline)| {
            baseline.bytes.len() as i64 - *size as i64
        }).collect::<Vec<_>>();
        let mut sorted = bytes.clone();
        sorted.sort_unstable();
        let options = corpus.variant.options.map(|options| json!({
            "structured_rows": options.structured_rows,
            "fresh_rows": options.fresh_rows,
            "packed_fields": options.packed_fields,
            "compact_integers": options.compact_integers,
            "factored_rounds": options.factored_rounds,
            "final_rows": options.final_rows,
            "derived_products": options.derived_products,
            "refined_metadata": options.refined_metadata,
            "duplicate_columns": options.duplicate_columns,
        }));
        let statistics = corpus.samples.iter().map(|sample| match &sample.proof {
            PreparedProof::Baseline(_) => None,
            PreparedProof::Compressed(proof) => {
                let mut statistics = proof.encoding_statistics().expect("encoding statistics succeed");
                let field_count = statistics["field_elements"].as_u64().unwrap() as f64;
                statistics["ideal_field_range_saving_bytes"] = json!(field_count * (31.0 - f64::from(F::ORDER_U32).log2()) / 8.0);
                // Removing every non-field bit is a conservative upper bound
                // for any optimization that only omits vector lengths.
                statistics["all_non_field_saving_bound_bytes"] = json!(statistics["refined_other_bits"].as_u64().unwrap() as f64 / 8.0);
                Some(statistics)
            },
        }).collect::<Vec<_>>();
        json!({
            "variant": corpus.variant.name,
            "options": options,
            "encoding_statistics": statistics,
            "proof_bytes": bytes,
            "bytes_saved_against_matched_baseline": saved,
            "min_bytes": sorted[0],
            "median_bytes": (sorted[(sorted.len() - 1) / 2] as f64 + sorted[sorted.len() / 2] as f64) / 2.0,
            "max_bytes": sorted[sorted.len() - 1],
            "mean_bytes": sorted.iter().sum::<usize>() as f64 / sorted.len() as f64,
        })
    }).collect::<Vec<_>>();
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let report = json!({
        "schema": 1,
        "workload": "sha256_2048b_full_zk_poseidon1_quintic_spark",
        "features": "parallel,poseidon1",
        "security_bits": SECURITY_BITS,
        "setup": setup,
        "shape": { "num_cons": fixture.shape.num_cons, "num_vars": fixture.shape.num_vars, "num_io": fixture.shape.num_io },
        "git_revision": revision,
        "rustflags": env::var("RUSTFLAGS").ok(),
        "threads": p3_maybe_rayon::prelude::current_num_threads(),
        "corpus_threads": 1,
        "fixture_workdir": env::var("SHA256_BENCH_WORKDIR").ok(),
        "corpus_size": baseline.len(),
        "rng_seed": RNG_SEED,
        "verified_every_sample": true,
        "matched_instance_bytes": true,
        "matched_postproof_extension_challenges": 16,
        "timed_variants": selected.iter().map(|variant| variant.name).collect::<Vec<_>>(),
        "phases": phases,
        "sample_size": env_usize("SPARK_COMPRESSION_SAMPLES", 10),
        "warmup_seconds": env_usize("SPARK_COMPRESSION_WARMUP_SECONDS", 3),
        "measurement_seconds": env_usize("SPARK_COMPRESSION_MEASUREMENT_SECONDS", 15),
        "variants": variants,
    });
    let path = env::var_os("SPARK_COMPRESSION_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/spark-proof-compression-sizes.json"));
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).expect("report directory exists");
    }
    fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).expect("size report writes");
    println!("proof_size_report: {}", path.display());
    println!(
        "proof_size_json: {}",
        serde_json::to_string(&report).unwrap()
    );
}

fn benchmark(c: &mut Criterion) {
    let all = Variant::all();
    let names = selected_names(
        "SPARK_COMPRESSION_VARIANTS",
        &all.iter().map(|variant| variant.name).collect::<Vec<_>>(),
    );
    let mut variants = all
        .into_iter()
        .filter(|variant| names.iter().any(|name| name == variant.name))
        .collect::<Vec<_>>();
    if env::var("SPARK_COMPRESSION_REVERSE").is_ok_and(|value| value == "1") {
        variants.reverse();
    }
    let phases = selected_names(
        "SPARK_COMPRESSION_PHASES",
        &["end_to_end", "encode", "decode_verify"],
    );
    let corpus_size = env_usize("SPARK_COMPRESSION_CORPUS_SIZE", 4);
    assert!(
        corpus_size >= 4,
        "SPARK_COMPRESSION_CORPUS_SIZE must be at least four"
    );
    let fixture = Sha256Fixture::load(MESSAGE_BYTES).expect("cached SHA256 fixture loads");
    let inputs = (0..corpus_size)
        .map(|sample| {
            let message = message(MESSAGE_BYTES, sample);
            let input = input_binary(&message);
            fixture
                .validate_input(&message, &input)
                .expect("linked witness matches SHA256");
            input
        })
        .collect::<Vec<_>>();
    let setup = config(&fixture);
    let (pk, vk) =
        ProvingKey::setup(fixture.shape.clone(), setup.clone()).expect("selected setup succeeds");
    // Parallel grinding may select a different valid witness on repeated
    // proofs. Build the matched corpus deterministically; timed proving still
    // uses the caller's configured Rayon pool.
    let corpus_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let witnesses = inputs
        .iter()
        .map(|input| {
            fixture
                .generator
                .generate_witness(input, fixture.shape.num_vars, fixture.shape.num_io)
                .expect("corpus witness generation succeeds")
        })
        .collect::<Vec<_>>();
    let corpora = corpus_pool.install(|| build_corpora(&witnesses, &pk, &vk, &variants));
    if let Some(directory) = env::var_os("SPARK_COMPRESSION_DUMP_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).expect("proof dump directory exists");
        for corpus in &corpora {
            fs::write(
                directory.join(format!("{}.bin", corpus.variant.name)),
                &corpus.samples[0].bytes,
            )
            .expect("sample proof writes");
        }
    }
    write_size_report(&fixture, &setup, &corpora, &variants, &phases);
    if env::var("SPARK_COMPRESSION_SIZES_ONLY").is_ok_and(|value| value == "1") {
        return;
    }

    for phase in &phases {
        let mut group = c.benchmark_group(format!("spark_proof_compression/{phase}"));
        group.throughput(Throughput::Elements(1));
        if phase == "end_to_end" {
            group.sampling_mode(SamplingMode::Flat);
        }
        for &variant in &variants {
            let corpus = corpora
                .iter()
                .find(|corpus| corpus.variant.name == variant.name)
                .unwrap();
            let mut next_sample = 0usize;
            group.bench_function(BenchmarkId::from_parameter(variant.name), |bencher| {
                match phase.as_str() {
                    "encode" => bencher.iter_batched(
                        || {
                            let sample = next_sample % corpus.samples.len();
                            next_sample += 1;
                            sample
                        },
                        |sample| black_box(corpus.samples[sample].proof.encode()),
                        BatchSize::PerIteration,
                    ),
                    "decode_verify" => bencher.iter_batched(
                        || {
                            let sample = next_sample % corpus.samples.len();
                            next_sample += 1;
                            sample
                        },
                        |sample| {
                            decode_and_verify(black_box(&vk), &corpus.samples[sample], variant)
                        },
                        BatchSize::PerIteration,
                    ),
                    "end_to_end" => bencher.iter_batched(
                        || {
                            let sample = next_sample;
                            next_sample += 1;
                            (sample, sample_rng(sample))
                        },
                        |(sample, mut rng)| {
                            let (witness, public_inputs) = fixture
                                .generator
                                .generate_witness(
                                    black_box(&inputs[sample % inputs.len()]),
                                    fixture.shape.num_vars,
                                    fixture.shape.num_io,
                                )
                                .expect("timed witness generation succeeds");
                            let mut challenger = poseidon1_challenger();
                            let (instance, proof) = match variant.options {
                                None => {
                                    let (instance, proof) = Protocol::prove_with_rng(
                                        &pk,
                                        &public_inputs,
                                        &witness,
                                        &mut challenger,
                                        &mut rng,
                                    )
                                    .expect("timed baseline proving succeeds");
                                    (instance, PreparedProof::Baseline(proof))
                                }
                                Some(options) => {
                                    let (instance, proof) = Protocol::prove_compressed_with_rng(
                                        &pk,
                                        &public_inputs,
                                        &witness,
                                        &mut challenger,
                                        &mut rng,
                                        options,
                                    )
                                    .expect("timed compressed proving succeeds");
                                    (instance, PreparedProof::Compressed(proof))
                                }
                            };
                            let bytes = proof.encode();
                            // Criterion drops large proof objects and output bytes
                            // after timing, consistently across all variants.
                            black_box((instance, proof, bytes))
                        },
                        BatchSize::PerIteration,
                    ),
                    _ => unreachable!("validated phase"),
                }
            });
        }
        group.finish();
    }
}

fn criterion_config() -> Criterion {
    let samples = env_usize("SPARK_COMPRESSION_SAMPLES", 10);
    let warmup = env_usize("SPARK_COMPRESSION_WARMUP_SECONDS", 3);
    let measurement = env_usize("SPARK_COMPRESSION_MEASUREMENT_SECONDS", 15);
    assert!(samples >= 10, "Criterion requires at least ten samples");
    assert!(warmup >= 1, "warmup must be at least one second");
    assert!(
        measurement >= 10,
        "measurement must be at least ten seconds"
    );
    Criterion::default()
        .sample_size(samples)
        .warm_up_time(Duration::from_secs(warmup as u64))
        .measurement_time(Duration::from_secs(measurement as u64))
}

criterion_group! { name = benches; config = criterion_config(); targets = benchmark }
criterion_main!(benches);
