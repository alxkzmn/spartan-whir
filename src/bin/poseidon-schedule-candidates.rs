use std::{env, panic, process};

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, FieldChallenger, GrindingChallenger};
use p3_field::{extension::BinomialExtensionField, ExtensionField, Field, TwoAdicField};
use p3_whir::parameters::{
    FoldingFactor, ProtocolParameters, SecurityAssumption as P3SecurityAssumption,
    WhirConfig as P3WhirConfig,
};
use serde::Serialize;
use spartan_whir::{
    engine::{PoseidonChallenger, F},
    MatrixClosingMode, OcticBinExtension, PoseidonZkSetupConfig, QuarticBinExtension,
    SecurityConfig, SoundnessAssumption, SpartanSnarkConfig, WhirFoldingSchedule, WhirParams,
    FINAL_SUMCHECK_MAX_VARIABLES,
};

const DEFAULT_SECURITY_BITS: usize = 123;
const DEFAULT_K_MAX: usize = 8;
const DEFAULT_LIR_MAX: usize = 8;
const DEFAULT_MAX_POW_BITS: usize = 22;
const DEFAULT_BEAM_WIDTH: usize = 64;
const POW_BITS_CANDIDATES: &[usize] = &[0, 4, 8, 12, 16, 20, 22];
const FIELD_BYTES: u128 = 4;
const POSEIDON_DIGEST_BYTES: u128 = 32;

type KoalaBearQuinticExtension = spartan_whir::QuinticExtension;
type BabyBearQuarticExtension = BinomialExtensionField<BabyBear, 4>;
type BabyBearQuinticExtension = BinomialExtensionField<BabyBear, 5>;
type BabyBearOcticExtension = BinomialExtensionField<BabyBear, 8>;
type BabyBearPoseidonChallenger = DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldProfile {
    KoalaBear,
    BabyBear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofMode {
    NoZk,
    FullZk,
}

impl ProofMode {
    const fn label(self) -> &'static str {
        match self {
            Self::NoZk => "no-zk",
            Self::FullZk => "full-zk",
        }
    }

    const fn is_full_zk(self) -> bool {
        matches!(self, Self::FullZk)
    }
}

impl FieldProfile {
    const fn label(self) -> &'static str {
        match self {
            Self::KoalaBear => "koalabear",
            Self::BabyBear => "babybear",
        }
    }
}

#[derive(Debug, Clone)]
struct Args {
    field: FieldProfile,
    num_variables: usize,
    security_bits: usize,
    merkle_security_bits: usize,
    k_max: usize,
    starting_log_inv_rate_max: usize,
    max_pow_bits: usize,
    final_sumcheck_max_variables: usize,
    beam_width: usize,
    include_invalid: bool,
    proof_mode: ProofMode,
    zk_ell: usize,
    zk_mask_log_inv_rate: usize,
}

#[derive(Debug, Serialize)]
struct CandidateDump {
    schema_version: u32,
    matrix_closing: MatrixClosingMode,
    base_field: &'static str,
    num_variables: usize,
    target_security_bits: usize,
    soundness: SoundnessAssumption,
    max_pow_bits: usize,
    proof_mode: &'static str,
    zk_ell: Option<usize>,
    zk_mask_log_inv_rate: Option<usize>,
    candidates: Vec<CandidateRow>,
}

#[derive(Debug, Serialize)]
struct CandidateRow {
    label: String,
    proof_mode: &'static str,
    base_field: &'static str,
    base_two_adicity: usize,
    extension: &'static str,
    extension_degree: usize,
    extension_two_adicity: usize,
    field_bits: usize,
    valid: bool,
    rejection_reason: Option<String>,
    security_bits_achieved: Option<f64>,
    max_derived_pow_bits: Option<usize>,
    pow_work_units: u128,
    dft_work: u128,
    merkle_work: u128,
    merkle_path_work: u128,
    row_work: u128,
    sumcheck_work: u128,
    proof_size_bytes_estimate: u128,
    zk_dft_work: Option<u128>,
    zk_merkle_work: Option<u128>,
    zk_merkle_path_work: Option<u128>,
    zk_row_work: Option<u128>,
    zk_sumcheck_work: Option<u128>,
    zk_proof_size_bytes_estimate: Option<u128>,
    zk_mask_queries: Option<usize>,
    zk_ell: Option<usize>,
    zk_mask_log_inv_rate: Option<usize>,
    commitment_ood_samples: Option<usize>,
    starting_folding_pow_bits: Option<usize>,
    final_queries: Option<usize>,
    final_pow_bits: Option<usize>,
    final_sumcheck_rounds: Option<usize>,
    final_folding_pow_bits: Option<usize>,
    rounds: Vec<RoundRow>,
    whir_params: WhirParams,
    setup_config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RoundRow {
    round_index: usize,
    num_variables: usize,
    folding_factor: usize,
    log_inv_rate: usize,
    domain_size: usize,
    num_queries: usize,
    ood_samples: usize,
    pow_bits: usize,
    folding_pow_bits: usize,
}

fn main() {
    let args = parse_args().unwrap_or_else(|error| {
        eprintln!("{error}");
        usage();
        process::exit(2);
    });

    let mut candidates = Vec::new();
    for schedule in schedules(&args) {
        for pow_bits in POW_BITS_CANDIDATES
            .iter()
            .copied()
            .filter(|pow| *pow <= args.max_pow_bits)
        {
            for starting_log_inv_rate in 1..=args.starting_log_inv_rate_max {
                let first = schedule.first_round();
                for rsv in 1..=first {
                    let round_log_inv_rates = match derived_round_log_inv_rates(
                        args.num_variables,
                        &schedule,
                        starting_log_inv_rate,
                        rsv,
                    ) {
                        Ok(rates) => rates,
                        Err(reason) => {
                            if args.include_invalid {
                                let whir_params = WhirParams {
                                    pow_bits: pow_bits as u32,
                                    folding_factor: first,
                                    starting_log_inv_rate,
                                    rs_domain_initial_reduction_factor: rsv,
                                    folding_schedule: Some(schedule.clone()),
                                    round_log_inv_rates: Vec::new(),
                                };
                                push_invalid_rate_candidates(
                                    &args,
                                    &mut candidates,
                                    whir_params,
                                    format!("unable to derive round log inverse rates: {reason}"),
                                );
                            }
                            continue;
                        }
                    };
                    let whir_params = WhirParams {
                        pow_bits: pow_bits as u32,
                        folding_factor: first,
                        starting_log_inv_rate,
                        rs_domain_initial_reduction_factor: rsv,
                        folding_schedule: Some(schedule.clone()),
                        round_log_inv_rates,
                    };
                    push_candidates(&args, &mut candidates, whir_params);
                }
            }
        }
    }

    let dump = CandidateDump {
        schema_version: 2,
        matrix_closing: MatrixClosingMode::DirectSparse,
        base_field: args.field.label(),
        num_variables: args.num_variables,
        target_security_bits: args.security_bits,
        soundness: SoundnessAssumption::JohnsonBound,
        max_pow_bits: args.max_pow_bits,
        proof_mode: args.proof_mode.label(),
        zk_ell: args.proof_mode.is_full_zk().then_some(args.zk_ell),
        zk_mask_log_inv_rate: args
            .proof_mode
            .is_full_zk()
            .then_some(args.zk_mask_log_inv_rate),
        candidates,
    };
    serde_json::to_writer_pretty(std::io::stdout(), &dump).expect("write candidate JSON");
    println!();
}

fn push_invalid_rate_candidates(
    args: &Args,
    out: &mut Vec<CandidateRow>,
    whir_params: WhirParams,
    reason: String,
) {
    match args.field {
        FieldProfile::KoalaBear => {
            push_invalid_rate_candidate::<F, QuarticBinExtension>(
                args,
                out,
                whir_params.clone(),
                args.field.label(),
                "quartic",
                4,
                reason.clone(),
            );
            push_invalid_rate_candidate::<F, KoalaBearQuinticExtension>(
                args,
                out,
                whir_params.clone(),
                args.field.label(),
                "quintic",
                5,
                reason.clone(),
            );
            push_invalid_rate_candidate::<F, OcticBinExtension>(
                args,
                out,
                whir_params,
                args.field.label(),
                "octic",
                8,
                reason,
            );
        }
        FieldProfile::BabyBear => {
            push_invalid_rate_candidate::<BabyBear, BabyBearQuarticExtension>(
                args,
                out,
                whir_params.clone(),
                args.field.label(),
                "quartic",
                4,
                reason.clone(),
            );
            push_invalid_rate_candidate::<BabyBear, BabyBearQuinticExtension>(
                args,
                out,
                whir_params.clone(),
                args.field.label(),
                "quintic",
                5,
                reason.clone(),
            );
            push_invalid_rate_candidate::<BabyBear, BabyBearOcticExtension>(
                args,
                out,
                whir_params,
                args.field.label(),
                "octic",
                8,
                reason,
            );
        }
    }
}

fn push_invalid_rate_candidate<Base, Ext>(
    args: &Args,
    out: &mut Vec<CandidateRow>,
    whir_params: WhirParams,
    base_field: &'static str,
    extension: &'static str,
    extension_degree: usize,
    reason: String,
) where
    Base: TwoAdicField,
    Ext: Field + TwoAdicField,
{
    let label = schedule_label(extension, &whir_params);
    out.push(invalid_row(
        args,
        label,
        base_field,
        Base::TWO_ADICITY,
        extension,
        extension_degree,
        Ext::TWO_ADICITY,
        Ext::bits(),
        whir_params,
        reason,
    ));
}

fn push_candidates(args: &Args, out: &mut Vec<CandidateRow>, whir_params: WhirParams) {
    match args.field {
        FieldProfile::KoalaBear => {
            derive_for_extension::<F, QuarticBinExtension, PoseidonChallenger>(
                args,
                out,
                whir_params.clone(),
                "quartic",
                4,
            );
            derive_for_extension::<F, KoalaBearQuinticExtension, PoseidonChallenger>(
                args,
                out,
                whir_params.clone(),
                "quintic",
                5,
            );
            derive_for_extension::<F, OcticBinExtension, PoseidonChallenger>(
                args,
                out,
                whir_params,
                "octic",
                8,
            );
        }
        FieldProfile::BabyBear => {
            derive_for_extension::<BabyBear, BabyBearQuarticExtension, BabyBearPoseidonChallenger>(
                args,
                out,
                whir_params.clone(),
                "quartic",
                4,
            );
            derive_for_extension::<BabyBear, BabyBearQuinticExtension, BabyBearPoseidonChallenger>(
                args,
                out,
                whir_params.clone(),
                "quintic",
                5,
            );
            derive_for_extension::<BabyBear, BabyBearOcticExtension, BabyBearPoseidonChallenger>(
                args,
                out,
                whir_params,
                "octic",
                8,
            );
        }
    }
}

fn derive_for_extension<Base, Ext, Challenger>(
    args: &Args,
    out: &mut Vec<CandidateRow>,
    whir_params: WhirParams,
    extension: &'static str,
    extension_degree: usize,
) where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let label = schedule_label(extension, &whir_params);
    let protocol_params = protocol_parameters(&whir_params, args.security_bits);
    let result = catch_unwind_silent(|| {
        P3WhirConfig::<Ext, Base, Challenger>::new(args.num_variables, protocol_params)
    });

    let config = match result {
        Ok(Ok(config)) => config,
        Ok(Err(reason)) => {
            if args.include_invalid {
                out.push(invalid_row(
                    args,
                    label,
                    args.field.label(),
                    Base::TWO_ADICITY,
                    extension,
                    extension_degree,
                    Ext::TWO_ADICITY,
                    Ext::bits(),
                    whir_params,
                    format!("backend rejected candidate: {reason}"),
                ));
            }
            return;
        }
        Err(reason) => {
            if args.include_invalid {
                out.push(invalid_row(
                    args,
                    label,
                    args.field.label(),
                    Base::TWO_ADICITY,
                    extension,
                    extension_degree,
                    Ext::TWO_ADICITY,
                    Ext::bits(),
                    whir_params,
                    format!("backend panicked while deriving candidate: {reason}"),
                ));
            }
            return;
        }
    };

    let achieved = achieved_security_bits::<Base, Ext, Challenger>(&config);
    let max_pow = max_derived_pow_bits::<Base, Ext, Challenger>(&config);
    let zk_rejection = if args.proof_mode.is_full_zk() {
        zk_compatibility_error::<Base, Ext, Challenger>(args, &config)
    } else {
        None
    };
    let valid = achieved >= args.security_bits as f64
        && max_pow <= args.max_pow_bits
        && zk_rejection.is_none();
    if !valid && !args.include_invalid {
        return;
    }

    let setup_config = valid.then(|| setup_config(args, whir_params.clone()));
    let rounds = config
        .round_parameters
        .iter()
        .enumerate()
        .map(|(round_index, round)| RoundRow {
            round_index,
            num_variables: round.num_variables,
            folding_factor: round.folding_factor,
            log_inv_rate: round.log_inv_rate,
            domain_size: round.domain_size,
            num_queries: round.num_queries,
            ood_samples: round.ood_samples,
            pow_bits: round.pow_bits,
            folding_pow_bits: round.folding_pow_bits,
        })
        .collect::<Vec<_>>();
    let pow_work_units = pow_work_units::<Base, Ext, Challenger>(&config);
    let dft_work = dft_work::<Base, Ext, Challenger>(&config);
    let merkle_work = merkle_work::<Base, Ext, Challenger>(&config);
    let merkle_path_work = merkle_path_work::<Base, Ext, Challenger>(&config);
    let row_work = row_work::<Base, Ext, Challenger>(&config);
    let sumcheck_work = sumcheck_work::<Base, Ext, Challenger>(&config);
    let plain_proof_size_bytes_estimate =
        proof_size_bytes_estimate::<Base, Ext, Challenger>(&config);
    let zk_estimates = if args.proof_mode.is_full_zk() && zk_rejection.is_none() {
        Some(zk_estimates::<Base, Ext, Challenger>(
            args,
            &config,
            ZkBaseEstimates {
                dft_work,
                merkle_work,
                merkle_path_work,
                row_work,
                sumcheck_work,
            },
        ))
    } else {
        None
    };
    let proof_size_bytes_estimate = zk_estimates
        .as_ref()
        .map(|estimate| estimate.proof_size_bytes_estimate)
        .unwrap_or(plain_proof_size_bytes_estimate);

    out.push(CandidateRow {
        label,
        proof_mode: args.proof_mode.label(),
        base_field: args.field.label(),
        base_two_adicity: Base::TWO_ADICITY,
        extension,
        extension_degree,
        extension_two_adicity: Ext::TWO_ADICITY,
        field_bits: Ext::bits(),
        valid,
        rejection_reason: (!valid).then(|| {
            if achieved < args.security_bits as f64 {
                format!(
                    "achieved security {:.3} below target {}",
                    achieved, args.security_bits
                )
            } else if max_pow > args.max_pow_bits {
                format!("derived PoW {max_pow} exceeds max {}", args.max_pow_bits)
            } else {
                zk_rejection.unwrap_or_else(|| "candidate rejected".to_owned())
            }
        }),
        security_bits_achieved: Some(achieved),
        max_derived_pow_bits: Some(max_pow),
        pow_work_units,
        dft_work,
        merkle_work,
        merkle_path_work,
        row_work,
        sumcheck_work,
        proof_size_bytes_estimate,
        zk_dft_work: zk_estimates.as_ref().map(|estimate| estimate.dft_work),
        zk_merkle_work: zk_estimates.as_ref().map(|estimate| estimate.merkle_work),
        zk_merkle_path_work: zk_estimates
            .as_ref()
            .map(|estimate| estimate.merkle_path_work),
        zk_row_work: zk_estimates.as_ref().map(|estimate| estimate.row_work),
        zk_sumcheck_work: zk_estimates.as_ref().map(|estimate| estimate.sumcheck_work),
        zk_proof_size_bytes_estimate: zk_estimates
            .as_ref()
            .map(|estimate| estimate.proof_size_bytes_estimate),
        zk_mask_queries: zk_estimates.as_ref().map(|estimate| estimate.mask_queries),
        zk_ell: args.proof_mode.is_full_zk().then_some(args.zk_ell),
        zk_mask_log_inv_rate: args
            .proof_mode
            .is_full_zk()
            .then_some(args.zk_mask_log_inv_rate),
        commitment_ood_samples: Some(config.commitment_ood_samples),
        starting_folding_pow_bits: Some(config.starting_folding_pow_bits),
        final_queries: Some(config.final_queries),
        final_pow_bits: Some(config.final_pow_bits),
        final_sumcheck_rounds: Some(config.final_sumcheck_rounds),
        final_folding_pow_bits: Some(config.final_folding_pow_bits),
        rounds,
        whir_params,
        setup_config,
    });
}

fn protocol_parameters(whir_params: &WhirParams, security_bits: usize) -> ProtocolParameters {
    ProtocolParameters {
        starting_log_inv_rate: whir_params.starting_log_inv_rate,
        round_log_inv_rates: whir_params.round_log_inv_rates.clone(),
        folding_factor: map_schedule(&whir_params.effective_folding_schedule()),
        soundness_type: P3SecurityAssumption::JohnsonBound,
        security_level: security_bits,
        pow_bits: whir_params.pow_bits as usize,
    }
}

struct ZkBaseEstimates {
    dft_work: u128,
    merkle_work: u128,
    merkle_path_work: u128,
    row_work: u128,
    sumcheck_work: u128,
}

struct ZkEstimates {
    dft_work: u128,
    merkle_work: u128,
    merkle_path_work: u128,
    row_work: u128,
    sumcheck_work: u128,
    proof_size_bytes_estimate: u128,
    mask_queries: usize,
}

fn zk_estimates<Base, Ext, Challenger>(
    args: &Args,
    config: &P3WhirConfig<Ext, Base, Challenger>,
    base: ZkBaseEstimates,
) -> ZkEstimates
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let n_rounds = config.n_rounds();
    let oracle_randomness = oracle_randomness(config);
    let mask_queries = zk_mask_queries(args, config);
    let sumcheck_rounds = zk_sumcheck_rounds(config);
    let sumcheck_mask_domain = mask_domain(args.zk_ell, mask_queries, args.zk_mask_log_inv_rate);
    let switch_mask_domains = (0..n_rounds)
        .map(|round| {
            mask_domain(
                oracle_randomness[round] + config.round_parameters[round].ood_samples,
                mask_queries,
                args.zk_mask_log_inv_rate,
            )
        })
        .collect::<Vec<_>>();

    let ext_dim = Ext::DIMENSION as u128;
    let sumcheck_mask_width: u128 = sumcheck_rounds.iter().sum::<usize>() as u128;
    let switch_mask_width = n_rounds as u128;
    let base_mask_width = sumcheck_mask_width.saturating_add(switch_mask_width);

    let sumcheck_mask_rows = (sumcheck_mask_domain as u128).saturating_mul(sumcheck_mask_width);
    let switch_mask_rows = switch_mask_domains
        .iter()
        .map(|domain| *domain as u128)
        .fold(0, u128::saturating_add);
    let mask_rows = sumcheck_mask_rows.saturating_add(switch_mask_rows);

    let sumcheck_work_extra = sumcheck_rounds
        .iter()
        .map(|rounds| (*rounds as u128).saturating_mul(args.zk_ell.max(3) as u128))
        .fold(0, u128::saturating_add);
    let dft_work_extra = mask_rows.saturating_mul(ext_dim);
    let merkle_work_extra = mask_rows.saturating_mul(ext_dim);

    let switch_mask_path_work = switch_mask_domains
        .iter()
        .map(|domain| (mask_queries as u128).saturating_mul(log2_usize(*domain)))
        .fold(0, u128::saturating_add);
    let sumcheck_mask_path_work = (mask_queries as u128)
        .saturating_mul(log2_usize(sumcheck_mask_domain))
        .saturating_mul((n_rounds + 1) as u128);
    let base_mask_path_work = (mask_queries as u128)
        .saturating_mul(base_mask_width)
        .saturating_mul(log2_usize(sumcheck_mask_domain));
    let merkle_path_work_extra = switch_mask_path_work
        .saturating_add(sumcheck_mask_path_work)
        .saturating_add(base_mask_path_work);

    let row_work_extra = (mask_queries as u128)
        .saturating_mul(
            switch_mask_width
                .saturating_add(sumcheck_mask_width)
                .saturating_add(base_mask_width.saturating_mul(2)),
        )
        .saturating_mul(ext_dim);

    let proof_size_bytes_estimate = zk_proof_size_bytes_estimate::<Base, Ext, Challenger>(
        args,
        config,
        &oracle_randomness,
        &sumcheck_rounds,
        mask_queries,
        sumcheck_mask_domain,
        &switch_mask_domains,
    );

    ZkEstimates {
        dft_work: base.dft_work.saturating_add(dft_work_extra),
        merkle_work: base.merkle_work.saturating_add(merkle_work_extra),
        merkle_path_work: base.merkle_path_work.saturating_add(merkle_path_work_extra),
        row_work: base.row_work.saturating_add(row_work_extra),
        sumcheck_work: base.sumcheck_work.saturating_add(sumcheck_work_extra),
        proof_size_bytes_estimate,
        mask_queries,
    }
}

fn zk_proof_size_bytes_estimate<Base, Ext, Challenger>(
    args: &Args,
    config: &P3WhirConfig<Ext, Base, Challenger>,
    oracle_randomness: &[usize],
    sumcheck_rounds: &[usize],
    mask_queries: usize,
    sumcheck_mask_domain: usize,
    switch_mask_domains: &[usize],
) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let n_rounds = config.n_rounds();
    let ext_bytes = extension_bytes::<Ext>();
    let field_bytes = FIELD_BYTES;
    let sumcheck_coeffs_per_round = args.zk_ell.saturating_sub(1).max(2) as u128;
    let sumcheck_bytes = sumcheck_rounds
        .iter()
        .enumerate()
        .map(|(index, rounds)| {
            let pow_bytes = if zk_sumcheck_pow_bits(config, index) > 0 {
                (*rounds as u128).saturating_mul(field_bytes)
            } else {
                0
            };
            ext_bytes
                .saturating_add(
                    (*rounds as u128)
                        .saturating_mul(sumcheck_coeffs_per_round)
                        .saturating_mul(ext_bytes),
                )
                .saturating_add(pow_bytes)
        })
        .fold(0, u128::saturating_add);
    let sumcheck_mask_commitments = ((n_rounds + 1) as u128).saturating_mul(POSEIDON_DIGEST_BYTES);
    let round_bytes = config
        .round_parameters
        .iter()
        .enumerate()
        .map(|(round, params)| {
            let query_bytes = actual_query_count(
                params.num_queries,
                params.domain_size,
                params.folding_factor,
            )
            .saturating_mul(
                row_width(params.folding_factor)
                    .saturating_mul(query_payload_degree::<Base, Ext>(round))
                    .saturating_mul(FIELD_BYTES)
                    .saturating_add(
                        path_depth(params.domain_size, params.folding_factor)
                            .saturating_mul(POSEIDON_DIGEST_BYTES),
                    ),
            );
            POSEIDON_DIGEST_BYTES
                .saturating_mul(2)
                .saturating_add((params.ood_samples as u128).saturating_mul(ext_bytes))
                .saturating_add(FIELD_BYTES)
                .saturating_add(query_bytes)
        })
        .fold(0, u128::saturating_add);

    let final_round = final_round_estimate(config);
    let final_queries = final_query_count(config);
    let source_query_bytes = final_queries.saturating_mul(
        row_width(final_round.folding_factor)
            .saturating_mul(final_payload_degree::<Base, Ext, Challenger>(config))
            .saturating_mul(FIELD_BYTES)
            .saturating_add(
                path_depth(final_round.domain_size, final_round.folding_factor)
                    .saturating_mul(POSEIDON_DIGEST_BYTES),
            ),
    );
    let fresh_main_query_bytes = final_queries.saturating_mul(
        ext_bytes.saturating_add(
            path_depth(final_round.domain_size, final_round.folding_factor)
                .saturating_mul(POSEIDON_DIGEST_BYTES),
        ),
    );
    let sumcheck_mask_width: u128 = sumcheck_rounds.iter().sum::<usize>() as u128;
    let switch_mask_width = n_rounds as u128;
    let base_mask_width = sumcheck_mask_width.saturating_add(switch_mask_width);
    let mask_query_bytes = (mask_queries as u128)
        .saturating_mul(base_mask_width)
        .saturating_mul(2)
        .saturating_mul(ext_bytes.saturating_add(
            log2_usize(sumcheck_mask_domain).saturating_mul(POSEIDON_DIGEST_BYTES),
        ));
    let switch_mask_query_bytes = switch_mask_domains
        .iter()
        .map(|domain| {
            (mask_queries as u128).saturating_mul(
                ext_bytes.saturating_add(log2_usize(*domain).saturating_mul(POSEIDON_DIGEST_BYTES)),
            )
        })
        .fold(0, u128::saturating_add);
    let base_blinded_bytes = final_message_len(config)
        .saturating_mul(ext_bytes)
        .saturating_add((oracle_randomness[n_rounds] as u128).saturating_mul(ext_bytes))
        .saturating_add(
            carried_mask_message_len(args, config, oracle_randomness).saturating_mul(ext_bytes),
        );
    let base_commitment_count = 1u128.saturating_add(base_mask_width);
    let base_case_bytes = base_commitment_count
        .saturating_mul(POSEIDON_DIGEST_BYTES)
        .saturating_add(ext_bytes)
        .saturating_add(base_blinded_bytes)
        .saturating_add(FIELD_BYTES)
        .saturating_add(source_query_bytes)
        .saturating_add(fresh_main_query_bytes)
        .saturating_add(mask_query_bytes);

    ext_bytes
        .saturating_add(sumcheck_bytes)
        .saturating_add(sumcheck_mask_commitments)
        .saturating_add(round_bytes)
        .saturating_add(switch_mask_query_bytes)
        .saturating_add(base_case_bytes)
}

fn oracle_randomness<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> Vec<usize>
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    (0..=config.n_rounds())
        .map(|round| {
            if round < config.n_rounds() {
                config.round_parameters[round].num_queries
            } else {
                config.final_queries
            }
        })
        .collect()
}

fn zk_mask_queries<Base, Ext, Challenger>(
    args: &Args,
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> usize
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let union = log2_ceil_usize(2 * config.n_rounds() + 2);
    query_count_for_assumption(
        config.params.soundness_type,
        config.params.security_level + union,
        args.zk_mask_log_inv_rate,
    )
}

fn zk_sumcheck_rounds<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> Vec<usize>
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    (0..=config.n_rounds())
        .map(|round| config.round_folding_factor(round))
        .collect()
}

fn zk_sumcheck_pow_bits<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
    batch: usize,
) -> usize
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    if batch == 0 {
        config.starting_folding_pow_bits
    } else if batch - 1 < config.round_parameters.len() {
        config.round_parameters[batch - 1].folding_pow_bits
    } else {
        config.final_folding_pow_bits
    }
}

fn mask_domain(message_len: usize, randomness_len: usize, log_inv_rate: usize) -> usize {
    (message_len + randomness_len).next_power_of_two() << log_inv_rate
}

fn extension_bytes<Ext>() -> u128
where
    Ext: Field,
{
    (Ext::bits() as u128).div_ceil(8)
}

fn final_message_len<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let final_round = final_round_estimate(config);
    folded_row_count(final_round.domain_size, final_round.folding_factor) as u128
}

fn carried_mask_message_len<Base, Ext, Challenger>(
    args: &Args,
    config: &P3WhirConfig<Ext, Base, Challenger>,
    oracle_randomness: &[usize],
) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let sumcheck_messages = zk_sumcheck_rounds(config).len().saturating_mul(args.zk_ell) as u128;
    let switch_messages = (0..config.n_rounds())
        .map(|round| oracle_randomness[round] + config.round_parameters[round].ood_samples)
        .sum::<usize>() as u128;
    sumcheck_messages.saturating_add(switch_messages)
}

fn zk_compatibility_error<Base, Ext, Challenger>(
    args: &Args,
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> Option<String>
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    if args.zk_ell < 3 {
        return Some(format!(
            "ZK mask length {} is below the minimum of 3",
            args.zk_ell
        ));
    }
    if args.zk_mask_log_inv_rate == 0 {
        return Some("ZK mask log inverse rate must be at least 1".to_owned());
    }

    let n_rounds = config.n_rounds();
    let oracle_randomness = (0..=n_rounds)
        .map(|round| {
            if round < n_rounds {
                config.round_parameters[round].num_queries
            } else {
                config.final_queries
            }
        })
        .collect::<Vec<_>>();

    for (round, &randomness) in oracle_randomness.iter().enumerate() {
        let Some((message_rows, height)) = oracle_shape(config, round) else {
            return Some(format!("ZK oracle shape overflows at round {round}"));
        };
        let slack = height.saturating_sub(message_rows);
        if randomness > slack {
            return Some(format!(
                "ZK round {round} randomness rows {randomness} exceed slack {slack}"
            ));
        }
    }

    let union = log2_ceil_usize(2 * n_rounds + 2);
    let mask_queries = query_count_for_assumption(
        config.params.soundness_type,
        config.params.security_level + union,
        args.zk_mask_log_inv_rate,
    );
    let mask_message_lens =
        core::iter::once(args.zk_ell)
            .chain((0..n_rounds).map(|round| {
                oracle_randomness[round] + config.round_parameters[round].ood_samples
            }));
    for message_len in mask_message_lens {
        let log_domain_size =
            log2_ceil_usize(message_len + mask_queries).saturating_add(args.zk_mask_log_inv_rate);
        if log_domain_size > Ext::TWO_ADICITY {
            return Some(format!(
                "ZK mask domain 2^{log_domain_size} exceeds extension-field two-adicity 2^{}",
                Ext::TWO_ADICITY
            ));
        }
    }
    None
}

fn oracle_shape<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
    round: usize,
) -> Option<(usize, usize)>
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    if round == 0 {
        let rows = 1usize.checked_shl(
            config
                .num_variables
                .checked_sub(config.round_folding_factor(0))? as u32,
        )?;
        Some((rows, rows.checked_shl(config.starting_log_inv_rate as u32)?))
    } else {
        let prev = &config.round_parameters[round - 1];
        let rows = 1usize.checked_shl(
            prev.num_variables
                .checked_sub(config.round_folding_factor(round))? as u32,
        )?;
        Some((rows, rows.checked_mul(config.inv_rate(round - 1))?))
    }
}

fn query_count_for_assumption(
    soundness: P3SecurityAssumption,
    protocol_security_level: usize,
    log_inv_rate: usize,
) -> usize {
    let num_queries_f = -(protocol_security_level as f64) / log_1_delta(soundness, log_inv_rate);
    num_queries_f.ceil() as usize
}

fn log_1_delta(soundness: P3SecurityAssumption, log_inv_rate: usize) -> f64 {
    let rate = 1.0 / ((1usize << log_inv_rate) as f64);
    let delta = match soundness {
        P3SecurityAssumption::UniqueDecoding => 0.5 * (1.0 - rate),
        P3SecurityAssumption::JohnsonBound => {
            1.0 - rate.sqrt() - 2f64.powf(-(0.5 * log_inv_rate as f64 + 10f64.log2() + 1.0))
        }
        P3SecurityAssumption::CapacityBound => {
            1.0 - rate - 2f64.powf(-(log_inv_rate as f64 + 10f64.log2() + 1.0))
        }
    };
    (1.0 - delta).log2()
}

fn log2_ceil_usize(value: usize) -> usize {
    if value <= 1 {
        0
    } else {
        usize::BITS as usize - (value - 1).leading_zeros() as usize
    }
}

fn catch_unwind_silent<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(panic::AssertUnwindSafe(f));
    panic::set_hook(previous);
    result.map_err(|payload| {
        if let Some(message) = payload.downcast_ref::<&str>() {
            (*message).to_owned()
        } else if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else {
            "non-string panic payload".to_owned()
        }
    })
}

fn invalid_row(
    args: &Args,
    label: String,
    base_field: &'static str,
    base_two_adicity: usize,
    extension: &'static str,
    extension_degree: usize,
    extension_two_adicity: usize,
    field_bits: usize,
    whir_params: WhirParams,
    reason: impl Into<String>,
) -> CandidateRow {
    CandidateRow {
        label,
        proof_mode: args.proof_mode.label(),
        base_field,
        base_two_adicity,
        extension,
        extension_degree,
        extension_two_adicity,
        field_bits,
        valid: false,
        rejection_reason: Some(reason.into()),
        security_bits_achieved: None,
        max_derived_pow_bits: None,
        pow_work_units: 0,
        dft_work: 0,
        merkle_work: 0,
        merkle_path_work: 0,
        row_work: 0,
        sumcheck_work: 0,
        proof_size_bytes_estimate: 0,
        zk_dft_work: None,
        zk_merkle_work: None,
        zk_merkle_path_work: None,
        zk_row_work: None,
        zk_sumcheck_work: None,
        zk_proof_size_bytes_estimate: None,
        zk_mask_queries: None,
        zk_ell: args.proof_mode.is_full_zk().then_some(args.zk_ell),
        zk_mask_log_inv_rate: args
            .proof_mode
            .is_full_zk()
            .then_some(args.zk_mask_log_inv_rate),
        commitment_ood_samples: None,
        starting_folding_pow_bits: None,
        final_queries: None,
        final_pow_bits: None,
        final_sumcheck_rounds: None,
        final_folding_pow_bits: None,
        rounds: Vec::new(),
        whir_params,
        setup_config: None,
    }
}

fn setup_config(args: &Args, whir_params: WhirParams) -> serde_json::Value {
    let security = SecurityConfig {
        security_level_bits: args.security_bits as u32,
        merkle_security_bits: args.merkle_security_bits as u32,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    match args.proof_mode {
        ProofMode::NoZk => serde_json::to_value(SpartanSnarkConfig {
            matrix_closing: MatrixClosingMode::DirectSparse,
            security,
            whir_params,
            spark_whir_params: None,
        }),
        ProofMode::FullZk => serde_json::to_value(PoseidonZkSetupConfig {
            matrix_closing: MatrixClosingMode::DirectSparse,
            security,
            whir_params,
            ell_zk: args.zk_ell,
            mask_log_inv_rate: args.zk_mask_log_inv_rate,
        }),
    }
    .expect("setup config serializes")
}

fn achieved_security_bits<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> f64
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    config.params.security_level as f64
}

#[cfg(any())]
fn folding_security(
    soundness: P3SecurityAssumption,
    field_bits: usize,
    num_variables: usize,
    log_inv_rate: usize,
    pow_bits: usize,
) -> f64 {
    soundness
        .prox_gaps_error(num_variables, log_inv_rate, field_bits, 2)
        .min(soundness.fold_sumcheck_error(field_bits, num_variables, log_inv_rate))
        + pow_bits as f64
}

fn max_derived_pow_bits<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> usize
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    config.round_parameters.iter().fold(
        config
            .starting_folding_pow_bits
            .max(config.final_pow_bits)
            .max(config.final_folding_pow_bits),
        |acc, round| acc.max(round.pow_bits).max(round.folding_pow_bits),
    )
}

fn pow_work_units<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    let mut bits = vec![
        config.starting_folding_pow_bits,
        config.final_pow_bits,
        config.final_folding_pow_bits,
    ];
    for round in &config.round_parameters {
        bits.push(round.pow_bits);
        bits.push(round.folding_pow_bits);
    }
    bits.into_iter()
        .filter(|bits| *bits > 0)
        .map(|bits| 1u128.checked_shl(bits as u32).unwrap_or(u128::MAX))
        .fold(0u128, u128::saturating_add)
}

fn dft_work<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    let initial = 1u128 << (config.num_variables + config.params.starting_log_inv_rate);
    config.round_parameters.iter().fold(initial, |acc, round| {
        acc.saturating_add(round.domain_size as u128)
    })
}

fn merkle_work<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let initial = config.starting_domain_size() as u128;
    (0..config.n_rounds())
        .map(|round| {
            let committed_domain =
                config.round_parameters[round].domain_size >> config.rs_reduction_factor(round);
            (committed_domain as u128).saturating_mul(Ext::DIMENSION as u128)
        })
        .fold(initial, u128::saturating_add)
}

fn merkle_path_work<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    config
        .round_parameters
        .iter()
        .map(|round| {
            actual_query_count(round.num_queries, round.domain_size, round.folding_factor)
                .saturating_mul(path_depth(round.domain_size, round.folding_factor))
        })
        .fold(0, u128::saturating_add)
        .saturating_add(final_query_count(config).saturating_mul(final_path_depth(config)))
}

fn row_work<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let final_round = final_round_estimate(config);
    config
        .round_parameters
        .iter()
        .enumerate()
        .map(|(round_index, round)| {
            actual_query_count(round.num_queries, round.domain_size, round.folding_factor)
                .saturating_mul(row_width(round.folding_factor))
                .saturating_mul(query_payload_degree::<Base, Ext>(round_index))
        })
        .fold(0, u128::saturating_add)
        .saturating_add(
            final_query_count(config)
                .saturating_mul(row_width(final_round.folding_factor))
                .saturating_mul(final_payload_degree::<Base, Ext, Challenger>(config)),
        )
}

fn proof_size_bytes_estimate<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let query_bytes = config
        .round_parameters
        .iter()
        .enumerate()
        .map(|(round_index, round)| {
            let leaf_bytes = row_width(round.folding_factor)
                .saturating_mul(query_payload_degree::<Base, Ext>(round_index))
                .saturating_mul(FIELD_BYTES);
            let path_bytes = path_depth(round.domain_size, round.folding_factor)
                .saturating_mul(POSEIDON_DIGEST_BYTES);
            actual_query_count(round.num_queries, round.domain_size, round.folding_factor)
                .saturating_mul(leaf_bytes.saturating_add(path_bytes))
        })
        .fold(0, u128::saturating_add);
    let final_round = final_round_estimate(config);
    let final_poly_bytes = row_width(config.final_sumcheck_rounds)
        .saturating_mul(Ext::DIMENSION as u128)
        .saturating_mul(FIELD_BYTES);
    let final_leaf_bytes = row_width(final_round.folding_factor)
        .saturating_mul(final_payload_degree::<Base, Ext, Challenger>(config))
        .saturating_mul(FIELD_BYTES);
    let final_path_bytes = path_depth(final_round.domain_size, final_round.folding_factor)
        .saturating_mul(POSEIDON_DIGEST_BYTES);
    let commitment_bytes =
        (config.round_parameters.len() as u128 + 1).saturating_mul(POSEIDON_DIGEST_BYTES);
    query_bytes
        .saturating_add(
            final_query_count(config)
                .saturating_mul(final_leaf_bytes.saturating_add(final_path_bytes)),
        )
        .saturating_add(final_poly_bytes)
        .saturating_add(commitment_bytes)
}

fn sumcheck_work<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    let initial = (config.num_variables as u128) * (1u128 << config.num_variables);
    let whir_rounds = config
        .round_parameters
        .iter()
        .map(|round| (round.folding_factor as u128) * (1u128 << round.num_variables))
        .fold(0, u128::saturating_add);
    initial.saturating_add(whir_rounds).saturating_add(
        config.final_sumcheck_rounds as u128 * (1u128 << config.final_sumcheck_rounds),
    )
}

fn row_width(folding_factor: usize) -> u128 {
    1u128
        .checked_shl(folding_factor as u32)
        .unwrap_or(u128::MAX)
}

fn query_payload_degree<Base, Ext>(round_index: usize) -> u128
where
    Base: Field,
    Ext: ExtensionField<Base>,
{
    if round_index == 0 {
        1
    } else {
        Ext::DIMENSION as u128
    }
}

fn final_payload_degree<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    if config.n_rounds() == 0 {
        1
    } else {
        Ext::DIMENSION as u128
    }
}

fn final_query_count<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let final_round = final_round_estimate(config);
    actual_query_count(
        config.final_queries,
        final_round.domain_size,
        final_round.folding_factor,
    )
}

fn actual_query_count(num_queries: usize, domain_size: usize, folding_factor: usize) -> u128 {
    num_queries.min(folded_row_count(domain_size, folding_factor)) as u128
}

fn final_path_depth<Base, Ext, Challenger>(config: &P3WhirConfig<Ext, Base, Challenger>) -> u128
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    let final_round = final_round_estimate(config);
    path_depth(final_round.domain_size, final_round.folding_factor)
}

struct FinalRoundEstimate {
    domain_size: usize,
    folding_factor: usize,
}

fn final_round_estimate<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> FinalRoundEstimate
where
    Base: TwoAdicField,
    Ext: ExtensionField<Base> + Field + TwoAdicField,
    Challenger: FieldChallenger<Base> + GrindingChallenger<Witness = Base>,
{
    if config.round_parameters.is_empty() {
        FinalRoundEstimate {
            domain_size: config.starting_domain_size(),
            folding_factor: config.round_folding_factor(0),
        }
    } else {
        let last_round = config.n_rounds() - 1;
        let last = &config.round_parameters[last_round];
        FinalRoundEstimate {
            domain_size: last.domain_size >> config.rs_reduction_factor(last_round),
            folding_factor: config.round_folding_factor(config.n_rounds()),
        }
    }
}

fn path_depth(domain_size: usize, folding_factor: usize) -> u128 {
    log2_usize(folded_row_count(domain_size, folding_factor))
}

fn folded_row_count(domain_size: usize, folding_factor: usize) -> usize {
    domain_size >> folding_factor
}

fn log2_usize(value: usize) -> u128 {
    if value <= 1 {
        0
    } else {
        value.ilog2() as u128
    }
}

fn schedules(args: &Args) -> Vec<WhirFoldingSchedule> {
    let mut out = Vec::new();
    for factor in 1..=args.k_max.min(args.num_variables) {
        out.push(WhirFoldingSchedule::Constant(factor));
    }
    for first in 1..=args.k_max.min(args.num_variables) {
        for rest in 1..=args.k_max.min(args.num_variables) {
            if first != rest {
                out.push(WhirFoldingSchedule::ConstantFromSecondRound { first, rest });
            }
        }
    }
    out.extend(per_round_schedules(args));
    out
}

fn per_round_schedules(args: &Args) -> Vec<WhirFoldingSchedule> {
    #[derive(Clone)]
    struct Partial {
        factors: Vec<usize>,
        remaining: usize,
        cost: u128,
    }

    let mut partials = vec![Partial {
        factors: Vec::new(),
        remaining: args.num_variables,
        cost: 0,
    }];
    let mut done = Vec::new();
    while !partials.is_empty() {
        let mut next = Vec::new();
        for partial in partials {
            let max_factor = args.k_max.min(partial.remaining);
            for factor in 1..=max_factor {
                let remaining = partial.remaining.saturating_sub(factor);
                let mut factors = partial.factors.clone();
                factors.push(factor);
                let cost = partial.cost.saturating_add(1u128 << factor);
                if remaining <= args.final_sumcheck_max_variables {
                    done.push(Partial {
                        factors,
                        remaining,
                        cost,
                    });
                } else {
                    next.push(Partial {
                        factors,
                        remaining,
                        cost,
                    });
                }
            }
        }
        next.sort_by_key(|partial| (partial.remaining, partial.cost));
        next.truncate(args.beam_width);
        partials = next;
    }
    done.sort_by_key(|partial| (partial.cost, partial.remaining, partial.factors.len()));
    done.truncate(args.beam_width);
    done.into_iter()
        .map(|partial| WhirFoldingSchedule::PerRound(partial.factors))
        .collect()
}

fn derived_round_log_inv_rates(
    num_variables: usize,
    schedule: &WhirFoldingSchedule,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> Result<Vec<usize>, String> {
    let folding = map_schedule(schedule);
    let (num_rounds, _) = folding
        .compute_number_of_rounds(num_variables)
        .map_err(|reason| format!("round count derivation failed: {reason}"))?;
    let mut rates = Vec::with_capacity(num_rounds);
    let mut rate = starting_log_inv_rate;
    for round in 0..num_rounds {
        let reduction = if round == 0 {
            rs_domain_initial_reduction_factor
        } else {
            1
        };
        rate = rate
            .checked_add(folding.at_round(round))
            .ok_or_else(|| format!("rate overflow at round {round}"))?
            .checked_sub(reduction)
            .ok_or_else(|| format!("rate underflow at round {round}"))?;
        rates.push(rate);
    }
    Ok(rates)
}

fn map_schedule(schedule: &WhirFoldingSchedule) -> FoldingFactor {
    match schedule {
        WhirFoldingSchedule::Constant(factor) => FoldingFactor::Constant(*factor),
        WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => {
            FoldingFactor::ConstantFromSecondRound(*first, *rest)
        }
        WhirFoldingSchedule::PerRound(factors) => FoldingFactor::PerRound(factors.clone()),
    }
}

fn schedule_label(extension: &str, params: &WhirParams) -> String {
    let schedule = params.effective_folding_schedule();
    match schedule {
        WhirFoldingSchedule::Constant(factor) => format!(
            "{extension}_constant_pow{}_ff{}_lir{}_rsv{}",
            params.pow_bits,
            factor,
            params.starting_log_inv_rate,
            params.rs_domain_initial_reduction_factor
        ),
        WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => format!(
            "{extension}_cfsr_pow{}_ff{}_rest{}_lir{}_rsv{}",
            params.pow_bits,
            first,
            rest,
            params.starting_log_inv_rate,
            params.rs_domain_initial_reduction_factor
        ),
        WhirFoldingSchedule::PerRound(factors) => format!(
            "{extension}_perround_pow{}_{}_lir{}_rsv{}",
            params.pow_bits,
            factors
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join("-"),
            params.starting_log_inv_rate,
            params.rs_domain_initial_reduction_factor
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> P3WhirConfig<OcticBinExtension, F, PoseidonChallenger> {
        let params = WhirParams {
            pow_bits: 0,
            folding_factor: 4,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 1,
            folding_schedule: Some(WhirFoldingSchedule::Constant(4)),
            round_log_inv_rates: vec![4, 7],
        };
        let protocol_params = ProtocolParameters {
            starting_log_inv_rate: params.starting_log_inv_rate,
            round_log_inv_rates: params.round_log_inv_rates.clone(),
            folding_factor: map_schedule(&params.effective_folding_schedule()),
            soundness_type: P3SecurityAssumption::JohnsonBound,
            security_level: DEFAULT_SECURITY_BITS,
            pow_bits: params.pow_bits as usize,
        };
        P3WhirConfig::<OcticBinExtension, F, PoseidonChallenger>::new(18, protocol_params)
            .expect("test WHIR config is valid")
    }

    #[test]
    fn setup_config_is_mode_specific() {
        let mut args = Args {
            field: FieldProfile::KoalaBear,
            num_variables: 20,
            security_bits: DEFAULT_SECURITY_BITS,
            merkle_security_bits: DEFAULT_SECURITY_BITS,
            k_max: DEFAULT_K_MAX,
            starting_log_inv_rate_max: DEFAULT_LIR_MAX,
            max_pow_bits: DEFAULT_MAX_POW_BITS,
            final_sumcheck_max_variables: FINAL_SUMCHECK_MAX_VARIABLES,
            beam_width: DEFAULT_BEAM_WIDTH,
            include_invalid: false,
            proof_mode: ProofMode::FullZk,
            zk_ell: 3,
            zk_mask_log_inv_rate: 1,
        };

        let config = setup_config(&args, WhirParams::default());

        let config: PoseidonZkSetupConfig =
            serde_json::from_value(config).expect("full-ZK setup config deserializes");
        assert_eq!(config.matrix_closing, MatrixClosingMode::DirectSparse);
        assert_eq!(config.whir_params, WhirParams::default());
        assert_eq!(config.ell_zk, 3);
        assert_eq!(config.mask_log_inv_rate, 1);

        args.proof_mode = ProofMode::NoZk;
        let config: SpartanSnarkConfig =
            serde_json::from_value(setup_config(&args, WhirParams::default()))
                .expect("no-ZK setup config deserializes");
        assert_eq!(config.matrix_closing, MatrixClosingMode::DirectSparse);
        assert_eq!(config.whir_params, WhirParams::default());
    }

    #[test]
    fn cost_model_units_match_constant_schedule_layout() {
        let config = test_config();
        assert_eq!(config.n_rounds(), 2);
        assert_eq!(config.final_sumcheck_rounds, 6);
        assert_eq!(config.round_parameters[0].domain_size, 1 << 19);
        assert_eq!(config.round_parameters[1].domain_size, 1 << 18);
        assert_eq!(config.rs_reduction_factor(0), 1);
        assert_eq!(config.rs_reduction_factor(1), 1);

        let first_queries = actual_query_count(
            config.round_parameters[0].num_queries,
            config.round_parameters[0].domain_size,
            config.round_parameters[0].folding_factor,
        );
        let second_queries = actual_query_count(
            config.round_parameters[1].num_queries,
            config.round_parameters[1].domain_size,
            config.round_parameters[1].folding_factor,
        );
        let final_round = config.final_round_config();
        let final_queries = final_query_count(&config);

        assert_eq!(
            merkle_work(&config),
            (1u128 << 19) + 8 * (1u128 << 18) + 8 * (1u128 << 17)
        );
        assert_eq!(
            row_work(&config),
            first_queries * 16 + second_queries * 16 * 8 + final_queries * 16 * 8
        );
        assert_eq!(
            merkle_path_work(&config),
            first_queries * 15
                + second_queries * 14
                + final_queries * path_depth(final_round.domain_size, final_round.folding_factor)
        );
        assert_eq!(
            proof_size_bytes_estimate(&config),
            first_queries * (16 * FIELD_BYTES + 15 * POSEIDON_DIGEST_BYTES)
                + second_queries * (16 * 8 * FIELD_BYTES + 14 * POSEIDON_DIGEST_BYTES)
                + final_queries
                    * (16 * 8 * FIELD_BYTES
                        + path_depth(final_round.domain_size, final_round.folding_factor)
                            * POSEIDON_DIGEST_BYTES)
                + (1u128 << 6) * 8 * FIELD_BYTES
                + 3 * POSEIDON_DIGEST_BYTES
        );
    }

    #[test]
    fn final_round_estimate_matches_backend_final_round_config() {
        let config = test_config();
        let estimate = final_round_estimate(&config);
        let backend = config.final_round_config();

        assert_eq!(estimate.domain_size, backend.domain_size);
        assert_eq!(estimate.folding_factor, backend.folding_factor);
    }

    #[test]
    fn actual_query_count_caps_at_folded_row_count() {
        assert_eq!(actual_query_count(100, 32, 3), 4);
        assert_eq!(path_depth(32, 3), 2);
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        field: FieldProfile::KoalaBear,
        num_variables: 0,
        security_bits: DEFAULT_SECURITY_BITS,
        merkle_security_bits: DEFAULT_SECURITY_BITS,
        k_max: DEFAULT_K_MAX,
        starting_log_inv_rate_max: DEFAULT_LIR_MAX,
        max_pow_bits: DEFAULT_MAX_POW_BITS,
        final_sumcheck_max_variables: FINAL_SUMCHECK_MAX_VARIABLES,
        beam_width: DEFAULT_BEAM_WIDTH,
        include_invalid: false,
        proof_mode: ProofMode::NoZk,
        zk_ell: spartan_whir::DEFAULT_ZK_ELL,
        zk_mask_log_inv_rate: spartan_whir::DEFAULT_ZK_MASK_LOG_INV_RATE,
    };
    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--field" => args.field = parse_field_profile(&mut iter, &arg)?,
            "--num-variables" => args.num_variables = parse_next(&mut iter, &arg)?,
            "--security-bits" => args.security_bits = parse_next(&mut iter, &arg)?,
            "--merkle-security-bits" => args.merkle_security_bits = parse_next(&mut iter, &arg)?,
            "--k-max" => args.k_max = parse_next(&mut iter, &arg)?,
            "--starting-log-inv-rate-max" => {
                args.starting_log_inv_rate_max = parse_next(&mut iter, &arg)?
            }
            "--max-pow-bits" => args.max_pow_bits = parse_next(&mut iter, &arg)?,
            "--final-sumcheck-max-variables" => {
                args.final_sumcheck_max_variables = parse_next(&mut iter, &arg)?
            }
            "--beam-width" => args.beam_width = parse_next(&mut iter, &arg)?,
            "--include-invalid" => args.include_invalid = true,
            "--proof-mode" => args.proof_mode = parse_proof_mode(&mut iter, &arg)?,
            "--zk-ell" => args.zk_ell = parse_next(&mut iter, &arg)?,
            "--zk-mask-log-inv-rate" => args.zk_mask_log_inv_rate = parse_next(&mut iter, &arg)?,
            "--help" | "-h" => {
                usage();
                process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.num_variables == 0 {
        return Err("--num-variables is required".to_owned());
    }
    Ok(args)
}

fn parse_next(iter: &mut impl Iterator<Item = String>, name: &str) -> Result<usize, String> {
    iter.next()
        .ok_or_else(|| format!("{name} requires a value"))?
        .parse()
        .map_err(|_| format!("{name} must be a non-negative integer"))
}

fn parse_field_profile(
    iter: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<FieldProfile, String> {
    match iter
        .next()
        .ok_or_else(|| format!("{name} requires a value"))?
        .as_str()
    {
        "koalabear" | "koala-bear" => Ok(FieldProfile::KoalaBear),
        "babybear" | "baby-bear" => Ok(FieldProfile::BabyBear),
        other => Err(format!(
            "{name} must be one of koalabear, koala-bear, babybear, baby-bear; got {other}"
        )),
    }
}

fn parse_proof_mode(
    iter: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<ProofMode, String> {
    match iter
        .next()
        .ok_or_else(|| format!("{name} requires a value"))?
        .as_str()
    {
        "no-zk" => Ok(ProofMode::NoZk),
        "full-zk" => Ok(ProofMode::FullZk),
        other => Err(format!(
            "{name} must be one of no-zk or full-zk; got {other}"
        )),
    }
}

fn usage() {
    eprintln!(
        "usage: poseidon-schedule-candidates --num-variables N [--field koalabear|babybear] [--security-bits 123] [--max-pow-bits 22] [--proof-mode no-zk|full-zk] [--include-invalid]"
    );
}
