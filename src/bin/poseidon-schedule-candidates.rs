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
    MatrixClosingMode, OcticBinExtension, PoseidonSetupConfig, QuarticBinExtension, SecurityConfig,
    SoundnessAssumption, SpartanSnarkConfig, SumcheckStrategy, WhirFoldingSchedule, WhirParams,
    WhirPcsConfig, FINAL_SUMCHECK_MAX_VARIABLES,
};

const DEFAULT_SECURITY_BITS: usize = 128;
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
    candidates: Vec<CandidateRow>,
}

#[derive(Debug, Serialize)]
struct CandidateRow {
    label: String,
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
    commitment_ood_samples: Option<usize>,
    starting_folding_pow_bits: Option<usize>,
    final_queries: Option<usize>,
    final_pow_bits: Option<usize>,
    final_sumcheck_rounds: Option<usize>,
    final_folding_pow_bits: Option<usize>,
    rounds: Vec<RoundRow>,
    whir_params: WhirParams,
    setup_config: Option<PoseidonSetupConfig>,
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
                out,
                whir_params.clone(),
                args.field.label(),
                "quartic",
                4,
                reason.clone(),
            );
            push_invalid_rate_candidate::<F, KoalaBearQuinticExtension>(
                out,
                whir_params.clone(),
                args.field.label(),
                "quintic",
                5,
                reason.clone(),
            );
            push_invalid_rate_candidate::<F, OcticBinExtension>(
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
                out,
                whir_params.clone(),
                args.field.label(),
                "quartic",
                4,
                reason.clone(),
            );
            push_invalid_rate_candidate::<BabyBear, BabyBearQuinticExtension>(
                out,
                whir_params.clone(),
                args.field.label(),
                "quintic",
                5,
                reason.clone(),
            );
            push_invalid_rate_candidate::<BabyBear, BabyBearOcticExtension>(
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
    let result = catch_unwind_silent(|| {
        let protocol_params = ProtocolParameters {
            starting_log_inv_rate: whir_params.starting_log_inv_rate,
            round_log_inv_rates: whir_params.round_log_inv_rates.clone(),
            folding_factor: map_schedule(&whir_params.effective_folding_schedule()),
            soundness_type: P3SecurityAssumption::JohnsonBound,
            security_level: args.security_bits,
            pow_bits: whir_params.pow_bits as usize,
        };
        P3WhirConfig::<Ext, Base, Challenger>::new(args.num_variables, protocol_params)
    });

    let config = match result {
        Ok(config) => config,
        Err(reason) => {
            if args.include_invalid {
                out.push(invalid_row(
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
    };

    let achieved = achieved_security_bits::<Base, Ext, Challenger>(&config);
    let max_pow = max_derived_pow_bits::<Base, Ext, Challenger>(&config);
    let valid = achieved >= args.security_bits as f64 && max_pow <= args.max_pow_bits;
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
    let proof_size_bytes_estimate = proof_size_bytes_estimate::<Base, Ext, Challenger>(&config);

    out.push(CandidateRow {
        label,
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
            } else {
                format!("derived PoW {max_pow} exceeds max {}", args.max_pow_bits)
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

fn invalid_row(
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

fn setup_config(args: &Args, whir_params: WhirParams) -> SpartanSnarkConfig {
    let security = SecurityConfig {
        security_level_bits: args.security_bits as u32,
        merkle_security_bits: args.merkle_security_bits as u32,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    SpartanSnarkConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security,
        whir_params: whir_params.clone(),
        pcs_config: WhirPcsConfig {
            num_variables: args.num_variables,
            security,
            whir: whir_params,
            sumcheck_strategy: SumcheckStrategy::Svo,
        },
        spark_whir_params: None,
    }
}

fn achieved_security_bits<Base, Ext, Challenger>(
    config: &P3WhirConfig<Ext, Base, Challenger>,
) -> f64
where
    Base: Field,
    Ext: ExtensionField<Base> + Field,
{
    let soundness = config.params.soundness_type;
    let field_bits = Ext::bits();
    let mut achieved = f64::INFINITY;

    achieved = achieved.min(soundness.ood_error(
        config.num_variables,
        config.params.starting_log_inv_rate,
        field_bits,
        config.commitment_ood_samples,
    ));
    achieved = achieved.min(folding_security(
        soundness,
        field_bits,
        config.num_variables,
        config.params.starting_log_inv_rate,
        config.starting_folding_pow_bits,
    ));

    let mut log_inv_rate = config.params.starting_log_inv_rate;
    for round in &config.round_parameters {
        let next_log_inv_rate = round.log_inv_rate;
        achieved = achieved.min(
            soundness
                .queries_error(log_inv_rate, round.num_queries)
                .min(soundness.queries_combination_error(
                    field_bits,
                    round.num_variables,
                    next_log_inv_rate,
                    round.ood_samples,
                    round.num_queries,
                ))
                + round.pow_bits as f64,
        );
        achieved = achieved.min(soundness.ood_error(
            round.num_variables,
            next_log_inv_rate,
            field_bits,
            round.ood_samples,
        ));
        achieved = achieved.min(folding_security(
            soundness,
            field_bits,
            round.num_variables,
            next_log_inv_rate,
            round.folding_pow_bits,
        ));
        log_inv_rate = next_log_inv_rate;
    }

    achieved = achieved.min(
        soundness.queries_error(log_inv_rate, config.final_queries) + config.final_pow_bits as f64,
    );
    achieved.min((field_bits - 1 + config.final_folding_pow_bits) as f64)
}

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
            folding_factor: config.folding_factor(0),
        }
    } else {
        let last_round = config.n_rounds() - 1;
        let last = &config.round_parameters[last_round];
        FinalRoundEstimate {
            domain_size: last.domain_size >> config.rs_reduction_factor(last_round),
            folding_factor: config.folding_factor(config.n_rounds()),
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
    let (num_rounds, _) = catch_unwind_silent(|| folding.compute_number_of_rounds(num_variables))
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
            security_level: 128,
            pow_bits: params.pow_bits as usize,
        };
        P3WhirConfig::<OcticBinExtension, F, PoseidonChallenger>::new(18, protocol_params)
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

fn usage() {
    eprintln!(
        "usage: poseidon-schedule-candidates --num-variables N [--field koalabear|babybear] [--security-bits 128] [--max-pow-bits 22] [--include-invalid]"
    );
}

fn catch_unwind_silent<T>(f: impl FnOnce() -> T + panic::UnwindSafe) -> Result<T, String> {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(f);
    panic::set_hook(previous);
    result.map_err(|payload| {
        if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = payload.downcast_ref::<&'static str>() {
            (*message).to_owned()
        } else {
            "unknown panic".to_owned()
        }
    })
}
