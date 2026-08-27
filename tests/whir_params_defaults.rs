use p3_whir::{
    parameters::{
        FoldingFactor as P3FoldingFactor, ProtocolParameters,
        SecurityAssumption as P3SecurityAssumption, WhirConfig as P3WhirConfig,
    },
    pcs::zk::{ZkParameters, ZkWhirConfig},
};
use spartan_whir::{
    engine::F, format_whir_params_label, parse_whir_params_label, recommended_octic_schedule,
    recommended_octic_spark_fixed_whir_params, recommended_octic_spark_read_whir_params,
    recommended_octic_whir_params, recommended_octic_zk_whir_params,
    recommended_quintic_spark_fixed_whir_params, recommended_quintic_spark_read_whir_params,
    recommended_quintic_spark_whir_params, recommended_quintic_spark_zk_whir_params,
    recommended_quintic_whir_params, recommended_quintic_zk_whir_params, OcticBinExtension,
    PoseidonChallenger, QuinticExtension, WhirFoldingSchedule, WhirParams, DEFAULT_ZK_ELL,
    DEFAULT_ZK_MASK_LOG_INV_RATE,
};

#[test]
fn whir_params_defaults_match_phase_one_contract() {
    let params = WhirParams::default();
    assert_eq!(params.pow_bits, 0);
    assert_eq!(params.folding_factor, 4);
    assert_eq!(params.starting_log_inv_rate, 1);
    assert_eq!(params.rs_domain_initial_reduction_factor, 1);
    assert_eq!(params.folding_schedule, None);
    assert!(params.round_log_inv_rates.is_empty());
}

#[test]
fn explicit_schedule_serializes_roundtrips() {
    let params = WhirParams {
        pow_bits: 22,
        folding_factor: 4,
        starting_log_inv_rate: 3,
        rs_domain_initial_reduction_factor: 2,
        folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 4, rest: 2 }),
        round_log_inv_rates: vec![5, 6],
    };
    let json = serde_json::to_string(&params).expect("params serialize");
    let decoded: WhirParams = serde_json::from_str(&json).expect("params deserialize");
    assert_eq!(decoded, params);
}

#[test]
fn whir_params_label_roundtrips_explicit_terminal_rate() {
    let params = recommended_quintic_spark_zk_whir_params(20);
    let label = format_whir_params_label("quintic", &params);

    assert_eq!(
        label,
        "quintic_cfsr_pow7_ff8_rest3_lir1_rsv7_round_log_inv_rates_derived"
    );
    assert_eq!(
        parse_whir_params_label(20, "quintic", &label).expect("label parses"),
        params
    );
}

#[test]
fn whir_params_label_roundtrips_derived_rates_and_legacy_folding_factor() {
    let explicit_schedule = recommended_quintic_spark_read_whir_params(25);
    let explicit_label = format_whir_params_label("quintic", &explicit_schedule);
    assert!(explicit_label.ends_with("_round_log_inv_rates_derived"));
    assert_eq!(
        parse_whir_params_label(25, "quintic", &explicit_label).expect("label parses"),
        explicit_schedule
    );

    let legacy_folding_factor = WhirParams::default();
    let legacy_label = format_whir_params_label("octic", &legacy_folding_factor);
    assert!(legacy_label.starts_with("octic_folding_factor_"));
    assert_eq!(
        parse_whir_params_label(12, "octic", &legacy_label).expect("label parses"),
        legacy_folding_factor
    );
}

#[test]
fn whir_params_label_roundtrips_per_round_schedule() {
    let params = WhirParams {
        pow_bits: 9,
        folding_factor: 5,
        starting_log_inv_rate: 2,
        rs_domain_initial_reduction_factor: 4,
        folding_schedule: Some(WhirFoldingSchedule::PerRound(vec![5, 4, 3])),
        round_log_inv_rates: vec![3, 6],
    };
    let label = format_whir_params_label("quintic", &params);

    assert_eq!(
        label,
        "quintic_perround_pow9_5-4-3_lir2_rsv4_round_log_inv_rates_3-6"
    );
    assert_eq!(
        parse_whir_params_label(18, "quintic", &label).expect("label parses"),
        params
    );
}

#[test]
fn whir_params_label_accepts_legacy_constant_and_cfsr_labels() {
    let constant = parse_whir_params_label(20, "quintic", "quintic_constant_pow4_ff8_lir1_rsv8")
        .expect("legacy constant label parses");
    assert_eq!(
        constant.folding_schedule,
        Some(WhirFoldingSchedule::Constant(8))
    );
    assert_eq!(constant.round_log_inv_rates, vec![1]);

    let cfsr = parse_whir_params_label(20, "quintic", "quintic_cfsr_pow6_ff8_rest6_lir1_rsv6")
        .expect("legacy constant-from-second-round label parses");
    assert_eq!(
        cfsr.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 })
    );
    assert_eq!(cfsr.round_log_inv_rates, vec![3]);
}

#[test]
fn recommended_octic_schedule_covers_known_spark_sizes_and_falls_back() {
    assert_eq!(
        recommended_octic_schedule(21),
        WhirFoldingSchedule::Constant(8)
    );
    assert_eq!(
        recommended_octic_schedule(22),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 4 }
    );
    assert_eq!(
        recommended_octic_schedule(24),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 5 }
    );
    assert_eq!(
        recommended_octic_schedule(26),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 }
    );
    assert_eq!(
        recommended_octic_schedule(27),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 7 }
    );
    assert_eq!(
        recommended_octic_schedule(28),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 8 }
    );
}

#[test]
fn recommended_octic_whir_params_are_valid_for_small_inputs() {
    let params = recommended_octic_whir_params(2);

    assert_eq!(params.folding_factor, 2);
    assert_eq!(params.rs_domain_initial_reduction_factor, 2);
    assert_eq!(params.folding_schedule, None);
}

#[test]
fn recommended_octic_spark_fixed_params_use_opening_tuned_reduction() {
    let params = recommended_octic_spark_fixed_whir_params(26);

    assert_eq!(params.rs_domain_initial_reduction_factor, 6);
    assert_eq!(
        params.effective_folding_schedule(),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 }
    );
}

#[test]
fn recommended_octic_spark_fixed_params_use_measured_sha256_2048_schedule() {
    let params = recommended_octic_spark_fixed_whir_params(25);

    assert_eq!(params.pow_bits, 4);
    assert_eq!(params.rs_domain_initial_reduction_factor, 8);
    assert_eq!(
        params.effective_folding_schedule(),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 }
    );
}

#[test]
fn recommended_octic_spark_read_params_use_measured_sha256_2048_schedule() {
    let params = recommended_octic_spark_read_whir_params(26);

    assert_eq!(params.pow_bits, 4);
    assert_eq!(params.rs_domain_initial_reduction_factor, 8);
    assert_eq!(
        params.effective_folding_schedule(),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 }
    );
}

#[test]
fn recommended_quintic_whir_params_use_measured_sha256_2048_schedule() {
    let params = recommended_quintic_whir_params(20);

    assert_eq!(params.pow_bits, 2);
    assert_eq!(params.rs_domain_initial_reduction_factor, 8);
    assert_eq!(
        params.effective_folding_schedule(),
        WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 7 }
    );
    assert!(params.round_log_inv_rates.is_empty());
    assert_eq!(
        format_whir_params_label("quintic", &params),
        "quintic_cfsr_pow2_ff8_rest7_lir1_rsv8_round_log_inv_rates_derived"
    );
}

#[test]
fn recommended_quintic_spark_params_use_selected_sha256_2048_schedules() {
    let plain = recommended_quintic_spark_whir_params(20);
    assert_eq!(plain.pow_bits, 6);
    assert_eq!(
        plain.folding_schedule,
        Some(WhirFoldingSchedule::Constant(8))
    );
    assert_eq!(plain.rs_domain_initial_reduction_factor, 8);
    assert!(plain.round_log_inv_rates.is_empty());
    assert_eq!(
        format_whir_params_label("quintic", &plain),
        "quintic_constant_pow6_ff8_lir1_rsv8_round_log_inv_rates_derived"
    );

    let zk = recommended_quintic_spark_zk_whir_params(20);
    assert_eq!(zk.pow_bits, 7);
    assert_eq!(
        zk.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 3 })
    );
    assert_eq!(zk.rs_domain_initial_reduction_factor, 7);
    assert!(zk.round_log_inv_rates.is_empty());

    let fixed_value = recommended_quintic_spark_fixed_whir_params(25);
    assert_eq!(fixed_value.pow_bits, 9);
    assert_eq!(
        fixed_value.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 4 })
    );
    assert!(fixed_value.round_log_inv_rates.is_empty());
    assert_eq!(
        format_whir_params_label("quintic", &fixed_value),
        "quintic_cfsr_pow9_ff8_rest4_lir1_rsv8_round_log_inv_rates_derived"
    );

    let fixed_audit = recommended_quintic_spark_fixed_whir_params(22);
    assert_eq!(fixed_audit.pow_bits, 6);
    assert_eq!(
        fixed_audit.folding_schedule,
        Some(WhirFoldingSchedule::Constant(8))
    );
    assert!(fixed_audit.round_log_inv_rates.is_empty());
    assert_eq!(
        format_whir_params_label("quintic", &fixed_audit),
        "quintic_constant_pow6_ff8_lir1_rsv8_round_log_inv_rates_derived"
    );

    let read = recommended_quintic_spark_read_whir_params(25);
    assert_eq!(read.pow_bits, 9);
    assert_eq!(
        read.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 4 })
    );
    assert!(read.round_log_inv_rates.is_empty());
    assert_eq!(
        format_whir_params_label("quintic", &read),
        "quintic_cfsr_pow9_ff8_rest4_lir1_rsv8_round_log_inv_rates_derived"
    );
}

#[test]
fn recommended_quintic_spark_params_meet_component_security_targets() {
    for (num_variables, params) in [
        (20, recommended_quintic_spark_whir_params(20)),
        (25, recommended_quintic_spark_fixed_whir_params(25)),
        (22, recommended_quintic_spark_fixed_whir_params(22)),
        (25, recommended_quintic_spark_read_whir_params(25)),
        (23, recommended_quintic_spark_read_whir_params(25)),
    ] {
        P3WhirConfig::<QuinticExtension, F, PoseidonChallenger>::new(
            num_variables,
            protocol_parameters_with_security(num_variables, &params, 120),
        )
        .unwrap_or_else(|err| {
            panic!("recommended quintic SPARK params rejected at {num_variables} variables: {err}")
        });
    }

    let params = recommended_quintic_spark_zk_whir_params(20);
    ZkWhirConfig::<QuinticExtension, F, PoseidonChallenger>::new(
        20,
        protocol_parameters_with_security(20, &params, 122),
        ZkParameters {
            ell_zk: DEFAULT_ZK_ELL,
            mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
        },
    )
    .expect("recommended full-ZK quintic SPARK witness params are valid");
}

#[test]
fn recommended_quintic_spark_fallbacks_reserve_grinding_by_variable_count() {
    assert_eq!(recommended_quintic_spark_fixed_whir_params(21).pow_bits, 22);
    assert_eq!(recommended_quintic_spark_read_whir_params(21).pow_bits, 22);
    assert_eq!(recommended_quintic_spark_fixed_whir_params(26).pow_bits, 26);
    assert_eq!(recommended_quintic_spark_read_whir_params(26).pow_bits, 26);
    assert_eq!(recommended_quintic_spark_fixed_whir_params(31).pow_bits, 31);
    assert_eq!(recommended_quintic_spark_read_whir_params(31).pow_bits, 31);
    assert_eq!(recommended_quintic_spark_zk_whir_params(19).pow_bits, 5);
}

#[test]
fn recommended_quintic_spark_fallbacks_meet_component_security_targets() {
    for num_variables in 1..=31 {
        for params in [
            recommended_quintic_spark_fixed_whir_params(num_variables),
            recommended_quintic_spark_read_whir_params(num_variables),
        ] {
            P3WhirConfig::<QuinticExtension, F, PoseidonChallenger>::new(
                num_variables,
                protocol_parameters_with_security(num_variables, &params, 120),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "recommended quintic SPARK table params rejected at {num_variables} variables: {error}"
                )
            });
        }

        let params = recommended_quintic_spark_zk_whir_params(num_variables);
        ZkWhirConfig::<QuinticExtension, F, PoseidonChallenger>::new(
            num_variables,
            protocol_parameters_with_security(num_variables, &params, 122),
            ZkParameters {
                ell_zk: DEFAULT_ZK_ELL,
                mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "recommended full-ZK quintic SPARK params rejected at {num_variables} variables: {error}"
            )
        });
    }
}

#[test]
fn recommended_octic_zk_whir_params_use_zk_safe_schedule() {
    let params = recommended_octic_zk_whir_params(26);

    assert_eq!(params.folding_factor, 8);
    assert_eq!(
        params.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 })
    );
    assert_eq!(params.starting_log_inv_rate, 1);
    assert_eq!(params.rs_domain_initial_reduction_factor, 7);
    assert_eq!(params.round_log_inv_rates, vec![2, 7]);
}

#[test]
fn recommended_octic_zk_whir_params_use_measured_sha256_2048_schedule() {
    let params = recommended_octic_zk_whir_params(20);

    assert_eq!(params.pow_bits, 4);
    assert_eq!(params.folding_factor, 8);
    assert_eq!(
        params.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 })
    );
    assert_eq!(params.starting_log_inv_rate, 1);
    assert_eq!(params.rs_domain_initial_reduction_factor, 6);
    assert_eq!(params.round_log_inv_rates, vec![4]);
}

#[test]
fn recommended_quintic_zk_whir_params_use_measured_sha256_2048_schedule() {
    let params = recommended_quintic_zk_whir_params(20);
    assert_eq!(params, recommended_octic_zk_whir_params(20));
    assert_eq!(
        format_whir_params_label("quintic", &params),
        "quintic_cfsr_pow4_ff8_rest6_lir1_rsv6_round_log_inv_rates_4"
    );
}

#[test]
fn recommended_quintic_zk_whir_params_reserve_small_domain_grinding() {
    assert_eq!(recommended_quintic_zk_whir_params(1).pow_bits, 22);
}

#[test]
fn recommended_octic_zk_whir_params_use_security_valid_sha256_1024_default() {
    let params = recommended_octic_zk_whir_params(19);

    assert_eq!(params.pow_bits, 4);
    assert_eq!(params.folding_factor, 8);
    assert_eq!(
        params.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 5 })
    );
    assert_eq!(params.starting_log_inv_rate, 1);
    assert_eq!(params.rs_domain_initial_reduction_factor, 7);
    assert_eq!(params.round_log_inv_rates, vec![4]);
}

#[test]
fn recommended_octic_zk_whir_params_are_accepted_by_zk_config() {
    for num_variables in 1..=31 {
        let params = recommended_octic_zk_whir_params(num_variables);
        ZkWhirConfig::<OcticBinExtension, F, PoseidonChallenger>::new(
            num_variables,
            protocol_parameters(num_variables, &params),
            ZkParameters {
                ell_zk: DEFAULT_ZK_ELL,
                mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
            },
        )
        .unwrap_or_else(|err| {
            panic!("recommended ZK octic WHIR params rejected at {num_variables} variables: {err}")
        });
    }
}

#[test]
fn recommended_quintic_zk_whir_params_are_accepted_by_zk_config() {
    for num_variables in 1..=31 {
        let params = recommended_quintic_zk_whir_params(num_variables);
        ZkWhirConfig::<QuinticExtension, F, PoseidonChallenger>::new(
            num_variables,
            protocol_parameters_with_security(num_variables, &params, 120),
            ZkParameters {
                ell_zk: DEFAULT_ZK_ELL,
                mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
            },
        )
        .unwrap_or_else(|err| {
            panic!(
                "recommended ZK quintic WHIR params rejected at {num_variables} variables: {err}"
            )
        });
    }
}

fn protocol_parameters(num_variables: usize, params: &WhirParams) -> ProtocolParameters {
    protocol_parameters_with_security(num_variables, params, 123)
}

fn protocol_parameters_with_security(
    num_variables: usize,
    params: &WhirParams,
    security_level: usize,
) -> ProtocolParameters {
    ProtocolParameters {
        starting_log_inv_rate: params.starting_log_inv_rate,
        round_log_inv_rates: round_log_inv_rates(num_variables, params),
        folding_factor: match params.effective_folding_schedule() {
            WhirFoldingSchedule::Constant(factor) => P3FoldingFactor::Constant(factor),
            WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => {
                P3FoldingFactor::ConstantFromSecondRound(first, rest)
            }
            WhirFoldingSchedule::PerRound(factors) => P3FoldingFactor::PerRound(factors),
        },
        soundness_type: P3SecurityAssumption::JohnsonBound,
        security_level,
        pow_bits: params.pow_bits as usize,
    }
}

fn round_log_inv_rates(num_variables: usize, params: &WhirParams) -> Vec<usize> {
    if !params.round_log_inv_rates.is_empty() {
        return params.round_log_inv_rates.clone();
    }

    let schedule = params.effective_folding_schedule();
    let num_rounds = folding_schedule_len(num_variables, &schedule).saturating_sub(1);
    let mut rate = params.starting_log_inv_rate;
    let mut out = Vec::with_capacity(num_rounds);
    for round in 0..num_rounds {
        let folding = match schedule.at_round(round) {
            Some(folding) => folding,
            None => break,
        };
        let reduction = if round == 0 {
            params.rs_domain_initial_reduction_factor
        } else {
            1
        };
        rate += folding - reduction;
        out.push(rate);
    }
    out
}

fn folding_schedule_len(num_variables: usize, schedule: &WhirFoldingSchedule) -> usize {
    let mut remaining = num_variables;
    let mut len = 0;
    for round in 0.. {
        let Some(folding) = schedule.at_round(round) else {
            break;
        };
        len += 1;
        remaining = remaining.saturating_sub(folding.min(remaining));
        if remaining <= spartan_whir::FINAL_SUMCHECK_MAX_VARIABLES {
            break;
        }
    }
    len
}
