use p3_whir::{
    parameters::{
        FoldingFactor as P3FoldingFactor, ProtocolParameters,
        SecurityAssumption as P3SecurityAssumption,
    },
    pcs::zk::{ZkParameters, ZkWhirConfig},
};
use spartan_whir::{
    engine::F, recommended_octic_schedule, recommended_octic_whir_params,
    recommended_octic_zk_whir_params, OcticBinExtension, PoseidonChallenger, WhirFoldingSchedule,
    WhirParams, DEFAULT_ZK_ELL, DEFAULT_ZK_MASK_LOG_INV_RATE,
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

    assert_eq!(params.pow_bits, 8);
    assert_eq!(params.folding_factor, 8);
    assert_eq!(
        params.folding_schedule,
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 })
    );
    assert_eq!(params.starting_log_inv_rate, 1);
    assert_eq!(params.rs_domain_initial_reduction_factor, 5);
    assert_eq!(params.round_log_inv_rates, vec![4]);
}

#[test]
fn recommended_octic_zk_whir_params_are_accepted_by_zk_config() {
    for num_variables in 18..=31 {
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

fn protocol_parameters(num_variables: usize, params: &WhirParams) -> ProtocolParameters {
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
        security_level: 123,
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
