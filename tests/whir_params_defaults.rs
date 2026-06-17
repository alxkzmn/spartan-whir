use spartan_whir::{
    recommended_octic_schedule, recommended_octic_whir_params, WhirFoldingSchedule, WhirParams,
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
