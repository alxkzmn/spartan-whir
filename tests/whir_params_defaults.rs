use spartan_whir::{WhirFoldingSchedule, WhirParams};

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
