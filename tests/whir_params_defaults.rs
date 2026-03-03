use spartan_whir::WhirParams;

#[test]
fn whir_params_defaults_match_phase_one_contract() {
    let params = WhirParams::default();
    assert_eq!(params.pow_bits, 0);
    assert_eq!(params.folding_factor, 4);
    assert_eq!(params.starting_log_inv_rate, 1);
    assert_eq!(params.rs_domain_initial_reduction_factor, 1);
}
