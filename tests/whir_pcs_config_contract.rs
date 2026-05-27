use spartan_whir::{
    InvalidConfigReason, SecurityConfig, SpartanWhirError, SumcheckStrategy, WhirFoldingSchedule,
    WhirParams, WhirPcsConfig,
};

fn base_config() -> WhirPcsConfig {
    WhirPcsConfig {
        num_variables: 24,
        security: SecurityConfig::default(),
        whir: WhirParams::default(),
        sumcheck_strategy: SumcheckStrategy::Svo,
    }
}

#[test]
fn validate_reports_zero_folding_factor() {
    let mut config = base_config();
    config.whir.folding_factor = 0;

    assert_eq!(
        config.validate(),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::ZeroFoldingFactor
        ))
    );
}

#[test]
fn validate_reports_zero_rs_domain_initial_reduction_factor() {
    let mut config = base_config();
    config.whir.rs_domain_initial_reduction_factor = 0;

    assert_eq!(
        config.validate(),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::ZeroRsDomainInitialReductionFactor
        ))
    );
}

#[test]
fn validate_reports_rs_reduction_larger_than_first_fold() {
    let mut config = base_config();
    config.whir.folding_factor = 2;
    config.whir.rs_domain_initial_reduction_factor = 3;

    assert_eq!(
        config.validate(),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::RsDomainInitialReductionFactorExceedsFirstFoldingFactor {
                rs_domain_initial_reduction_factor: 3,
                first_folding_factor: 2,
            }
        ))
    );
}

#[test]
fn validate_reports_invalid_folding_schedule() {
    let mut config = base_config();
    config.whir.folding_schedule =
        Some(WhirFoldingSchedule::ConstantFromSecondRound { first: 4, rest: 0 });

    assert_eq!(
        config.validate(),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::InvalidFoldingSchedule { num_variables: 24 }
        ))
    );
}

#[test]
fn validate_reports_two_adicity_minimum_first_fold() {
    let mut config = base_config();
    config.num_variables = 25;
    config.whir.folding_factor = 1;

    assert_eq!(
        config.validate(),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::FoldedDomainExceedsBaseTwoAdicity {
                log_folded_domain_size: 25,
                base_two_adicity: 24,
                min_first_folding_factor: 2,
            }
        ))
    );
}
