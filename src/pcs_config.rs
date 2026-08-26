use p3_field::TwoAdicField;
use serde::{Deserialize, Serialize};

use crate::{engine::F, InvalidConfigReason, SecurityConfig, SpartanWhirError, WhirParams};

pub const DEFAULT_ZK_ELL: usize = 3;
pub const DEFAULT_ZK_MASK_LOG_INV_RATE: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhirPcsConfig {
    pub num_variables: usize,
    pub security: SecurityConfig,
    pub whir: WhirParams,
}

impl Default for WhirPcsConfig {
    fn default() -> Self {
        Self {
            num_variables: 0,
            security: SecurityConfig::default(),
            whir: WhirParams::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkWhirPcsConfig {
    pub base: WhirPcsConfig,
    pub ell_zk: usize,
    pub mask_log_inv_rate: usize,
}

impl Default for ZkWhirPcsConfig {
    fn default() -> Self {
        Self {
            base: WhirPcsConfig::default(),
            ell_zk: DEFAULT_ZK_ELL,
            mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
        }
    }
}

impl ZkWhirPcsConfig {
    pub fn validate(&self) -> Result<(), SpartanWhirError> {
        self.base.validate()
    }
}

impl WhirPcsConfig {
    pub fn validate(&self) -> Result<(), SpartanWhirError> {
        self.security.validate()?;

        let folding_schedule = self.whir.effective_folding_schedule();
        let first_folding_factor = folding_schedule.first_round();

        if first_folding_factor == 0 {
            return Err(SpartanWhirError::invalid_config_reason(
                InvalidConfigReason::ZeroFoldingFactor,
            ));
        }
        if self.whir.rs_domain_initial_reduction_factor == 0 {
            return Err(SpartanWhirError::invalid_config_reason(
                InvalidConfigReason::ZeroRsDomainInitialReductionFactor,
            ));
        }
        if self.whir.rs_domain_initial_reduction_factor > first_folding_factor {
            return Err(SpartanWhirError::invalid_config_reason(
                InvalidConfigReason::RsDomainInitialReductionFactorExceedsFirstFoldingFactor {
                    rs_domain_initial_reduction_factor: self
                        .whir
                        .rs_domain_initial_reduction_factor,
                    first_folding_factor,
                },
            ));
        }
        if !folding_schedule.is_valid_for(self.num_variables) {
            return Err(SpartanWhirError::invalid_config_reason(
                InvalidConfigReason::InvalidFoldingSchedule {
                    num_variables: self.num_variables,
                },
            ));
        }

        let log_domain_size = self
            .num_variables
            .checked_add(self.whir.starting_log_inv_rate)
            .ok_or_else(|| {
                SpartanWhirError::invalid_config_reason(
                    InvalidConfigReason::FoldedDomainSizeOverflow {
                        num_variables: self.num_variables,
                        starting_log_inv_rate: self.whir.starting_log_inv_rate,
                    },
                )
            })?;
        let log_folded_domain_size = log_domain_size
            .checked_sub(first_folding_factor)
            .ok_or_else(|| {
                SpartanWhirError::invalid_config_reason(
                    InvalidConfigReason::FirstFoldingFactorExceedsDomain {
                        first_folding_factor,
                        log_domain_size,
                    },
                )
            })?;

        if log_folded_domain_size > F::TWO_ADICITY {
            return Err(SpartanWhirError::invalid_config_reason(
                InvalidConfigReason::FoldedDomainExceedsBaseTwoAdicity {
                    log_folded_domain_size,
                    base_two_adicity: F::TWO_ADICITY,
                    min_first_folding_factor: log_domain_size.saturating_sub(F::TWO_ADICITY),
                },
            ));
        }

        Ok(())
    }
}
