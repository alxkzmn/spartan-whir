use alloc::format;

use p3_field::TwoAdicField;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{engine::F, InvalidConfigReason, SecurityConfig, SpartanWhirError, WhirParams};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SumcheckStrategy {
    /// Legacy `whir-p3` sumcheck path.
    Classic,
    /// Legacy `whir-p3` sparse-variable-offload sumcheck path.
    Svo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirPcsConfig {
    pub num_variables: usize,
    pub security: SecurityConfig,
    pub whir: WhirParams,
    /// Consumed only by the legacy `whir-p3-backend` Keccak path.
    ///
    /// The Poseidon Plonky3-WHIR backend uses Plonky3's internal opening
    /// layout and does not observe this field.
    pub sumcheck_strategy: SumcheckStrategy,
}

#[derive(Serialize, Deserialize)]
struct WhirPcsConfigSerde {
    num_variables: usize,
    security: SecurityConfig,
    whir: WhirParams,
    sumcheck_strategy: u8,
}

impl Serialize for WhirPcsConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let sumcheck_strategy = match self.sumcheck_strategy {
            // Keep stable on the wire: 0 = Classic, 1 = Svo.
            SumcheckStrategy::Classic => 0,
            SumcheckStrategy::Svo => 1,
        };
        WhirPcsConfigSerde {
            num_variables: self.num_variables,
            security: self.security,
            whir: self.whir.clone(),
            sumcheck_strategy,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WhirPcsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let config = WhirPcsConfigSerde::deserialize(deserializer)?;
        let sumcheck_strategy = match config.sumcheck_strategy {
            // Keep stable on the wire: 0 = Classic, 1 = Svo.
            0 => SumcheckStrategy::Classic,
            1 => SumcheckStrategy::Svo,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unsupported sumcheck strategy {other}"
                )));
            }
        };
        Ok(Self {
            num_variables: config.num_variables,
            security: config.security,
            whir: config.whir,
            sumcheck_strategy,
        })
    }
}

impl Default for WhirPcsConfig {
    fn default() -> Self {
        Self {
            num_variables: 0,
            security: SecurityConfig::default(),
            whir: WhirParams::default(),
            sumcheck_strategy: SumcheckStrategy::Svo,
        }
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
