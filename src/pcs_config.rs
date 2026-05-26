use alloc::format;

use p3_field::TwoAdicField;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{engine::F, SecurityConfig, SpartanWhirError, WhirParams};

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

        if first_folding_factor == 0
            || self.whir.rs_domain_initial_reduction_factor == 0
            || self.whir.rs_domain_initial_reduction_factor > first_folding_factor
            || !folding_schedule.is_valid_for(self.num_variables)
        {
            return Err(SpartanWhirError::InvalidConfig);
        }

        let log_folded_domain_size = self
            .num_variables
            .checked_add(self.whir.starting_log_inv_rate)
            .and_then(|v| v.checked_sub(first_folding_factor))
            .ok_or(SpartanWhirError::InvalidConfig)?;

        if log_folded_domain_size > F::TWO_ADICITY {
            return Err(SpartanWhirError::InvalidConfig);
        }

        Ok(())
    }
}
