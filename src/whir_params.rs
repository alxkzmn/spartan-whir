extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Maximum number of variables left for the final WHIR sumcheck.
pub const FINAL_SUMCHECK_MAX_VARIABLES: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhirFoldingSchedule {
    /// Use the same folding factor in every WHIR round.
    Constant(usize),
    /// Use one folding factor for the first round and another for all later rounds.
    ConstantFromSecondRound { first: usize, rest: usize },
    /// Use an explicit per-round folding factor list.
    PerRound(Vec<usize>),
}

impl WhirFoldingSchedule {
    pub fn first_round(&self) -> usize {
        match self {
            Self::Constant(factor) => *factor,
            Self::ConstantFromSecondRound { first, .. } => *first,
            Self::PerRound(factors) => factors.first().copied().unwrap_or(0),
        }
    }

    pub fn at_round(&self, round: usize) -> Option<usize> {
        match self {
            Self::Constant(factor) => Some(*factor),
            Self::ConstantFromSecondRound { first, rest } => {
                Some(if round == 0 { *first } else { *rest })
            }
            Self::PerRound(factors) => factors.get(round).copied(),
        }
    }

    pub fn is_valid_for(&self, num_variables: usize) -> bool {
        match self {
            Self::Constant(factor) => {
                if *factor == 0 || *factor > num_variables {
                    return false;
                }
                if num_variables <= FINAL_SUMCHECK_MAX_VARIABLES {
                    return true;
                }
                let rounds = (num_variables - FINAL_SUMCHECK_MAX_VARIABLES).div_ceil(*factor);
                rounds.saturating_mul(*factor) <= num_variables
            }
            Self::ConstantFromSecondRound { first, rest } => {
                if *first == 0 || *rest == 0 || *first > num_variables || *rest > num_variables {
                    return false;
                }
                let Some(remaining) = num_variables.checked_sub(*first) else {
                    return false;
                };
                if remaining < FINAL_SUMCHECK_MAX_VARIABLES {
                    return true;
                }
                let rounds = (remaining - FINAL_SUMCHECK_MAX_VARIABLES).div_ceil(*rest);
                rounds.saturating_mul(*rest) <= remaining
            }
            Self::PerRound(factors) => {
                if factors.is_empty() {
                    return false;
                }
                let mut remaining = num_variables;
                for factor in factors {
                    if *factor == 0 || *factor > remaining {
                        return false;
                    }
                    remaining -= *factor;
                    if remaining <= FINAL_SUMCHECK_MAX_VARIABLES {
                        return true;
                    }
                }
                false
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhirParams {
    pub pow_bits: u32,
    /// Legacy constant folding factor.
    ///
    /// When `folding_schedule` is `None`, this is interpreted as
    /// `WhirFoldingSchedule::Constant(folding_factor)`.
    pub folding_factor: usize,
    pub starting_log_inv_rate: usize,
    pub rs_domain_initial_reduction_factor: usize,
    /// Optional explicit folding schedule.
    ///
    /// `None` and `Some(WhirFoldingSchedule::Constant(folding_factor))` are
    /// canonicalized to the same transcript when `round_log_inv_rates` is empty.
    #[serde(default)]
    pub folding_schedule: Option<WhirFoldingSchedule>,
    /// Optional explicit WHIR round log inverse rates.
    ///
    /// Non-empty values are transcript-bound and must match the backend-derived
    /// round count.
    #[serde(default)]
    pub round_log_inv_rates: Vec<usize>,
}

impl Default for WhirParams {
    fn default() -> Self {
        Self {
            pow_bits: 0,
            folding_factor: 4,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 1,
            folding_schedule: None,
            round_log_inv_rates: Vec::new(),
        }
    }
}

impl WhirParams {
    pub fn effective_folding_schedule(&self) -> WhirFoldingSchedule {
        self.folding_schedule
            .clone()
            .unwrap_or(WhirFoldingSchedule::Constant(self.folding_factor))
    }

    pub fn first_folding_factor(&self) -> usize {
        self.effective_folding_schedule().first_round()
    }
}

pub fn recommended_octic_schedule(num_variables: usize) -> WhirFoldingSchedule {
    match num_variables {
        0..=8 => WhirFoldingSchedule::Constant(num_variables.max(1)),
        9..=21 => WhirFoldingSchedule::Constant(8),
        22 => WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 4 },
        23 | 24 => WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 5 },
        25 | 26 => WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 },
        27 => WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 7 },
        _ => WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 8 },
    }
}

pub fn recommended_octic_whir_params(num_variables: usize) -> WhirParams {
    let schedule = recommended_octic_schedule(num_variables);
    let folding_factor = schedule.first_round();
    let folding_schedule = match schedule {
        WhirFoldingSchedule::Constant(factor) if factor == folding_factor => None,
        schedule => Some(schedule),
    };
    WhirParams {
        pow_bits: 0,
        folding_factor,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 8.min(folding_factor),
        folding_schedule,
        round_log_inv_rates: Vec::new(),
    }
}
