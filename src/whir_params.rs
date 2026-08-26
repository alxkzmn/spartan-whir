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

/// Plain-WHIR octic default parameters.
///
/// These parameters are not checked against full-ZK mask slack limits. Use
/// [`recommended_octic_zk_whir_params`] for the full-ZK witness commitment.
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

/// Plain-WHIR quintic parameters for 116-bit DirectSparse proofs.
///
/// The 20-variable case is the measured SHA-256 2048-byte schedule. Other
/// sizes reserve enough grinding headroom for backend-derived parameters.
pub fn recommended_quintic_whir_params(num_variables: usize) -> WhirParams {
    let mut params = recommended_octic_whir_params(num_variables);
    params.pow_bits = if num_variables == 20 {
        4
    } else {
        u32::try_from(num_variables).unwrap_or(u32::MAX).max(22)
    };
    params
}

/// Plain-WHIR octic parameters for fixed SPARK table openings.
///
/// Initial fixed-table commitments are prepared during setup. These parameters
/// optimize the fold commitments and openings performed for each proof. The
/// 25-variable case is the measured SHA-256 2048-byte fixed-value schedule.
pub fn recommended_octic_spark_fixed_whir_params(num_variables: usize) -> WhirParams {
    let mut params = recommended_octic_whir_params(num_variables);
    if num_variables == 25 {
        params.pow_bits = 4;
        return params;
    }
    params.rs_domain_initial_reduction_factor = params.rs_domain_initial_reduction_factor.min(6);
    params
}

/// Plain-WHIR octic parameters for SPARK read-table openings.
///
/// The 26-variable case is the measured SHA-256 2048-byte schedule.
pub fn recommended_octic_spark_read_whir_params(num_variables: usize) -> WhirParams {
    let mut params = recommended_octic_whir_params(num_variables);
    if num_variables == 26 {
        params.pow_bits = 4;
    }
    params
}

/// Octic parameters for full-ZK WHIR witness commitments.
///
/// The 19- and 20-variable cases use measured SHA-256 schedules. Other sizes
/// use ZK-valid defaults; tune benchmarked workloads with
/// `poseidon-schedule-candidates --proof-mode full-zk`.
pub fn recommended_octic_zk_whir_params(num_variables: usize) -> WhirParams {
    if num_variables < 18 {
        let schedule = WhirFoldingSchedule::Constant(1);
        let starting_log_inv_rate = if num_variables == 1 { 6 } else { 5 };
        return WhirParams {
            pow_bits: 0,
            folding_factor: 1,
            starting_log_inv_rate,
            rs_domain_initial_reduction_factor: 1,
            round_log_inv_rates: derived_round_log_inv_rates(
                num_variables,
                &schedule,
                starting_log_inv_rate,
                1,
            ),
            folding_schedule: Some(schedule),
        };
    }

    if num_variables == 19 {
        let schedule = WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 5 };
        return WhirParams {
            pow_bits: 4,
            folding_factor: 8,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 7,
            round_log_inv_rates: derived_round_log_inv_rates(num_variables, &schedule, 1, 7),
            folding_schedule: Some(schedule),
        };
    }

    if num_variables == 20 {
        let schedule = WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 };
        return WhirParams {
            pow_bits: 4,
            folding_factor: 8,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 6,
            round_log_inv_rates: derived_round_log_inv_rates(num_variables, &schedule, 1, 6),
            folding_schedule: Some(schedule),
        };
    }

    if num_variables <= 21 {
        let schedule = WhirFoldingSchedule::Constant(1);
        return WhirParams {
            pow_bits: 0,
            folding_factor: 1,
            starting_log_inv_rate: 2,
            rs_domain_initial_reduction_factor: 1,
            round_log_inv_rates: derived_round_log_inv_rates(num_variables, &schedule, 2, 1),
            folding_schedule: Some(schedule),
        };
    }

    let schedule = WhirFoldingSchedule::ConstantFromSecondRound { first: 8, rest: 6 };
    WhirParams {
        pow_bits: 0,
        folding_factor: 8,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 7,
        round_log_inv_rates: derived_round_log_inv_rates(num_variables, &schedule, 1, 7),
        folding_schedule: Some(schedule),
    }
}

/// Quintic parameters for 116-bit full-ZK DirectSparse witness commitments.
///
/// The 20-variable case is the measured SHA-256 2048-byte schedule. The WHIR
/// schedule matches the octic profile; the prover-time improvement comes from
/// using the quintic extension for the DirectSparse protocol. The composed
/// security budget gives this witness argument a 118-bit component target and
/// the hiding-WHIR protocol a 120-bit target.
pub fn recommended_quintic_zk_whir_params(num_variables: usize) -> WhirParams {
    let mut params = recommended_octic_zk_whir_params(num_variables);
    // Unmeasured sizes use a permissive ceiling; the backend derives the
    // actual grinding from the security target and schedule.
    params.pow_bits = if matches!(num_variables, 19 | 20) {
        params.pow_bits.max(4)
    } else {
        u32::try_from(num_variables).unwrap_or(u32::MAX).max(22)
    };
    params
}

fn derived_round_log_inv_rates(
    num_variables: usize,
    schedule: &WhirFoldingSchedule,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> Vec<usize> {
    let num_rounds = compute_number_of_rounds(num_variables, schedule);
    let mut rate = starting_log_inv_rate;
    let mut out = Vec::with_capacity(num_rounds);
    for round in 0..num_rounds {
        let Some(folding) = schedule.at_round(round) else {
            break;
        };
        let reduction = if round == 0 {
            rs_domain_initial_reduction_factor
        } else {
            1
        };
        rate = rate + folding - reduction;
        out.push(rate);
    }
    out
}

fn compute_number_of_rounds(num_variables: usize, schedule: &WhirFoldingSchedule) -> usize {
    compute_folding_schedule(num_variables, schedule)
        .len()
        .saturating_sub(1)
}

pub(crate) fn whir_folding_round_count(
    num_variables: usize,
    params: &WhirParams,
) -> Result<usize, crate::SpartanWhirError> {
    let schedule = params.effective_folding_schedule();
    if !schedule.is_valid_for(num_variables) {
        return Err(crate::SpartanWhirError::invalid_config());
    }
    Ok(compute_number_of_rounds(num_variables, &schedule))
}

fn compute_folding_schedule(num_variables: usize, schedule: &WhirFoldingSchedule) -> Vec<usize> {
    match schedule {
        WhirFoldingSchedule::Constant(factor) => {
            let mut remaining = num_variables;
            let mut out = Vec::new();
            loop {
                let round_factor = (*factor).min(remaining);
                out.push(round_factor);
                remaining -= round_factor;
                if remaining <= FINAL_SUMCHECK_MAX_VARIABLES {
                    return out;
                }
            }
        }
        WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => {
            let mut remaining = num_variables;
            let mut out = Vec::new();
            out.push(*first);
            remaining -= *first;
            while remaining > FINAL_SUMCHECK_MAX_VARIABLES {
                let round_factor = (*rest).min(remaining);
                out.push(round_factor);
                remaining -= round_factor;
            }
            out
        }
        WhirFoldingSchedule::PerRound(factors) => {
            let mut remaining = num_variables;
            let mut out = Vec::new();
            for factor in factors {
                out.push(*factor);
                remaining -= *factor;
                if remaining <= FINAL_SUMCHECK_MAX_VARIABLES {
                    return out;
                }
            }
            out
        }
    }
}
