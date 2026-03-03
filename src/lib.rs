#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod codec;
pub mod config;
pub mod domain_separator;
pub mod error;
pub mod pcs;
pub mod poly;
pub mod protocol;
pub mod r1cs;
pub mod security;
pub mod statement;
pub mod sumcheck;
pub mod whir_params;

pub use codec::{effective_digest_bytes, ProofCodecConfig};
pub use config::SpartanWhirEngine;
pub use domain_separator::DomainSeparator;
pub use error::SpartanWhirError;
pub use pcs::MlePcs;
pub use poly::{CubicRoundPoly, EqPolynomial, Evaluations, MultilinearPoint, QuadraticRoundPoly};
pub use protocol::{ProvingKey, SpartanProof, SpartanProtocol, VerifyingKey};
pub use r1cs::{R1csInstance, R1csShape, R1csWitness, SparseMatEntry, SparseMatrix};
pub use security::{SecurityConfig, SoundnessAssumption, MIN_SECURITY_BITS};
pub use statement::{LinearConstraintClaim, PcsStatement, PcsStatementBuilder, PointEvalClaim};
pub use sumcheck::{
    prove_inner, prove_outer, verify_inner, verify_outer, InnerSumcheckProof, OuterSumcheckProof,
};
pub use whir_params::WhirParams;
