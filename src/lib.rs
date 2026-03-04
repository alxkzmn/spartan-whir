#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod codec;
pub mod config;
pub mod domain_separator;
pub mod engine;
pub mod error;
pub mod hashers;
pub mod pcs;
pub mod poly;
pub mod profiling;
pub mod protocol;
pub mod r1cs;
pub mod security;
pub mod statement;
pub mod sumcheck;
pub mod whir_params;
pub mod whir_pcs;

pub use codec::{effective_digest_bytes, ProofCodecConfig};
pub use config::SpartanWhirEngine;
pub use domain_separator::DomainSeparator;
pub use engine::{
    new_koala_keccak_challenger, new_koala_keccak_merkle_compress, new_koala_keccak_merkle_hash,
    KoalaExtension, KoalaField, KoalaKeccakChallenger, KoalaKeccakCompress, KoalaKeccakEngine,
    KoalaKeccakFieldHash,
};
pub use error::SpartanWhirError;
pub use hashers::{
    digest_from_bytes, digest_to_bytes, effective_digest_bytes_for_security_bits,
    merkle_security_bits_or_default, Keccak256NodeCompress, KeccakFieldLeafHasher,
    KECCAK_DIGEST_ELEMS,
};
pub use pcs::MlePcs;
pub use poly::{
    evaluate_mle_table, CubicRoundPoly, EqPolynomial, Evaluations, MultilinearPoint,
    QuadraticRoundPoly,
};
pub use profiling::{NoopObserver, ProtocolObserver, ProtocolStage};
pub use protocol::{ProvingKey, SpartanProof, SpartanProtocol, VerifyingKey};
pub use r1cs::{R1csInstance, R1csShape, R1csWitness, SparseMatEntry, SparseMatrix};
pub use security::{SecurityConfig, SoundnessAssumption, MIN_SECURITY_BITS};
pub use statement::{LinearConstraintClaim, PcsStatement, PcsStatementBuilder, PointEvalClaim};
pub use sumcheck::{
    prove_inner, prove_outer, verify_inner, verify_outer, InnerSumcheckProof, OuterSumcheckProof,
};
pub use whir_params::WhirParams;
pub use whir_pcs::{
    observe_whir_fs_domain_separator, verify_finalize, verify_parse_commitment,
    ParsedWhirCommitment, SumcheckStrategy, WhirPcs, WhirPcsConfig, WhirProverData,
};
