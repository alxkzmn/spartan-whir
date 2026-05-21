#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod canonical_challenger;
pub mod codec;
mod codec_v1;
pub mod config;
pub mod domain_separator;
pub mod engine;
pub mod error;
pub mod fixtures;
pub mod hashers;
mod keccak_challenger;
pub mod pcs;
pub mod poly;
pub mod profiling;
pub mod protocol;
pub mod r1cs;
pub mod security;
pub mod spark;
pub mod statement;
pub mod sumcheck;
pub mod whir_params;
pub mod whir_pcs;

pub use canonical_challenger::CanonicalSerializingChallenger32;
pub use codec::{
    decode_spartan_blob, decode_spartan_blob_v1, effective_digest_bytes, encode_spartan_blob,
    encode_spartan_blob_v1, encode_spartan_blob_v1_with_report, ProofCodecConfig,
    SpartanBlobDecodeContext,
};
pub use config::SpartanWhirEngine;
pub use domain_separator::{DomainSeparator, MatrixClosingMode};
pub use engine::{
    new_keccak_challenger, new_keccak_merkle_compress, new_keccak_merkle_hash, KeccakChallenger,
    KeccakEngine, KeccakFieldHash, KeccakNodeCompress, KeccakOcticEngine, KeccakQuarticEngine,
    KeccakQuinticEngine, OcticBinExtension, QuarticBinExtension, QuinticExtension,
};
pub use error::SpartanWhirError;
pub use fixtures::{
    generate_satisfiable_fixture, generate_satisfiable_fixture_for_pow2, SyntheticR1csConfig,
    SyntheticR1csFixture,
};
pub use hashers::{
    digest_from_bytes, digest_to_bytes, effective_digest_bytes_for_security_bits,
    merkle_security_bits_or_default, Keccak256NodeCompress, KeccakFieldLeafHasher,
    KECCAK_DIGEST_ELEMS,
};
pub use keccak_challenger::{CanonicalKeccakChallenger32, KeccakByteChallenger};
pub use pcs::MlePcs;
pub use poly::{
    evaluate_mle_table, CubicRoundPoly, EqPolynomial, Evaluations, MultilinearPoint,
    QuadraticRoundPoly,
};
pub use profiling::{
    profile_spartan_blob_v1, trace_proof_size_report, NoopObserver, ProofSizeCounters,
    ProofSizeReport, ProofSizeSection, ProtocolObserver, ProtocolStage, SectionSize,
};
pub use protocol::{
    ProvingKey, SparkFixedCommitments, SparkFixedOpeningProof, SparkReadOpeningProof,
    SparkSpartanProof, SpartanProof, SpartanProofKind, SpartanProtocol, SpartanSnarkConfig,
    VerifyingKey,
};
pub use r1cs::{R1csInstance, R1csShape, R1csWitness, SparseMatEntry, SparseMatrix};
pub use security::{SecurityConfig, SoundnessAssumption, MIN_SECURITY_BITS};
pub use spark::{
    check_spark_memory_product_equations, compare_spark_layout_profile, compare_spark_layouts,
    compute_spark_read_tables, preprocess_joint_spark_tables,
    preprocess_joint_with_split_vals_spark_tables, preprocess_per_matrix_spark_tables,
    preprocess_shared_union_spark_tables, preprocess_spark_tables,
    prove_spark_batched_memory_products, prove_spark_batched_memory_products_with_leaf_claims,
    prove_spark_batched_product, prove_spark_grand_product, prove_spark_grand_product_terms,
    prove_spark_memory_grand_products, prove_spark_memory_grand_products_with_leaf_claims,
    prove_spark_memory_products, prove_spark_value_sumcheck, prove_spark_value_sumcheck_with_reads,
    spark_selector_from_high_bits, spark_selector_from_joint_point, spark_selector_from_slot,
    verify_spark_batched_memory_leaf_claims_with_openings,
    verify_spark_batched_memory_product_claims, verify_spark_batched_memory_products_with_tables,
    verify_spark_batched_product, verify_spark_grand_product,
    verify_spark_grand_product_with_values, verify_spark_memory_grand_product_claims,
    verify_spark_memory_grand_products_with_tables, verify_spark_memory_leaf_claims_with_tables,
    verify_spark_memory_products_with_tables, verify_spark_value_sumcheck,
    verify_spark_value_sumcheck_with_openings, verify_spark_value_sumcheck_with_read_tables,
    verify_spark_value_sumcheck_with_tables, SparkAxisGrandProductLeafClaims,
    SparkAxisGrandProductProof, SparkBatchedMemoryProductsLeafClaims,
    SparkBatchedMemoryProductsProof, SparkBatchedProductLayerProof, SparkBatchedProductLeafClaims,
    SparkBatchedProductProof, SparkDotProductCircuit, SparkFixedTableOpeningEvals,
    SparkGrandProductLayerProof, SparkGrandProductLeafClaim, SparkGrandProductProof,
    SparkGrandProductTree, SparkLayoutComparison, SparkLayoutDecision, SparkLayoutEstimate,
    SparkLayoutKind, SparkMatrixSlot, SparkMemoryAxis, SparkMemoryGrandProductLeafClaims,
    SparkMemoryGrandProductProof, SparkMemoryProductClaim, SparkMemoryProductProof,
    SparkReadTableOpeningEvals, SparkReadTables, SparkShapeProfile, SparkSolidityGasEstimate,
    SparkSolidityGasModel, SparkTables, SparkValueFinalEvals, SparkValueRoundPoly,
    SparkValueSumcheckProof, SparkVerifierOperationReport,
};
pub use statement::{LinearConstraintClaim, PcsStatement, PcsStatementBuilder, PointEvalClaim};
pub use sumcheck::{
    prove_inner, prove_outer, verify_inner, verify_outer, InnerSumcheckProof, OuterSumcheckProof,
};
pub use whir_params::WhirParams;
pub use whir_pcs::{
    observe_whir_fs_domain_separator, prepare_committed_opening, verify_finalize,
    verify_parse_commitment, ParsedWhirCommitment, SumcheckStrategy, WhirPcs, WhirPcsConfig,
    WhirProverData,
};
