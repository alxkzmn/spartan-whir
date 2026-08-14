extern crate alloc;

mod canonical_challenger;
pub mod circom;
pub mod config;
pub mod domain_separator;
pub mod engine;
pub mod error;
pub mod fixtures;
pub mod hashers;
mod keccak_challenger;
pub mod pcs;
pub mod pcs_config;
pub mod plonky3_whir_pcs;
pub mod poly;
pub mod poseidon;
pub mod profiling;
pub mod protocol;
pub mod r1cs;
pub mod security;
pub mod spark;
pub mod statement;
pub mod sumcheck;
mod sumcheck_replay;
pub mod whir_params;

pub use canonical_challenger::CanonicalSerializingChallenger32;
pub use circom::{
    import_bytes, import_paths, import_r1cs_bytes, import_r1cs_path, import_witness_bytes,
    import_witness_bytes_with_layout, import_witness_path, import_witness_values,
    import_witness_values_with_layout, validate_satisfaction, CircomAdapterError, CircomR1cs,
    ImportedWitness,
};
pub use config::SpartanWhirEngine;
pub use domain_separator::{
    DomainSeparator, MatrixClosingMode, FULL_ZK_PROTOCOL_ID, NO_ZK_PROTOCOL_ID,
};
pub use engine::{
    keccak_challenger, poseidon_challenger, poseidon_merkle_compress, poseidon_merkle_hash,
    KeccakChallenger, KeccakEngine, KeccakFieldHash, KeccakNodeCompress, KeccakOcticEngine,
    KeccakQuarticEngine, KeccakQuinticEngine, OcticBinExtension, PoseidonChallenger,
    PoseidonEngine, PoseidonFieldHash, PoseidonNodeCompress, PoseidonOcticEngine,
    PoseidonQuarticEngine, PoseidonQuinticEngine, QuarticBinExtension, QuinticExtension,
};
pub use error::{InvalidConfigReason, SecurityBoundComponent, SpartanWhirError};
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
pub(crate) use pcs::SealedNoZkPcs;
pub use pcs::{CommittedPolynomialView, MlePcs, NoZkPcs, ProtocolPcs};
pub use pcs_config::{
    WhirPcsConfig, ZkWhirPcsConfig, DEFAULT_ZK_ELL, DEFAULT_ZK_MASK_LOG_INV_RATE,
};
pub use plonky3_whir_pcs::{
    Plonky3HidingWhirPcs, Plonky3WhirPcs, Plonky3WhirProverData, PoseidonProvingKey,
    PoseidonSparkSpartanProof, PoseidonSpartanProof, PoseidonSpartanProtocol,
    PoseidonSpartanSnarkConfig, PoseidonVerifyingKey,
};
pub use poly::{
    evaluate_mle_table, CubicRoundPoly, EqPolynomial, Evaluations, MultilinearPoint,
    QuadraticRoundPoly,
};
pub use poseidon::{
    setup_poseidon, setup_poseidon_zk, PoseidonProof, PoseidonProofKind, PoseidonSetupConfig,
    PoseidonZkProof, PoseidonZkProvingKey, PoseidonZkSetupConfig, PoseidonZkVerifyingKey,
};
pub use poseidon::{
    LinkedWitnessFreeCircuitFn, LinkedWitnessGeneratorFn, LinkedWitnessLoadCircuitFn,
    PoseidonWitnessGenerator, PoseidonWitnessGeneratorError, LINKED_WITNESS_GENERATOR_OK,
};
pub use profiling::{
    trace_proof_size_report, NoopObserver, ProofSizeCounters, ProofSizeReport, ProofSizeSection,
    ProtocolObserver, ProtocolStage, SectionSize,
};
pub use protocol::{
    PoseidonZkSpartanProtocol, ProvingKey, SparkFixedCommitments, SparkFixedOpeningProof,
    SparkPcsConfigs, SparkReadOpeningProof, SparkSpartanProof, SparkWhirParams, SpartanProof,
    SpartanProofKind, SpartanProtocol, SpartanSnarkConfig, VerifyingKey, ZkMatrixClosingProof,
    ZkSparkClosingProof, ZkSpartanProof,
};
pub use r1cs::{R1csInstance, R1csShape, R1csWitness, SparseMatEntry, SparseMatrix};
pub use security::{SecurityConfig, SoundnessAssumption, MAX_SECURITY_BITS, MIN_SECURITY_BITS};
pub use spark::{
    check_spark_memory_product_equations, compare_spark_layout_profile, compare_spark_layouts,
    compute_spark_read_tables, preprocess_joint_spark_tables,
    preprocess_joint_with_split_vals_spark_tables, preprocess_per_matrix_spark_tables,
    preprocess_shared_union_spark_tables, preprocess_spark_tables,
    prove_spark_batched_memory_products, prove_spark_batched_memory_products_with_leaf_claims,
    prove_spark_batched_memory_products_with_read_tables_and_leaf_claims,
    prove_spark_batched_product, prove_spark_grand_product, prove_spark_grand_product_terms,
    prove_spark_memory_grand_products, prove_spark_memory_grand_products_with_leaf_claims,
    prove_spark_memory_products, prove_spark_value_sumcheck, prove_spark_value_sumcheck_with_reads,
    spark_selector_from_high_bits, spark_selector_from_joint_point, spark_selector_from_slot,
    verify_spark_batched_memory_leaf_claims_with_openings,
    verify_spark_batched_memory_product_claims,
    verify_spark_batched_memory_product_claims_with_metadata,
    verify_spark_batched_memory_products_with_tables, verify_spark_batched_product,
    verify_spark_grand_product, verify_spark_grand_product_with_values,
    verify_spark_memory_grand_product_claims, verify_spark_memory_grand_products_with_tables,
    verify_spark_memory_leaf_claims_with_tables, verify_spark_memory_products_with_tables,
    verify_spark_value_sumcheck, verify_spark_value_sumcheck_with_openings,
    verify_spark_value_sumcheck_with_read_tables, verify_spark_value_sumcheck_with_tables,
    SparkAxisGrandProductLeafClaims, SparkAxisGrandProductProof,
    SparkBatchedMemoryProductsLeafClaims, SparkBatchedMemoryProductsProof,
    SparkBatchedProductLayerProof, SparkBatchedProductLeafClaims, SparkBatchedProductProof,
    SparkDotProductCircuit, SparkFixedTableOpeningEvals, SparkGrandProductLayerProof,
    SparkGrandProductLeafClaim, SparkGrandProductProof, SparkGrandProductTree,
    SparkLayoutComparison, SparkLayoutDecision, SparkLayoutEstimate, SparkLayoutKind,
    SparkMatrixSlot, SparkMemoryAxis, SparkMemoryGrandProductLeafClaims,
    SparkMemoryGrandProductProof, SparkMemoryProductClaim, SparkMemoryProductProof,
    SparkReadTableOpeningEvals, SparkReadTables, SparkShapeProfile, SparkSolidityGasEstimate,
    SparkSolidityGasModel, SparkTableMetadata, SparkTables, SparkValueFinalEvals,
    SparkValueRoundPoly, SparkValueSumcheckProof, SparkVerifierOperationReport,
};
pub use statement::{LinearConstraintClaim, PcsStatement, PcsStatementBuilder, PointEvalClaim};
pub use sumcheck::{
    prove_inner, prove_inner_base_first, prove_outer, prove_outer_split_eq_base_first_owned,
    prove_outer_split_eq_owned, verify_inner, verify_outer, InnerSumcheckProof, OuterSumcheckProof,
    ZkOuterSumcheckProof,
};
pub use whir_params::{
    recommended_octic_schedule, recommended_octic_whir_params, recommended_octic_zk_whir_params,
    WhirFoldingSchedule, WhirParams, FINAL_SUMCHECK_MAX_VARIABLES,
};
