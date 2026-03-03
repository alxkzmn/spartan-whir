#![allow(dead_code)]

use spartan_whir::{
    DomainSeparator, Evaluations, LinearConstraintClaim, MlePcs, MultilinearPoint, PcsStatement,
    PcsStatementBuilder, PointEvalClaim, R1csInstance, R1csShape, R1csWitness, SecurityConfig,
    SparseMatEntry, SparseMatrix, SpartanWhirEngine, SpartanWhirError, WhirParams,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DummyChallenger;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DummyEngine;

impl SpartanWhirEngine for DummyEngine {
    type F = u64;
    type EF = u64;
    type Challenger = DummyChallenger;
    type Hash = ();
    type Compress = ();
    type W = u64;

    const DIGEST_ELEMS: usize = 4;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DummyPcs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DummyPcsConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DummyPcsProof;

impl MlePcs<DummyEngine> for DummyPcs {
    type Commitment = [u64; 4];
    type ProverData = ();
    type Proof = DummyPcsProof;
    type Config = DummyPcsConfig;

    fn commit(
        _config: &Self::Config,
        _poly: &Evaluations<<DummyEngine as SpartanWhirEngine>::F>,
        _challenger: &mut <DummyEngine as SpartanWhirEngine>::Challenger,
    ) -> Result<(Self::Commitment, Self::ProverData), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("pcs::commit"))
    }

    fn open(
        _config: &Self::Config,
        _prover_data: Self::ProverData,
        _statement: &PcsStatement<DummyEngine>,
        _challenger: &mut <DummyEngine as SpartanWhirEngine>::Challenger,
    ) -> Result<Self::Proof, SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("pcs::open"))
    }

    fn verify(
        _config: &Self::Config,
        _commitment: &Self::Commitment,
        _statement: &PcsStatement<DummyEngine>,
        _proof: &Self::Proof,
        _challenger: &mut <DummyEngine as SpartanWhirEngine>::Challenger,
    ) -> Result<(), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("pcs::verify"))
    }
}

pub fn sample_sparse_matrix() -> SparseMatrix<u64> {
    SparseMatrix {
        num_rows: 1,
        num_cols: 3,
        entries: vec![SparseMatEntry {
            row: 0,
            col: 0,
            val: 1,
        }],
    }
}

pub fn sample_shape() -> R1csShape<u64> {
    R1csShape {
        num_cons: 1,
        num_vars: 1,
        num_io: 1,
        a: sample_sparse_matrix(),
        b: sample_sparse_matrix(),
        c: sample_sparse_matrix(),
    }
}

pub fn sample_instance() -> R1csInstance<u64, [u64; 4]> {
    R1csInstance {
        public_inputs: vec![7],
        witness_commitment: [0; 4],
    }
}

pub fn sample_witness() -> R1csWitness<u64> {
    R1csWitness { w: vec![42] }
}

pub fn sample_statement() -> PcsStatement<DummyEngine> {
    PcsStatementBuilder::<DummyEngine>::new()
        .add_point_eval(PointEvalClaim {
            point: MultilinearPoint(vec![0, 1]),
            value: 9,
        })
        .finalize()
        .expect("non-empty statement finalizes")
}

pub fn sample_linear_statement() -> PcsStatement<DummyEngine> {
    PcsStatementBuilder::<DummyEngine>::new()
        .add_linear_constraint(LinearConstraintClaim {
            coefficients: vec![1, 2, 3],
            expected: 6,
        })
        .finalize()
        .expect("non-empty statement finalizes")
}

pub fn sample_domain_separator() -> DomainSeparator {
    DomainSeparator::new(
        &sample_shape(),
        &SecurityConfig::default(),
        &WhirParams::default(),
    )
}
