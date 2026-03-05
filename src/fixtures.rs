use alloc::vec::Vec;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::{engine::F, R1csShape, R1csWitness, SparseMatEntry, SparseMatrix, SpartanWhirError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticR1csConfig {
    pub target_log2_witness_poly: usize,
    pub num_constraints: usize,
    pub num_io: usize,
    pub a_terms_per_constraint: usize,
    pub b_terms_per_constraint: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticR1csFixture {
    pub shape: R1csShape<F>,
    pub witness: R1csWitness<F>,
    pub public_inputs: Vec<F>,
    pub target_poly_size: usize,
    pub target_log2: usize,
}

pub fn generate_satisfiable_fixture(
    cfg: &SyntheticR1csConfig,
) -> Result<SyntheticR1csFixture, SpartanWhirError> {
    if cfg.target_log2_witness_poly < 1 || cfg.num_constraints == 0 {
        return Err(SpartanWhirError::InvalidConfig);
    }

    let target_poly_size = 1usize
        .checked_shl(cfg.target_log2_witness_poly as u32)
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if cfg.num_io >= target_poly_size {
        return Err(SpartanWhirError::InvalidConfig);
    }

    let num_cols = target_poly_size
        .checked_add(1)
        .and_then(|n| n.checked_add(cfg.num_io))
        .ok_or(SpartanWhirError::InvalidConfig)?;

    if cfg.a_terms_per_constraint == 0
        || cfg.b_terms_per_constraint == 0
        || cfg.a_terms_per_constraint > num_cols
        || cfg.b_terms_per_constraint > num_cols
    {
        return Err(SpartanWhirError::InvalidConfig);
    }

    let mut rng = XorShift64::new(cfg.seed);

    let witness_vals: Vec<F> = (0..target_poly_size).map(|_| rng.next_field()).collect();
    let public_inputs: Vec<F> = (0..cfg.num_io).map(|_| rng.next_field()).collect();

    let mut z = Vec::with_capacity(num_cols);
    z.extend_from_slice(&witness_vals);
    z.push(F::ONE);
    z.extend_from_slice(&public_inputs);

    let mut a_entries = Vec::with_capacity(cfg.num_constraints * cfg.a_terms_per_constraint);
    let mut b_entries = Vec::with_capacity(cfg.num_constraints * cfg.b_terms_per_constraint);
    let mut c_entries = Vec::with_capacity(cfg.num_constraints);

    for row in 0..cfg.num_constraints {
        let row_a = sample_sparse_row(row, cfg.a_terms_per_constraint, num_cols, &mut rng);
        let row_b = sample_sparse_row(row, cfg.b_terms_per_constraint, num_cols, &mut rng);

        let a_eval = dot_sparse_row(&row_a, &z);
        let b_eval = dot_sparse_row(&row_b, &z);
        // Column `num_vars` is the constant-1 slot in [W | 1 | X].
        let c_val = a_eval * b_eval;

        a_entries.extend(row_a);
        b_entries.extend(row_b);
        c_entries.push(SparseMatEntry {
            row,
            col: target_poly_size,
            val: c_val,
        });
    }

    let shape = R1csShape {
        num_cons: cfg.num_constraints,
        num_vars: target_poly_size,
        num_io: cfg.num_io,
        a: SparseMatrix {
            num_rows: cfg.num_constraints,
            num_cols,
            entries: a_entries,
        },
        b: SparseMatrix {
            num_rows: cfg.num_constraints,
            num_cols,
            entries: b_entries,
        },
        c: SparseMatrix {
            num_rows: cfg.num_constraints,
            num_cols,
            entries: c_entries,
        },
    };

    Ok(SyntheticR1csFixture {
        shape,
        witness: R1csWitness { w: witness_vals },
        public_inputs,
        target_poly_size,
        target_log2: cfg.target_log2_witness_poly,
    })
}

pub fn generate_satisfiable_fixture_for_pow2(
    target_log2_witness_poly: usize,
) -> Result<SyntheticR1csFixture, SpartanWhirError> {
    generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly,
        num_constraints: 1,
        num_io: 1,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 0xC0DE_F11E_5EED_1234,
    })
}

fn sample_sparse_row(
    row: usize,
    num_terms: usize,
    num_cols: usize,
    rng: &mut XorShift64,
) -> Vec<SparseMatEntry<F>> {
    let mut cols = Vec::with_capacity(num_terms);
    while cols.len() < num_terms {
        let candidate = rng.next_usize(num_cols);
        if !cols.contains(&candidate) {
            cols.push(candidate);
        }
    }

    cols.into_iter()
        .map(|col| SparseMatEntry {
            row,
            col,
            val: rng.next_nonzero_field(),
        })
        .collect()
}

fn dot_sparse_row(entries: &[SparseMatEntry<F>], z: &[F]) -> F {
    entries
        .iter()
        .fold(F::ZERO, |acc, entry| acc + entry.val * z[entry.col])
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }

    fn next_field(&mut self) -> F {
        // Canonical reduction from PRNG output into Koala field range.
        let raw = (self.next_u64() as u32) % F::ORDER_U32;
        F::from_u32(raw)
    }

    fn next_nonzero_field(&mut self) -> F {
        let order = F::ORDER_U32;
        let raw = if order > 1 {
            ((self.next_u64() as u32) % (order - 1)) + 1
        } else {
            0
        };
        F::from_u32(raw)
    }
}
