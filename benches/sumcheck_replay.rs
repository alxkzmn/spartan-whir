use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use p3_field::PrimeCharacteristicRing;
use p3_sumcheck::generic_degree::GenericDegreeProof;
use spartan_whir::{
    engine::F, poseidon_challenger, verify_inner, verify_outer, verify_spark_value_sumcheck,
    CubicRoundPoly, InnerSumcheckProof, OcticBinExtension as EF, OuterSumcheckProof,
    QuadraticRoundPoly, SparkValueFinalEvals, SparkValueRoundPoly, SparkValueSumcheckProof,
};

fn ef(value: u32) -> EF {
    EF::from(F::from_u32(value))
}

fn benchmark_sumcheck_replay(c: &mut Criterion) {
    let outer_rounds = 20;
    let outer_proof = OuterSumcheckProof {
        rounds: (0..outer_rounds)
            .map(|round| {
                let offset = round as u32 * 3;
                CubicRoundPoly([ef(offset + 1), ef(offset + 2), ef(offset + 3)])
            })
            .collect(),
    };
    c.bench_function("outer_cubic_20_rounds_octic_poseidon", |b| {
        b.iter(|| {
            let mut challenger = poseidon_challenger();
            black_box(
                verify_outer::<F, EF, _>(
                    black_box(&outer_proof),
                    black_box(ef(17)),
                    outer_rounds,
                    &mut challenger,
                )
                .unwrap(),
            )
        });
    });

    let inner_rounds = 21;
    let inner_proof = InnerSumcheckProof {
        rounds: (0..inner_rounds)
            .map(|round| {
                let offset = round as u32 * 2;
                QuadraticRoundPoly([ef(offset + 1), ef(offset + 2)])
            })
            .collect(),
    };
    c.bench_function("inner_quadratic_21_rounds_octic_poseidon", |b| {
        b.iter(|| {
            let mut challenger = poseidon_challenger();
            black_box(
                verify_inner::<F, EF, _>(
                    black_box(&inner_proof),
                    black_box(ef(19)),
                    inner_rounds,
                    &mut challenger,
                )
                .unwrap(),
            )
        });
    });

    let quartic_rounds = 20;
    let initial_claim = ef(23);
    let quartic_evals = (0..quartic_rounds)
        .map(|round| {
            let offset = round as u32 * 4;
            vec![
                ef(offset + 1),
                ef(offset + 2),
                ef(offset + 3),
                ef(offset + 4),
            ]
        })
        .collect::<Vec<_>>();
    let mut setup_challenger = poseidon_challenger();
    let (_, final_claim) = GenericDegreeProof::<F, EF> {
        claimed_sum: initial_claim,
        round_polys: quartic_evals.clone(),
        pow_witnesses: Vec::new(),
    }
    .verify(&mut setup_challenger, quartic_rounds, 4, 0)
    .unwrap();
    let quartic_proof = SparkValueSumcheckProof {
        rounds: quartic_evals.into_iter().map(SparkValueRoundPoly).collect(),
        final_evals: SparkValueFinalEvals {
            selector: final_claim,
            val: EF::ONE,
            val_a: EF::ZERO,
            val_b: EF::ZERO,
            val_c: EF::ZERO,
            erow: EF::ONE,
            ecol: EF::ONE,
        },
    };
    c.bench_function("spark_quartic_20_rounds_octic_poseidon", |b| {
        b.iter(|| {
            let mut challenger = poseidon_challenger();
            black_box(
                verify_spark_value_sumcheck(
                    black_box(&quartic_proof),
                    black_box(initial_claim),
                    quartic_rounds,
                    &mut challenger,
                )
                .unwrap(),
            )
        });
    });
}

criterion_group!(benches, benchmark_sumcheck_replay);
criterion_main!(benches);
