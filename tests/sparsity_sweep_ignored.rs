mod common;

use std::time::Instant;

use spartan_whir::{
    encode_spartan_blob_v1_with_report, generate_satisfiable_fixture,
    KeccakQuarticEngine as KeccakEngine, ProofCodecConfig, SpartanProtocol, SyntheticR1csConfig,
    WhirPcs,
};

#[test]
#[ignore = "Manual benchmark-style sweep for sparsity effects"]
fn sparsity_sweep_target_2_pow_18() {
    const K: usize = 18;
    const NUM_CONSTRAINTS: usize = 16;
    let grid = [1usize, 2, 4, 8, 16];
    let codec = ProofCodecConfig::default();
    let mut baseline_blob_len: Option<usize> = None;

    println!(
        "sparsity sweep (k={K}, constraints={NUM_CONSTRAINTS})\n\
         a_terms,b_terms,prove_ms,verify_ms,blob_bytes,digest_bytes"
    );

    for &a_terms in &grid {
        for &b_terms in &grid {
            let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
                target_log2_witness_poly: K,
                num_constraints: NUM_CONSTRAINTS,
                num_io: 1,
                a_terms_per_constraint: a_terms,
                b_terms_per_constraint: b_terms,
                seed: 0xAA55_AA55_0000_0000 ^ ((a_terms as u64) << 32) ^ (b_terms as u64),
            })
            .expect("fixture generation succeeds");

            let (pk, vk) = SpartanProtocol::<KeccakEngine, WhirPcs>::setup(
                &fixture.shape,
                &common::phase3_security(),
                &common::phase3_whir_params(),
                &common::phase3_pcs_config(),
            )
            .expect("setup succeeds");

            let mut prover_challenger = spartan_whir::new_keccak_challenger();
            let prove_t0 = Instant::now();
            let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove(
                &pk,
                &fixture.public_inputs,
                &fixture.witness,
                &mut prover_challenger,
            )
            .expect("prove succeeds");
            let prove_ms = prove_t0.elapsed().as_millis();

            let mut verifier_challenger = spartan_whir::new_keccak_challenger();
            let verify_t0 = Instant::now();
            let verify_result = SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
                &vk,
                &instance,
                &proof,
                &mut verifier_challenger,
            );
            let verify_ms = verify_t0.elapsed().as_millis();
            assert_eq!(
                verify_result,
                Ok(()),
                "verify failed for ({a_terms},{b_terms})"
            );

            let (blob, report) =
                encode_spartan_blob_v1_with_report(&codec, &vk.pcs_config, &instance, &proof)
                    .expect("encoding succeeds");
            assert_eq!(blob.len(), report.total_bytes);

            if let Some(expected) = baseline_blob_len {
                assert_eq!(
                    blob.len(),
                    expected,
                    "blob size drift at a_terms={a_terms}, b_terms={b_terms}: expected \
                     {expected}, got {}",
                    blob.len()
                );
            } else {
                baseline_blob_len = Some(blob.len());
            }

            println!(
                "{a_terms},{b_terms},{prove_ms},{verify_ms},{},{}",
                blob.len(),
                report.effective_digest_byte_width
            );
        }
    }
}
