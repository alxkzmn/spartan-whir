mod common;

use common::DummyEngine;
use spartan_whir::SpartanWhirEngine;

#[test]
fn engine_exposes_digest_word_type_and_digest_elems() {
    fn assert_word_type<E: SpartanWhirEngine>()
    where
        E::W: Copy + Default,
    {
    }

    assert_word_type::<DummyEngine>();

    let digest: [u8; DummyEngine::DIGEST_ELEMS] = [0; 4];
    assert_eq!(digest.len(), 4);
}
