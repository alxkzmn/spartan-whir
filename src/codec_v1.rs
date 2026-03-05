use alloc::{vec, vec::Vec};

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};

use whir_p3::whir::{
    merkle_multiproof::MerkleMultiProof,
    proof::{QueryBatchOpening, SumcheckData, WhirProof, WhirRoundProof},
};

use crate::{
    codec::{effective_digest_bytes, ProofCodecConfig, SpartanBlobDecodeContext},
    digest_from_bytes, digest_to_bytes,
    engine::F,
    CubicRoundPoly, InnerSumcheckProof, KeccakEngine, MlePcs, OuterSumcheckProof,
    ProofSizeCounters, ProofSizeReport, ProofSizeSection, QuadraticRoundPoly, R1csInstance,
    SectionSize, SpartanProof, SpartanWhirError, WhirPcs, EF,
};
use crate::{whir_pcs::derive_whir_proof_expectations, WhirPcsConfig};

const MAGIC: [u8; 4] = *b"SPWB";
const VERSION_V1: u16 = 1;
const SECTION_COUNT: usize = 6;
const HEADER_BYTES: usize = 4 + 2 + 2 + 1 + 1 + (SECTION_COUNT * 4);

type WhirPcsProof = <WhirPcs as MlePcs<KeccakEngine>>::Proof;

pub(crate) struct V1EncodeOutput {
    pub blob: Vec<u8>,
    pub report: ProofSizeReport,
}

struct WhirSectionEncoding {
    bytes: Vec<u8>,
    initial_bytes: usize,
    rounds_bytes: usize,
    final_bytes: usize,
    digest_data_bytes: usize,
}

pub(crate) fn encode_spartan_blob_v1(
    codec: &ProofCodecConfig,
    pcs_config: &WhirPcsConfig,
    instance: &R1csInstance<F, [u64; 4]>,
    proof: &SpartanProof<KeccakEngine, WhirPcs>,
) -> Result<V1EncodeOutput, SpartanWhirError> {
    if codec.proof_blob_version != VERSION_V1 {
        return Err(SpartanWhirError::UnsupportedBlobVersion);
    }
    if !codec.compact_query_encoding {
        return Err(SpartanWhirError::InvalidBlobFlags);
    }

    let digest_width = effective_digest_bytes(
        pcs_config.security.merkle_security_bits,
        codec.digest_bytes_override,
    ) as usize;
    let whir_expectations = derive_whir_proof_expectations(pcs_config)?;

    validate_encoder_whir_shape(instance, proof, &whir_expectations)?;

    let mut counters = ProofSizeCounters {
        num_outer_rounds: proof.outer_sumcheck.rounds.len(),
        num_inner_rounds: proof.inner_sumcheck.rounds.len(),
        num_whir_rounds: proof.pcs_proof.rounds.len(),
        ..Default::default()
    };

    let mut digest_data_bytes = 0usize;

    let section_instance = encode_instance_section(instance, digest_width, &mut digest_data_bytes)?;
    let section_outer_sumcheck = encode_outer_sumcheck_section(&proof.outer_sumcheck)?;
    let section_outer_claims = encode_outer_claims_section(proof.outer_claims);
    let section_inner_sumcheck = encode_inner_sumcheck_section(&proof.inner_sumcheck)?;
    let section_witness_eval = {
        let mut bytes = Vec::with_capacity(16);
        put_extension(&mut bytes, &proof.witness_eval);
        bytes
    };
    let section_whir = encode_whir_proof_section(
        &proof.pcs_proof,
        digest_width,
        &whir_expectations,
        &mut counters,
    )?;
    digest_data_bytes = digest_data_bytes
        .checked_add(section_whir.digest_data_bytes)
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;

    let section_lens_usize = [
        section_instance.len(),
        section_outer_sumcheck.len(),
        section_outer_claims.len(),
        section_inner_sumcheck.len(),
        section_witness_eval.len(),
        section_whir.bytes.len(),
    ];

    let mut section_lens_u32 = [0u32; SECTION_COUNT];
    for (i, len) in section_lens_usize.iter().copied().enumerate() {
        section_lens_u32[i] =
            u32::try_from(len).map_err(|_| SpartanWhirError::ProofEncodeFailed)?;
    }

    let mut blob = Vec::with_capacity(
        HEADER_BYTES
            + section_lens_usize
                .iter()
                .try_fold(0usize, |acc, &x| acc.checked_add(x))
                .ok_or(SpartanWhirError::ProofEncodeFailed)?,
    );

    blob.extend_from_slice(&MAGIC);
    put_u16(&mut blob, VERSION_V1);
    put_u16(&mut blob, 0x0001);
    put_u8(
        &mut blob,
        u8::try_from(digest_width).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    put_u8(
        &mut blob,
        u8::try_from(SECTION_COUNT).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for len in section_lens_u32 {
        put_u32(&mut blob, len);
    }

    blob.extend_from_slice(&section_instance);
    blob.extend_from_slice(&section_outer_sumcheck);
    blob.extend_from_slice(&section_outer_claims);
    blob.extend_from_slice(&section_inner_sumcheck);
    blob.extend_from_slice(&section_witness_eval);
    blob.extend_from_slice(&section_whir.bytes);

    let sections = vec![
        SectionSize {
            section: ProofSizeSection::Header,
            bytes: HEADER_BYTES,
        },
        SectionSize {
            section: ProofSizeSection::Instance,
            bytes: section_lens_usize[0],
        },
        SectionSize {
            section: ProofSizeSection::OuterSumcheck,
            bytes: section_lens_usize[1],
        },
        SectionSize {
            section: ProofSizeSection::OuterClaims,
            bytes: section_lens_usize[2],
        },
        SectionSize {
            section: ProofSizeSection::InnerSumcheck,
            bytes: section_lens_usize[3],
        },
        SectionSize {
            section: ProofSizeSection::WitnessEval,
            bytes: section_lens_usize[4],
        },
        SectionSize {
            section: ProofSizeSection::WhirInitial,
            bytes: section_whir.initial_bytes,
        },
        SectionSize {
            section: ProofSizeSection::WhirRounds,
            bytes: section_whir.rounds_bytes,
        },
        SectionSize {
            section: ProofSizeSection::WhirFinal,
            bytes: section_whir.final_bytes,
        },
    ];

    let total_bytes = blob.len();
    let section_sum = sections
        .iter()
        .try_fold(0usize, |acc, s| acc.checked_add(s.bytes))
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;
    if section_sum != total_bytes {
        return Err(SpartanWhirError::ProofEncodeFailed);
    }

    Ok(V1EncodeOutput {
        blob,
        report: ProofSizeReport {
            total_bytes,
            effective_digest_byte_width: digest_width,
            total_digest_data_bytes: digest_data_bytes,
            sections,
            counters,
        },
    })
}

pub(crate) fn decode_spartan_blob_v1(
    codec: &ProofCodecConfig,
    ctx: &SpartanBlobDecodeContext,
    blob: &[u8],
) -> Result<
    (
        R1csInstance<F, [u64; 4]>,
        SpartanProof<KeccakEngine, WhirPcs>,
    ),
    SpartanWhirError,
> {
    if !codec.compact_query_encoding {
        return Err(SpartanWhirError::InvalidBlobFlags);
    }

    let mut reader = Reader::new(blob);

    let mut magic = [0u8; 4];
    magic.copy_from_slice(reader.read_exact(4)?);
    if magic != MAGIC {
        return Err(SpartanWhirError::InvalidBlobHeader);
    }

    let version = reader.read_u16()?;
    if version != VERSION_V1 {
        return Err(SpartanWhirError::UnsupportedBlobVersion);
    }

    let flags = reader.read_u16()?;
    if flags != 0x0001 {
        return Err(SpartanWhirError::InvalidBlobFlags);
    }

    let digest_width = reader.read_u8()? as usize;
    let expected_digest_width =
        effective_digest_bytes(ctx.merkle_security_bits, codec.digest_bytes_override) as usize;
    if digest_width != expected_digest_width {
        return Err(SpartanWhirError::DigestBytesMismatch);
    }

    let section_count = reader.read_u8()? as usize;
    if section_count != SECTION_COUNT {
        return Err(SpartanWhirError::InvalidBlobHeader);
    }

    let mut section_lens = [0usize; SECTION_COUNT];
    for len in &mut section_lens {
        *len = reader.read_u32()? as usize;
    }

    let payload_start = reader.pos;
    let payload_len = section_lens
        .iter()
        .try_fold(0usize, |acc, &x| acc.checked_add(x))
        .ok_or(SpartanWhirError::InvalidBlobLayout)?;
    let expected_total = payload_start
        .checked_add(payload_len)
        .ok_or(SpartanWhirError::InvalidBlobLayout)?;
    if expected_total != blob.len() {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    let section_instance = reader.read_exact(section_lens[0])?;
    let section_outer_sumcheck = reader.read_exact(section_lens[1])?;
    let section_outer_claims = reader.read_exact(section_lens[2])?;
    let section_inner_sumcheck = reader.read_exact(section_lens[3])?;
    let section_witness_eval = reader.read_exact(section_lens[4])?;
    let section_whir = reader.read_exact(section_lens[5])?;

    if !reader.is_finished() {
        return Err(SpartanWhirError::TrailingBytes);
    }

    let instance = decode_instance_section(section_instance, digest_width)?;
    if instance.public_inputs.len() != ctx.expected_num_io {
        return Err(SpartanWhirError::InvalidPublicInputLength);
    }

    let outer_sumcheck = decode_outer_sumcheck_section(section_outer_sumcheck)?;
    if outer_sumcheck.rounds.len() != ctx.expected_outer_rounds {
        return Err(SpartanWhirError::InvalidRoundCount);
    }

    let outer_claims = decode_outer_claims_section(section_outer_claims)?;

    let inner_sumcheck = decode_inner_sumcheck_section(section_inner_sumcheck)?;
    if inner_sumcheck.rounds.len() != ctx.expected_inner_rounds {
        return Err(SpartanWhirError::InvalidRoundCount);
    }

    let witness_eval = decode_single_extension(section_witness_eval)?;

    let pcs_proof = decode_whir_proof_section(
        section_whir,
        digest_width,
        &instance.witness_commitment,
        &ctx.whir,
    )?;

    Ok((
        instance,
        SpartanProof {
            outer_sumcheck,
            outer_claims,
            inner_sumcheck,
            witness_eval,
            pcs_proof,
        },
    ))
}

fn validate_encoder_whir_shape(
    instance: &R1csInstance<F, [u64; 4]>,
    proof: &SpartanProof<KeccakEngine, WhirPcs>,
    expectations: &crate::whir_pcs::WhirProofExpectations,
) -> Result<(), SpartanWhirError> {
    let whir = &proof.pcs_proof;

    if instance.witness_commitment != whir.initial_commitment {
        return Err(SpartanWhirError::CommitmentMismatch);
    }

    if whir.rounds.len() != expectations.n_rounds {
        return Err(SpartanWhirError::ProofEncodeFailed);
    }

    for (idx, round) in whir.rounds.iter().enumerate() {
        let Some(query_batch) = round.query_batch.as_ref() else {
            return Err(SpartanWhirError::ProofEncodeFailed);
        };

        let expected = expectations.round_num_queries[idx];
        match query_batch {
            QueryBatchOpening::Base { values, .. } => {
                if values.len() > expected {
                    return Err(SpartanWhirError::ProofEncodeFailed);
                }
            }
            QueryBatchOpening::Extension { values, .. } => {
                if values.len() > expected {
                    return Err(SpartanWhirError::ProofEncodeFailed);
                }
            }
        }
    }

    match whir.final_query_batch.as_ref() {
        Some(QueryBatchOpening::Base { values, .. }) => {
            if values.len() > expectations.final_num_queries {
                return Err(SpartanWhirError::ProofEncodeFailed);
            }
        }
        Some(QueryBatchOpening::Extension { values, .. }) => {
            if values.len() > expectations.final_num_queries {
                return Err(SpartanWhirError::ProofEncodeFailed);
            }
        }
        None if expectations.requires_final_query_batch => {
            return Err(SpartanWhirError::ProofEncodeFailed);
        }
        None => {}
    }

    if whir.final_sumcheck.is_some() != expectations.requires_final_sumcheck {
        return Err(SpartanWhirError::ProofEncodeFailed);
    }

    if let Some(final_poly) = &whir.final_poly {
        if final_poly.num_evals() == 0 || !final_poly.num_evals().is_power_of_two() {
            return Err(SpartanWhirError::ProofEncodeFailed);
        }
        if final_poly.num_variables() != expectations.final_poly_num_variables {
            return Err(SpartanWhirError::ProofEncodeFailed);
        }
    }

    Ok(())
}

fn encode_instance_section(
    instance: &R1csInstance<F, [u64; 4]>,
    digest_width: usize,
    digest_data_bytes: &mut usize,
) -> Result<Vec<u8>, SpartanWhirError> {
    let mut out = Vec::new();
    put_u32(
        &mut out,
        u32::try_from(instance.public_inputs.len())
            .map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for value in &instance.public_inputs {
        put_field(&mut out, value);
    }
    put_digest(&mut out, &instance.witness_commitment, digest_width)?;
    *digest_data_bytes = digest_data_bytes
        .checked_add(digest_width)
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;
    Ok(out)
}

fn decode_instance_section(
    bytes: &[u8],
    digest_width: usize,
) -> Result<R1csInstance<F, [u64; 4]>, SpartanWhirError> {
    let mut reader = Reader::new(bytes);
    let len = reader.read_u32()? as usize;
    let mut public_inputs = Vec::with_capacity(len);
    for _ in 0..len {
        public_inputs.push(reader.read_field()?);
    }
    let commitment = reader.read_digest(digest_width)?;
    reader.ensure_finished()?;

    Ok(R1csInstance {
        public_inputs,
        witness_commitment: commitment,
    })
}

fn encode_outer_sumcheck_section(
    proof: &OuterSumcheckProof<EF>,
) -> Result<Vec<u8>, SpartanWhirError> {
    let mut out = Vec::new();
    put_u32(
        &mut out,
        u32::try_from(proof.rounds.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for round in &proof.rounds {
        put_extension(&mut out, &round.0[0]);
        put_extension(&mut out, &round.0[1]);
        put_extension(&mut out, &round.0[2]);
    }
    Ok(out)
}

fn decode_outer_sumcheck_section(bytes: &[u8]) -> Result<OuterSumcheckProof<EF>, SpartanWhirError> {
    let mut reader = Reader::new(bytes);
    let rounds_len = reader.read_u32()? as usize;
    let mut rounds = Vec::with_capacity(rounds_len);
    for _ in 0..rounds_len {
        rounds.push(CubicRoundPoly([
            reader.read_extension()?,
            reader.read_extension()?,
            reader.read_extension()?,
        ]));
    }
    reader.ensure_finished()?;
    Ok(OuterSumcheckProof { rounds })
}

fn encode_outer_claims_section(claims: (EF, EF, EF)) -> Vec<u8> {
    let mut out = Vec::new();
    put_extension(&mut out, &claims.0);
    put_extension(&mut out, &claims.1);
    put_extension(&mut out, &claims.2);
    out
}

fn decode_outer_claims_section(bytes: &[u8]) -> Result<(EF, EF, EF), SpartanWhirError> {
    let mut reader = Reader::new(bytes);
    let claims = (
        reader.read_extension()?,
        reader.read_extension()?,
        reader.read_extension()?,
    );
    reader.ensure_finished()?;
    Ok(claims)
}

fn encode_inner_sumcheck_section(
    proof: &InnerSumcheckProof<EF>,
) -> Result<Vec<u8>, SpartanWhirError> {
    let mut out = Vec::new();
    put_u32(
        &mut out,
        u32::try_from(proof.rounds.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for round in &proof.rounds {
        put_extension(&mut out, &round.0[0]);
        put_extension(&mut out, &round.0[1]);
    }
    Ok(out)
}

fn decode_inner_sumcheck_section(bytes: &[u8]) -> Result<InnerSumcheckProof<EF>, SpartanWhirError> {
    let mut reader = Reader::new(bytes);
    let rounds_len = reader.read_u32()? as usize;
    let mut rounds = Vec::with_capacity(rounds_len);
    for _ in 0..rounds_len {
        rounds.push(QuadraticRoundPoly([
            reader.read_extension()?,
            reader.read_extension()?,
        ]));
    }
    reader.ensure_finished()?;
    Ok(InnerSumcheckProof { rounds })
}

fn decode_single_extension(bytes: &[u8]) -> Result<EF, SpartanWhirError> {
    let mut reader = Reader::new(bytes);
    let value = reader.read_extension()?;
    reader.ensure_finished()?;
    Ok(value)
}

fn encode_whir_proof_section(
    proof: &WhirPcsProof,
    digest_width: usize,
    expectations: &crate::whir_pcs::WhirProofExpectations,
    counters: &mut ProofSizeCounters,
) -> Result<WhirSectionEncoding, SpartanWhirError> {
    let mut out = Vec::new();
    let mut digest_data_bytes = 0usize;

    put_u32(
        &mut out,
        u32::try_from(proof.initial_ood_answers.len())
            .map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for v in &proof.initial_ood_answers {
        put_extension(&mut out, v);
    }
    encode_sumcheck_data(&mut out, &proof.initial_sumcheck)?;

    put_u32(
        &mut out,
        u32::try_from(proof.rounds.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );

    let initial_bytes = out.len();
    let rounds_start = out.len();

    for (idx, round) in proof.rounds.iter().enumerate() {
        let expected_queries = expectations.round_num_queries[idx];
        let round_digest_bytes =
            encode_whir_round_payload(&mut out, round, digest_width, expected_queries, counters)?;
        digest_data_bytes = digest_data_bytes
            .checked_add(round_digest_bytes)
            .ok_or(SpartanWhirError::ProofEncodeFailed)?;
    }

    let rounds_bytes = out
        .len()
        .checked_sub(rounds_start)
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;
    let final_start = out.len();

    match &proof.final_poly {
        None => put_u8(&mut out, 0),
        Some(poly) => {
            put_u8(&mut out, 1);
            put_u32(
                &mut out,
                u32::try_from(poly.num_evals()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );
            for v in poly.as_slice() {
                put_extension(&mut out, v);
            }
        }
    }

    put_field(&mut out, &proof.final_pow_witness);

    match &proof.final_query_batch {
        None => put_u8(&mut out, 0),
        Some(q) => {
            put_u8(&mut out, 1);
            let query_digest_bytes = encode_query_batch_payload(
                &mut out,
                q,
                digest_width,
                expectations.final_num_queries,
                counters,
            )?;
            digest_data_bytes = digest_data_bytes
                .checked_add(query_digest_bytes)
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
        }
    }

    match &proof.final_sumcheck {
        None => put_u8(&mut out, 0),
        Some(sumcheck) => {
            put_u8(&mut out, 1);
            encode_sumcheck_data(&mut out, sumcheck)?;
        }
    }

    let final_bytes = out
        .len()
        .checked_sub(final_start)
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;

    Ok(WhirSectionEncoding {
        bytes: out,
        initial_bytes,
        rounds_bytes,
        final_bytes,
        digest_data_bytes,
    })
}

fn decode_whir_proof_section(
    bytes: &[u8],
    digest_width: usize,
    commitment: &[u64; 4],
    expectations: &crate::whir_pcs::WhirProofExpectations,
) -> Result<WhirPcsProof, SpartanWhirError> {
    let mut reader = Reader::new(bytes);

    let initial_ood_len = reader.read_u32()? as usize;
    let mut initial_ood_answers = Vec::with_capacity(initial_ood_len);
    for _ in 0..initial_ood_len {
        initial_ood_answers.push(reader.read_extension()?);
    }

    let initial_sumcheck = decode_sumcheck_data(&mut reader)?;

    let rounds_len = reader.read_u32()? as usize;
    if rounds_len != expectations.n_rounds {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    let mut rounds = Vec::with_capacity(rounds_len);
    for expected_queries in &expectations.round_num_queries {
        rounds.push(decode_whir_round_payload(
            &mut reader,
            digest_width,
            *expected_queries,
        )?);
    }

    let final_poly_tag = reader.read_u8()?;
    let final_poly = match final_poly_tag {
        0 => None,
        1 => {
            let len = reader.read_u32()? as usize;
            if len == 0 || !len.is_power_of_two() {
                return Err(SpartanWhirError::InvalidBlobLayout);
            }
            if len.ilog2() as usize != expectations.final_poly_num_variables {
                return Err(SpartanWhirError::InvalidBlobLayout);
            }
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(reader.read_extension()?);
            }
            Some(whir_p3::poly::evals::EvaluationsList::new(values))
        }
        _ => return Err(SpartanWhirError::InvalidBlobLayout),
    };

    let final_pow_witness = reader.read_field()?;

    let final_query_tag = reader.read_u8()?;
    let final_query_batch = match final_query_tag {
        0 => None,
        1 => Some(decode_query_batch_payload(
            &mut reader,
            digest_width,
            expectations.final_num_queries,
        )?),
        _ => return Err(SpartanWhirError::InvalidBlobLayout),
    };

    if final_query_batch.is_none() && expectations.requires_final_query_batch {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    let final_sumcheck_tag = reader.read_u8()?;
    let final_sumcheck = match final_sumcheck_tag {
        0 => None,
        1 => Some(decode_sumcheck_data(&mut reader)?),
        _ => return Err(SpartanWhirError::InvalidBlobLayout),
    };

    if final_sumcheck.is_some() != expectations.requires_final_sumcheck {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    reader.ensure_finished()?;

    Ok(WhirProof {
        initial_commitment: *commitment,
        initial_ood_answers,
        initial_sumcheck,
        rounds,
        final_poly,
        final_pow_witness,
        final_query_batch,
        final_sumcheck,
    })
}

fn encode_whir_round_payload(
    out: &mut Vec<u8>,
    round: &WhirRoundProof<F, EF, u64, 4>,
    digest_width: usize,
    expected_queries: usize,
    counters: &mut ProofSizeCounters,
) -> Result<usize, SpartanWhirError> {
    let mut digest_data_bytes = 0usize;

    put_digest(out, &round.commitment, digest_width)?;
    digest_data_bytes = digest_data_bytes
        .checked_add(digest_width)
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;

    put_u32(
        out,
        u32::try_from(round.ood_answers.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for v in &round.ood_answers {
        put_extension(out, v);
    }

    put_field(out, &round.pow_witness);

    match &round.query_batch {
        None => put_u8(out, 0),
        Some(q) => {
            put_u8(out, 1);
            let query_digest_bytes =
                encode_query_batch_payload(out, q, digest_width, expected_queries, counters)?;
            digest_data_bytes = digest_data_bytes
                .checked_add(query_digest_bytes)
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
        }
    }

    if round.query_batch.is_none() {
        return Err(SpartanWhirError::ProofEncodeFailed);
    }

    encode_sumcheck_data(out, &round.sumcheck)?;
    Ok(digest_data_bytes)
}

fn decode_whir_round_payload(
    reader: &mut Reader<'_>,
    digest_width: usize,
    expected_queries: usize,
) -> Result<WhirRoundProof<F, EF, u64, 4>, SpartanWhirError> {
    let commitment = reader.read_digest(digest_width)?;

    let ood_len = reader.read_u32()? as usize;
    let mut ood_answers = Vec::with_capacity(ood_len);
    for _ in 0..ood_len {
        ood_answers.push(reader.read_extension()?);
    }

    let pow_witness = reader.read_field()?;

    let query_tag = reader.read_u8()?;
    let query_batch = match query_tag {
        0 => None,
        1 => Some(decode_query_batch_payload(
            reader,
            digest_width,
            expected_queries,
        )?),
        _ => return Err(SpartanWhirError::InvalidBlobLayout),
    };

    if query_batch.is_none() {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    let sumcheck = decode_sumcheck_data(reader)?;

    Ok(WhirRoundProof {
        commitment,
        ood_answers,
        pow_witness,
        query_batch,
        sumcheck,
    })
}

fn encode_sumcheck_data(
    out: &mut Vec<u8>,
    data: &SumcheckData<F, EF>,
) -> Result<(), SpartanWhirError> {
    put_u32(
        out,
        u32::try_from(data.polynomial_evaluations.len())
            .map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for [c0, c2] in &data.polynomial_evaluations {
        put_extension(out, c0);
        put_extension(out, c2);
    }

    put_u32(
        out,
        u32::try_from(data.pow_witnesses.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
    );
    for witness in &data.pow_witnesses {
        put_field(out, witness);
    }

    Ok(())
}

fn decode_sumcheck_data(reader: &mut Reader<'_>) -> Result<SumcheckData<F, EF>, SpartanWhirError> {
    let eval_len = reader.read_u32()? as usize;
    let mut polynomial_evaluations = Vec::with_capacity(eval_len);
    for _ in 0..eval_len {
        polynomial_evaluations.push([reader.read_extension()?, reader.read_extension()?]);
    }

    let witness_len = reader.read_u32()? as usize;
    let mut pow_witnesses = Vec::with_capacity(witness_len);
    for _ in 0..witness_len {
        pow_witnesses.push(reader.read_field()?);
    }

    Ok(SumcheckData {
        polynomial_evaluations,
        pow_witnesses,
    })
}

fn encode_query_batch_payload(
    out: &mut Vec<u8>,
    query: &QueryBatchOpening<F, EF, u64, 4>,
    digest_width: usize,
    expected_queries: usize,
    counters: &mut ProofSizeCounters,
) -> Result<usize, SpartanWhirError> {
    let mut digest_data_bytes = 0usize;
    counters.num_query_batches = counters
        .num_query_batches
        .checked_add(1)
        .ok_or(SpartanWhirError::ProofEncodeFailed)?;

    match query {
        QueryBatchOpening::Base { values, proof } => {
            put_u8(out, 0);
            if values.len() > expected_queries {
                return Err(SpartanWhirError::ProofEncodeFailed);
            }

            put_u32(
                out,
                u32::try_from(values.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );
            let row_len = uniform_row_len_base(values)?;
            put_u32(
                out,
                u32::try_from(row_len).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );

            for row in values {
                for value in row {
                    put_field(out, value);
                }
            }

            counters.num_base_query_values = counters
                .num_base_query_values
                .checked_add(
                    values
                        .len()
                        .checked_mul(row_len)
                        .ok_or(SpartanWhirError::ProofEncodeFailed)?,
                )
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;

            put_u32(
                out,
                u32::try_from(proof.decommitments.len())
                    .map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );
            for digest in &proof.decommitments {
                put_digest(out, digest, digest_width)?;
            }

            let bytes = proof
                .decommitments
                .len()
                .checked_mul(digest_width)
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
            digest_data_bytes = digest_data_bytes
                .checked_add(bytes)
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
            counters.num_decommitments = counters
                .num_decommitments
                .checked_add(proof.decommitments.len())
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
        }
        QueryBatchOpening::Extension { values, proof } => {
            put_u8(out, 1);
            if values.len() > expected_queries {
                return Err(SpartanWhirError::ProofEncodeFailed);
            }

            put_u32(
                out,
                u32::try_from(values.len()).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );
            let row_len = uniform_row_len_ext(values)?;
            put_u32(
                out,
                u32::try_from(row_len).map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );

            for row in values {
                for value in row {
                    put_extension(out, value);
                }
            }

            counters.num_extension_query_values = counters
                .num_extension_query_values
                .checked_add(
                    values
                        .len()
                        .checked_mul(row_len)
                        .ok_or(SpartanWhirError::ProofEncodeFailed)?,
                )
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;

            put_u32(
                out,
                u32::try_from(proof.decommitments.len())
                    .map_err(|_| SpartanWhirError::ProofEncodeFailed)?,
            );
            for digest in &proof.decommitments {
                put_digest(out, digest, digest_width)?;
            }

            let bytes = proof
                .decommitments
                .len()
                .checked_mul(digest_width)
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
            digest_data_bytes = digest_data_bytes
                .checked_add(bytes)
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
            counters.num_decommitments = counters
                .num_decommitments
                .checked_add(proof.decommitments.len())
                .ok_or(SpartanWhirError::ProofEncodeFailed)?;
        }
    }

    Ok(digest_data_bytes)
}

fn decode_query_batch_payload(
    reader: &mut Reader<'_>,
    digest_width: usize,
    expected_queries: usize,
) -> Result<QueryBatchOpening<F, EF, u64, 4>, SpartanWhirError> {
    let variant = reader.read_u8()?;
    let num_queries = reader.read_u32()? as usize;
    if num_queries > expected_queries {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    let row_len = reader.read_u32()? as usize;
    let n_values = num_queries
        .checked_mul(row_len)
        .ok_or(SpartanWhirError::InvalidBlobLayout)?;

    let batch = match variant {
        0 => {
            let mut flat = Vec::with_capacity(n_values);
            for _ in 0..n_values {
                flat.push(reader.read_field()?);
            }
            let values = reshape_vec(flat, num_queries, row_len)?;

            let decommitments_len = reader.read_u32()? as usize;
            let mut decommitments = Vec::with_capacity(decommitments_len);
            for _ in 0..decommitments_len {
                decommitments.push(reader.read_digest(digest_width)?);
            }

            QueryBatchOpening::Base {
                values,
                proof: MerkleMultiProof { decommitments },
            }
        }
        1 => {
            let mut flat = Vec::with_capacity(n_values);
            for _ in 0..n_values {
                flat.push(reader.read_extension()?);
            }
            let values = reshape_vec(flat, num_queries, row_len)?;

            let decommitments_len = reader.read_u32()? as usize;
            let mut decommitments = Vec::with_capacity(decommitments_len);
            for _ in 0..decommitments_len {
                decommitments.push(reader.read_digest(digest_width)?);
            }

            QueryBatchOpening::Extension {
                values,
                proof: MerkleMultiProof { decommitments },
            }
        }
        _ => return Err(SpartanWhirError::InvalidBlobLayout),
    };

    Ok(batch)
}

fn uniform_row_len_base(values: &[Vec<F>]) -> Result<usize, SpartanWhirError> {
    let row_len = values.first().map_or(0usize, Vec::len);
    for row in values {
        if row.len() != row_len {
            return Err(SpartanWhirError::ProofEncodeFailed);
        }
    }
    Ok(row_len)
}

fn uniform_row_len_ext(values: &[Vec<EF>]) -> Result<usize, SpartanWhirError> {
    let row_len = values.first().map_or(0usize, Vec::len);
    for row in values {
        if row.len() != row_len {
            return Err(SpartanWhirError::ProofEncodeFailed);
        }
    }
    Ok(row_len)
}

fn reshape_vec<T>(flat: Vec<T>, rows: usize, cols: usize) -> Result<Vec<Vec<T>>, SpartanWhirError> {
    if rows == 0 {
        return Ok(Vec::new());
    }
    if flat.len()
        != rows
            .checked_mul(cols)
            .ok_or(SpartanWhirError::InvalidBlobLayout)?
    {
        return Err(SpartanWhirError::InvalidBlobLayout);
    }

    let mut out = Vec::with_capacity(rows);
    let mut iter = flat.into_iter();
    for _ in 0..rows {
        let mut row = Vec::with_capacity(cols);
        for _ in 0..cols {
            row.push(iter.next().ok_or(SpartanWhirError::InvalidBlobLayout)?);
        }
        out.push(row);
    }
    Ok(out)
}

fn put_digest(
    out: &mut Vec<u8>,
    digest: &[u64; 4],
    digest_width: usize,
) -> Result<(), SpartanWhirError> {
    if !(1..=32).contains(&digest_width) {
        return Err(SpartanWhirError::ProofEncodeFailed);
    }
    let bytes = digest_to_bytes(digest);
    out.extend_from_slice(&bytes[..digest_width]);
    Ok(())
}

fn put_field(out: &mut Vec<u8>, value: &F) {
    out.extend_from_slice(&value.as_canonical_u32().to_be_bytes());
}

fn put_extension(out: &mut Vec<u8>, value: &EF) {
    let coeffs = value.as_basis_coefficients_slice();
    put_field(out, &coeffs[0]);
    put_field(out, &coeffs[1]);
    put_field(out, &coeffs[2]);
    put_field(out, &coeffs[3]);
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], SpartanWhirError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SpartanWhirError::InvalidBlobLayout)?;
        if end > self.bytes.len() {
            return Err(SpartanWhirError::InvalidBlobLayout);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, SpartanWhirError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, SpartanWhirError> {
        let mut tmp = [0u8; 2];
        tmp.copy_from_slice(self.read_exact(2)?);
        Ok(u16::from_be_bytes(tmp))
    }

    fn read_u32(&mut self) -> Result<u32, SpartanWhirError> {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_be_bytes(tmp))
    }

    fn read_field(&mut self) -> Result<F, SpartanWhirError> {
        let raw = self.read_u32()?;
        if raw >= F::ORDER_U32 {
            return Err(SpartanWhirError::NonCanonicalEncoding);
        }
        Ok(F::from_u32(raw))
    }

    fn read_extension(&mut self) -> Result<EF, SpartanWhirError> {
        let c0 = self.read_field()?;
        let c1 = self.read_field()?;
        let c2 = self.read_field()?;
        let c3 = self.read_field()?;
        Ok(EF::from([c0, c1, c2, c3]))
    }

    fn read_digest(&mut self, digest_width: usize) -> Result<[u64; 4], SpartanWhirError> {
        if !(1..=32).contains(&digest_width) {
            return Err(SpartanWhirError::InvalidBlobLayout);
        }
        let mut bytes = [0u8; 32];
        let prefix = self.read_exact(digest_width)?;
        bytes[..digest_width].copy_from_slice(prefix);
        Ok(digest_from_bytes(&bytes))
    }

    fn ensure_finished(&self) -> Result<(), SpartanWhirError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(SpartanWhirError::TrailingBytes)
        }
    }

    fn is_finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}
