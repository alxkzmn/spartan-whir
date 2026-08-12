use std::{
    fmt,
    fs::File,
    io::Read,
    path::Path,
    string::{String, ToString},
    vec::Vec,
};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

use crate::{engine::F, R1csShape, R1csWitness, SparseMatEntry, SparseMatrix, SpartanWhirError};

pub const KOALABEAR_MODULUS: u32 = 2_130_706_433;
pub const MAX_CIRCOM_FILE_BYTES: usize = 1 << 30;
pub const MAX_CIRCOM_SECTIONS: usize = 64;
pub const MAX_CIRCOM_DIMENSION: usize = 1 << 24;
pub const MAX_CIRCOM_TERMS: usize = 1 << 24;
const R1CS_MAGIC: &[u8; 4] = b"r1cs";
const WTNS_MAGIC: &[u8; 4] = b"wtns";

pub type ImportedCircuit = (R1csShape<F>, R1csWitness<F>, Vec<F>);
pub type ImportedWitness = (R1csWitness<F>, Vec<F>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircomR1cs {
    pub shape: R1csShape<F>,
    pub public_outputs: usize,
    pub public_inputs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircomAdapterError {
    Io(String),
    UnexpectedEof,
    InvalidMagic(&'static str),
    UnsupportedVersion {
        format: &'static str,
        version: u32,
    },
    MissingSection(u32),
    DuplicateSection(u32),
    UnsupportedSection {
        id: u32,
    },
    InvalidFieldSize {
        expected: u32,
        actual: u32,
    },
    InvalidModulus {
        expected: u32,
        actual: Vec<u8>,
    },
    InvalidFieldElement,
    InvalidWitnessLength {
        expected: usize,
        actual: usize,
    },
    ResourceLimitExceeded {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
    AllocationFailed(&'static str),
    InvalidShape,
    UnsatisfiedConstraint {
        row: usize,
    },
}

impl fmt::Display for CircomAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::UnexpectedEof => write!(f, "unexpected end of file"),
            Self::InvalidMagic(format) => write!(f, "invalid {format} magic"),
            Self::UnsupportedVersion { format, version } => {
                write!(f, "unsupported {format} version {version}")
            }
            Self::MissingSection(id) => write!(f, "missing section {id}"),
            Self::DuplicateSection(id) => write!(f, "duplicate section {id}"),
            Self::UnsupportedSection { id: 4 | 5 } => {
                write!(f, "custom-gate R1CS sections are not supported")
            }
            Self::UnsupportedSection { id } => write!(f, "unsupported R1CS section {id}"),
            Self::InvalidFieldSize { expected, actual } => {
                write!(f, "invalid field size: expected {expected}, got {actual}")
            }
            Self::InvalidModulus { .. } => write!(f, "invalid modulus"),
            Self::InvalidFieldElement => write!(f, "field element is not canonical KoalaBear"),
            Self::InvalidWitnessLength { expected, actual } => {
                write!(
                    f,
                    "invalid witness length: expected {expected}, got {actual}"
                )
            }
            Self::ResourceLimitExceeded {
                resource,
                limit,
                actual,
            } => write!(
                f,
                "Circom {resource} exceeds limit: maximum {limit}, got {actual}"
            ),
            Self::AllocationFailed(resource) => {
                write!(f, "failed to allocate memory for Circom {resource}")
            }
            Self::InvalidShape => write!(f, "invalid R1CS shape"),
            Self::UnsatisfiedConstraint { row } => write!(f, "unsatisfied constraint at row {row}"),
        }
    }
}

impl std::error::Error for CircomAdapterError {}

impl From<std::io::Error> for CircomAdapterError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

fn ensure_limit(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), CircomAdapterError> {
    if actual > limit {
        return Err(CircomAdapterError::ResourceLimitExceeded {
            resource,
            limit: limit as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

fn validate_file_size(bytes: &[u8], resource: &'static str) -> Result<(), CircomAdapterError> {
    ensure_limit(resource, bytes.len(), MAX_CIRCOM_FILE_BYTES)
}

fn read_path_bounded(
    path: impl AsRef<Path>,
    resource: &'static str,
) -> Result<Vec<u8>, CircomAdapterError> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CIRCOM_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    validate_file_size(&bytes, resource)?;
    Ok(bytes)
}

fn try_vec_with_capacity<T>(
    capacity: usize,
    resource: &'static str,
) -> Result<Vec<T>, CircomAdapterError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CircomAdapterError::AllocationFailed(resource))?;
    Ok(values)
}

/// Import a KoalaBear Circom `.r1cs` and `.wtns` pair.
///
/// Import validates the file headers, remaps Circom wires into Spartan-WHIR's
/// `[witness | constant_one | public_outputs || public_inputs]` layout, and
/// runs a constraint-satisfaction check against the imported witness.
pub fn import_paths(
    r1cs_path: impl AsRef<Path>,
    wtns_path: impl AsRef<Path>,
) -> Result<ImportedCircuit, CircomAdapterError> {
    let r1cs = read_path_bounded(r1cs_path, "R1CS file")?;
    let wtns = read_path_bounded(wtns_path, "witness file")?;
    import_bytes(&r1cs, &wtns)
}

pub fn import_bytes(r1cs: &[u8], wtns: &[u8]) -> Result<ImportedCircuit, CircomAdapterError> {
    validate_file_size(r1cs, "R1CS file")?;
    validate_file_size(wtns, "witness file")?;
    let r1cs = parse_r1cs(r1cs)?;
    let witness = parse_wtns(wtns)?;
    import_parsed(r1cs, witness)
}

pub fn import_r1cs_path(r1cs_path: impl AsRef<Path>) -> Result<CircomR1cs, CircomAdapterError> {
    let r1cs = read_path_bounded(r1cs_path, "R1CS file")?;
    import_r1cs_bytes(&r1cs)
}

pub fn import_r1cs_bytes(r1cs: &[u8]) -> Result<CircomR1cs, CircomAdapterError> {
    validate_file_size(r1cs, "R1CS file")?;
    build_circom_r1cs(parse_r1cs(r1cs)?)
}

pub fn import_witness_path(
    shape: &R1csShape<F>,
    wtns_path: impl AsRef<Path>,
) -> Result<ImportedWitness, CircomAdapterError> {
    let wtns = read_path_bounded(wtns_path, "witness file")?;
    import_witness_bytes(shape, &wtns)
}

pub fn import_witness_bytes(
    shape: &R1csShape<F>,
    wtns: &[u8],
) -> Result<ImportedWitness, CircomAdapterError> {
    validate_file_size(wtns, "witness file")?;
    let witness_values = parse_wtns(wtns)?;
    import_witness_values(shape, witness_values)
}

pub fn import_witness_bytes_with_layout(
    validation_shape: &R1csShape<F>,
    num_vars: usize,
    num_io: usize,
    wtns: &[u8],
) -> Result<ImportedWitness, CircomAdapterError> {
    validate_file_size(wtns, "witness file")?;
    let witness_values = parse_wtns(wtns)?;
    import_witness_values_with_layout(validation_shape, num_vars, num_io, witness_values)
}

pub fn import_witness_values(
    shape: &R1csShape<F>,
    witness_values: Vec<F>,
) -> Result<ImportedWitness, CircomAdapterError> {
    import_witness_values_with_layout(shape, shape.num_vars, shape.num_io, witness_values)
}

pub fn import_witness_values_with_layout(
    validation_shape: &R1csShape<F>,
    num_vars: usize,
    num_io: usize,
    witness_values: Vec<F>,
) -> Result<ImportedWitness, CircomAdapterError> {
    let (witness, public_inputs) =
        split_witness_values_with_layout(num_vars, num_io, witness_values)?;
    validate_satisfaction(validation_shape, &witness, &public_inputs)?;
    Ok((witness, public_inputs))
}

fn split_witness_values_with_layout(
    num_vars: usize,
    num_io: usize,
    witness_values: Vec<F>,
) -> Result<ImportedWitness, CircomAdapterError> {
    let expected = num_vars
        .checked_add(num_io)
        .and_then(|n| n.checked_add(1))
        .ok_or(CircomAdapterError::InvalidShape)?;
    if witness_values.len() != expected {
        return Err(CircomAdapterError::InvalidWitnessLength {
            expected,
            actual: witness_values.len(),
        });
    }
    let one_plus_io = num_io
        .checked_add(1)
        .ok_or(CircomAdapterError::InvalidShape)?;
    let mut public_inputs = try_vec_with_capacity(num_io, "public inputs")?;
    public_inputs.extend_from_slice(&witness_values[1..one_plus_io]);
    let witness_len = witness_values.len() - one_plus_io;
    let mut witness_values_out = try_vec_with_capacity(witness_len, "witness values")?;
    witness_values_out.extend_from_slice(&witness_values[one_plus_io..]);
    let witness = R1csWitness {
        w: witness_values_out,
    };
    Ok((witness, public_inputs))
}

fn import_parsed(
    r1cs: ParsedR1cs,
    witness_values: Vec<F>,
) -> Result<ImportedCircuit, CircomAdapterError> {
    let circom_r1cs = build_circom_r1cs(r1cs)?;
    let (witness, public_inputs) = import_witness_values(&circom_r1cs.shape, witness_values)?;
    Ok((circom_r1cs.shape, witness, public_inputs))
}

fn build_circom_r1cs(r1cs: ParsedR1cs) -> Result<CircomR1cs, CircomAdapterError> {
    let num_io = r1cs
        .header
        .public_outputs
        .checked_add(r1cs.header.public_inputs)
        .ok_or(CircomAdapterError::InvalidShape)?;
    let one_plus_io = num_io
        .checked_add(1)
        .ok_or(CircomAdapterError::InvalidShape)?;
    let non_private_wires = one_plus_io
        .checked_add(r1cs.header.private_inputs)
        .ok_or(CircomAdapterError::InvalidShape)?;
    if non_private_wires > r1cs.header.total_wires {
        return Err(CircomAdapterError::InvalidShape);
    }
    let num_vars = r1cs
        .header
        .total_wires
        .checked_sub(one_plus_io)
        .ok_or(CircomAdapterError::InvalidShape)?;
    let num_cols = num_vars
        .checked_add(one_plus_io)
        .ok_or(CircomAdapterError::InvalidShape)?;

    let remap = |wire: usize| -> Result<usize, CircomAdapterError> {
        if wire >= r1cs.header.total_wires {
            return Err(CircomAdapterError::InvalidShape);
        }
        if wire == 0 {
            Ok(num_vars)
        } else if wire <= num_io {
            Ok(num_vars + wire)
        } else {
            Ok(wire - num_io - 1)
        }
    };

    let map_matrix = |lcs: &[LinearCombination]| -> Result<SparseMatrix<F>, CircomAdapterError> {
        let entry_count = lcs.iter().try_fold(0usize, |count, lc| {
            count
                .checked_add(lc.terms.len())
                .ok_or(CircomAdapterError::ResourceLimitExceeded {
                    resource: "matrix terms",
                    limit: MAX_CIRCOM_TERMS as u64,
                    actual: u64::MAX,
                })
        })?;
        ensure_limit("matrix terms", entry_count, MAX_CIRCOM_TERMS)?;
        let mut entries = try_vec_with_capacity(entry_count, "matrix terms")?;
        for (row, lc) in lcs.iter().enumerate() {
            for term in &lc.terms {
                entries.push(SparseMatEntry {
                    row,
                    col: remap(term.wire)?,
                    val: term.coeff,
                });
            }
        }
        Ok(SparseMatrix {
            num_rows: r1cs.header.number_of_constraints,
            num_cols,
            entries,
        })
    };

    let shape = R1csShape {
        num_cons: r1cs.header.number_of_constraints,
        num_vars,
        num_io,
        a: map_matrix(&r1cs.a)?,
        b: map_matrix(&r1cs.b)?,
        c: map_matrix(&r1cs.c)?,
    };

    Ok(CircomR1cs {
        shape,
        public_outputs: r1cs.header.public_outputs,
        public_inputs: r1cs.header.public_inputs,
    })
}

/// Validate an imported Circom witness against a Spartan-WHIR R1CS shape.
///
/// `shape` may be the padded shape stored in a proving key. The witness may be
/// unpadded; it is zero-padded to `shape.num_vars` before matrix evaluation.
pub fn validate_satisfaction(
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), CircomAdapterError> {
    let mut z = shape.witness_to_mle(&witness.w).map_err(|err| match err {
        SpartanWhirError::InvalidWitnessLength => CircomAdapterError::InvalidWitnessLength {
            expected: shape.num_vars,
            actual: witness.w.len(),
        },
        _ => CircomAdapterError::InvalidShape,
    })?;
    z.push(F::ONE);
    z.extend_from_slice(public_inputs);
    let (az, bz, cz) = shape.multiply_vec(&z).map_err(|err| match err {
        SpartanWhirError::InvalidWitnessLength => CircomAdapterError::InvalidShape,
        _ => CircomAdapterError::InvalidShape,
    })?;
    for row in 0..shape.num_cons {
        if az[row] * bz[row] != cz[row] {
            return Err(CircomAdapterError::UnsatisfiedConstraint { row });
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ParsedR1cs {
    header: R1csHeader,
    a: Vec<LinearCombination>,
    b: Vec<LinearCombination>,
    c: Vec<LinearCombination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct R1csHeader {
    total_wires: usize,
    public_outputs: usize,
    public_inputs: usize,
    private_inputs: usize,
    number_of_constraints: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinearCombination {
    terms: Vec<Term>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Term {
    wire: usize,
    coeff: F,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Section<'a> {
    id: u32,
    data: &'a [u8],
}

fn parse_r1cs(bytes: &[u8]) -> Result<ParsedR1cs, CircomAdapterError> {
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != R1CS_MAGIC {
        return Err(CircomAdapterError::InvalidMagic("r1cs"));
    }
    let version = reader.u32()?;
    if version != 1 {
        return Err(CircomAdapterError::UnsupportedVersion {
            format: "r1cs",
            version,
        });
    }
    let sections = read_sections(&mut reader)?;
    for section in &sections {
        match section.id {
            1 | 2 | 3 => {}
            id => return Err(CircomAdapterError::UnsupportedSection { id }),
        }
    }
    let header = parse_r1cs_header(section(&sections, 1)?)?;
    let (a, b, c) = parse_constraints(section(&sections, 2)?, &header)?;
    Ok(ParsedR1cs { header, a, b, c })
}

fn parse_r1cs_header(bytes: &[u8]) -> Result<R1csHeader, CircomAdapterError> {
    let mut reader = Reader::new(bytes);
    let field_size = reader.u32()?;
    if field_size != 4 {
        return Err(CircomAdapterError::InvalidFieldSize {
            expected: 4,
            actual: field_size,
        });
    }
    validate_modulus(reader.take(4)?)?;
    let total_wires = reader.u32()? as usize;
    let public_outputs = reader.u32()? as usize;
    let public_inputs = reader.u32()? as usize;
    let private_inputs = reader.u32()? as usize;
    let number_of_labels = reader.u64()?;
    let number_of_constraints = reader.u32()? as usize;
    ensure_limit("wires", total_wires, MAX_CIRCOM_DIMENSION)?;
    ensure_limit("public outputs", public_outputs, MAX_CIRCOM_DIMENSION)?;
    ensure_limit("public inputs", public_inputs, MAX_CIRCOM_DIMENSION)?;
    ensure_limit("private inputs", private_inputs, MAX_CIRCOM_DIMENSION)?;
    if number_of_labels > MAX_CIRCOM_DIMENSION as u64 {
        return Err(CircomAdapterError::ResourceLimitExceeded {
            resource: "labels",
            limit: MAX_CIRCOM_DIMENSION as u64,
            actual: number_of_labels,
        });
    }
    ensure_limit("constraints", number_of_constraints, MAX_CIRCOM_DIMENSION)?;
    Ok(R1csHeader {
        total_wires,
        public_outputs,
        public_inputs,
        private_inputs,
        number_of_constraints,
    })
}

type ConstraintTriples = (
    Vec<LinearCombination>,
    Vec<LinearCombination>,
    Vec<LinearCombination>,
);

fn parse_constraints(
    bytes: &[u8],
    header: &R1csHeader,
) -> Result<ConstraintTriples, CircomAdapterError> {
    let mut reader = Reader::new(bytes);
    if header.number_of_constraints > reader.remaining() / 12 {
        return Err(CircomAdapterError::UnexpectedEof);
    }
    let mut a = try_vec_with_capacity(header.number_of_constraints, "A constraints")?;
    let mut b = try_vec_with_capacity(header.number_of_constraints, "B constraints")?;
    let mut c = try_vec_with_capacity(header.number_of_constraints, "C constraints")?;
    let mut total_terms = 0usize;
    for _ in 0..header.number_of_constraints {
        a.push(parse_lc(&mut reader, &mut total_terms)?);
        b.push(parse_lc(&mut reader, &mut total_terms)?);
        c.push(parse_lc(&mut reader, &mut total_terms)?);
    }
    Ok((a, b, c))
}

fn parse_lc(
    reader: &mut Reader<'_>,
    total_terms: &mut usize,
) -> Result<LinearCombination, CircomAdapterError> {
    let n = reader.u32()? as usize;
    let next_total =
        total_terms
            .checked_add(n)
            .ok_or(CircomAdapterError::ResourceLimitExceeded {
                resource: "linear-combination terms",
                limit: MAX_CIRCOM_TERMS as u64,
                actual: u64::MAX,
            })?;
    ensure_limit("linear-combination terms", next_total, MAX_CIRCOM_TERMS)?;
    *total_terms = next_total;
    if n > reader.remaining() / 8 {
        return Err(CircomAdapterError::UnexpectedEof);
    }
    let mut terms = try_vec_with_capacity(n, "linear-combination terms")?;
    for _ in 0..n {
        terms.push(Term {
            wire: reader.u32()? as usize,
            coeff: parse_field(reader.take(4)?)?,
        });
    }
    Ok(LinearCombination { terms })
}

fn parse_wtns(bytes: &[u8]) -> Result<Vec<F>, CircomAdapterError> {
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != WTNS_MAGIC {
        return Err(CircomAdapterError::InvalidMagic("wtns"));
    }
    let version = reader.u32()?;
    if version != 2 {
        return Err(CircomAdapterError::UnsupportedVersion {
            format: "wtns",
            version,
        });
    }
    let sections = read_sections(&mut reader)?;
    let header = section(&sections, 1)?;
    let witness = section(&sections, 2)?;

    let mut header_reader = Reader::new(header);
    let n8 = header_reader.u32()?;
    if n8 != 4 {
        return Err(CircomAdapterError::InvalidFieldSize {
            expected: 4,
            actual: n8,
        });
    }
    validate_modulus(header_reader.take(4)?)?;
    let n_witness = header_reader.u32()? as usize;
    ensure_limit("witness values", n_witness, MAX_CIRCOM_DIMENSION)?;
    let expected_witness_bytes =
        n_witness
            .checked_mul(4)
            .ok_or(CircomAdapterError::ResourceLimitExceeded {
                resource: "witness bytes",
                limit: MAX_CIRCOM_FILE_BYTES as u64,
                actual: u64::MAX,
            })?;
    if witness.len() != expected_witness_bytes {
        return Err(CircomAdapterError::InvalidWitnessLength {
            expected: n_witness,
            actual: witness.len() / 4,
        });
    }

    let mut values = try_vec_with_capacity(n_witness, "witness values")?;
    for bytes in witness.chunks_exact(4) {
        values.push(parse_field(bytes)?);
    }
    Ok(values)
}

fn read_sections<'a>(reader: &mut Reader<'a>) -> Result<Vec<Section<'a>>, CircomAdapterError> {
    let n_sections = reader.u32()? as usize;
    ensure_limit("sections", n_sections, MAX_CIRCOM_SECTIONS)?;
    if n_sections > reader.remaining() / 12 {
        return Err(CircomAdapterError::UnexpectedEof);
    }
    let mut sections = try_vec_with_capacity(n_sections, "sections")?;
    for _ in 0..n_sections {
        let id = reader.u32()?;
        if sections
            .iter()
            .any(|section: &Section<'_>| section.id == id)
        {
            return Err(CircomAdapterError::DuplicateSection(id));
        }
        let len_u64 = reader.u64()?;
        let len =
            usize::try_from(len_u64).map_err(|_| CircomAdapterError::ResourceLimitExceeded {
                resource: "section bytes",
                limit: MAX_CIRCOM_FILE_BYTES as u64,
                actual: len_u64,
            })?;
        ensure_limit("section bytes", len, MAX_CIRCOM_FILE_BYTES)?;
        let data = reader.take(len)?;
        sections.push(Section { id, data });
    }
    Ok(sections)
}

fn section<'a>(sections: &'a [Section<'a>], id: u32) -> Result<&'a [u8], CircomAdapterError> {
    sections
        .iter()
        .find(|section| section.id == id)
        .map(|section| section.data)
        .ok_or(CircomAdapterError::MissingSection(id))
}

fn validate_modulus(bytes: &[u8]) -> Result<(), CircomAdapterError> {
    if bytes == KOALABEAR_MODULUS.to_le_bytes() {
        Ok(())
    } else {
        Err(CircomAdapterError::InvalidModulus {
            expected: KOALABEAR_MODULUS,
            actual: bytes.to_vec(),
        })
    }
}

fn parse_field(bytes: &[u8]) -> Result<F, CircomAdapterError> {
    let raw = u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| CircomAdapterError::UnexpectedEof)?,
    );
    if raw >= KOALABEAR_MODULUS {
        return Err(CircomAdapterError::InvalidFieldElement);
    }
    Ok(F::from_u32(raw))
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CircomAdapterError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CircomAdapterError::UnexpectedEof)?;
        if end > self.bytes.len() {
            return Err(CircomAdapterError::UnexpectedEof);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn u32(&mut self) -> Result<u32, CircomAdapterError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CircomAdapterError::UnexpectedEof)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, CircomAdapterError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| CircomAdapterError::UnexpectedEof)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_le(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn u64_le(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn field(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn section(out: &mut Vec<u8>, id: u32, data: &[u8]) {
        u32_le(out, id);
        u64_le(out, data.len() as u64);
        out.extend_from_slice(data);
    }

    fn lc(out: &mut Vec<u8>, terms: &[(u32, u32)]) {
        u32_le(out, terms.len() as u32);
        for (wire, coeff) in terms {
            u32_le(out, *wire);
            field(out, *coeff);
        }
    }

    fn sample_r1cs(custom_gates: bool, modulus: u32) -> Vec<u8> {
        sample_r1cs_with_constraints(custom_gates, modulus, 2)
    }

    fn sample_r1cs_with_constraints(
        custom_gates: bool,
        modulus: u32,
        constraints_count: u32,
    ) -> Vec<u8> {
        let mut header = Vec::new();
        u32_le(&mut header, 4);
        field(&mut header, modulus);
        u32_le(&mut header, 5); // [1, output, public input, private input, internal]
        u32_le(&mut header, 1);
        u32_le(&mut header, 1);
        u32_le(&mut header, 1);
        u64_le(&mut header, 5);
        u32_le(&mut header, constraints_count);

        let mut constraints = Vec::new();
        lc(&mut constraints, &[(3, 1)]);
        lc(&mut constraints, &[(2, 1)]);
        lc(&mut constraints, &[(4, 1)]);
        lc(&mut constraints, &[(4, 1), (0, 1)]);
        lc(&mut constraints, &[(0, 1)]);
        lc(&mut constraints, &[(1, 1)]);
        if constraints_count == 3 {
            lc(&mut constraints, &[(0, 1)]);
            lc(&mut constraints, &[(0, 1)]);
            lc(&mut constraints, &[(0, 1)]);
        }

        let mut r1cs = Vec::new();
        r1cs.extend_from_slice(R1CS_MAGIC);
        u32_le(&mut r1cs, 1);
        u32_le(&mut r1cs, if custom_gates { 4 } else { 3 });
        section(&mut r1cs, 1, &header);
        section(&mut r1cs, 2, &constraints);
        section(&mut r1cs, 3, &[]);
        if custom_gates {
            section(&mut r1cs, 4, &[]);
        }
        r1cs
    }

    fn sample_wtns(values: &[u32], n8: u32, modulus: u32) -> Vec<u8> {
        let mut header = Vec::new();
        u32_le(&mut header, n8);
        let mut modulus_bytes = [0u8; 8];
        modulus_bytes[..4].copy_from_slice(&modulus.to_le_bytes());
        header.extend_from_slice(&modulus_bytes[..n8 as usize]);
        u32_le(&mut header, values.len() as u32);

        let mut body = Vec::new();
        for value in values {
            let mut bytes = [0u8; 8];
            bytes[..4].copy_from_slice(&value.to_le_bytes());
            body.extend_from_slice(&bytes[..n8 as usize]);
        }

        let mut wtns = Vec::new();
        wtns.extend_from_slice(WTNS_MAGIC);
        u32_le(&mut wtns, 2);
        u32_le(&mut wtns, 2);
        section(&mut wtns, 1, &header);
        section(&mut wtns, 2, &body);
        wtns
    }

    #[test]
    fn imports_unpadded_layout() {
        let r1cs = sample_r1cs(false, KOALABEAR_MODULUS);
        let wtns = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS);

        let (shape, witness, public_inputs) = import_bytes(&r1cs, &wtns).unwrap();

        assert_eq!(public_inputs, vec![F::from_u32(36), F::from_u32(5)]);
        assert_eq!(witness.w, vec![F::from_u32(7), F::from_u32(35)]);
        assert_eq!(shape.num_cons, 2);
        assert_eq!(shape.num_vars, 2);
        assert_eq!(shape.num_io, 2);
    }

    #[test]
    fn imported_shape_can_be_regular_padded_by_protocol_setup_path() {
        let r1cs = sample_r1cs_with_constraints(false, KOALABEAR_MODULUS, 3);
        let wtns = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS);

        let (shape, witness, public_inputs) = import_bytes(&r1cs, &wtns).unwrap();
        assert_eq!(shape.num_cons, 3);
        assert_eq!(shape.num_vars, witness.w.len());

        let padded = shape.pad_regular().unwrap();
        assert_eq!(padded.num_cons, 4);
        assert_eq!(padded.num_vars, 4);

        let mut z = padded.witness_to_mle(&witness.w).unwrap();
        z.push(F::ONE);
        z.extend_from_slice(&public_inputs);
        let (az, bz, cz) = padded.multiply_vec(&z).unwrap();
        for row in 0..padded.num_cons {
            assert_eq!(az[row] * bz[row], cz[row]);
        }
    }

    #[test]
    fn accepts_boundary_coefficients() {
        assert_eq!(parse_field(&0u32.to_le_bytes()).unwrap(), F::from_u32(0));
        assert_eq!(parse_field(&1u32.to_le_bytes()).unwrap(), F::from_u32(1));
        assert_eq!(
            parse_field(&(KOALABEAR_MODULUS - 1).to_le_bytes()).unwrap(),
            F::from_u32(KOALABEAR_MODULUS - 1)
        );
        assert_eq!(
            parse_field(&KOALABEAR_MODULUS.to_le_bytes()),
            Err(CircomAdapterError::InvalidFieldElement)
        );
    }

    #[test]
    fn accepts_omitted_label_map_count() {
        let mut r1cs = sample_r1cs(false, KOALABEAR_MODULUS);
        let labels_offset = 48;
        r1cs[labels_offset..labels_offset + 8].fill(0);
        let wtns = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS);

        let (shape, _, _) = import_bytes(&r1cs, &wtns).unwrap();
        assert_eq!(shape.num_vars, 2);
    }

    #[test]
    fn rejects_wrong_r1cs_modulus() {
        let r1cs = sample_r1cs(false, KOALABEAR_MODULUS - 2);
        let wtns = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS);
        assert!(matches!(
            import_bytes(&r1cs, &wtns),
            Err(CircomAdapterError::InvalidModulus { .. })
        ));
    }

    #[test]
    fn rejects_wrong_wtns_width_and_modulus() {
        let r1cs = sample_r1cs(false, KOALABEAR_MODULUS);
        let wrong_width = sample_wtns(&[1, 36, 5, 7, 35], 8, KOALABEAR_MODULUS);
        assert!(matches!(
            import_bytes(&r1cs, &wrong_width),
            Err(CircomAdapterError::InvalidFieldSize { actual: 8, .. })
        ));

        let wrong_modulus = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS - 1);
        assert!(matches!(
            import_bytes(&r1cs, &wrong_modulus),
            Err(CircomAdapterError::InvalidModulus { .. })
        ));
    }

    #[test]
    fn rejects_malformed_wtns_and_mismatched_lengths() {
        let r1cs = sample_r1cs(false, KOALABEAR_MODULUS);
        assert!(matches!(
            import_bytes(&r1cs, b"wtn"),
            Err(CircomAdapterError::UnexpectedEof)
        ));

        let short = sample_wtns(&[1, 36, 5, 7], 4, KOALABEAR_MODULUS);
        assert!(matches!(
            import_bytes(&r1cs, &short),
            Err(CircomAdapterError::InvalidWitnessLength {
                expected: 5,
                actual: 4
            })
        ));
    }

    #[test]
    fn rejects_custom_gate_r1cs() {
        let r1cs = sample_r1cs(true, KOALABEAR_MODULUS);
        let wtns = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS);
        assert!(matches!(
            import_bytes(&r1cs, &wtns),
            Err(CircomAdapterError::UnsupportedSection { id: 4 })
        ));
    }

    #[test]
    fn rejects_unknown_r1cs_section_without_calling_it_custom_gates() {
        let mut r1cs = sample_r1cs(false, KOALABEAR_MODULUS);
        r1cs[8..12].copy_from_slice(&4u32.to_le_bytes());
        section(&mut r1cs, 9, &[]);
        let wtns = sample_wtns(&[1, 36, 5, 7, 35], 4, KOALABEAR_MODULUS);

        assert!(matches!(
            import_bytes(&r1cs, &wtns),
            Err(CircomAdapterError::UnsupportedSection { id: 9 })
        ));
    }

    #[test]
    fn rejects_oversized_section_count_before_allocation() {
        let mut bytes = Vec::new();
        u32_le(&mut bytes, (MAX_CIRCOM_SECTIONS + 1) as u32);
        let mut reader = Reader::new(&bytes);

        assert_eq!(
            read_sections(&mut reader),
            Err(CircomAdapterError::ResourceLimitExceeded {
                resource: "sections",
                limit: MAX_CIRCOM_SECTIONS as u64,
                actual: (MAX_CIRCOM_SECTIONS + 1) as u64,
            })
        );
    }

    #[test]
    fn rejects_oversized_r1cs_dimensions_before_allocation() {
        let mut header = Vec::new();
        u32_le(&mut header, 4);
        field(&mut header, KOALABEAR_MODULUS);
        u32_le(&mut header, 5);
        u32_le(&mut header, 1);
        u32_le(&mut header, 1);
        u32_le(&mut header, 1);
        u64_le(&mut header, 5);
        u32_le(&mut header, (MAX_CIRCOM_DIMENSION + 1) as u32);

        assert_eq!(
            parse_r1cs_header(&header),
            Err(CircomAdapterError::ResourceLimitExceeded {
                resource: "constraints",
                limit: MAX_CIRCOM_DIMENSION as u64,
                actual: (MAX_CIRCOM_DIMENSION + 1) as u64,
            })
        );
    }

    #[test]
    fn rejects_oversized_linear_combination_before_allocation() {
        let mut bytes = Vec::new();
        u32_le(&mut bytes, (MAX_CIRCOM_TERMS + 1) as u32);
        let mut reader = Reader::new(&bytes);
        let mut total_terms = 0;

        assert_eq!(
            parse_lc(&mut reader, &mut total_terms),
            Err(CircomAdapterError::ResourceLimitExceeded {
                resource: "linear-combination terms",
                limit: MAX_CIRCOM_TERMS as u64,
                actual: (MAX_CIRCOM_TERMS + 1) as u64,
            })
        );
    }

    #[test]
    fn rejects_oversized_witness_count_before_allocation() {
        let mut header = Vec::new();
        u32_le(&mut header, 4);
        field(&mut header, KOALABEAR_MODULUS);
        u32_le(&mut header, (MAX_CIRCOM_DIMENSION + 1) as u32);

        let mut wtns = Vec::new();
        wtns.extend_from_slice(WTNS_MAGIC);
        u32_le(&mut wtns, 2);
        u32_le(&mut wtns, 2);
        section(&mut wtns, 1, &header);
        section(&mut wtns, 2, &[]);

        assert_eq!(
            parse_wtns(&wtns),
            Err(CircomAdapterError::ResourceLimitExceeded {
                resource: "witness values",
                limit: MAX_CIRCOM_DIMENSION as u64,
                actual: (MAX_CIRCOM_DIMENSION + 1) as u64,
            })
        );
    }
}
