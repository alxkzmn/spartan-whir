#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpartanWhirError {
    Unimplemented(&'static str),
    InvalidR1csShape,
    InvalidWitnessLength,
    PaddingError,
    SecurityBelowMinimum,
    MerkleSecurityBelowMinimum,
    TranscriptMismatch,
    SumcheckFailed,
    PcsVerificationFailed,
    ProofDecodeFailed,
    UnsupportedMode,
    InvalidConfig,
}

impl core::fmt::Display for SpartanWhirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unimplemented(where_) => write!(f, "unimplemented: {where_}"),
            Self::InvalidR1csShape => write!(f, "invalid R1CS shape"),
            Self::InvalidWitnessLength => write!(f, "invalid witness length"),
            Self::PaddingError => write!(f, "padding error"),
            Self::SecurityBelowMinimum => write!(f, "security level below minimum"),
            Self::MerkleSecurityBelowMinimum => write!(f, "merkle security below minimum"),
            Self::TranscriptMismatch => write!(f, "transcript mismatch"),
            Self::SumcheckFailed => write!(f, "sumcheck verification failed"),
            Self::PcsVerificationFailed => write!(f, "PCS verification failed"),
            Self::ProofDecodeFailed => write!(f, "proof decode failed"),
            Self::UnsupportedMode => write!(f, "unsupported mode"),
            Self::InvalidConfig => write!(f, "invalid configuration"),
        }
    }
}
