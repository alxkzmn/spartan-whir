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
    UnsupportedStatementType,
    InvalidConfig,
    WhirCommitFailed,
    WhirOpenFailed,
    WhirVerifyFailed,
    CommitmentMismatch,
    InvalidPolynomialLength,
    InvalidNumVariables,
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
            Self::UnsupportedStatementType => write!(f, "unsupported statement type"),
            Self::InvalidConfig => write!(f, "invalid configuration"),
            Self::WhirCommitFailed => write!(f, "WHIR commitment failed"),
            Self::WhirOpenFailed => write!(f, "WHIR opening failed"),
            Self::WhirVerifyFailed => write!(f, "WHIR verification failed"),
            Self::CommitmentMismatch => write!(f, "commitment mismatch"),
            Self::InvalidPolynomialLength => write!(f, "invalid polynomial length"),
            Self::InvalidNumVariables => write!(f, "invalid number of variables"),
        }
    }
}
