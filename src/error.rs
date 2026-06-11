#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidConfigReason {
    Generic,
    ZeroFoldingFactor,
    ZeroRsDomainInitialReductionFactor,
    RsDomainInitialReductionFactorExceedsFirstFoldingFactor {
        rs_domain_initial_reduction_factor: usize,
        first_folding_factor: usize,
    },
    InvalidFoldingSchedule {
        num_variables: usize,
    },
    FoldedDomainSizeOverflow {
        num_variables: usize,
        starting_log_inv_rate: usize,
    },
    FirstFoldingFactorExceedsDomain {
        first_folding_factor: usize,
        log_domain_size: usize,
    },
    FoldedDomainExceedsBaseTwoAdicity {
        log_folded_domain_size: usize,
        base_two_adicity: usize,
        min_first_folding_factor: usize,
    },
    MissingDerivedProverData,
}

impl core::fmt::Display for InvalidConfigReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Generic => write!(f, "unspecified reason"),
            Self::ZeroFoldingFactor => write!(f, "first folding factor is zero"),
            Self::ZeroRsDomainInitialReductionFactor => {
                write!(f, "RS domain initial reduction factor is zero")
            }
            Self::RsDomainInitialReductionFactorExceedsFirstFoldingFactor {
                rs_domain_initial_reduction_factor,
                first_folding_factor,
            } => write!(
                f,
                "RS domain initial reduction factor {rs_domain_initial_reduction_factor} exceeds first folding factor {first_folding_factor}"
            ),
            Self::InvalidFoldingSchedule { num_variables } => write!(
                f,
                "folding schedule is invalid for {num_variables} variables"
            ),
            Self::FoldedDomainSizeOverflow {
                num_variables,
                starting_log_inv_rate,
            } => write!(
                f,
                "domain log size overflows for {num_variables} variables and starting log inverse rate {starting_log_inv_rate}"
            ),
            Self::FirstFoldingFactorExceedsDomain {
                first_folding_factor,
                log_domain_size,
            } => write!(
                f,
                "first folding factor {first_folding_factor} exceeds domain log size {log_domain_size}"
            ),
            Self::FoldedDomainExceedsBaseTwoAdicity {
                log_folded_domain_size,
                base_two_adicity,
                min_first_folding_factor,
            } => write!(
                f,
                "folded domain log size {log_folded_domain_size} exceeds base two-adicity {base_two_adicity}; first folding factor must be at least {min_first_folding_factor}"
            ),
            Self::MissingDerivedProverData => write!(f, "derived prover data is missing"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpartanWhirError {
    Unimplemented(&'static str),
    InvalidR1csShape,
    InvalidWitnessLength,
    InvalidPublicInputLength,
    PaddingError,
    SecurityBelowMinimum,
    MerkleSecurityBelowMinimum,
    TranscriptMismatch,
    SumcheckFailed,
    PcsVerificationFailed,
    ProofDecodeFailed,
    ProofKindMismatch,
    UnsupportedMode,
    UnsupportedStatementType,
    InvalidConfig(InvalidConfigReason),
    WhirCommitFailed,
    WhirOpenFailed,
    WhirVerifyFailed,
    CommitmentMismatch,
    InvalidPolynomialLength,
    InvalidNumVariables,
    InvalidRoundCount,
    InvalidRoundPolynomial,
    NonInvertibleElement,
    ProofEncodeFailed,
    UnsupportedBlobVersion,
    InvalidBlobHeader,
    InvalidBlobLayout,
    InvalidBlobFlags,
    TrailingBytes,
    DigestBytesMismatch,
    NonCanonicalEncoding,
}

impl SpartanWhirError {
    pub const fn invalid_config() -> Self {
        Self::InvalidConfig(InvalidConfigReason::Generic)
    }

    pub const fn invalid_config_reason(reason: InvalidConfigReason) -> Self {
        Self::InvalidConfig(reason)
    }
}

impl core::fmt::Display for SpartanWhirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unimplemented(where_) => write!(f, "unimplemented: {where_}"),
            Self::InvalidR1csShape => write!(f, "invalid R1CS shape"),
            Self::InvalidWitnessLength => write!(f, "invalid witness length"),
            Self::InvalidPublicInputLength => write!(f, "invalid public input length"),
            Self::PaddingError => write!(f, "padding error"),
            Self::SecurityBelowMinimum => write!(f, "security level below minimum"),
            Self::MerkleSecurityBelowMinimum => write!(f, "merkle security below minimum"),
            Self::TranscriptMismatch => write!(f, "transcript mismatch"),
            Self::SumcheckFailed => write!(f, "sumcheck verification failed"),
            Self::PcsVerificationFailed => write!(f, "PCS verification failed"),
            Self::ProofDecodeFailed => write!(f, "proof decode failed"),
            Self::ProofKindMismatch => write!(f, "proof kind mismatch"),
            Self::UnsupportedMode => write!(f, "unsupported mode"),
            Self::UnsupportedStatementType => write!(f, "unsupported statement type"),
            Self::InvalidConfig(reason) => write!(f, "invalid configuration: {reason}"),
            Self::WhirCommitFailed => write!(f, "WHIR commitment failed"),
            Self::WhirOpenFailed => write!(f, "WHIR opening failed"),
            Self::WhirVerifyFailed => write!(f, "WHIR verification failed"),
            Self::CommitmentMismatch => write!(f, "commitment mismatch"),
            Self::InvalidPolynomialLength => write!(f, "invalid polynomial length"),
            Self::InvalidNumVariables => write!(f, "invalid number of variables"),
            Self::InvalidRoundCount => write!(f, "invalid sumcheck round count"),
            Self::InvalidRoundPolynomial => write!(f, "invalid sumcheck round polynomial"),
            Self::NonInvertibleElement => write!(f, "non-invertible field element"),
            Self::ProofEncodeFailed => write!(f, "proof encode failed"),
            Self::UnsupportedBlobVersion => write!(f, "unsupported blob version"),
            Self::InvalidBlobHeader => write!(f, "invalid blob header"),
            Self::InvalidBlobLayout => write!(f, "invalid blob layout"),
            Self::InvalidBlobFlags => write!(f, "invalid blob flags"),
            Self::TrailingBytes => write!(f, "trailing bytes"),
            Self::DigestBytesMismatch => write!(f, "digest bytes mismatch"),
            Self::NonCanonicalEncoding => write!(f, "non-canonical encoding"),
        }
    }
}
