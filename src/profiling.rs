#[cfg(feature = "whir-p3-backend")]
use crate::engine::{ExtField, F};
use serde::{Deserialize, Serialize};
use tracing::info_span;

#[cfg(feature = "circom")]
use alloc::string::{String, ToString};
#[cfg(feature = "circom")]
use core::cell::RefCell;
#[cfg(feature = "circom")]
use std::{env, thread_local, time::Instant};
#[cfg(feature = "circom")]
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolStage {
    SetupStart,
    SetupEnd,
    ProveStart,
    ProveEnd,
    VerifyStart,
    VerifyEnd,
    PcsCommit,
    PcsOpen,
    PcsVerify,
}

pub trait ProtocolObserver {
    fn on_stage(&mut self, _stage: ProtocolStage) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NoopObserver;

impl ProtocolObserver for NoopObserver {}

#[cfg(feature = "circom")]
#[derive(Debug, Clone)]
struct ProfileContext {
    engine: String,
    mode: String,
}

#[cfg(feature = "circom")]
thread_local! {
    static PROFILE_CONTEXT: RefCell<Option<ProfileContext>> = const { RefCell::new(None) };
}

#[cfg(feature = "circom")]
pub struct ProfileContextGuard {
    previous: Option<ProfileContext>,
}

#[cfg(feature = "circom")]
impl Drop for ProfileContextGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        PROFILE_CONTEXT.with(|context| {
            *context.borrow_mut() = previous;
        });
    }
}

#[cfg(feature = "circom")]
pub struct ProfileScope {
    phase: &'static str,
    start: Instant,
    enabled: bool,
}

#[cfg(feature = "circom")]
impl Drop for ProfileScope {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        record_profile_phase(self.phase, self.start.elapsed());
    }
}

#[cfg(feature = "circom")]
pub fn profile_enabled() -> bool {
    env::var_os("SHA256_BENCH_PROFILE")
        .and_then(|value| value.into_string().ok())
        .is_some_and(|value| {
            let value = value.trim();
            !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
        })
}

#[cfg(not(feature = "circom"))]
pub const fn profile_enabled() -> bool {
    false
}

#[cfg(feature = "circom")]
pub fn set_profile_context(engine: &str, mode: &str) -> ProfileContextGuard {
    let next = profile_enabled().then(|| ProfileContext {
        engine: engine.to_string(),
        mode: mode.to_string(),
    });
    let previous = PROFILE_CONTEXT.with(|context| context.replace(next));
    ProfileContextGuard { previous }
}

#[cfg(not(feature = "circom"))]
pub struct ProfileContextGuard;

#[cfg(not(feature = "circom"))]
pub const fn set_profile_context(_engine: &str, _mode: &str) -> ProfileContextGuard {
    ProfileContextGuard
}

#[cfg(feature = "circom")]
pub fn profile_scope(phase: &'static str) -> ProfileScope {
    ProfileScope {
        phase,
        start: Instant::now(),
        enabled: profile_enabled(),
    }
}

#[cfg(not(feature = "circom"))]
pub struct ProfileScope;

#[cfg(not(feature = "circom"))]
pub const fn profile_scope(_phase: &'static str) -> ProfileScope {
    ProfileScope
}

#[cfg(feature = "circom")]
pub fn record_profile_phase(phase: &'static str, elapsed: std::time::Duration) {
    if !profile_enabled() {
        return;
    }
    let (engine, mode) = PROFILE_CONTEXT.with(|context| {
        context
            .borrow()
            .as_ref()
            .map(|context| (context.engine.clone(), context.mode.clone()))
            .unwrap_or_else(|| ("bench".to_string(), "global".to_string()))
    });
    info!(
        target: "spartan_whir::profile",
        "profile engine={engine} mode={mode} phase={phase} ms={} us={}",
        elapsed.as_millis(),
        elapsed.as_micros()
    );
}

#[cfg(not(feature = "circom"))]
pub fn record_profile_phase(_phase: &'static str, _elapsed: core::time::Duration) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSizeSection {
    Header,
    Instance,
    OuterSumcheck,
    OuterClaims,
    InnerSumcheck,
    WitnessEval,
    WhirInitial,
    WhirRounds,
    WhirFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionSize {
    pub section: ProofSizeSection,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProofSizeCounters {
    pub num_outer_rounds: usize,
    pub num_inner_rounds: usize,
    pub num_whir_rounds: usize,
    pub num_query_batches: usize,
    pub num_base_query_values: usize,
    pub num_extension_query_values: usize,
    pub num_decommitments: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProofSizeReport {
    pub total_bytes: usize,
    pub effective_digest_byte_width: usize,
    pub total_digest_data_bytes: usize,
    pub sections: alloc::vec::Vec<SectionSize>,
    pub counters: ProofSizeCounters,
}

impl ProofSizeSection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Instance => "instance",
            Self::OuterSumcheck => "outer_sumcheck",
            Self::OuterClaims => "outer_claims",
            Self::InnerSumcheck => "inner_sumcheck",
            Self::WitnessEval => "witness_eval",
            Self::WhirInitial => "whir_initial",
            Self::WhirRounds => "whir_rounds",
            Self::WhirFinal => "whir_final",
        }
    }

    fn is_whir(self) -> bool {
        matches!(self, Self::WhirInitial | Self::WhirRounds | Self::WhirFinal)
    }
}

pub fn trace_proof_size_report(report: &ProofSizeReport) {
    let root = info_span!(
        "proof_size_breakdown",
        total_bytes = report.total_bytes as u64,
        total_decimal_kb_x1000 = decimal_kb_x1000(report.total_bytes),
        total_binary_kib_x1000 = binary_kib_x1000(report.total_bytes),
        effective_digest_bytes = report.effective_digest_byte_width as u64,
        total_digest_data_bytes = report.total_digest_data_bytes as u64,
        num_outer_rounds = report.counters.num_outer_rounds as u64,
        num_inner_rounds = report.counters.num_inner_rounds as u64,
        num_whir_rounds = report.counters.num_whir_rounds as u64,
        num_query_batches = report.counters.num_query_batches as u64,
        num_base_query_values = report.counters.num_base_query_values as u64,
        num_extension_query_values = report.counters.num_extension_query_values as u64,
        num_decommitments = report.counters.num_decommitments as u64,
    );
    let _root = root.enter();

    let whir_bytes = report
        .sections
        .iter()
        .filter(|section| section.section.is_whir())
        .map(|section| section.bytes)
        .sum::<usize>();

    for section in &report.sections {
        if !section.section.is_whir() {
            trace_section(section.section, section.bytes, report.total_bytes);
        }
    }

    let whir_group = info_span!(
        "proof_component_group",
        component = "whir",
        bytes = whir_bytes as u64,
        decimal_kb_x1000 = decimal_kb_x1000(whir_bytes),
        binary_kib_x1000 = binary_kib_x1000(whir_bytes),
        pct_basis_points = pct_basis_points(whir_bytes, report.total_bytes),
    );
    let _whir_group = whir_group.enter();

    for section in &report.sections {
        if section.section.is_whir() {
            trace_section(section.section, section.bytes, report.total_bytes);
        }
    }
}

fn trace_section(section: ProofSizeSection, bytes: usize, total_bytes: usize) {
    match section {
        ProofSizeSection::WhirInitial => {
            let span = info_span!(
                "whir_initial",
                component = section.as_str(),
                bytes = bytes as u64,
                decimal_kb_x1000 = decimal_kb_x1000(bytes),
                binary_kib_x1000 = binary_kib_x1000(bytes),
                pct_basis_points = pct_basis_points(bytes, total_bytes),
            );
            let _span = span.enter();
        }
        ProofSizeSection::WhirRounds => {
            let span = info_span!(
                "whir_rounds",
                component = section.as_str(),
                bytes = bytes as u64,
                decimal_kb_x1000 = decimal_kb_x1000(bytes),
                binary_kib_x1000 = binary_kib_x1000(bytes),
                pct_basis_points = pct_basis_points(bytes, total_bytes),
            );
            let _span = span.enter();
        }
        ProofSizeSection::WhirFinal => {
            let span = info_span!(
                "whir_final",
                component = section.as_str(),
                bytes = bytes as u64,
                decimal_kb_x1000 = decimal_kb_x1000(bytes),
                binary_kib_x1000 = binary_kib_x1000(bytes),
                pct_basis_points = pct_basis_points(bytes, total_bytes),
            );
            let _span = span.enter();
        }
        _ => {
            let span = info_span!(
                "proof_component",
                component = section.as_str(),
                bytes = bytes as u64,
                decimal_kb_x1000 = decimal_kb_x1000(bytes),
                binary_kib_x1000 = binary_kib_x1000(bytes),
                pct_basis_points = pct_basis_points(bytes, total_bytes),
            );
            let _span = span.enter();
        }
    }
}

fn decimal_kb_x1000(bytes: usize) -> u64 {
    bytes as u64
}

fn binary_kib_x1000(bytes: usize) -> u64 {
    ((bytes as u128) * 1000 / 1024) as u64
}

fn pct_basis_points(bytes: usize, total_bytes: usize) -> u64 {
    if total_bytes == 0 {
        0
    } else {
        ((bytes as u128) * 10_000 / (total_bytes as u128)) as u64
    }
}

#[cfg(feature = "whir-p3-backend")]
pub fn profile_spartan_blob_v1<EF>(
    codec: &crate::ProofCodecConfig,
    pcs_config: &crate::WhirPcsConfig,
    instance: &crate::R1csInstance<F, [u64; 4]>,
    proof: &crate::SpartanProof<crate::KeccakEngine<EF>, crate::WhirPcs>,
) -> Result<ProofSizeReport, crate::SpartanWhirError>
where
    EF: ExtField,
{
    let (_, report) =
        crate::codec::encode_spartan_blob_v1_with_report::<EF>(codec, pcs_config, instance, proof)?;
    Ok(report)
}
