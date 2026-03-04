#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoopObserver;

impl ProtocolObserver for NoopObserver {}
