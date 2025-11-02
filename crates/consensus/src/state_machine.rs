//! Consensus state machine.

/// Consensus step enum.
pub enum ConsensusStep {
    /// New height phase.
    NewHeight,
    /// Propose phase.
    Propose,
    /// Prepare phase.
    Prepare,
    /// Commit phase.
    Commit,
    /// Finalized phase.
    Finalized,
}

/// Consensus state structure.
pub struct ConsensusState {
    // TODO: Add fields
}
