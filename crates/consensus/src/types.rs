use std::cmp::Ordering;
use std::fmt::{Debug, Display};

use cipherbft_data_chain::Cut;
use cipherbft_types::Hash;

/// Consensus height wrapper to keep Malachite types explicit.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ConsensusHeight(pub u64);

impl ConsensusHeight {
    /// Advance to the next height.
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<u64> for ConsensusHeight {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ConsensusHeight> for u64 {
    fn from(value: ConsensusHeight) -> Self {
        value.0
    }
}

impl Display for ConsensusHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Consensus value ID (hash of a `Cut`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ConsensusValueId(pub Hash);

impl Display for ConsensusValueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Consensus value wrapper (DCL `Cut`).
#[derive(Clone, Debug)]
pub struct ConsensusValue(pub Cut);

impl ConsensusValue {
    /// Access the inner cut.
    pub fn cut(&self) -> &Cut {
        &self.0
    }

    /// Consume into the inner cut.
    pub fn into_cut(self) -> Cut {
        self.0
    }
}

impl PartialEq for ConsensusValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash() == other.0.hash()
    }
}

impl Eq for ConsensusValue {}

impl PartialOrd for ConsensusValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConsensusValue {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.hash().cmp(&other.0.hash())
    }
}

#[cfg(feature = "malachite")]
mod malachite_impls {
    use super::{ConsensusHeight, ConsensusValue, ConsensusValueId};
    use cipherbft_data_chain::Cut;
    use cipherbft_types::Hash;
    use informalsystems_malachitebft_core_types::{Height as MalachiteHeight, Round, Value};

    /// Use Malachite's `Round` type directly for consensus.
    pub type ConsensusRound = Round;

    impl MalachiteHeight for ConsensusHeight {
        const ZERO: Self = Self(0);
        const INITIAL: Self = Self(1);

        fn increment_by(&self, n: u64) -> Self {
            Self(self.0.saturating_add(n))
        }

        fn decrement_by(&self, n: u64) -> Option<Self> {
            self.0.checked_sub(n).map(Self)
        }

        fn as_u64(&self) -> u64 {
            self.0
        }
    }

    impl Value for ConsensusValue {
        type Id = ConsensusValueId;

        fn id(&self) -> Self::Id {
            ConsensusValueId(self.0.hash())
        }
    }

    impl From<Cut> for ConsensusValue {
        fn from(cut: Cut) -> Self {
            Self(cut)
        }
    }

    impl From<ConsensusValueId> for Hash {
        fn from(value: ConsensusValueId) -> Self {
            value.0
        }
    }
}

#[cfg(feature = "malachite")]
pub use malachite_impls::ConsensusRound;

#[cfg(not(feature = "malachite"))]
/// Placeholder round type when Malachite is disabled.
pub type ConsensusRound = i64;
