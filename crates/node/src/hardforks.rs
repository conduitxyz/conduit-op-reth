use reth_chainspec::{ForkCondition, hardfork};
use reth_optimism_forks::OpHardforks;

hardfork!(
    /// ConduitOp hardforks for custom state transitions on OP Stack chains.
    ConduitOpHardfork {
        /// Applies account state overrides (bytecode, storage) upon activation.
        StateOverrideFork0,
        /// Applies the second round of account state overrides upon activation.
        StateOverrideFork1,
        /// Applies the third round of account state overrides upon activation.
        StateOverrideFork2,
        /// Applies the fourth round of account state overrides upon activation.
        StateOverrideFork3,
        /// Applies the fifth round of account state overrides upon activation.
        StateOverrideFork4,
        /// Applies the sixth round of account state overrides upon activation.
        StateOverrideFork5,
        /// Applies the seventh round of account state overrides upon activation.
        StateOverrideFork6,
        /// Applies the eighth round of account state overrides upon activation.
        StateOverrideFork7,
        /// Applies the ninth round of account state overrides upon activation.
        StateOverrideFork8,
        /// Applies the tenth round of account state overrides upon activation.
        StateOverrideFork9,
        /// Applies configured EVM limits while preserving the active OP hardfork semantics.
        EvmLimitsFork0,
    }
);

/// The state override hardforks, in activation order.
///
/// A network schedules one entry per round of overrides; each carries its own genesis
/// configuration and activation timestamp, and all of them share the same transition logic in
/// [`state_override`](crate::state_override). Adding a further round means adding a variant to
/// [`ConduitOpHardfork`], appending it here, extending
/// [`ConduitOpHardfork::state_override_index`], and adding the matching genesis key.
pub const STATE_OVERRIDE_FORKS: [ConduitOpHardfork; 10] = [
    ConduitOpHardfork::StateOverrideFork0,
    ConduitOpHardfork::StateOverrideFork1,
    ConduitOpHardfork::StateOverrideFork2,
    ConduitOpHardfork::StateOverrideFork3,
    ConduitOpHardfork::StateOverrideFork4,
    ConduitOpHardfork::StateOverrideFork5,
    ConduitOpHardfork::StateOverrideFork6,
    ConduitOpHardfork::StateOverrideFork7,
    ConduitOpHardfork::StateOverrideFork8,
    ConduitOpHardfork::StateOverrideFork9,
];

impl ConduitOpHardfork {
    /// Index of this fork within [`STATE_OVERRIDE_FORKS`], or `None` for forks that do not apply
    /// state overrides.
    pub const fn state_override_index(&self) -> Option<usize> {
        match self {
            Self::StateOverrideFork0 => Some(0),
            Self::StateOverrideFork1 => Some(1),
            Self::StateOverrideFork2 => Some(2),
            Self::StateOverrideFork3 => Some(3),
            Self::StateOverrideFork4 => Some(4),
            Self::StateOverrideFork5 => Some(5),
            Self::StateOverrideFork6 => Some(6),
            Self::StateOverrideFork7 => Some(7),
            Self::StateOverrideFork8 => Some(8),
            Self::StateOverrideFork9 => Some(9),
            Self::EvmLimitsFork0 => None,
        }
    }
}

/// Trait for querying ConduitOp hardfork activation status.
///
/// Extends [`OpHardforks`] (which extends [`EthereumHardforks`](reth_chainspec::EthereumHardforks))
/// to form the full hardfork trait chain.
pub trait ConduitOpHardforks: OpHardforks {
    /// Returns activation condition for a ConduitOp hardfork.
    fn conduit_op_fork_activation(&self, fork: ConduitOpHardfork) -> ForkCondition;

    /// Checks if a ConduitOp hardfork is active at the given timestamp.
    fn is_conduit_op_fork_active_at_timestamp(
        &self,
        fork: ConduitOpHardfork,
        timestamp: u64,
    ) -> bool {
        self.conduit_op_fork_activation(fork).active_at_timestamp(timestamp)
    }

    /// Checks if EvmLimitsFork0 is active at the given timestamp.
    fn is_evm_limits_fork0_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.is_conduit_op_fork_active_at_timestamp(ConduitOpHardfork::EvmLimitsFork0, timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state override fork must report the index it occupies in [`STATE_OVERRIDE_FORKS`],
    /// and no other fork may claim one — the chain spec indexes its per-round arrays by it.
    #[test]
    fn state_override_indices_match_fork_order() {
        for (idx, fork) in STATE_OVERRIDE_FORKS.into_iter().enumerate() {
            assert_eq!(fork.state_override_index(), Some(idx), "{fork} index mismatch");
        }
        assert_eq!(ConduitOpHardfork::EvmLimitsFork0.state_override_index(), None);
    }

    /// Guards against a variant being added to the enum but left out of `STATE_OVERRIDE_FORKS`.
    #[test]
    fn every_state_override_variant_is_listed() {
        let listed = ConduitOpHardfork::VARIANTS
            .iter()
            .filter(|fork| fork.state_override_index().is_some())
            .count();
        assert_eq!(listed, STATE_OVERRIDE_FORKS.len());
    }
}
