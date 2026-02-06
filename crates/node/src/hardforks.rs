use reth_chainspec::{ForkCondition, hardfork};
use reth_optimism_forks::OpHardforks;

hardfork!(
    /// ConduitOp hardforks for custom state transitions on OP Stack chains.
    ConduitOpHardfork {
        /// Applies account state overrides (bytecode, storage) upon activation.
        StateOverrideFork0,
    }
);

/// Trait for querying ConduitOp hardfork activation status.
///
/// Extends [`OpHardforks`] (which extends [`EthereumHardforks`](reth_chainspec::EthereumHardforks))
/// to form the full hardfork trait chain.
pub trait ConduitOpHardforks: OpHardforks {
    /// Returns activation condition for a ConduitOp hardfork.
    fn conduit_op_fork_activation(&self, fork: ConduitOpHardfork) -> ForkCondition;

    /// Checks if StateOverrideFork0 is active at the given timestamp.
    fn is_state_override_fork0_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0)
            .active_at_timestamp(timestamp)
    }
}
