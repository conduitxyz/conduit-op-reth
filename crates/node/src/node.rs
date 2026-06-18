use crate::{
    chainspec::ConduitOpChainSpec,
    evm::{ConduitOpExecutorBuilder, conduit_evm_limits},
};
use reth_db::DatabaseEnv;
use reth_evm::EvmLimitParams;
use reth_node_api::{FullNodeComponents, PayloadAttributesBuilder, PayloadTypes};
use reth_node_builder::{
    DebugNode, Node, NodeAdapter, NodeComponentsBuilder, NodeTypes, RethFullAdapter,
    components::{BasicPayloadServiceBuilder, ComponentsBuilder},
    node::FullNodeTypes,
    rpc::BasicEngineValidatorBuilder,
};
use reth_optimism_node::{
    OpDAConfig, OpEngineApiBuilder, OpEngineTypes, OpStorage,
    args::RollupArgs,
    node::{
        OpAddOns, OpAddOnsBuilder, OpConsensusBuilder, OpEngineValidatorBuilder, OpFullNodeTypes,
        OpNetworkBuilder, OpNode, OpNodeTypes, OpPayloadBuilder, OpPoolBuilder,
    },
};
use reth_optimism_payload_builder::{
    OpPayloadAttrs,
    config::{OpGasLimitConfig, SdmPostExecOptIn},
};
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_rpc::eth::OpEthApiBuilder;
use reth_primitives_traits::SealedHeader;

type OpLocalNodeAdapter = NodeAdapter<RethFullAdapter<DatabaseEnv, OpNode>>;

/// Type configuration for the ConduitOp OP Stack node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ConduitOpNode {
    /// Optimism rollup arguments.
    pub args: RollupArgs,
    /// Data availability configuration for the OP builder.
    ///
    /// Used to throttle the size of the data availability payloads (configured by the batcher via
    /// the `miner_` api).
    ///
    /// By default no throttling is applied.
    pub da_config: OpDAConfig,
    /// Gas limit configuration for the OP builder.
    /// Used to control the gas limit of the blocks produced by the OP builder (configured by the
    /// batcher via the `miner_` api).
    pub gas_limit_config: OpGasLimitConfig,
    /// Local operator opt-in for SDM `PostExec` production.
    pub sdm_post_exec_opt_in: SdmPostExecOptIn,
    /// Optional EVM limit overrides (e.g. Conduit's higher code/initcode sizes).
    ///
    /// When `Some`, the executor in the node pipeline applies these limits to every EVM
    /// environment. When `None`, standard OP Stack defaults apply.
    pub evm_limits: Option<EvmLimitParams>,
}

impl ConduitOpNode {
    /// Creates a new instance of the ConduitOp node type.
    pub fn new(args: RollupArgs) -> Self {
        Self {
            args,
            da_config: OpDAConfig::default(),
            gas_limit_config: OpGasLimitConfig::default(),
            sdm_post_exec_opt_in: SdmPostExecOptIn::default(),
            evm_limits: None,
        }
    }

    /// Configure the data availability configuration for the OP builder.
    pub fn with_da_config(mut self, da_config: OpDAConfig) -> Self {
        self.da_config = da_config;
        self
    }

    /// Configure the gas limit configuration for the OP builder.
    pub fn with_gas_limit_config(mut self, gas_limit_config: OpGasLimitConfig) -> Self {
        self.gas_limit_config = gas_limit_config;
        self
    }

    /// Enable Conduit's higher EVM limits (614KB max code size, 1.2MB max initcode size).
    pub fn with_evm_limits(mut self, enabled: bool) -> Self {
        self.evm_limits = enabled.then(conduit_evm_limits);
        self
    }
}

impl NodeTypes for ConduitOpNode {
    type Primitives = OpPrimitives;
    type ChainSpec = ConduitOpChainSpec;
    type Storage = OpStorage;
    type Payload = OpEngineTypes;
}

impl<N> Node<N> for ConduitOpNode
where
    N: FullNodeTypes<
        Types: OpFullNodeTypes + OpNodeTypes + NodeTypes<ChainSpec = ConduitOpChainSpec>,
    >,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        OpPoolBuilder,
        BasicPayloadServiceBuilder<OpPayloadBuilder>,
        OpNetworkBuilder,
        ConduitOpExecutorBuilder,
        OpConsensusBuilder,
    >;

    type AddOns = OpAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
        OpEthApiBuilder,
        OpEngineValidatorBuilder,
        OpEngineApiBuilder<OpEngineValidatorBuilder>,
        BasicEngineValidatorBuilder<OpEngineValidatorBuilder>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        let RollupArgs { disable_txpool_gossip, compute_pending_block, discovery_v4, .. } =
            self.args;
        ComponentsBuilder::default()
            .node_types::<N>()
            .executor(ConduitOpExecutorBuilder { limits: self.evm_limits })
            .pool(
                OpPoolBuilder::default()
                    .with_enable_tx_conditional(self.args.enable_tx_conditional)
                    .with_interop(self.args.interop_http.clone(), self.args.interop_safety_level),
            )
            .payload(BasicPayloadServiceBuilder::new(
                OpPayloadBuilder::new(compute_pending_block)
                    .with_da_config(self.da_config.clone())
                    .with_gas_limit_config(self.gas_limit_config.clone())
                    .with_sdm_post_exec_opt_in(self.sdm_post_exec_opt_in.clone()),
            ))
            .network(OpNetworkBuilder::new(disable_txpool_gossip, !discovery_v4))
            .consensus(OpConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        OpAddOnsBuilder::default()
            .with_sequencer(self.args.sequencer.clone())
            .with_sequencer_headers(self.args.sequencer_headers.clone())
            .with_da_config(self.da_config.clone())
            .with_gas_limit_config(self.gas_limit_config.clone())
            .with_sdm_post_exec_opt_in(self.sdm_post_exec_opt_in.clone())
            .with_enable_tx_conditional(self.args.enable_tx_conditional)
            .with_min_suggested_priority_fee(self.args.min_suggested_priority_fee)
            .with_historical_rpc(self.args.historical_rpc.clone())
            .with_flashblocks(self.args.flashblocks_url.clone())
            .with_flashblock_consensus(self.args.flashblock_consensus)
            .build()
    }
}

impl<N> DebugNode<N> for ConduitOpNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types_eth::Block<op_alloy_consensus::OpTxEnvelope>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_node_api::BlockTy<Self> {
        rpc_block.into_consensus()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes> {
        // Reuse upstream OP's dev-mode payload attrs builder, adapting from Conduit's wrapper
        // chain spec to the inner OP chain spec so L1-info tx and OP_DEV_* handling stay aligned.
        let inner = <OpNode as DebugNode<OpLocalNodeAdapter>>::local_payload_attributes_builder(
            &chain_spec.inner,
        );

        move |parent: SealedHeader| inner.build(&parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::EthChainSpec;
    use reth_cli::chainspec::ChainSpecParser;
    use reth_db::DatabaseEnv;
    use reth_node_builder::{DebugNode, NodeAdapter, RethFullAdapter};

    type TestNode = NodeAdapter<RethFullAdapter<DatabaseEnv, ConduitOpNode>>;

    fn build_local_payload_attrs() -> OpPayloadAttrs {
        let chain_spec = crate::chainspec::ConduitOpChainSpecParser::parse("dev").unwrap();
        let builder =
            <ConduitOpNode as DebugNode<TestNode>>::local_payload_attributes_builder(&chain_spec);
        let parent = SealedHeader::seal_slow(chain_spec.genesis_header().clone());

        builder.build(&parent)
    }

    #[test]
    fn local_payload_attrs_include_op_system_tx() {
        let attrs = build_local_payload_attrs().0;
        let txs = attrs.transactions.expect("dev attrs must include L1-info system tx");

        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].len(), 251);
        assert_eq!(txs[0][0], 0x7e);
        assert_eq!(attrs.payload_attributes.slot_number, None);
    }
}
