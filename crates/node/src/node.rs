use crate::{chainspec::ConduitOpChainSpec, evm::ConduitOpExecutorBuilder};
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_node_api::{FullNodeComponents, PayloadAttributesBuilder, PayloadTypes};
use reth_node_builder::{
    DebugNode, Node, NodeAdapter, NodeComponentsBuilder, NodeTypes,
    components::{BasicPayloadServiceBuilder, ComponentsBuilder},
    node::FullNodeTypes,
    rpc::BasicEngineValidatorBuilder,
};
use reth_optimism_node::{
    OpDAConfig, OpEngineApiBuilder, OpEngineTypes, OpStorage,
    args::RollupArgs,
    node::{
        OpAddOns, OpAddOnsBuilder, OpConsensusBuilder, OpEngineValidatorBuilder, OpFullNodeTypes,
        OpNetworkBuilder, OpNodeTypes, OpPayloadBuilder, OpPoolBuilder,
    },
};
use reth_optimism_payload_builder::config::OpGasLimitConfig;
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_rpc::eth::OpEthApiBuilder;
use std::sync::Arc;

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
}

impl ConduitOpNode {
    /// Creates a new instance of the ConduitOp node type.
    pub fn new(args: RollupArgs) -> Self {
        Self {
            args,
            da_config: OpDAConfig::default(),
            gas_limit_config: OpGasLimitConfig::default(),
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
            .pool(
                OpPoolBuilder::default()
                    .with_enable_tx_conditional(self.args.enable_tx_conditional)
                    .with_supervisor(
                        self.args.supervisor_http.clone(),
                        self.args.supervisor_safety_level,
                    ),
            )
            .executor(ConduitOpExecutorBuilder)
            .payload(BasicPayloadServiceBuilder::new(
                OpPayloadBuilder::new(compute_pending_block)
                    .with_da_config(self.da_config.clone())
                    .with_gas_limit_config(self.gas_limit_config.clone()),
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
        LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}
