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
use reth_optimism_payload_builder::{
    OpPayloadAttrs,
    config::{OpBuilderConfig, OpGasLimitConfig, OperatorSdmOptIn},
};
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_rpc::eth::OpEthApiBuilder;
use reth_optimism_txpool::interop::InteropFailsafe;
use reth_primitives_traits::SealedHeader;
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
    /// Local operator opt-in for SDM `PostExec` production. Shared (via Arc clones) between the
    /// payload builder and the `admin_setOperatorSdmOptIn` RPC handler.
    pub operator_sdm_opt_in: OperatorSdmOptIn,
    /// Interop failsafe gate shared between the txpool's interop filter client and payload
    /// builder.
    pub interop_failsafe: InteropFailsafe,
}

impl ConduitOpNode {
    /// Creates a new instance of the ConduitOp node type.
    pub fn new(args: RollupArgs) -> Self {
        let operator_sdm_opt_in = OperatorSdmOptIn::default();
        operator_sdm_opt_in.set(args.operator_sdm_opt_in);
        Self {
            args,
            da_config: OpDAConfig::default(),
            gas_limit_config: OpGasLimitConfig::default(),
            operator_sdm_opt_in,
            interop_failsafe: InteropFailsafe::default(),
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

    /// The [`OpBuilderConfig`] this node's payload builder is configured with.
    ///
    /// Assembled as a struct literal rather than through the individual `with_*` setters: because
    /// [`OpBuilderConfig`] is not `#[non_exhaustive]`, an upstream field addition breaks the build
    /// here instead of silently defaulting on our node.
    fn builder_config(&self) -> OpBuilderConfig {
        OpBuilderConfig {
            da_config: self.da_config.clone(),
            gas_limit_config: self.gas_limit_config.clone(),
            operator_sdm_opt_in: self.operator_sdm_opt_in.clone(),
            interop_failsafe: self.interop_failsafe.clone(),
            max_uncompressed_block_size: self.args.max_uncompressed_block_size,
        }
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
            .executor(ConduitOpExecutorBuilder)
            .pool(
                OpPoolBuilder::default()
                    .with_enable_tx_conditional(self.args.enable_tx_conditional)
                    .with_interop(
                        self.args.interop_http.clone(),
                        self.args.interop_min_responses,
                        self.args.interop_safety_level,
                    )
                    .with_interop_failsafe(self.interop_failsafe.clone()),
            )
            .payload(BasicPayloadServiceBuilder::new(
                OpPayloadBuilder::new(compute_pending_block)
                    .with_builder_config(self.builder_config()),
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
            .with_operator_sdm_opt_in(self.operator_sdm_opt_in.clone())
            .with_enable_tx_conditional(self.args.enable_tx_conditional)
            .with_min_suggested_priority_fee(self.args.min_suggested_priority_fee)
            .with_historical_rpc(self.args.historical_rpc.clone())
            .with_flashblocks(self.args.flashblocks_url.clone())
            .with_flashblock_consensus(self.args.flashblock_consensus)
            .with_retain_forwarded_txs(self.args.retain_forwarded_txs)
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
        let inner = LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()));
        // This allows us to run --dev mode. Fixed in upstream https://github.com/paradigmxyz/reth/pull/21855/changes
        move |parent: SealedHeader| {
            // L1-info deposit system transaction, injected as tx[0] of every dev block.
            // Without it op-reth's `extract_l1_info` has no L1 block info to parse, so
            // `eth_getTransactionReceipt` fails with "invalid l1 block info transaction
            // calldata in the L2 block". OP Mainnet transaction at index 0 in block
            // 124665056; matches upstream `OpLocalPayloadAttributesBuilder`.
            const TX_SET_L1_BLOCK: [u8; 251] = alloy_primitives::hex!(
                "7ef8f8a0683079df94aa5b9cf86687d739a60a9b4f0835e520ec4d664e2e415dca17a6df94deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b8a4440a5e200000146b000f79c500000000000000040000000066d052e700000000013ad8a3000000000000000000000000000000000000000000000000000000003ef1278700000000000000000000000000000000000000000000000000000000000000012fdf87b89884a61e74b322bbcf60386f543bfae7827725efaaf0ab1de2294a590000000000000000000000006887246668a3b87f54deb3b94ba47a6f63f32985"
            );

            let mut attrs = op_alloy_rpc_types_engine::OpPayloadAttributes {
                payload_attributes: inner.build(&parent),
                transactions: Some(vec![TX_SET_L1_BLOCK.into()]),
                no_tx_pool: None,
                gas_limit: None,
                eip_1559_params: None,
                min_base_fee: None,
            };

            // Encode default OP EIP-1559 params: denominator=50, elasticity=6
            attrs.eip_1559_params = Some(alloy_primitives::B64::from_slice(&[
                0, 0, 0, 50, // denominator
                0, 0, 0, 6, // elasticity
            ]));
            attrs.min_base_fee = Some(0);
            OpPayloadAttrs(attrs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
    use alloy_eips::{Decodable2718, Encodable2718};
    use alloy_primitives::{B256, Bytes, Signature};
    use op_alloy_consensus::{OpTxEnvelope, TxDeposit, build_post_exec_tx};
    use op_alloy_rpc_types_engine::{OpPayloadAttributes, flashblock::OpFlashblockPayload};
    use reth_optimism_payload_builder::OpPayloadBuilderAttributes;
    use reth_primitives_traits::NodePrimitives;

    /// Exercise the payload/flashblock boundaries with the exact transaction type our node
    /// uses, rather than only testing the upstream canonical-decoding helper in isolation.
    #[test]
    fn payloads_and_flashblocks_require_canonical_transactions() {
        type Tx = <OpPrimitives as NodePrimitives>::SignedTx;
        let typed = TxEip1559 {
            chain_id: 10,
            nonce: 1,
            gas_limit: 21_000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            ..Default::default()
        }
        .into_signed(Signature::test_signature())
        .encoded_2718();
        let legacy = TxLegacy::default().into_signed(Signature::test_signature()).encoded_2718();
        let deposit = TxDeposit::default().encoded_2718();
        let post_exec = build_post_exec_tx(7, vec![]).encoded_2718();

        // Generic typed decoders previously accepted some missing-type-byte encodings;
        // merely checking successful RLP decoding is not a canonicality check.
        for canonical in [typed, deposit, post_exec, legacy] {
            let mut trailing = canonical.clone();
            trailing.push(0);
            let malformed = if canonical[0] < 0x80 {
                canonical[1..].to_vec()
            } else {
                [vec![0], canonical.clone()].concat()
            };
            for (encoded, valid) in [(canonical, true), (malformed, false), (trailing, false)] {
                let bytes = Bytes::from(encoded);
                let attrs = OpPayloadAttributes {
                    transactions: Some(vec![bytes.clone()]),
                    ..Default::default()
                };
                let decoded = attrs.decoded_transactions().next().unwrap();
                assert_eq!(decoded.is_ok(), valid, "attributes: {bytes}");
                let built = OpPayloadBuilderAttributes::<Tx>::try_new(B256::ZERO, attrs, 3);
                assert_eq!(built.is_ok(), valid, "builder: {bytes}");

                let mut flashblock = OpFlashblockPayload::default();
                flashblock.diff.transactions = vec![bytes.clone()];
                let streamed = flashblock.decoded_transaction::<Tx>().next().unwrap();
                assert_eq!(streamed.is_ok(), valid, "flashblock: {bytes}");
                if valid {
                    assert_eq!(decoded.unwrap().encoded_2718().as_slice(), bytes.as_ref());
                    assert_eq!(streamed.unwrap().encoded_2718().as_slice(), bytes.as_ref());
                    assert_eq!(built.unwrap().transactions.len(), 1);
                }
            }
        }

        // The concrete deposit decoder must not accept a bare body either.
        let deposit = TxDeposit::default().encoded_2718();
        assert!(TxDeposit::decode_2718_exact(&deposit).is_ok());
        assert!(TxDeposit::decode_2718_exact(&deposit[1..]).is_err());
        assert!(OpTxEnvelope::decode_2718_exact(&deposit).is_ok());
    }
}
