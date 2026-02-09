use crate::e2e::{launch_test_node, parse_chain_spec};
use alloy_rpc_types_engine::PayloadStatusEnum;
use conduit_op_reth_node::node::ConduitOpNode;
use reth_node_api::PayloadTypes;
use reth_node_builder::NodeTypes;

/// Ensures the saigon genesis fixture (with lowercase `extradata`) is rejected by
/// `engine_newPayload`.
#[tokio::test]
async fn test_saigon_genesis_invalid_for_new_payload() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let genesis_json = super::BASE_GENESIS;
    let chain_spec = parse_chain_spec(genesis_json);

    // Build a payload on a producer so we get a fully-formed block for block 1.
    let (_tasks_producer, mut producer) = launch_test_node!(chain_spec.clone());
    let (_tasks_receiver, receiver) = launch_test_node!(chain_spec);
    let payload = producer.new_payload().await?;

    type Payload = <ConduitOpNode as NodeTypes>::Payload;
    let status = receiver
        .inner
        .add_ons_handle
        .beacon_engine_handle
        .new_payload(Payload::block_to_payload(payload.block().clone()))
        .await?;

    match status.status {
        PayloadStatusEnum::Invalid { validation_error } => {
            assert!(
                validation_error.contains("base fee missing"),
                "expected base fee missing, got: {validation_error}"
            );
        }
        other => {
            eyre::bail!("expected INVALID status, got {other:?}");
        }
    }

    Ok(())
}
