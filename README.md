<div align="center">

<img src="assets/conduit-reth.png" alt="Conduit Reth" width="400"/>

</div>

# Conduit-OP-Reth

A customized high performance OP Stack execution client built with the Reth SDK.

Fully compatible with existing OP Stack networks, serving as a drop-in replacement for op-reth.

## Getting Started

### Prerequisites

- Rust 1.95+
- Git

### Production Build

```bash
git clone https://github.com/conduitxyz/conduit-op-reth.git
cd conduit-op-reth
cargo build --profile maxperf
```

### Local Dev Chain

Run a local OP Stack chain with 2-second block times:

```bash
make dev
```

This builds a debug binary, clears any previous state, and starts the node using the Saigon test genesis.

### Milliblocks

Use `--milliblocks-url <URL>` to receive streamed preconfirmations for pending-state
RPC requests. Add `--milliblock-consensus` when the stream should also advance the
chain through the Engine API. Both options configure the existing upstream client.

Only these Milliblocks CLI spellings are accepted. Update existing node launch
arguments before upgrading; legacy spellings are rejected.
Slipstream response keys remain unchanged for existing builders and clients.
Conduit-owned code and log messages use milliblocks; upstream dependency symbols,
metrics, and log messages retain their upstream names.

### Optional tracked nonce enforcement

`conduit-op-reth node --txpool.enforce-tracked-nonce` enables Reth's
`PoolConfig::enforce_tracked_nonce`. It is disabled by default. When enabled, pool
insertion uses the tracked sender nonce and balance if validation used a lower
nonce, and rejects a transaction below that tracked nonce. Transactions exempt
from nonce checks keep the validator's result.

**OP sequencers can reorg.** Reorg maintenance loads sender state from the new
chain, including accounts changed only on the discarded chain, and updates the
pool before reinserting discarded transactions. These updates can lower the
tracked nonce. However, maintenance is asynchronous, failed account loads are
retried, and validation results are not tied to the tracked state's block hash.
Until the lower nonce is applied, this option can reject transactions that are
valid on the new chain. Validation still in flight from the discarded chain can
also supply outdated state after a reorg. Rejected submissions need to be retried;
they are not kept for automatic admission later.

Keep the option off unless a controlled canary justifies the tradeoff. Test nonce
rollback and transaction resubmission during reorgs, and monitor nonce-too-low
errors, sender progress, and pool memory before enabling it more broadly. The
option retains tracked sender state after account updates remove a sender's last
transaction, which can increase memory use. It is not a guarantee against all
transaction-pool stalls.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
