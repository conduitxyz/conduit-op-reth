<div align="center">

<img src="assets/conduit-reth.png" alt="Conduit Reth" width="400"/>

</div>

# Conduit-OP-Reth

A customized high performance OP Stack execution client built with the Reth SDK.

Fully compatible with existing OP Stack networks, serving as a drop-in replacement for op-reth.

## Getting Started

### Prerequisites

- Rust 1.92+
- Git

### Production Build

```bash
git clone https://github.com/conduit-xyz/conduit-op-reth.git
cd conduit-op-reth
cargo build --profile maxperf
```

### Local Dev Chain

Run a local OP Stack chain with 2-second block times:

```bash
make dev
```

This builds a debug binary, clears any previous state, and starts the node using the Saigon test genesis.

### Historical RPC for migrated chains

Use the first locally served block as the exclusive historical RPC cutoff:

```bash
conduit-op-reth node --chain genesis.json \
  --rollup.historicalrpc https://historical.example.com \
  --rollup.historicalrpc.block 32956469
```

Supported requests for blocks below `32956469` are forwarded; the cutoff block and later blocks
are served locally. The override also works when Bedrock activated at block zero. It does not
change the genesis hash, hardfork activation, or peer fork ID.

Alternatively, set `"migrationBlock": 32956469` in the genesis `config.conduit` object
and supply only `--rollup.historicalrpc` on the CLI.
The cutoff precedence is CLI `--rollup.historicalrpc.block` → genesis `config.conduit.migrationBlock` →
upstream `bedrockBlock`. `migrationBlock` accepts an unsigned 64-bit JSON integer; omitted or
`null` means unset, while zero is an explicit cutoff. A CLI cutoff of zero also overrides genesis.

With neither cutoff configured, upstream behavior is preserved, including disabled forwarding
when Bedrock has no positive block activation. The CLI cutoff requires `--rollup.historicalrpc`;
genesis `migrationBlock` alone does not require an endpoint or enable forwarding.

All cutoffs use upstream op-reth historical RPC middleware unchanged, including its limitations:
forwarding can occur before enabled-method checks, forwarded responses/batches can bypass normal
RPC response-size limits, and no additional historical request timeout or concurrency cap is added.
Use a trusted historical endpoint and enforce method access and resource limits at ingress.

Unknown block/transaction hashes are forwarded optimistically, even with an explicit zero cutoff.
Backend failures fall back to local handling. Upstream's legacy l2geth receipt fallback is retained;
one `eth_getBlockReceipts` request can issue additional per-transaction historical requests.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
