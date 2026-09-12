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

The existing upstream historical RPC middleware forwards supported requests for blocks below
`32956469`; the cutoff block and later blocks are served locally. The override also works when
Bedrock activated at block zero. It does not change the genesis, hardfork activation, or peer fork ID.

Omit `--rollup.historicalrpc.block` to preserve upstream behavior: use `bedrockBlock` as the cutoff,
with forwarding disabled when Bedrock has no positive block activation. The override requires
`--rollup.historicalrpc`. Upstream method coverage, unknown-hash forwarding, and fallback behavior
are unchanged; an explicit cutoff of zero does not disable unknown-hash forwarding.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
