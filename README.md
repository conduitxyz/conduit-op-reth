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

## License

TBD
