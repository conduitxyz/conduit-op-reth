//! Shared Conduit EVM logic for custom fork transitions.
//!
//! This crate contains data types and state transition logic for Conduit-specific
//! hardforks on OP Stack chains. It is designed to be consumed by both
//! `conduit-op-reth` (validator) and `conduit-op-rbuilder` (block builder) to
//! ensure identical consensus behavior.
//!
//! **No reth dependencies** — only alloy/revm primitives, so it works across
//! different reth version pins.

pub mod state_override;
