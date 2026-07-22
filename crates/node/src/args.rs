use reth_optimism_node::args::RollupArgs;

fn parse_nonzero_usize(value: &str) -> Result<usize, String> {
    let value = value.parse::<usize>().map_err(|err| err.to_string())?;
    if value == 0 {
        return Err("value must be greater than zero".to_string());
    }
    Ok(value)
}

/// Parameters for the RPC-node half of the experimental Slipstream side-channel.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct SlipstreamArgs {
    /// Enable `slipstream_sendRawTransactionBatch` and forward requests to the configured
    /// sequencer.
    #[arg(
        id = "experimental_slipstream",
        long = "experimental.slipstream",
        env = "EXPERIMENTAL_SLIPSTREAM",
        default_value = "false"
    )]
    pub experimental: bool,

    /// Compute EIP-2930 access-list hints before forwarding Slipstream batches.
    #[arg(
        id = "slipstream_compute_hints",
        long = "slipstream.compute-hints",
        env = "SLIPSTREAM_COMPUTE_HINTS",
        default_value = "false"
    )]
    pub compute_hints: bool,

    /// Maximum concurrent Slipstream batches forwarded to the active sequencer.
    #[arg(
        long = "slipstream.forward-concurrency",
        env = "SLIPSTREAM_FORWARD_CONCURRENCY",
        default_value = "100",
        value_parser = parse_nonzero_usize
    )]
    pub forward_concurrency: usize,

    /// Timeout in milliseconds for acquiring forwarding capacity and for each active-sequencer
    /// request. Waiting for hint simulation capacity is not charged against this timeout.
    #[arg(
        long = "slipstream.forward-timeout-ms",
        env = "SLIPSTREAM_FORWARD_TIMEOUT_MS",
        default_value = "5000",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub forward_timeout_ms: u64,

    /// Maximum concurrent access-list simulations on this forwarding node.
    #[arg(
        long = "slipstream.hint-build-concurrency",
        env = "SLIPSTREAM_HINT_BUILD_CONCURRENCY",
        default_value = "8",
        value_parser = parse_nonzero_usize
    )]
    pub hint_build_concurrency: usize,

    /// Maximum time in milliseconds to spend computing one access-list hint.
    #[arg(
        long = "slipstream.hint-build-timeout-ms",
        env = "SLIPSTREAM_HINT_BUILD_TIMEOUT_MS",
        default_value = "250",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub hint_build_timeout_ms: u64,

    /// Maximum serialized bytes for a hinted transaction array. Larger arrays are forwarded
    /// through the plain Slipstream method.
    #[arg(
        long = "slipstream.max-hinted-batch-bytes",
        env = "SLIPSTREAM_MAX_HINTED_BATCH_BYTES",
        default_value = "10485760",
        value_parser = parse_nonzero_usize
    )]
    pub max_hinted_batch_bytes: usize,
}

impl Default for SlipstreamArgs {
    fn default() -> Self {
        use clap::{Args, FromArgMatches};

        let matches = Self::augment_args(clap::Command::new("dummy")).get_matches_from(["dummy"]);
        Self::from_arg_matches(&matches).expect("default Slipstream arguments")
    }
}

/// Conduit OP-Reth node arguments.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ConduitArgs {
    #[command(flatten)]
    pub rollup: RollupArgs,
    #[command(flatten)]
    pub slipstream: SlipstreamArgs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, FromArgMatches};

    #[test]
    fn slipstream_defaults_and_hint_flags_parse() {
        let defaults = SlipstreamArgs::default();
        assert!(!defaults.experimental);
        assert!(!defaults.compute_hints);
        assert_eq!(defaults.forward_concurrency, 100);
        assert_eq!(defaults.forward_timeout_ms, 5_000);
        assert_eq!(defaults.hint_build_concurrency, 8);
        assert_eq!(defaults.hint_build_timeout_ms, 250);
        assert_eq!(defaults.max_hinted_batch_bytes, 10 * 1024 * 1024);

        let matches = SlipstreamArgs::augment_args(clap::Command::new("dummy")).get_matches_from([
            "dummy",
            "--experimental.slipstream",
            "--slipstream.compute-hints",
            "--slipstream.forward-concurrency",
            "50",
            "--slipstream.forward-timeout-ms",
            "3000",
            "--slipstream.hint-build-concurrency",
            "4",
            "--slipstream.hint-build-timeout-ms",
            "125",
            "--slipstream.max-hinted-batch-bytes",
            "5242880",
        ]);
        let args = SlipstreamArgs::from_arg_matches(&matches).expect("arguments parse");
        assert!(args.experimental);
        assert!(args.compute_hints);
        assert_eq!(args.forward_concurrency, 50);
        assert_eq!(args.forward_timeout_ms, 3_000);
        assert_eq!(args.hint_build_concurrency, 4);
        assert_eq!(args.hint_build_timeout_ms, 125);
        assert_eq!(args.max_hinted_batch_bytes, 5 * 1024 * 1024);

        assert!(
            SlipstreamArgs::augment_args(clap::Command::new("dummy"))
                .try_get_matches_from(["dummy", "--slipstream.hint-build-concurrency", "0",])
                .is_err()
        );
        assert!(
            SlipstreamArgs::augment_args(clap::Command::new("dummy"))
                .try_get_matches_from(["dummy", "--slipstream.forward-concurrency", "0"])
                .is_err()
        );
    }
}
