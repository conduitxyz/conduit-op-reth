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

    /// Maximum time in milliseconds to spend computing hints for one batch.
    #[arg(
        long = "slipstream.hint-batch-timeout-ms",
        env = "SLIPSTREAM_HINT_BATCH_TIMEOUT_MS",
        default_value = "1000",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub hint_batch_timeout_ms: u64,

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
        assert_eq!(defaults.hint_build_concurrency, 8);
        assert_eq!(defaults.hint_build_timeout_ms, 250);
        assert_eq!(defaults.hint_batch_timeout_ms, 1_000);
        assert_eq!(defaults.max_hinted_batch_bytes, 10 * 1024 * 1024);

        let matches = SlipstreamArgs::augment_args(clap::Command::new("dummy")).get_matches_from([
            "dummy",
            "--experimental.slipstream",
            "--slipstream.compute-hints",
            "--slipstream.hint-build-concurrency",
            "4",
            "--slipstream.hint-build-timeout-ms",
            "125",
            "--slipstream.hint-batch-timeout-ms",
            "750",
            "--slipstream.max-hinted-batch-bytes",
            "5242880",
        ]);
        let args = SlipstreamArgs::from_arg_matches(&matches).expect("arguments parse");
        assert!(args.experimental);
        assert!(args.compute_hints);
        assert_eq!(args.hint_build_concurrency, 4);
        assert_eq!(args.hint_build_timeout_ms, 125);
        assert_eq!(args.hint_batch_timeout_ms, 750);
        assert_eq!(args.max_hinted_batch_bytes, 5 * 1024 * 1024);

        assert!(
            SlipstreamArgs::augment_args(clap::Command::new("dummy"))
                .try_get_matches_from(["dummy", "--slipstream.hint-build-concurrency", "0",])
                .is_err()
        );
    }
}
