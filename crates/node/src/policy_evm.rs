//! EVM and EVM factory enforcing the allowlist precompiles.
//!
//! [`ConduitOpEvm`] wraps the upstream [`OpEvm`] and is what [`ConduitOpEvmConfig`] hands to
//! every executor and block builder, so anything executing or building through that config,
//! including external builders, enforces
//! [`DeployerAllowListFork0`](crate::hardforks::ConduitOpHardfork::DeployerAllowListFork0) and
//! [`TxAllowListFork0`](crate::hardforks::ConduitOpHardfork::TxAllowListFork0) the same way. See
//! [`crate::deployer_allowlist`] and [`crate::tx_allowlist`] for the rules themselves.
//!
//! [`ConduitOpEvmConfig`]: crate::evm::ConduitOpEvmConfig

use crate::{
    chainspec::ConduitOpChainSpec,
    deployer_allowlist::{DEPLOYER_ALLOWLIST, deny_top_level_create, install_create_guards},
    hardforks::{ConduitOpHardfork, ConduitOpHardforks},
    tx_allowlist::{TX_ALLOWLIST, TxSenderCheck, allow_tx_sender},
};
use alloy_evm::{Database, Evm, EvmEnv, EvmFactory, precompiles::PrecompilesMap};
use alloy_op_evm::{
    OpEvm, OpEvmContext, OpTx, OpTxError,
    post_exec::{PostExecEvm, PostExecExecutedTx, PostExecTxContext},
};
use alloy_primitives::{Address, Bytes};
use op_revm::{
    L1BlockInfo, OpBuilder, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError,
    precompiles::OpPrecompiles,
};
use reth_chainspec::ForkCondition;
use revm::{
    Context, Inspector, MainContext,
    context::{BlockEnv, CfgEnv},
    context_interface::result::{EVMError, InvalidTransaction, ResultAndState},
    inspector::NoOpInspector,
};
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// OP EVM that enforces each allowlist once its fork is active.
#[allow(missing_debug_implementations)] // the upstream `OpEvm` has no `Debug` impl
pub struct ConduitOpEvm<DB: Database, I> {
    inner: OpEvm<DB, I, PrecompilesMap, OpTx>,
    /// Whether `DeployerAllowListFork0` is active for this EVM's block.
    deployer_allowlist_active: bool,
    /// Whether `TxAllowListFork0` is active for this EVM's block.
    tx_allowlist_active: bool,
}

impl<DB: Database, I> ConduitOpEvm<DB, I> {
    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &OpEvmContext<DB> {
        self.inner.ctx()
    }

    /// Provides a mutable reference to the EVM context.
    pub const fn ctx_mut(&mut self) -> &mut OpEvmContext<DB> {
        self.inner.ctx_mut()
    }

    /// Consumes self and returns the wrapped upstream EVM.
    pub fn into_inner(self) -> OpEvm<DB, I, PrecompilesMap, OpTx> {
        self.inner
    }
}

impl<DB: Database, I> Deref for ConduitOpEvm<DB, I> {
    type Target = OpEvmContext<DB>;

    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I> DerefMut for ConduitOpEvm<DB, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I> Evm for ConduitOpEvm<DB, I>
where
    DB: Database,
    I: Inspector<OpEvmContext<DB>>,
{
    type DB = DB;
    type Tx = OpTx;
    type Error = EVMError<DB::Error, OpTxError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        self.inner.block()
    }

    fn cfg_env(&self) -> &CfgEnv<OpSpecId> {
        self.inner.cfg_env()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(
        &mut self,
        mut tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        // RPC simulations (`eth_call`, `eth_estimateGas`, `eth_simulateV1`) are the only callers
        // that disable EIP-3607, which consensus execution never does. They skip the sender
        // check so read-only calls from unlisted or omitted senders keep working.
        let simulation = self.inner.cfg_env().disable_eip3607;
        let block_number = self.inner.block.number.saturating_to();
        // Between transactions the journal is empty, so the database holds each policy as
        // committed by every earlier transaction in the block.
        let db = &mut self.inner.ctx_mut().journaled_state.database;

        // The transaction allowlist is checked first. A deposit it denies has already been
        // rewritten into a reverted no-op, so the deployer allowlist has nothing left to check.
        let check = if self.tx_allowlist_active && !simulation {
            allow_tx_sender(&mut tx, block_number, |key| db.storage(TX_ALLOWLIST.address, key))
                .map_err(EVMError::Database)?
        } else {
            TxSenderCheck::Allowed
        };
        match check {
            TxSenderCheck::Rejected => {
                return Err(EVMError::Transaction(OpTxError(OpTransactionError::Base(
                    InvalidTransaction::Str("transaction sender is not allowlisted".into()),
                ))));
            }
            TxSenderCheck::Allowed if self.deployer_allowlist_active => {
                deny_top_level_create(&mut tx, block_number, !simulation, |key| {
                    db.storage(DEPLOYER_ALLOWLIST.address, key)
                })
                .map_err(EVMError::Database)?;
            }
            TxSenderCheck::Allowed | TxSenderCheck::DepositDenied => {}
        }
        self.inner.transact_raw(tx)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled);
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        self.inner.components_mut()
    }
}

impl<DB, I> PostExecEvm for ConduitOpEvm<DB, I>
where
    DB: Database,
    I: Inspector<OpEvmContext<DB>>,
{
    /// The inner `OpEvm` runs the default `NullRefundPolicy`, whose refund snapshot is empty.
    type Snapshot = ();

    fn begin_post_exec_tx(&mut self, ctx: PostExecTxContext) {
        self.inner.begin_post_exec_tx(ctx);
    }

    fn take_last_post_exec_tx_result(&mut self) -> PostExecExecutedTx {
        self.inner.take_last_post_exec_tx_result()
    }

    fn refund_snapshot(&self) -> Self::Snapshot {
        self.inner.refund_snapshot()
    }

    fn seed_refund_snapshot(&mut self, state: Self::Snapshot) {
        self.inner.seed_refund_snapshot(state);
    }
}

/// Factory producing [`ConduitOpEvm`]s.
#[derive(Debug, Clone)]
pub struct ConduitOpEvmFactory {
    deployer_allowlist_fork: ForkCondition,
    tx_allowlist_fork: ForkCondition,
    /// Accounts the transaction allowlist may never deny, such as the aliased L1 messenger.
    tx_allowlist_protected: Arc<[Address]>,
}

impl ConduitOpEvmFactory {
    /// Creates a factory enforcing the allowlist forks configured in `chain_spec`.
    pub fn new(chain_spec: &ConduitOpChainSpec) -> Self {
        Self {
            deployer_allowlist_fork: chain_spec
                .conduit_op_fork_activation(ConduitOpHardfork::DeployerAllowListFork0),
            tx_allowlist_fork: chain_spec
                .conduit_op_fork_activation(ConduitOpHardfork::TxAllowListFork0),
            tx_allowlist_protected: chain_spec
                .tx_allowlist_fork0
                .as_ref()
                .map(|config| config.protected_addresses.as_slice().into())
                .unwrap_or_default(),
        }
    }

    /// UPSTREAM-MIRROR(copy): alloy-op-evm@0.32.0 `OpEvm::from_env`
    ///
    /// Mirrors upstream construction, plus each active allowlist's precompile and, for the
    /// deployer allowlist, the CREATE/CREATE2 guards. A change to upstream's construction needs
    /// mirroring here.
    fn build<DB: Database, I>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId, BlockEnv>,
        inspector: I,
        inspect: bool,
    ) -> ConduitOpEvm<DB, I> {
        let timestamp = input.block_env.timestamp.saturating_to();
        let deployer_allowlist_active = self.deployer_allowlist_fork.active_at_timestamp(timestamp);
        let tx_allowlist_active = self.tx_allowlist_fork.active_at_timestamp(timestamp);

        let spec_id = input.cfg_env.spec;
        let mut inner = Context::mainnet()
            .with_tx(OpTx(OpTransaction::builder().build_fill()))
            .with_cfg(CfgEnv::new_with_spec(OpSpecId::BEDROCK))
            .with_chain(L1BlockInfo::default())
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env)
            .build_op_with_inspector(inspector)
            .with_precompiles(PrecompilesMap::from_static(
                OpPrecompiles::new_with_spec(spec_id).precompiles(),
            ));
        if deployer_allowlist_active {
            let precompile = DEPLOYER_ALLOWLIST.precompile(Arc::from([]));
            inner.0.precompiles.apply_precompile(&DEPLOYER_ALLOWLIST.address, |_| Some(precompile));
            install_create_guards(&mut inner.0.instruction);
        }
        if tx_allowlist_active {
            let precompile = TX_ALLOWLIST.precompile(self.tx_allowlist_protected.clone());
            inner.0.precompiles.apply_precompile(&TX_ALLOWLIST.address, |_| Some(precompile));
        }

        ConduitOpEvm {
            inner: OpEvm::new(inner, inspect),
            deployer_allowlist_active,
            tx_allowlist_active,
        }
    }
}

impl EvmFactory for ConduitOpEvmFactory {
    type Evm<DB: Database, I: Inspector<OpEvmContext<DB>>> = ConduitOpEvm<DB, I>;
    type Context<DB: Database> = OpEvmContext<DB>;
    type Tx = OpTx;
    type Error<DBError: revm::context::DBErrorMarker> = EVMError<DBError, OpTxError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId, BlockEnv>,
    ) -> Self::Evm<DB, NoOpInspector> {
        self.build(db, input, NoOpInspector {}, false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId, BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        self.build(db, input, inspector, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        allowlist::{
            AllowList, IConduitAllowList, POLICY_VIOLATION_REVERT_DATA, READ_GAS, Role,
            SYSTEM_SENDERS,
        },
        chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser, l1_to_l2_alias},
        deployer_allowlist::ensure_deployer_allowlist,
        tx_allowlist::ensure_tx_allowlist,
    };
    use alloy_primitives::{B256, TxKind, U256, address, bytes, keccak256};
    use alloy_sol_types::{SolCall, SolError, SolEvent};
    use reth_cli::chainspec::ChainSpecParser;
    use revm::{
        bytecode::Bytecode,
        context::TxEnv,
        context_interface::result::{ExecutionResult, Output},
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
    };
    use std::sync::Arc;

    const ACTIVATION: u64 = 1_000;
    const ADMIN: Address = address!("00000000000000000000000000000000000ad111");
    const MANAGER: Address = address!("0000000000000000000000000000000000000222");
    const ENABLED: Address = address!("00000000000000000000000000000000000a11ce");
    const OTHER: Address = address!("0000000000000000000000000000000000000b0b");
    const FACTORY: Address = address!("00000000000000000000000000000000000fac70");
    const FACTORY2: Address = address!("00000000000000000000000000000000000fac71");
    const PROXY: Address = address!("0000000000000000000000000000000000000f00");
    const DELEGATE_PROXY: Address = address!("0000000000000000000000000000000000000f01");
    const POLICY_HELPER: Address = address!("0000000000000000000000000000000000000f02");
    /// L1 address of the chain's `L1CrossDomainMessenger`.
    const L1_MESSENGER: Address = address!("25ace71c97b33cc4729cf772ae268934f7ab5fa1");

    /// Initcode deploying the one-byte runtime `0x00`.
    const DEPLOYABLE_INITCODE: Bytes = bytes!("60016000f3");

    /// Factory runtime: `CREATE`s [`DEPLOYABLE_INITCODE`], then stores the created address in
    /// slot 0, `RETURNDATASIZE` in slot 1 and the first returned word in slot 2.
    const CREATE_FACTORY: Bytes = bytes!(
        "6460016000f3600052"           // MSTORE initcode at memory[27..32]
        "6005601b6000f0"               // CREATE(value 0, offset 27, size 5)
        "600055"                       // SSTORE(0, address)
        "3d600155"                     // SSTORE(1, RETURNDATASIZE)
        "3d600060003e600051600255"     // SSTORE(2, first returned word)
        "00"
    );

    /// Same as [`CREATE_FACTORY`], but using `CREATE2` with salt 0.
    const CREATE2_FACTORY: Bytes = bytes!(
        "6460016000f3600052"
        "60006005601b6000f5"           // CREATE2(value 0, offset 27, size 5, salt 0)
        "600055"
        "3d600155"
        "3d600060003e600051600255"
        "00"
    );

    /// Proxy runtime forwarding its calldata to the precompile with `op` (STATICCALL or
    /// DELEGATECALL), storing the success flag in slot 0 and the first returned word in slot 1.
    fn forwarding_proxy(op: u8) -> Bytes {
        let mut code = bytes!("366000600037" "6020600036600073").to_vec();
        code.extend_from_slice(DEPLOYER_ALLOWLIST.address.as_slice());
        code.extend_from_slice(&[0x5a, op]);
        code.extend_from_slice(&bytes!("600055" "3d600060003e" "600051600155" "00"));
        code.into()
    }

    /// A chain spec with the allowlists for which a mode is given, both activating at
    /// [`ACTIVATION`] with the same initial roles.
    /// Helper runtime: forwards its calldata to the deployer allowlist precompile with CALL, then
    /// runs [`CREATE_FACTORY`]'s create, storing the created address in slot 0.
    fn policy_then_create_helper() -> Bytes {
        let mut code = bytes!("366000600037" "60006000366000600073").to_vec();
        code.extend_from_slice(DEPLOYER_ALLOWLIST.address.as_slice());
        code.extend_from_slice(
            &bytes!("5af150" "6460016000f3600052" "6005601b6000f0" "600055" "00"),
        );
        code.into()
    }

    fn chain_spec(deployer_mode: Option<&str>, tx_mode: Option<&str>) -> Arc<ConduitOpChainSpec> {
        let allowlist = |time: u64, mode: &str| {
            serde_json::json!({
                "time": time,
                "mode": mode,
                "adminAddresses": [ADMIN],
                "managerAddresses": [MANAGER],
                "enabledAddresses": [ENABLED],
                "blockedAddresses": [OTHER],
            })
        };
        let mut conduit = serde_json::Map::new();
        if let Some(mode) = deployer_mode {
            conduit.insert("deployerAllowListFork0".into(), allowlist(ACTIVATION, mode));
        }
        if let Some(mode) = tx_mode {
            // Each fork needs its own timestamp, so this one activates a block earlier.
            let mut tx_allowlist = allowlist(ACTIVATION - 1, mode);
            tx_allowlist["enabledAddresses"] =
                serde_json::json!([ENABLED, l1_to_l2_alias(L1_MESSENGER)]);
            tx_allowlist["l1CrossDomainMessenger"] = serde_json::json!(L1_MESSENGER);
            conduit.insert("txAllowListFork0".into(), tx_allowlist);
        }
        let genesis = serde_json::json!({
            "config": {
                "chainId": 901,
                "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
                "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
                "istanbulBlock": 0, "muirGlacierBlock": 0, "berlinBlock": 0, "londonBlock": 0,
                "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0, "bedrockBlock": 0,
                "regolithTime": 0, "canyonTime": 0, "ecotoneTime": 0, "fjordTime": 0,
                "graniteTime": 0, "holoceneTime": 0, "isthmusTime": 0,
                "conduit": conduit,
            },
            "difficulty": "0x0",
            "gasLimit": "0x1c9c380",
            "alloc": {}
        });
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = tempfile_dir();
        let path = dir.join(format!("genesis-{}-{id}.json", std::process::id()));
        std::fs::write(&path, genesis.to_string()).unwrap();
        let spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        spec
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("conduit-op-reth-policy-evm-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A database with the factories, proxies and a funded admin, seeded as the activation block
    /// would seed it.
    struct Chain {
        spec: Arc<ConduitOpChainSpec>,
        db: CacheDB<EmptyDB>,
        nonces: std::collections::HashMap<Address, u64>,
    }

    impl Chain {
        /// A chain with only the deployer allowlist, in `mode`.
        fn new(mode: &str) -> Self {
            Self::with(Some(mode), None)
        }

        /// A chain with only the transaction allowlist, in `mode`.
        fn tx(mode: &str) -> Self {
            Self::with(None, Some(mode))
        }

        fn with(deployer_mode: Option<&str>, tx_mode: Option<&str>) -> Self {
            let spec = chain_spec(deployer_mode, tx_mode);
            let mut db = CacheDB::new(EmptyDB::default());
            for (address, code) in [
                (FACTORY, CREATE_FACTORY),
                (FACTORY2, CREATE2_FACTORY),
                (PROXY, forwarding_proxy(0xfa)),
                (DELEGATE_PROXY, forwarding_proxy(0xf4)),
                (POLICY_HELPER, policy_then_create_helper()),
            ] {
                db.insert_account_info(
                    address,
                    AccountInfo {
                        nonce: 1,
                        code: Some(Bytecode::new_raw(code)),
                        ..Default::default()
                    },
                );
            }
            db.insert_account_info(
                ADMIN,
                AccountInfo { balance: U256::from(1_000_000), ..Default::default() },
            );
            ensure_deployer_allowlist(&spec, ACTIVATION, &mut db).unwrap();
            ensure_tx_allowlist(&spec, ACTIVATION, &mut db).unwrap();
            Self { spec, db, nonces: Default::default() }
        }

        fn factory(&self) -> ConduitOpEvmFactory {
            ConduitOpEvmFactory::new(&self.spec)
        }

        fn run_at(&mut self, timestamp: u64, tx: OpTx) -> ExecutionResult<OpHaltReason> {
            self.try_run_at(timestamp, tx, false).expect("transaction executes")
        }

        /// Runs `tx`, as an RPC simulation if `simulation` is set.
        fn try_run_at(
            &mut self,
            timestamp: u64,
            tx: OpTx,
            simulation: bool,
        ) -> Result<ExecutionResult<OpHaltReason>, EVMError<core::convert::Infallible, OpTxError>>
        {
            let mut cfg_env = CfgEnv::new_with_spec(OpSpecId::ISTHMUS);
            cfg_env.chain_id = 901;
            cfg_env.disable_eip3607 = simulation;
            let block_env = BlockEnv {
                number: U256::from(10),
                timestamp: U256::from(timestamp),
                gas_limit: 30_000_000,
                ..Default::default()
            };
            let factory = self.factory();
            let mut evm = factory.create_evm(&mut self.db, EvmEnv { cfg_env, block_env });
            evm.transact_commit(tx)
        }

        /// Runs `tx` through an EVM with an inspector attached, as tracing does.
        fn run_inspected(&mut self, tx: OpTx) -> ExecutionResult<OpHaltReason> {
            let mut cfg_env = CfgEnv::new_with_spec(OpSpecId::ISTHMUS);
            cfg_env.chain_id = 901;
            let block_env = BlockEnv {
                number: U256::from(10),
                timestamp: U256::from(ACTIVATION),
                gas_limit: 30_000_000,
                ..Default::default()
            };
            let factory = self.factory();
            let mut evm = factory.create_evm_with_inspector(
                &mut self.db,
                EvmEnv { cfg_env, block_env },
                NoOpInspector {},
            );
            evm.transact_commit(tx).expect("transaction executes")
        }

        fn run(&mut self, tx: OpTx) -> ExecutionResult<OpHaltReason> {
            self.run_at(ACTIVATION, tx)
        }

        /// An L2 transaction from `from`, with the next nonce.
        fn l2(&mut self, from: Address, kind: TxKind, data: Bytes, value: u64) -> OpTx {
            let nonce = self.nonces.entry(from).or_default();
            let tx = OpTx(
                OpTransaction::builder()
                    .base(
                        TxEnv::builder()
                            .caller(from)
                            .nonce(*nonce)
                            .kind(kind)
                            .data(data)
                            .value(U256::from(value))
                            .gas_limit(1_000_000)
                            .chain_id(Some(901)),
                    )
                    .build_fill(),
            );
            *nonce += 1;
            tx
        }

        /// Calls the deployer allowlist precompile.
        fn call(&mut self, from: Address, call: impl SolCall) -> ExecutionResult<OpHaltReason> {
            self.call_list(DEPLOYER_ALLOWLIST, from, call)
        }

        fn call_list(
            &mut self,
            list: AllowList,
            from: Address,
            call: impl SolCall,
        ) -> ExecutionResult<OpHaltReason> {
            let tx = self.l2(from, TxKind::Call(list.address), call.abi_encode().into(), 0);
            self.run(tx)
        }

        fn storage(&self, address: Address, slot: u64) -> U256 {
            self.db
                .cache
                .accounts
                .get(&address)
                .and_then(|account| account.storage.get(&U256::from(slot)).copied())
                .unwrap_or_default()
        }

        fn nonce(&self, address: Address) -> u64 {
            self.db.cache.accounts.get(&address).map_or(0, |account| account.info.nonce)
        }

        fn code_len(&self, address: Address) -> usize {
            self.db
                .cache
                .accounts
                .get(&address)
                .and_then(|account| account.info.code.as_ref())
                .map_or(0, |code| code.original_bytes().len())
        }

        fn role(&mut self, account: Address) -> U256 {
            output(self.call(ADMIN, IConduitAllowList::readAllowListCall { addr: account }))
                .as_ref()
                .try_into()
                .map(U256::from_be_bytes::<32>)
                .unwrap()
        }
    }

    fn deposit(from: Address, kind: TxKind, data: Bytes, mint: u128) -> OpTx {
        OpTx(
            OpTransaction::builder()
                .base(TxEnv::builder().caller(from).kind(kind).data(data).gas_limit(1_000_000))
                .is_deposit_tx()
                .source_hash(B256::with_last_byte(1))
                .mint(mint)
                .build_fill(),
        )
    }

    fn output(result: ExecutionResult<OpHaltReason>) -> Bytes {
        match result {
            ExecutionResult::Success { output, .. } => output.into_data(),
            other => panic!("expected success, got {other:?}"),
        }
    }

    fn revert_output(result: ExecutionResult<OpHaltReason>) -> Bytes {
        match result {
            ExecutionResult::Revert { output, .. } => output,
            other => panic!("expected revert, got {other:?}"),
        }
    }

    /// Asserts the factory's last create was denied exactly as if its initcode reverted.
    fn assert_create_denied(chain: &Chain, factory: Address) {
        assert_eq!(chain.storage(factory, 0), U256::ZERO, "caller sees address zero");
        assert_eq!(chain.storage(factory, 1), U256::from(4), "revert data length");
        // Only the first 4 bytes of the word were overwritten by the returned data.
        assert_eq!(
            chain.storage(factory, 2) >> 224,
            U256::from_be_slice(&POLICY_VIOLATION_REVERT_DATA),
            "revert data is PolicyViolation()"
        );
        assert_eq!(chain.nonce(factory), 2, "creator nonce is bumped");
        assert_eq!(chain.code_len(factory.create(1)), 0, "nothing is deployed");
    }

    fn assert_create_allowed(chain: &Chain, factory: Address) {
        let created = Address::from_word(chain.storage(factory, 0).into());
        assert_ne!(created, Address::ZERO);
        assert_eq!(chain.code_len(created), 1);
    }

    #[test]
    fn allowlist_denies_unlisted_nested_creates_on_both_paths() {
        for factory in [FACTORY, FACTORY2] {
            let mut chain = Chain::new("allowlist");
            let tx = chain.l2(OTHER, TxKind::Call(factory), Bytes::new(), 0);
            // The transaction itself succeeds and is included; only its create fails.
            assert!(chain.run(tx).is_success());
            assert_create_denied(&chain, factory);

            let mut chain = Chain::new("allowlist");
            assert!(chain.run(deposit(OTHER, TxKind::Call(factory), Bytes::new(), 0)).is_success());
            assert_create_denied(&chain, factory);
        }
    }

    #[test]
    fn allowlist_permits_every_role_through_any_factory() {
        for origin in [ENABLED, MANAGER, ADMIN] {
            let mut chain = Chain::new("allowlist");
            let tx = chain.l2(origin, TxKind::Call(FACTORY), Bytes::new(), 0);
            assert!(chain.run(tx).is_success());
            assert_create_allowed(&chain, FACTORY);
        }

        let mut chain = Chain::new("allowlist");
        assert!(chain.run(deposit(ENABLED, TxKind::Call(FACTORY), Bytes::new(), 0)).is_success());
        assert_create_allowed(&chain, FACTORY);
    }

    #[test]
    fn denied_top_level_creates_revert_on_both_paths() {
        let mut chain = Chain::new("allowlist");
        let tx = chain.l2(OTHER, TxKind::Create, DEPLOYABLE_INITCODE, 0);
        assert_eq!(revert_output(chain.run(tx)), POLICY_VIOLATION_REVERT_DATA);
        assert_eq!(chain.nonce(OTHER), 1, "sender nonce is bumped");
        assert_eq!(chain.code_len(OTHER.create(0)), 0);

        let mut chain = Chain::new("allowlist");
        let result = chain.run(deposit(OTHER, TxKind::Create, DEPLOYABLE_INITCODE, 1_000));
        assert_eq!(revert_output(result), POLICY_VIOLATION_REVERT_DATA);
        assert_eq!(chain.nonce(OTHER), 1, "sender nonce is bumped");
        let balance = chain.db.cache.accounts.get(&OTHER).unwrap().info.balance;
        assert_eq!(balance, U256::from(1_000), "mint is kept");
        assert_eq!(chain.code_len(OTHER.create(0)), 0);
    }

    #[test]
    fn system_senders_may_always_deploy() {
        let mut chain = Chain::new("allowlist");
        let result = chain.run(deposit(SYSTEM_SENDERS[0], TxKind::Call(FACTORY), Bytes::new(), 0));
        assert!(result.is_success());
        assert_create_allowed(&chain, FACTORY);

        let result = chain.run(deposit(SYSTEM_SENDERS[1], TxKind::Create, DEPLOYABLE_INITCODE, 0));
        match result {
            ExecutionResult::Success { output: Output::Create(_, Some(address)), .. } => {
                assert_eq!(chain.code_len(address), 1)
            }
            other => panic!("expected successful create, got {other:?}"),
        }
    }

    #[test]
    fn nothing_is_enforced_before_activation() {
        let mut chain = Chain::new("allowlist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run_at(ACTIVATION - 1, tx).is_success());
        assert_create_allowed(&chain, FACTORY);

        // The precompile is not installed either, so the call runs the marker code, which
        // halts. (On a real chain the account is only seeded once the fork is active.)
        let tx = chain.l2(
            ADMIN,
            TxKind::Call(DEPLOYER_ALLOWLIST.address),
            IConduitAllowList::readAllowListCall { addr: ADMIN }.abi_encode().into(),
            0,
        );
        assert!(matches!(chain.run_at(ACTIVATION - 1, tx), ExecutionResult::Halt { .. }));
    }

    #[test]
    fn seeding_writes_the_configured_roles_once() {
        let mut chain = Chain::new("allowlist");
        assert_eq!(chain.role(ADMIN), U256::from(Role::Admin as u8));
        assert_eq!(chain.role(MANAGER), U256::from(Role::Manager as u8));
        assert_eq!(chain.role(ENABLED), U256::from(Role::Enabled as u8));
        assert_eq!(chain.role(OTHER), U256::from(Role::None as u8));

        // A later block finds the account seeded and leaves changed roles alone.
        chain.call(ADMIN, IConduitAllowList::setNoneCall { addr: ENABLED });
        ensure_deployer_allowlist(&chain.spec, ACTIVATION + 1, &mut chain.db).unwrap();
        assert_eq!(chain.role(ENABLED), U256::from(Role::None as u8));
    }

    #[test]
    fn admin_grants_take_effect_for_later_transactions() {
        let mut chain = Chain::new("allowlist");
        let result = chain.call(ADMIN, IConduitAllowList::setEnabledCall { addr: OTHER });
        let ExecutionResult::Success { logs, .. } = &result else { panic!("{result:?}") };
        let event = IConduitAllowList::RoleSet::decode_log_data(&logs[0].data).unwrap();
        assert_eq!(logs[0].address, DEPLOYER_ALLOWLIST.address);
        assert_eq!(event.role, U256::from(Role::Enabled as u8));
        assert_eq!(event.account, OTHER);
        assert_eq!(event.sender, ADMIN);
        assert_eq!(event.oldRole, U256::from(Role::None as u8));

        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
        assert_create_allowed(&chain, FACTORY);
    }

    #[test]
    fn role_changes_follow_the_permission_rules() {
        let unauthorized =
            |sender| Bytes::from(IConduitAllowList::Unauthorized { sender }.abi_encode());
        let mut chain = Chain::new("allowlist");

        // Accounts without a privileged role cannot change anything.
        for sender in [ENABLED, OTHER] {
            let result = chain.call(sender, IConduitAllowList::setEnabledCall { addr: OTHER });
            assert_eq!(revert_output(result), unauthorized(sender));
        }

        // Managers manage the Enabled role of non-privileged accounts only.
        assert!(
            chain.call(MANAGER, IConduitAllowList::setEnabledCall { addr: OTHER }).is_success()
        );
        assert!(chain.call(MANAGER, IConduitAllowList::setNoneCall { addr: OTHER }).is_success());
        let result = chain.call(MANAGER, IConduitAllowList::setAdminCall { addr: OTHER });
        assert_eq!(revert_output(result), unauthorized(MANAGER));
        let result = chain.call(MANAGER, IConduitAllowList::setManagerCall { addr: OTHER });
        assert_eq!(revert_output(result), unauthorized(MANAGER));
        let result = chain.call(MANAGER, IConduitAllowList::setNoneCall { addr: ADMIN });
        assert_eq!(revert_output(result), unauthorized(MANAGER));
        let result = chain.call(MANAGER, IConduitAllowList::setModeCall { mode: U256::ZERO });
        assert_eq!(revert_output(result), unauthorized(MANAGER));

        // Admins manage every role.
        assert!(chain.call(ADMIN, IConduitAllowList::setManagerCall { addr: OTHER }).is_success());
        assert_eq!(chain.role(OTHER), U256::from(Role::Manager as u8));
        assert!(chain.call(ADMIN, IConduitAllowList::setNoneCall { addr: MANAGER }).is_success());
        assert_eq!(chain.role(MANAGER), U256::from(Role::None as u8));
    }

    #[test]
    fn denylist_blocks_only_blocked_accounts() {
        let mut chain = Chain::new("denylist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
        assert_create_denied(&chain, FACTORY);

        // Unlisted accounts may deploy, on both paths.
        let unlisted = address!("0000000000000000000000000000000000000c0c");
        let mut chain = Chain::new("denylist");
        assert!(chain.run(deposit(unlisted, TxKind::Call(FACTORY), Bytes::new(), 0)).is_success());
        assert_create_allowed(&chain, FACTORY);

        // Managers block and unblock non-privileged accounts.
        let mut chain = Chain::new("denylist");
        let result =
            chain.call(MANAGER, IConduitAllowList::setBlockedCall { addr: OTHER, blocked: false });
        assert!(result.is_success());
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
        assert_create_allowed(&chain, FACTORY);
    }

    #[test]
    fn admin_switches_modes() {
        let mut chain = Chain::new("allowlist");
        let result = chain.call(ADMIN, IConduitAllowList::setModeCall { mode: U256::ZERO });
        let ExecutionResult::Success { logs, .. } = &result else { panic!("{result:?}") };
        let event = IConduitAllowList::ModeSet::decode_log_data(&logs[0].data).unwrap();
        assert_eq!((event.oldMode, event.newMode), (U256::from(1), U256::ZERO));

        // Off: anyone may deploy.
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
        assert_create_allowed(&chain, FACTORY);

        let result = chain.call(ADMIN, IConduitAllowList::setModeCall { mode: U256::from(3) });
        assert_eq!(
            revert_output(result),
            Bytes::from(IConduitAllowList::InvalidMode { mode: U256::from(3) }.abi_encode())
        );
    }

    #[test]
    fn views_report_the_policy() {
        let mut chain = Chain::new("allowlist");
        let is_allowed = |chain: &mut Chain, addr| {
            output(chain.call(ADMIN, IConduitAllowList::isAllowedCall { addr }))
        };
        let word = |value: u64| Bytes::from(U256::from(value).to_be_bytes::<32>());

        assert_eq!(output(chain.call(OTHER, IConduitAllowList::modeCall {})), word(1));
        assert_eq!(is_allowed(&mut chain, ENABLED), word(1));
        assert_eq!(is_allowed(&mut chain, OTHER), word(0));
        assert_eq!(is_allowed(&mut chain, SYSTEM_SENDERS[0]), word(1));
        assert_eq!(
            output(chain.call(OTHER, IConduitAllowList::isBlockedCall { addr: OTHER })),
            word(1)
        );
    }

    #[test]
    fn rejects_static_writes_delegatecalls_and_value() {
        let mut chain = Chain::new("allowlist");
        let set_enabled: Bytes =
            IConduitAllowList::setEnabledCall { addr: OTHER }.abi_encode().into();

        // A write through STATICCALL fails.
        let tx = chain.l2(ADMIN, TxKind::Call(PROXY), set_enabled.clone(), 0);
        assert!(chain.run(tx).is_success());
        assert_eq!(chain.storage(PROXY, 0), U256::ZERO, "inner call failed");
        assert_eq!(
            chain.storage(PROXY, 1) >> 224,
            U256::from_be_slice(&IConduitAllowList::StaticCallNotAllowed::SELECTOR)
        );

        // DELEGATECALL into the precompile fails, even from an admin.
        let tx = chain.l2(ADMIN, TxKind::Call(DELEGATE_PROXY), set_enabled.clone(), 0);
        assert!(chain.run(tx).is_success());
        assert_eq!(chain.storage(DELEGATE_PROXY, 0), U256::ZERO, "inner call failed");
        assert_eq!(
            chain.storage(DELEGATE_PROXY, 1) >> 224,
            U256::from_be_slice(&IConduitAllowList::DelegateCallNotAllowed::SELECTOR)
        );

        // Sending value fails.
        let tx = chain.l2(ADMIN, TxKind::Call(DEPLOYER_ALLOWLIST.address), set_enabled, 1);
        assert_eq!(
            revert_output(chain.run(tx)),
            Bytes::from(IConduitAllowList::ValueNotAllowed {}.abi_encode())
        );

        assert_eq!(chain.role(OTHER), U256::from(Role::None as u8), "no write took effect");
    }

    fn invalid_tx_reason(
        result: Result<
            ExecutionResult<OpHaltReason>,
            EVMError<core::convert::Infallible, OpTxError>,
        >,
    ) -> String {
        match result {
            Err(EVMError::Transaction(OpTxError(OpTransactionError::Base(
                InvalidTransaction::Str(reason),
            )))) => reason.into_owned(),
            other => panic!("expected an invalid-transaction error, got {other:?}"),
        }
    }

    #[test]
    fn tx_allowlist_rejects_unlisted_l2_senders() {
        let mut chain = Chain::tx("allowlist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        let reason = invalid_tx_reason(chain.try_run_at(ACTIVATION, tx, false));
        assert!(reason.contains("not allowlisted"), "{reason}");
        assert_eq!(chain.nonce(OTHER), 0, "a rejected transaction keeps its nonce");
        assert_eq!(chain.nonce(FACTORY), 1, "and has no effect");

        for sender in [ENABLED, MANAGER, ADMIN] {
            let tx = chain.l2(sender, TxKind::Call(FACTORY), Bytes::new(), 0);
            assert!(chain.run(tx).is_success(), "{sender} may transact");
        }
    }

    #[test]
    fn tx_allowlist_turns_denied_deposits_into_reverted_no_ops() {
        let mut chain = Chain::tx("allowlist");
        let result = chain.run(deposit(OTHER, TxKind::Call(FACTORY), Bytes::new(), 1_000));

        assert_eq!(revert_output(result), POLICY_VIOLATION_REVERT_DATA);
        assert_eq!(chain.nonce(OTHER), 1, "the deposit's nonce is bumped");
        let balance = chain.db.cache.accounts.get(&OTHER).unwrap().info.balance;
        assert_eq!(balance, U256::from(1_000), "the mint is kept");
        assert_eq!(chain.nonce(FACTORY), 1, "the call never ran");
        assert_eq!(chain.storage(FACTORY, 0), U256::ZERO);
    }

    #[test]
    fn tx_allowlist_exempts_system_deposits() {
        let mut chain = Chain::tx("allowlist");
        for sender in [SYSTEM_SENDERS[0], Address::ZERO] {
            let result = chain.run(deposit(sender, TxKind::Call(FACTORY), Bytes::new(), 0));
            assert!(result.is_success(), "{sender}: {result:?}");
        }
    }

    #[test]
    fn tx_denylist_never_locks_out_admins() {
        let mut chain = Chain::tx("denylist");

        // OTHER is blocked at genesis; unlisted accounts may transact.
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        invalid_tx_reason(chain.try_run_at(ACTIVATION, tx, false));
        let unlisted = address!("0000000000000000000000000000000000000c0c");
        let tx = chain.l2(unlisted, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());

        // An admin that blocks itself can still transact, and so can still undo it.
        let block_self = IConduitAllowList::setBlockedCall { addr: ADMIN, blocked: true };
        assert!(chain.call_list(TX_ALLOWLIST, ADMIN, block_self).is_success());
        let unblock_self = IConduitAllowList::setBlockedCall { addr: ADMIN, blocked: false };
        assert!(chain.call_list(TX_ALLOWLIST, ADMIN, unblock_self).is_success());
    }

    #[test]
    fn tx_allowlist_grants_take_effect_for_later_transactions() {
        let mut chain = Chain::tx("allowlist");
        let grant = IConduitAllowList::setEnabledCall { addr: OTHER };
        assert!(chain.call_list(TX_ALLOWLIST, ADMIN, grant).is_success());

        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
    }

    #[test]
    fn tx_allowlist_is_skipped_by_rpc_simulations() {
        let mut chain = Chain::tx("allowlist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        let result = chain.try_run_at(ACTIVATION, tx, true).expect("simulations run");
        assert!(result.is_success());
    }

    #[test]
    fn allowlists_are_independent() {
        let mut chain = Chain::with(Some("allowlist"), Some("allowlist"));
        // Allowed to transact but not to deploy.
        let grant = IConduitAllowList::setEnabledCall { addr: OTHER };
        assert!(chain.call_list(TX_ALLOWLIST, ADMIN, grant).is_success());

        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
        assert_create_denied(&chain, FACTORY);
    }

    #[test]
    fn tx_allowlist_admits_bridge_deposits() {
        let mut chain = Chain::tx("allowlist");
        let messenger = l1_to_l2_alias(L1_MESSENGER);
        let result = chain.run(deposit(messenger, TxKind::Call(FACTORY), Bytes::new(), 1_000));
        assert!(result.is_success(), "{result:?}");
        assert_eq!(chain.nonce(FACTORY), 2, "the relayed call ran");
    }

    #[test]
    fn tx_allowlist_never_denies_the_messenger() {
        let protected =
            |account| Bytes::from(IConduitAllowList::ProtectedAccount { account }.abi_encode());
        let messenger = l1_to_l2_alias(L1_MESSENGER);
        let mut chain = Chain::tx("denylist");

        // Neither removing its role nor blocking it is possible, even for an admin.
        let result = chain.call_list(
            TX_ALLOWLIST,
            ADMIN,
            IConduitAllowList::setNoneCall { addr: messenger },
        );
        assert_eq!(revert_output(result), protected(messenger));
        let block = IConduitAllowList::setBlockedCall { addr: messenger, blocked: true };
        assert_eq!(
            revert_output(chain.call_list(TX_ALLOWLIST, ADMIN, block)),
            protected(messenger)
        );

        // Other role changes and unblocking stay allowed, and it keeps a role throughout.
        for call in [
            IConduitAllowList::setManagerCall { addr: messenger }.abi_encode(),
            IConduitAllowList::setEnabledCall { addr: messenger }.abi_encode(),
            IConduitAllowList::setBlockedCall { addr: messenger, blocked: false }.abi_encode(),
        ] {
            let tx = chain.l2(ADMIN, TxKind::Call(TX_ALLOWLIST.address), call.into(), 0);
            assert!(chain.run(tx).is_success());
        }

        // Switching to allowlist mode cannot strand bridge deposits either.
        let to_allowlist = IConduitAllowList::setModeCall { mode: U256::from(1) };
        assert!(chain.call_list(TX_ALLOWLIST, ADMIN, to_allowlist).is_success());
        let result = chain.run(deposit(messenger, TxKind::Call(FACTORY), Bytes::new(), 0));
        assert!(result.is_success(), "{result:?}");
    }

    #[test]
    fn deployer_allowlist_has_no_protected_accounts() {
        let mut chain = Chain::new("allowlist");
        let result = chain.call(ADMIN, IConduitAllowList::setNoneCall { addr: ENABLED });
        assert!(result.is_success(), "{result:?}");
    }

    fn gas_used(result: &ExecutionResult<OpHaltReason>) -> u64 {
        result.tx_gas_used()
    }

    #[test]
    fn admins_cannot_demote_themselves() {
        let self_demotion = Bytes::from(IConduitAllowList::SelfDemotion {}.abi_encode());
        let mut chain = Chain::new("allowlist");
        for call in [
            IConduitAllowList::setNoneCall { addr: ADMIN }.abi_encode(),
            IConduitAllowList::setEnabledCall { addr: ADMIN }.abi_encode(),
            IConduitAllowList::setManagerCall { addr: ADMIN }.abi_encode(),
        ] {
            let tx = chain.l2(ADMIN, TxKind::Call(DEPLOYER_ALLOWLIST.address), call.into(), 0);
            assert_eq!(revert_output(chain.run(tx)), self_demotion);
        }
        assert_eq!(chain.role(ADMIN), U256::from(Role::Admin as u8));

        // Re-granting its own Admin role is a no-op, and another admin can remove it.
        assert!(chain.call(ADMIN, IConduitAllowList::setAdminCall { addr: ADMIN }).is_success());
        assert!(chain.call(ADMIN, IConduitAllowList::setAdminCall { addr: OTHER }).is_success());
        assert!(chain.call(OTHER, IConduitAllowList::setNoneCall { addr: ADMIN }).is_success());
        assert_eq!(chain.role(ADMIN), U256::from(Role::None as u8));
    }

    #[test]
    fn malformed_precompile_input_reverts_and_is_charged() {
        let mut chain = Chain::new("allowlist");
        // `setEnabled` with dirty high bits in the address word.
        let mut data = IConduitAllowList::setEnabledCall { addr: OTHER }.abi_encode();
        data[4] = 0xff;
        let tx = chain.l2(ADMIN, TxKind::Call(DEPLOYER_ALLOWLIST.address), data.into(), 0);
        let result = chain.run(tx);
        assert!(gas_used(&result) >= 21_000 + READ_GAS, "decode failures are charged");
        assert_eq!(revert_output(result), Bytes::new());
        assert_eq!(chain.role(OTHER), U256::from(Role::None as u8));
    }

    #[test]
    fn denied_top_level_creates_pay_for_their_full_initcode() {
        // 1,000 nonzero bytes: `JUMPDEST`s, then the deployable initcode.
        let initcode: Bytes = [vec![0x5b; 1_000], DEPLOYABLE_INITCODE.to_vec()].concat().into();
        let mut chain = Chain::new("allowlist");
        let tx = chain.l2(OTHER, TxKind::Create, initcode.clone(), 0);
        let result = chain.run(tx);
        // Base and create costs plus calldata for every original byte.
        let intrinsic = 21_000 + 32_000 + 16 * initcode.len() as u64;
        assert!(gas_used(&result) >= intrinsic, "{} < {intrinsic}", gas_used(&result));
        assert_eq!(revert_output(result), POLICY_VIOLATION_REVERT_DATA);
    }

    #[test]
    fn denied_create2_deploys_nothing_at_the_original_address() {
        let mut chain = Chain::new("allowlist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY2), Bytes::new(), 0);
        assert!(chain.run(tx).is_success());
        let original = FACTORY2.create2(B256::ZERO, keccak256(&DEPLOYABLE_INITCODE));
        assert_eq!(chain.code_len(original), 0);
        assert_create_denied(&chain, FACTORY2);
    }

    #[test]
    fn a_policy_change_applies_later_in_the_same_transaction() {
        let mut chain = Chain::new("denylist");
        // Make the helper an admin so it can change the policy mid-transaction.
        assert!(
            chain.call(ADMIN, IConduitAllowList::setAdminCall { addr: POLICY_HELPER }).is_success()
        );

        // The admin's own transaction blocks the admin, then tries to deploy.
        let block_admin = IConduitAllowList::setBlockedCall { addr: ADMIN, blocked: true };
        let tx = chain.l2(ADMIN, TxKind::Call(POLICY_HELPER), block_admin.abi_encode().into(), 0);
        assert!(chain.run(tx).is_success());
        assert_eq!(chain.storage(POLICY_HELPER, 0), U256::ZERO, "the create was denied");
        assert_eq!(chain.code_len(POLICY_HELPER.create(1)), 0);
    }

    #[test]
    fn tracing_enforces_the_same_policy() {
        let mut chain = Chain::new("allowlist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        assert!(chain.run_inspected(tx).is_success());
        assert_create_denied(&chain, FACTORY);
    }

    #[test]
    fn rpc_simulations_still_enforce_the_deployer_allowlist() {
        let mut chain = Chain::new("allowlist");
        let tx = chain.l2(OTHER, TxKind::Call(FACTORY), Bytes::new(), 0);
        let result = chain.try_run_at(ACTIVATION, tx, true).expect("simulations run");
        assert!(result.is_success());
        assert_create_denied(&chain, FACTORY);
    }

    #[test]
    fn denied_deposits_too_small_for_a_create_become_failed_deposits() {
        let mut chain = Chain::tx("allowlist");
        let mut tx = deposit(OTHER, TxKind::Call(FACTORY), Bytes::new(), 1_000);
        tx.0.base.gas_limit = 21_000;
        let result = chain.run(tx);

        assert!(
            matches!(result, ExecutionResult::Halt { reason: OpHaltReason::FailedDeposit, .. }),
            "{result:?}"
        );
        assert_eq!(chain.nonce(OTHER), 1, "the deposit's nonce is bumped");
        let balance = chain.db.cache.accounts.get(&OTHER).unwrap().info.balance;
        assert_eq!(balance, U256::from(1_000), "the mint is kept");
        assert_eq!(chain.nonce(FACTORY), 1, "the call never ran");
    }
}
