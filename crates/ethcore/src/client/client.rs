// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use blockchain::{
    BlockChain, BlockChainDB, BlockProvider, BlockReceipts, ExtrasInsert,
    ImportRoute, TransactionAddress, TreeRoute,
};
use bytes::Bytes;
use db::{DBTransaction, DBValue};
use ethereum_types::{Address, H256, U256};
use hash::keccak;
use parking_lot::{Mutex, RwLock};
use trie::{Trie, TrieFactory, TrieSpec};
use types::{
    ancestry_action::AncestryAction,
    encoded,
    filter::Filter,
    header::{ExtendedHeader, Header},
    log_entry::LocalizedLogEntry,
    receipt::{LocalizedReceipt, TypedReceipt},
    transaction::{Action, LocalizedTransaction, SignedTransaction},
    BlockNumber,
};
use vm::{EnvInfo, LastHashes};

use block::{enact_verified, Drain, LockedBlock, OpenBlock, SealedBlock};
use client::{
    AccountData, Balance, BlockChain as BlockChainTrait, BlockChainClient,
    BlockId, BlockInfo, Call,
    CallAnalytics, ChainInfo, ClientConfig,
    EngineInfo, ImportBlock, ImportSealedBlock,
    Nonce, PrepareOpenBlock, ProvingBlockChainClient, PruningInfo,
    StateInfo, StateOrBlock, TraceFilter, TraceId,
    TransactionId,
};
use engines::{EthEngine, ForkChoice};
use error::{
    BlockError, CallError, Error as EthcoreError, ErrorKind as EthcoreErrorKind,
    EthcoreResult, ExecutionError, ImportErrorKind,
};
use executive::{contract_address, Executed, Executive, TransactOptions};
use factory::{Factories, VmFactory};
use spec::Spec;
use state::{self, State};
use state_db::StateDB;
use trace::{
    self, Database as TraceDatabase, ImportRequest as TraceImportRequest, LocalizedTrace, TraceDB,
};
use transaction_ext::Transaction;
use verification::{self, queue::kind::{blocks::Unverified, BlockLike}, PreverifiedBlock, Verifier, BlockVerifier};
// re-export
pub use types::{block_status::BlockStatus, blockchain_info::BlockChainInfo};

struct Importer {
    /// Lock used during block import
    pub import_lock: Mutex<()>, // FIXME Maybe wrap the whole `Importer` instead?

    /// Used to verify blocks
    pub verifier: Box<dyn Verifier<Client>>,

	/// Queue containing pending blocks
	pub block_verifier: BlockVerifier,

    /// Ethereum engine to be used during import
    pub engine: Arc<dyn EthEngine>,
}

/// Blockchain database client backed by a persistent database. Owns and manages a blockchain and a block queue.
/// Call `import_block()` to import a block asynchronously; `flush_queue()` flushes the queue.
pub struct Client {
    chain: RwLock<Arc<BlockChain>>,
    tracedb: RwLock<TraceDB<BlockChain>>,
    engine: Arc<dyn EthEngine>,

    /// Client uses this to store blocks, traces, etc.
    db: RwLock<Arc<dyn BlockChainDB>>,

    state_db: RwLock<StateDB>,
    last_hashes: RwLock<VecDeque<H256>>,
    factories: Factories,
    importer: Importer,
}

impl Importer {
    pub fn new(
        config: &ClientConfig,
        engine: Arc<dyn EthEngine>,
    ) -> Result<Importer, EthcoreError> {
		let block_verifier = BlockVerifier::new(engine.clone(), config.verifier_type.verifying_seal());
        Ok(Importer {
            import_lock: Mutex::new(()),
            verifier: verification::new(config.verifier_type.clone()),
			block_verifier,
            engine,
        })
    }
    // t_nb 6.0.1 check and lock block,
    fn check_and_lock_block(
        &self,
        block: PreverifiedBlock,
        client: &Client,
    ) -> EthcoreResult<LockedBlock> {
        let engine = &*self.engine;
        let header = block.header.clone();

        // Check the block isn't so old we won't be able to enact it.
        // t_nb 7.1 check if block is older then last pruned block
        let best_block_number = client.chain.read().best_block_number();
        if client.pruning_info().earliest_state > header.number() {
            warn!(target: "client", "Block import failed for #{} ({})\nBlock is ancient (current best block: #{}).", header.number(), header.hash(), best_block_number);
            bail!("Block is ancient");
        }

        // t_nb 7.2 Check if parent is in chain
        let parent = match client.block_header_decoded(BlockId::Hash(*header.parent_hash())) {
            Some(h) => h,
            None => {
                warn!(target: "client", "Block import failed for #{} ({}): Parent not found ({}) ", header.number(), header.hash(), header.parent_hash());
                bail!("Parent not found");
            }
        };

        let chain = client.chain.read();
        // t_nb 7.3 verify block family
        let verify_family_result = self.verifier.verify_block_family(
            &header,
            &parent,
            engine,
            Some(verification::FullFamilyParams {
                block: &block,
                block_provider: &**chain,
                client,
            }),
        );

        if let Err(e) = verify_family_result {
            warn!(target: "client", "Stage 3 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
            bail!(e);
        };

        // t_nb 7.4 verify block external
        let verify_external_result = self.verifier.verify_block_external(&header, engine);
        if let Err(e) = verify_external_result {
            warn!(target: "client", "Stage 4 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
            bail!(e);
        };

        // Enact Verified Block
        // t_nb 7.5 Get build last hashes. Get parent state db. Get epoch_transition
        let last_hashes = client.build_last_hashes(header.parent_hash());

        let db = client
            .state_db
            .read()
            .boxed_clone_canon(header.parent_hash());

        // t_nb 8.0 Block enacting. Execution of transactions.
        let enact_result = enact_verified(
            block,
            engine,
            client.tracedb.read().tracing_enabled(),
            db,
            &parent,
            last_hashes,
            client.factories.clone(),
        );

        let mut locked_block = match enact_result {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "client", "Block import failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
                bail!(e);
            }
        };

        // t_nb 7.6 Strip receipts for blocks before validate_receipts_transition,
        // if the expected receipts root header does not match.
        // (i.e. allow inconsistency in receipts outcome before the transition block)
        if header.number() < engine.params().validate_receipts_transition
            && header.receipts_root() != locked_block.header.receipts_root()
        {
            locked_block.strip_receipts_outcomes();
        }

        // t_nb 7.7 Final Verification. See if block that we created (executed) matches exactly with block that we received.
        if let Err(e) = self
            .verifier
            .verify_block_final(&header, &locked_block.header)
        {
            warn!(target: "client", "Stage 5 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
            bail!(e);
        }

        Ok(locked_block)
    }

    // NOTE: the header of the block passed here is not necessarily sealed, as
    // it is for reconstructing the state transition.
    //
    // The header passed is from the original block data and is sealed.
    // TODO: should return an error if ImportRoute is none, issue #9910
    fn commit_block<B>(
        &self,
        block: B,
        header: &Header,
        block_data: encoded::Block,
        client: &Client,
    ) -> ImportRoute
    where
        B: Drain,
    {
        let hash = &header.hash();
        let number = header.number();
        let parent = header.parent_hash();
        let chain = client.chain.read();
        let mut is_finalized = false;

        // Commit results
        let block = block.drain();
        debug_assert_eq!(header.hash(), block_data.header_view().hash());

        let mut batch = DBTransaction::new();

        // t_nb 9.1 Gather all ancestry actions. (Used only by AuRa)
        let ancestry_actions = self
            .engine
            .ancestry_actions(&header, &mut chain.ancestry_with_metadata_iter(*parent));

        let receipts = block.receipts;
        let traces = block.traces.drain();
        let best_hash = chain.best_block_hash();

        let new = ExtendedHeader {
            header: header.clone(),
            is_finalized,
            parent_total_difficulty: chain
                .block_details(&parent)
                .expect("Parent block is in the database; qed")
                .total_difficulty,
        };

        let best = {
            let hash = best_hash;
            let header = chain
                .block_header_data(&hash)
                .expect("Best block is in the database; qed")
                .decode(self.engine.params().eip1559_transition)
                .expect("Stored block header is valid RLP; qed");
            let details = chain
                .block_details(&hash)
                .expect("Best block is in the database; qed");

            ExtendedHeader {
                parent_total_difficulty: details.total_difficulty - *header.difficulty(),
                is_finalized: details.is_finalized,
                header: header,
            }
        };

        // t_nb 9.2 calcuate route between current and latest block.
        let route = chain.tree_route(best_hash, *parent).expect("forks are only kept when it has common ancestors; tree route from best to prospective's parent always exists; qed");

        // t_nb 9.3 Check block total difficulty
        let fork_choice = if route.is_from_route_finalized {
            ForkChoice::Old
        } else {
            self.engine.fork_choice(&new, &best)
        };

        // t_nb 9.4 CHECK! I *think* this is fine, even if the state_root is equal to another
        // already-imported block of the same number.
        // TODO: Prove it with a test.
        let mut state = block.state.drop().1;

        // t_nb 9.6 push state to database Transaction. (It calls journal_under from JournalDB)
        state
            .journal_under(&mut batch, number, hash)
            .expect("DB commit failed");

        let _finalized: Vec<_> = ancestry_actions
            .into_iter()
            .map(|ancestry_action| {
                let AncestryAction::MarkFinalized(a) = ancestry_action;

                if a != header.hash() {
                    // t_nb 9.7 if there are finalized ancester, mark that chainge in block in db. (Used by AuRa)
                    chain
                        .mark_finalized(&mut batch, a)
                        .expect("Engine's ancestry action must be known blocks; qed");
                } else {
                    // we're finalizing the current block
                    is_finalized = true;
                }

                a
            })
            .collect();

        // t_nb 9.8 insert block
        let route = chain.insert_block(
            &mut batch,
            block_data,
            receipts.clone(),
            ExtrasInsert {
                fork_choice: fork_choice,
                is_finalized,
            },
        );

        // t_nb 9.9 insert traces (if they are enabled)
        client.tracedb.read().import(
            &mut batch,
            TraceImportRequest {
                traces: traces.into(),
                block_hash: hash.clone(),
                block_number: number,
                enacted: route.enacted.clone(),
                retracted: route.retracted.len(),
            },
        );

        let is_canon = route.enacted.last().map_or(false, |h| h == hash);

        // t_nb 9.10 sync cache
        state.sync_cache(&route.enacted, &route.retracted, is_canon);
        // Final commit to the DB
        // t_nb 9.11 Write Transaction to database (cached)
        client.db.read().key_value().write_buffered(batch);
        // t_nb 9.12 commit changed to become current greatest by applying pending insertion updates (Sync point)
        chain.commit();

        // t_nb 9.14 update last hashes. They are build in step 7.5
        client.update_last_hashes(&parent, hash);

        route
    }
}

impl Client {
    /// Create a new client with given parameters.
    /// The database is assumed to have been initialized with the correct columns.
    pub fn new(
        config: ClientConfig,
        spec: &Spec,
        db: Arc<dyn BlockChainDB>,
    ) -> Result<Arc<Client>, ::error::Error> {
        let trie_spec = match config.fat_db {
            true => TrieSpec::Fat,
            false => TrieSpec::Secure,
        };

        let trie_factory = TrieFactory::new(trie_spec);
        let factories = Factories {
            vm: VmFactory::new(config.vm_type.clone(), config.jump_table_size),
            trie: trie_factory,
            accountdb: Default::default(),
        };

        let journal_db = journaldb::new(db.key_value().clone(), config.pruning, ::db::COL_STATE);
        let mut state_db = StateDB::new(journal_db, config.state_cache_size);
        if state_db.journal_db().is_empty() {
            // Sets the correct state root.
            state_db = spec.ensure_db_good(state_db, &factories)?;
            let mut batch = DBTransaction::new();
            state_db.journal_under(&mut batch, 0, &spec.genesis_header().hash())?;
            db.key_value().write(batch)?;
        }

        let gb = spec.genesis_block();
        let chain = Arc::new(BlockChain::new(
            config.blockchain.clone(),
            &gb,
            db.clone(),
            spec.params().eip1559_transition,
        ));
        let tracedb = RwLock::new(TraceDB::new(
            config.tracing.clone(),
            db.clone(),
            chain.clone(),
        ));

        trace!(
            "Cleanup journal: DB Earliest = {:?}, Latest = {:?}",
            state_db.journal_db().earliest_era(),
            state_db.journal_db().latest_era()
        );

        if !chain
            .block_header_data(&chain.best_block_hash())
            .map_or(true, |h| state_db.journal_db().contains(&h.state_root()))
        {
            warn!(
                "State root not found for block #{} ({:x})",
                chain.best_block_number(),
                chain.best_block_hash()
            );
        }

        let engine = spec.engine.clone();
        let importer = Importer::new(&config, engine.clone())?;
        let client = Arc::new(Client {
            chain: RwLock::new(chain),
            tracedb,
            engine,
            db: RwLock::new(db.clone()),
            state_db: RwLock::new(state_db),
            last_hashes: RwLock::new(VecDeque::new()),
            factories,
            importer,
        });

        // ensure buffered changes are flushed.
        client.db.read().key_value().flush()?;
        Ok(client)
    }

    /// signals shutdown of application. We do cleanup here.
    pub fn shutdown(&self) { }

    /// Returns engine reference.
    pub fn engine(&self) -> &dyn EthEngine {
        &*self.engine
    }

    /// The env info as of the best block.
    pub fn latest_env_info(&self) -> EnvInfo {
        self.env_info(BlockId::Latest)
            .expect("Best block header always stored; qed")
    }

    /// The env info as of a given block.
    /// returns `None` if the block unknown.
    pub fn env_info(&self, id: BlockId) -> Option<EnvInfo> {
        self.block_header(id).map(|header| EnvInfo {
            number: header.number(),
            author: header.author(),
            timestamp: header.timestamp(),
            difficulty: header.difficulty(),
            last_hashes: self.build_last_hashes(&header.parent_hash()),
            gas_used: U256::default(),
            gas_limit: header.gas_limit(),
            base_fee: if header.number() >= self.engine.params().eip1559_transition {
                Some(header.base_fee())
            } else {
                None
            },
        })
    }

    fn build_last_hashes(&self, parent_hash: &H256) -> Arc<LastHashes> {
        {
            let hashes = self.last_hashes.read();
            if hashes.front().map_or(false, |h| h == parent_hash) {
                let mut res = Vec::from(hashes.clone());
                res.resize(256, H256::default());
                return Arc::new(res);
            }
        }
        let mut last_hashes = LastHashes::new();
        last_hashes.resize(256, H256::default());
        last_hashes[0] = parent_hash.clone();
        let chain = self.chain.read();
        for i in 0..255 {
            match chain.block_details(&last_hashes[i]) {
                Some(details) => {
                    last_hashes[i + 1] = details.parent.clone();
                }
                None => break,
            }
        }
        let mut cached_hashes = self.last_hashes.write();
        *cached_hashes = VecDeque::from(last_hashes.clone());
        Arc::new(last_hashes)
    }

    /// This is triggered by a message coming from a block queue when the block is ready for insertion
    pub fn import_verified_blocks(&self) -> usize {
		return 0;
    }

    // t_nb 9.14 update last hashes. They are build in step 7.5
    fn update_last_hashes(&self, parent: &H256, hash: &H256) {
        let mut hashes = self.last_hashes.write();
        if hashes.front().map_or(false, |h| h == parent) {
            if hashes.len() > 255 {
                hashes.pop_back();
            }
            hashes.push_front(hash.clone());
        }
    }

    #[cfg(test)]
    pub fn chain(&self) -> Arc<BlockChain> {
        self.chain.read().clone()
    }

    /// Get a copy of the best block's state.
    pub fn latest_state_and_header(&self) -> (State<StateDB>, Header) {
        let mut nb_tries = 5;
        // Here, we are taking latest block and then latest state. If in between those two calls `best` block got prunned app will panic.
        // This is something that should not happend often and it is edge case.
        // Locking read best_block lock would be more straighforward, but can introduce overlaping locks,
        // because of this we are just taking 5 tries to get best state in most cases it will work on first try.
        while nb_tries != 0 {
            let header = self.best_block_header();
            match State::from_existing(
                self.state_db.read().boxed_clone_canon(&header.hash()),
                *header.state_root(),
                self.engine.account_start_nonce(header.number()),
                self.factories.clone(),
            ) {
                Ok(ret) => return (ret, header),
                Err(_) => {
                    warn!("Couldn't fetch state of best block header: {:?}", header);
                    nb_tries -= 1;
                }
            }
        }
        panic!("Couldn't get latest state in 5 tries");
    }

    /// Attempt to get a copy of a specific block's final state.
    ///
    /// This will not fail if given BlockId::Latest.
    /// Otherwise, this can fail (but may not) if the DB prunes state or the block
    /// is unknown.
    pub fn state_at(&self, id: BlockId) -> Option<State<StateDB>> {
        // fast path for latest state.
        if let BlockId::Latest = id {
            let (state, _) = self.latest_state_and_header();
            return Some(state);
        }

        let block_number = self.block_number(id)?;

        self.block_header(id).and_then(|header| {
            let db = self.state_db.read().boxed_clone();

            // early exit for pruned blocks
            if db.is_pruned() && self.pruning_info().earliest_state > block_number {
                return None;
            }

            let root = header.state_root();
            State::from_existing(
                db,
                root,
                self.engine.account_start_nonce(block_number),
                self.factories.clone(),
            )
            .ok()
        })
    }

    /// Attempt to get a copy of a specific block's beginning state.
    ///
    /// This will not fail if given BlockId::Latest.
    /// Otherwise, this can fail (but may not) if the DB prunes state.
    pub fn state_at_beginning(&self, id: BlockId) -> Option<State<StateDB>> {
        match self.block_number(id) {
            None => None,
            Some(0) => self.state_at(id),
            Some(n) => self.state_at(BlockId::Number(n - 1)),
        }
    }

    /// Get a copy of the best block's state.
    pub fn state(&self) -> impl StateInfo {
        let (state, _) = self.latest_state_and_header();
        state
    }

    fn block_hash(chain: &BlockChain, id: BlockId) -> Option<H256> {
        match id {
            BlockId::Hash(hash) => Some(hash),
            BlockId::Number(number) => chain.block_hash(number),
            BlockId::Earliest => chain.block_hash(0),
            BlockId::Latest => Some(chain.best_block_hash()),
        }
    }

    fn transaction_address(&self, id: TransactionId) -> Option<TransactionAddress> {
        match id {
            TransactionId::Hash(ref hash) => self.chain.read().transaction_address(hash),
            TransactionId::Location(id, index) => {
                Self::block_hash(&self.chain.read(), id).map(|hash| TransactionAddress {
                    block_hash: hash,
                    index: index,
                })
            }
        }
    }

    fn do_virtual_call(
        machine: &::machine::EthereumMachine,
        env_info: &EnvInfo,
        state: &mut State<StateDB>,
        t: &SignedTransaction,
        analytics: CallAnalytics,
    ) -> Result<Executed, CallError> {
        fn call<V, T>(
            state: &mut State<StateDB>,
            env_info: &EnvInfo,
            machine: &::machine::EthereumMachine,
            state_diff: bool,
            transaction: &SignedTransaction,
            options: TransactOptions<T, V>,
        ) -> Result<Executed<T::Output, V::Output>, CallError>
        where
            T: trace::Tracer,
            V: trace::VMTracer,
        {
            let options = options.dont_check_nonce().save_output_from_contract();
            let original_state = if state_diff {
                Some(state.clone())
            } else {
                None
            };
            let schedule = machine.schedule(env_info.number);

            let mut ret = Executive::new(state, env_info, &machine, &schedule)
                .transact_virtual(transaction, options)?;

            if let Some(original) = original_state {
                ret.state_diff = Some(state.diff_from(original).map_err(ExecutionError::from)?);
            }
            Ok(ret)
        }

        let state_diff = analytics.state_diffing;

        match (analytics.transaction_tracing, analytics.vm_tracing) {
            (true, true) => call(
                state,
                env_info,
                machine,
                state_diff,
                t,
                TransactOptions::with_tracing_and_vm_tracing(),
            ),
            (true, false) => call(
                state,
                env_info,
                machine,
                state_diff,
                t,
                TransactOptions::with_tracing(),
            ),
            (false, true) => call(
                state,
                env_info,
                machine,
                state_diff,
                t,
                TransactOptions::with_vm_tracing(),
            ),
            (false, false) => call(
                state,
                env_info,
                machine,
                state_diff,
                t,
                TransactOptions::with_no_tracing(),
            ),
        }
    }

    fn block_number_ref(&self, id: &BlockId) -> Option<BlockNumber> {
        match *id {
            BlockId::Number(number) => Some(number),
            BlockId::Hash(ref hash) => self.chain.read().block_number(hash),
            BlockId::Earliest => Some(0),
            BlockId::Latest => Some(self.chain.read().best_block_number()),
        }
    }

    /// Retrieve a decoded header given `BlockId`
    ///
    /// This method optimizes access patterns for latest block header
    /// to avoid excessive RLP encoding, decoding and hashing.
    fn block_header_decoded(&self, id: BlockId) -> Option<Header> {
        match id {
            BlockId::Latest => Some(self.chain.read().best_block_header()),
            BlockId::Hash(ref hash) if hash == &self.chain.read().best_block_hash() => {
                Some(self.chain.read().best_block_header())
            }
            BlockId::Number(number) if number == self.chain.read().best_block_number() => {
                Some(self.chain.read().best_block_header())
            }
            _ => self
                .block_header(id)
                .and_then(|h| h.decode(self.engine.params().eip1559_transition).ok()),
        }
    }
}

impl Nonce for Client {
    fn nonce(&self, address: &Address, id: BlockId) -> Option<U256> {
        self.state_at(id).and_then(|s| s.nonce(address).ok())
    }
}

impl Balance for Client {
    fn balance(&self, address: &Address, state: StateOrBlock) -> Option<U256> {
        match state {
            StateOrBlock::State(s) => s.balance(address).ok(),
            StateOrBlock::Block(id) => self.state_at(id).and_then(|s| s.balance(address).ok()),
        }
    }
}

impl AccountData for Client {}

impl ChainInfo for Client {
    fn chain_info(&self) -> BlockChainInfo {
        let mut chain_info = self.chain.read().chain_info();
        chain_info.pending_total_difficulty = chain_info.total_difficulty;
        chain_info
    }
}

impl BlockInfo for Client {
    fn block_header(&self, id: BlockId) -> Option<encoded::Header> {
        let chain = self.chain.read();

        Self::block_hash(&chain, id).and_then(|hash| chain.block_header_data(&hash))
    }

    fn best_block_header(&self) -> Header {
        self.chain.read().best_block_header()
    }

    fn block(&self, id: BlockId) -> Option<encoded::Block> {
        let chain = self.chain.read();

        Self::block_hash(&chain, id).and_then(|hash| chain.block(&hash))
    }

    fn code_hash(&self, address: &Address, id: BlockId) -> Option<H256> {
        self.state_at(id)
            .and_then(|s| s.code_hash(address).unwrap_or(None))
    }
}

impl BlockChainTrait for Client {}

impl ImportBlock for Client {
    // t_nb 2.0 import block to client
    fn import_block(&self, unverified: Unverified) -> EthcoreResult<H256> {
        // t_nb 2.1 check if header hash is known to us.
        if self.chain.read().is_known(&unverified.hash()) {
            bail!(EthcoreErrorKind::Import(ImportErrorKind::AlreadyInChain));
        }

        // t_nb 2.2 check if parent is known
        let status = self.block_status(BlockId::Hash(unverified.parent_hash()));
        if status == BlockStatus::Unknown {
            bail!(EthcoreErrorKind::Block(BlockError::UnknownParent(
                unverified.parent_hash()
            )));
        }

        // t_nb 2.3
		let block = self.importer.block_verifier.verify(unverified)?;
		let header = block.header.clone();
		let bytes = block.bytes.clone();
		let hash = header.hash();
		// t_nb 7.0 check and lock block
		let closed_block =  self.importer.check_and_lock_block(block, self)?;
		trace!(target:"block_import","Block #{}({}) check pass",header.number(),header.hash());
		// t_nb 8.0 commit block to db
		self.importer.commit_block(closed_block, &header, encoded::Block::new(bytes), self);
		trace!(target:"block_import","Flush block to db");
		let db = self.db.read();
		db.key_value().flush().expect("DB flush failed.");
		Ok(hash)
	}
}

impl Drop for Client {
	fn drop(&mut self) {
		self.shutdown()
	}
}

impl Call for Client {
	type State = State<::state_db::StateDB>;

	fn call(
		&self,
		transaction: &SignedTransaction,
		analytics: CallAnalytics,
		state: &mut Self::State,
		header: &Header,
	) -> Result<Executed, CallError> {
		let env_info = EnvInfo {
			number: header.number(),
			author: header.author().clone(),
			timestamp: header.timestamp(),
            difficulty: header.difficulty().clone(),
            last_hashes: self.build_last_hashes(header.parent_hash()),
            gas_used: U256::default(),
            gas_limit: U256::max_value(),
            //if gas pricing is not defined, force base_fee to zero
            base_fee: if transaction.effective_gas_price(header.base_fee()).is_zero() {
                Some(0.into())
            } else {
                header.base_fee()
            },
        };
        let machine = self.engine.machine();

        Self::do_virtual_call(&machine, &env_info, state, transaction, analytics)
    }

    fn call_many(
        &self,
        transactions: &[(SignedTransaction, CallAnalytics)],
        state: &mut Self::State,
        header: &Header,
    ) -> Result<Vec<Executed>, CallError> {
        let mut env_info = EnvInfo {
            number: header.number(),
            author: header.author().clone(),
            timestamp: header.timestamp(),
            difficulty: header.difficulty().clone(),
            last_hashes: self.build_last_hashes(header.parent_hash()),
            gas_used: U256::default(),
            gas_limit: U256::max_value(),
            base_fee: header.base_fee(),
        };

        let mut results = Vec::with_capacity(transactions.len());
        let machine = self.engine.machine();

        for &(ref t, analytics) in transactions {
            //if gas pricing is not defined, force base_fee to zero
            if t.effective_gas_price(header.base_fee()).is_zero() {
                env_info.base_fee = Some(0.into());
            } else {
                env_info.base_fee = header.base_fee()
            }

            let ret = Self::do_virtual_call(machine, &env_info, state, t, analytics)?;
            env_info.gas_used = ret.cumulative_gas_used;
            results.push(ret);
        }

        Ok(results)
    }

    fn estimate_gas(
        &self,
        t: &SignedTransaction,
        state: &Self::State,
        header: &Header,
    ) -> Result<U256, CallError> {
        let (mut upper, max_upper, env_info) = {
            let init = *header.gas_limit();
            let max = init * U256::from(10);

            let env_info = EnvInfo {
                number: header.number(),
                author: header.author().clone(),
                timestamp: header.timestamp(),
                difficulty: header.difficulty().clone(),
                last_hashes: self.build_last_hashes(header.parent_hash()),
                gas_used: U256::default(),
                gas_limit: max,
                base_fee: if t.effective_gas_price(header.base_fee()).is_zero() {
                    Some(0.into())
                } else {
                    header.base_fee()
                },
            };

            (init, max, env_info)
        };

        let sender = t.sender();
        let options = || TransactOptions::with_tracing().dont_check_nonce();

        let exec = |gas| {
            let mut tx = t.as_unsigned().clone();
            tx.tx_mut().gas = gas;
            let tx = tx.fake_sign(sender);

            let mut clone = state.clone();
            let machine = self.engine.machine();
            let schedule = machine.schedule(env_info.number);
            Executive::new(&mut clone, &env_info, &machine, &schedule)
                .transact_virtual(&tx, options())
        };

        let cond = |gas| exec(gas).ok().map_or(false, |r| r.exception.is_none());

        if !cond(upper) {
            upper = max_upper;
            match exec(upper) {
                Ok(v) => {
                    if let Some(exception) = v.exception {
                        return Err(CallError::Exceptional(exception));
                    }
                }
                Err(_e) => {
                    trace!(target: "estimate_gas", "estimate_gas failed with {}", upper);
                    let err = ExecutionError::Internal(format!(
                        "Requires higher than upper limit of {}",
                        upper
                    ));
                    return Err(err.into());
                }
            }
        }
        let lower = t
            .tx()
            .gas_required(&self.engine.schedule(env_info.number))
            .into();
        if cond(lower) {
            trace!(target: "estimate_gas", "estimate_gas succeeded with {}", lower);
            return Ok(lower);
        }

        /// Find transition point between `lower` and `upper` where `cond` changes from `false` to `true`.
        /// Returns the lowest value between `lower` and `upper` for which `cond` returns true.
        /// We assert: `cond(lower) = false`, `cond(upper) = true`
        fn binary_chop<F, E>(mut lower: U256, mut upper: U256, mut cond: F) -> Result<U256, E>
        where
            F: FnMut(U256) -> bool,
        {
            while upper - lower > 1.into() {
                let mid = (lower + upper) / 2;
                trace!(target: "estimate_gas", "{} .. {} .. {}", lower, mid, upper);
                let c = cond(mid);
                match c {
                    true => upper = mid,
                    false => lower = mid,
                };
                trace!(target: "estimate_gas", "{} => {} .. {}", c, lower, upper);
            }
            Ok(upper)
        }

        // binary chop to non-excepting call with gas somewhere between 21000 and block gas limit
        trace!(target: "estimate_gas", "estimate_gas chopping {} .. {}", lower, upper);
        binary_chop(lower, upper, cond)
    }
}

impl EngineInfo for Client {
    fn engine(&self) -> &dyn EthEngine {
        Client::engine(self)
    }
}

impl BlockChainClient for Client {
    fn block_number(&self, id: BlockId) -> Option<BlockNumber> {
        self.block_number_ref(&id)
    }

    fn block_body(&self, id: BlockId) -> Option<encoded::Body> {
        let chain = self.chain.read();

        Self::block_hash(&chain, id).and_then(|hash| chain.block_body(&hash))
    }

    fn block_status(&self, id: BlockId) -> BlockStatus {
        let chain = self.chain.read();
        match Self::block_hash(&chain, id) {
            Some(ref hash) if chain.is_known(hash) => BlockStatus::InChain,
            _ => BlockStatus::Unknown,
        }
    }

    fn storage_root(&self, address: &Address, id: BlockId) -> Option<H256> {
        self.state_at(id)
            .and_then(|s| s.storage_root(address).ok())
            .and_then(|x| x)
    }

    fn block_hash(&self, id: BlockId) -> Option<H256> {
        let chain = self.chain.read();
        Self::block_hash(&chain, id)
    }

    fn code(&self, address: &Address, state: StateOrBlock) -> Option<Option<Bytes>> {
        let result = match state {
            StateOrBlock::State(s) => s.code(address).ok(),
            StateOrBlock::Block(id) => self.state_at(id).and_then(|s| s.code(address).ok()),
        };

        // Converting from `Option<Option<Arc<Bytes>>>` to `Option<Option<Bytes>>`
        result.map(|c| c.map(|c| (&*c).clone()))
    }

    fn storage_at(&self, address: &Address, position: &H256, state: StateOrBlock) -> Option<H256> {
        match state {
            StateOrBlock::State(s) => s.storage_at(address, position).ok(),
            StateOrBlock::Block(id) => self
                .state_at(id)
                .and_then(|s| s.storage_at(address, position).ok()),
        }
    }

    fn list_accounts(
        &self,
        id: BlockId,
        after: Option<&Address>,
        count: u64,
    ) -> Option<Vec<Address>> {
        if !self.factories.trie.is_fat() {
            trace!(target: "fatdb", "list_accounts: Not a fat DB");
            return None;
        }

        let state = match self.state_at(id) {
            Some(state) => state,
            _ => return None,
        };

        let (root, db) = state.drop();
        let db = &db.as_hash_db();
        let trie = match self.factories.trie.readonly(db, &root) {
            Ok(trie) => trie,
            _ => {
                trace!(target: "fatdb", "list_accounts: Couldn't open the DB");
                return None;
            }
        };

        let mut iter = match trie.iter() {
            Ok(iter) => iter,
            _ => return None,
        };

        if let Some(after) = after {
            if let Err(e) = iter.seek(after.as_bytes()) {
                trace!(target: "fatdb", "list_accounts: Couldn't seek the DB: {:?}", e);
            } else {
                // Position the iterator after the `after` element
                iter.next();
            }
        }

        let accounts = iter
            .filter_map(|item| item.ok().map(|(addr, _)| Address::from_slice(&addr)))
            .take(count as usize)
            .collect();

        Some(accounts)
    }

    fn list_storage(
        &self,
        id: BlockId,
        account: &Address,
        after: Option<&H256>,
        count: u64,
    ) -> Option<Vec<H256>> {
        if !self.factories.trie.is_fat() {
            trace!(target: "fatdb", "list_storage: Not a fat DB");
            return None;
        }

        let state = match self.state_at(id) {
            Some(state) => state,
            _ => return None,
        };

        let root = match state.storage_root(account) {
            Ok(Some(root)) => root,
            _ => return None,
        };

        let (_, db) = state.drop();
        let account_db = &self
            .factories
            .accountdb
            .readonly(db.as_hash_db(), keccak(account));
        let account_db = &account_db.as_hash_db();
        let trie = match self.factories.trie.readonly(account_db, &root) {
            Ok(trie) => trie,
            _ => {
                trace!(target: "fatdb", "list_storage: Couldn't open the DB");
                return None;
            }
        };

        let mut iter = match trie.iter() {
            Ok(iter) => iter,
            _ => return None,
        };

        if let Some(after) = after {
            if let Err(e) = iter.seek(after.as_bytes()) {
                trace!(target: "fatdb", "list_storage: Couldn't seek the DB: {:?}", e);
            } else {
                // Position the iterator after the `after` element
                iter.next();
            }
        }

        let keys = iter
            .filter_map(|item| item.ok().map(|(key, _)| H256::from_slice(&key)))
            .take(count as usize)
            .collect();

        Some(keys)
    }

    fn transaction_receipt(&self, id: TransactionId) -> Option<LocalizedReceipt> {
        // NOTE Don't use block_receipts here for performance reasons
        let address = self.transaction_address(id)?;
        let hash = address.block_hash;
        let chain = self.chain.read();
        let number = chain.block_number(&hash)?;
        let body = chain.block_body(&hash)?;
        let header = chain.block_header_data(&hash)?;
        let mut receipts = chain.block_receipts(&hash)?.receipts;
        receipts.truncate(address.index + 1);

        let transaction = body
            .view()
            .localized_transaction_at(&hash, number, address.index)?;
        let receipt = receipts.pop()?;
        let gas_used = receipts.last().map_or_else(|| 0.into(), |r| r.gas_used);
        let no_of_logs = receipts
            .into_iter()
            .map(|receipt| receipt.logs.len())
            .sum::<usize>();
        let base_fee = if number >= self.engine().params().eip1559_transition {
            Some(header.base_fee())
        } else {
            None
        };

        let receipt = transaction_receipt(
            self.engine().machine(),
            transaction,
            receipt,
            gas_used,
            no_of_logs,
            base_fee,
        );
        Some(receipt)
    }

    fn localized_block_receipts(&self, id: BlockId) -> Option<Vec<LocalizedReceipt>> {
        let hash = self.block_hash(id)?;

        let chain = self.chain.read();
        let receipts = chain.block_receipts(&hash)?;
        let number = chain.block_number(&hash)?;
        let body = chain.block_body(&hash)?;
        let header = chain.block_header_data(&hash)?;
        let engine = self.engine.clone();
        let base_fee = if number >= engine.params().eip1559_transition {
            Some(header.base_fee())
        } else {
            None
        };

        let mut gas_used = 0.into();
        let mut no_of_logs = 0;

        Some(
            body.view()
                .localized_transactions(&hash, number)
                .into_iter()
                .zip(receipts.receipts)
                .map(move |(transaction, receipt)| {
                    let result = transaction_receipt(
                        engine.machine(),
                        transaction,
                        receipt,
                        gas_used,
                        no_of_logs,
                        base_fee,
                    );
                    gas_used = result.cumulative_gas_used;
                    no_of_logs += result.logs.len();
                    result
                })
                .collect(),
        )
    }

    fn tree_route(&self, from: &H256, to: &H256) -> Option<TreeRoute> {
        let chain = self.chain.read();
        match chain.is_known(from) && chain.is_known(to) {
            true => chain.tree_route(from.clone(), to.clone()),
            false => None,
        }
    }

    fn block_receipts(&self, hash: &H256) -> Option<BlockReceipts> {
        self.chain.read().block_receipts(hash)
    }

    fn additional_params(&self) -> BTreeMap<String, String> {
        self.engine.additional_params().into_iter().collect()
    }

    fn logs(&self, filter: Filter) -> Result<Vec<LocalizedLogEntry>, BlockId> {
        let chain = self.chain.read();

        // First, check whether `filter.from_block` and `filter.to_block` is on the canon chain. If so, we can use the
        // optimized version.
        let is_canon = |id| {
            match id {
                // If it is referred by number, then it is always on the canon chain.
                &BlockId::Earliest | &BlockId::Latest | &BlockId::Number(_) => true,
                // If it is referred by hash, we see whether a hash -> number -> hash conversion gives us the same
                // result.
                &BlockId::Hash(ref hash) => chain.is_canon(hash),
            }
        };

        let blocks = if is_canon(&filter.from_block) && is_canon(&filter.to_block) {
            // If we are on the canon chain, use bloom filter to fetch required hashes.
            //
            // If we are sure the block does not exist (where val > best_block_number), then return error. Note that we
            // don't need to care about pending blocks here because RPC query sets pending back to latest (or handled
            // pending logs themselves).
            let from = match self.block_number_ref(&filter.from_block) {
                Some(val) if val <= chain.best_block_number() => val,
                _ => return Err(filter.from_block.clone()),
            };
            let to = match self.block_number_ref(&filter.to_block) {
                Some(val) if val <= chain.best_block_number() => val,
                _ => return Err(filter.to_block.clone()),
            };

            // If from is greater than to, then the current bloom filter behavior is to just return empty
            // result. There's no point to continue here.
            if from > to {
                return Err(filter.to_block.clone());
            }

            chain
                .blocks_with_bloom(&filter.bloom_possibilities(), from, to)
                .into_iter()
                .filter_map(|n| chain.block_hash(n))
                .collect::<Vec<H256>>()
        } else {
            // Otherwise, we use a slower version that finds a link between from_block and to_block.
            let from_hash = Self::block_hash(&chain, filter.from_block)
                .ok_or_else(|| filter.from_block.clone())?;
            let from_number = chain
                .block_number(&from_hash)
                .ok_or_else(|| BlockId::Hash(from_hash))?;
            let to_hash =
                Self::block_hash(&chain, filter.to_block).ok_or_else(|| filter.to_block.clone())?;

            let blooms = filter.bloom_possibilities();
            let bloom_match = |header: &encoded::Header| {
                blooms
                    .iter()
                    .any(|bloom| header.log_bloom().contains_bloom(bloom))
            };

            let (blocks, last_hash) = {
                let mut blocks = Vec::new();
                let mut current_hash = to_hash;

                loop {
                    let header = chain
                        .block_header_data(&current_hash)
                        .ok_or_else(|| BlockId::Hash(current_hash))?;
                    if bloom_match(&header) {
                        blocks.push(current_hash);
                    }

                    // Stop if `from` block is reached.
                    if header.number() <= from_number {
                        break;
                    }
                    current_hash = header.parent_hash();
                }

                blocks.reverse();
                (blocks, current_hash)
            };

            // Check if we've actually reached the expected `from` block.
            if last_hash != from_hash || blocks.is_empty() {
                // In this case, from_hash is the cause (for not matching last_hash).
                return Err(BlockId::Hash(from_hash));
            }

            blocks
        };

        Ok(chain.logs(blocks, |entry| filter.matches(entry), filter.limit))
    }

    fn filter_traces(&self, filter: TraceFilter) -> Option<Vec<LocalizedTrace>> {
        if !self.tracedb.read().tracing_enabled() {
            return None;
        }

        let start = self.block_number(filter.range.start)?;
        let end = self.block_number(filter.range.end)?;

        let db_filter = trace::Filter {
            range: start as usize..end as usize,
            from_address: filter.from_address.into(),
            to_address: filter.to_address.into(),
        };

        let traces = self
            .tracedb
            .read()
            .filter(&db_filter)
            .into_iter()
            .skip(filter.after.unwrap_or(0))
            .take(filter.count.unwrap_or(usize::max_value()))
            .collect();
        Some(traces)
    }

    fn trace(&self, trace: TraceId) -> Option<LocalizedTrace> {
        if !self.tracedb.read().tracing_enabled() {
            return None;
        }

        let trace_address = trace.address;
        self.transaction_address(trace.transaction)
            .and_then(|tx_address| {
                self.block_number(BlockId::Hash(tx_address.block_hash))
                    .and_then(|number| {
                        self.tracedb
                            .read()
                            .trace(number, tx_address.index, trace_address)
                    })
            })
    }

    fn transaction_traces(&self, transaction: TransactionId) -> Option<Vec<LocalizedTrace>> {
        if !self.tracedb.read().tracing_enabled() {
            return None;
        }

        self.transaction_address(transaction)
            .and_then(|tx_address| {
                self.block_number(BlockId::Hash(tx_address.block_hash))
                    .and_then(|number| {
                        self.tracedb
                            .read()
                            .transaction_traces(number, tx_address.index)
                    })
            })
    }

    fn last_hashes(&self) -> LastHashes {
        (*self.build_last_hashes(&self.chain.read().best_block_hash())).clone()
    }

    fn pruning_info(&self) -> PruningInfo {
        PruningInfo {
            earliest_chain: self.chain.read().first_block_number().unwrap_or(1),
            earliest_state: self
                .state_db
                .read()
                .journal_db()
                .earliest_era()
                .unwrap_or(0),
        }
    }

    fn state_data(&self, hash: &H256) -> Option<Bytes> {
        self.state_db.read().journal_db().state(hash)
    }
}

impl PrepareOpenBlock for Client {
    fn prepare_open_block(
        &self,
        author: Address,
        gas_range_target: (U256, U256),
        extra_data: Bytes,
    ) -> Result<OpenBlock, EthcoreError> {
        let engine = &*self.engine;
        let chain = self.chain.read();
        let best_header = chain.best_block_header();
        let h = best_header.hash();

        let open_block = OpenBlock::new(
            engine,
            self.factories.clone(),
            self.tracedb.read().tracing_enabled(),
            self.state_db.read().boxed_clone_canon(&h),
            &best_header,
            self.build_last_hashes(&h),
            author,
            gas_range_target,
            extra_data,
        )?;

        Ok(open_block)
    }
}

impl ImportSealedBlock for Client {
    fn import_sealed_block(&self, block: SealedBlock) -> EthcoreResult<H256> {
        let header = block.header.clone();
        let hash = header.hash();
		// Do a super duper basic verification to detect potential bugs
		if let Err(e) = self.engine.verify_block_basic(&header) {
			return Err(e.into());
		}

		// scope for self.import_lock
		let _import_lock = self.importer.import_lock.lock();

		let block_data = block.rlp_bytes();
		let route = self.importer.commit_block(
			block,
			&header,
			encoded::Block::new(block_data),
			self,
		);
		trace!(target: "client", "Imported sealed block #{} ({})", header.number(), hash);
		self.state_db
			.write()
			.sync_cache(&route.enacted, &route.retracted, false);
        self.db
            .read()
            .key_value()
            .flush()
            .expect("DB flush failed.");
        Ok(hash)
    }
}

impl super::traits::EngineClient for Client {
    fn as_full_client(&self) -> Option<&dyn BlockChainClient> {
        Some(self)
    }

    fn block_number(&self, id: BlockId) -> Option<BlockNumber> {
        <dyn BlockChainClient>::block_number(self, id)
    }

    fn block_header(&self, id: BlockId) -> Option<encoded::Header> {
        <dyn BlockChainClient>::block_header(self, id)
    }
}

impl ProvingBlockChainClient for Client {
    fn prove_storage(&self, key1: H256, key2: H256, id: BlockId) -> Option<(Vec<Bytes>, H256)> {
        self.state_at(id)
            .and_then(move |state| state.prove_storage(key1, key2).ok())
    }

    fn prove_account(
        &self,
        key1: H256,
        id: BlockId,
    ) -> Option<(Vec<Bytes>, ::types::basic_account::BasicAccount)> {
        self.state_at(id)
            .and_then(move |state| state.prove_account(key1).ok())
    }

    fn prove_transaction(
        &self,
        transaction: SignedTransaction,
        id: BlockId,
    ) -> Option<(Bytes, Vec<DBValue>)> {
        let (header, mut env_info) = match (self.block_header(id), self.env_info(id)) {
            (Some(s), Some(e)) => (s, e),
            _ => return None,
        };

        env_info.gas_limit = transaction.tx().gas.clone();
        let mut jdb = self.state_db.read().journal_db().boxed_clone();

        state::prove_transaction_virtual(
            jdb.as_hash_db_mut(),
            header.state_root().clone(),
            &transaction,
            self.engine.machine(),
            &env_info,
            self.factories.clone(),
        )
    }
}

/// Returns `LocalizedReceipt` given `LocalizedTransaction`
/// and a vector of receipts from given block up to transaction index.
fn transaction_receipt(
    machine: &::machine::EthereumMachine,
    mut tx: LocalizedTransaction,
    receipt: TypedReceipt,
    prior_gas_used: U256,
    prior_no_of_logs: usize,
    base_fee: Option<U256>,
) -> LocalizedReceipt {
    let sender = tx.sender();
    let transaction_hash = tx.hash();
    let block_hash = tx.block_hash;
    let block_number = tx.block_number;
    let transaction_index = tx.transaction_index;
    let transaction_type = tx.tx_type();

    let receipt = receipt.receipt().clone();

    LocalizedReceipt {
        from: sender,
        to: match tx.tx().action {
            Action::Create => None,
            Action::Call(ref address) => Some(address.clone().into()),
        },
        transaction_hash: transaction_hash,
        transaction_index: transaction_index,
        transaction_type: transaction_type,
        block_hash: block_hash,
        block_number: block_number,
        cumulative_gas_used: receipt.gas_used,
        gas_used: receipt.gas_used - prior_gas_used,
        contract_address: match tx.tx().action {
            Action::Call(_) => None,
            Action::Create => Some(
                contract_address(
                    machine.create_address_scheme(block_number),
                    &sender,
                    &tx.tx().nonce,
                    &tx.tx().data,
                )
                .0,
            ),
        },
        logs: receipt
            .logs
            .into_iter()
            .enumerate()
            .map(|(i, log)| LocalizedLogEntry {
                entry: log,
                block_hash: block_hash,
                block_number: block_number,
                transaction_hash: transaction_hash,
                transaction_index: transaction_index,
                transaction_log_index: i,
                log_index: prior_no_of_logs + i,
            })
            .collect(),
        log_bloom: receipt.log_bloom,
        outcome: receipt.outcome.clone(),
        effective_gas_price: tx.effective_gas_price(base_fee),
    }
}

#[cfg(test)]
mod tests {
    use blockchain::{BlockProvider, ExtrasInsert};
    use ethereum_types::{H160, H256};
    use spec::Spec;
    use test_helpers::generate_dummy_client_with_spec_and_data;

    #[test]
    fn should_not_cache_details_before_commit() {
        use client::{BlockChainClient, ChainInfo};
        use test_helpers::{generate_dummy_client, get_good_dummy_block_hash};

        use kvdb::DBTransaction;
        use std::{
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
            time::Duration,
        };
        use types::encoded;

        let client = generate_dummy_client(0);
        let genesis = client.chain_info().best_block_hash;
        let (new_hash, new_block) = get_good_dummy_block_hash();

        let go = {
            // Separate thread uncommitted transaction
            let go = Arc::new(AtomicBool::new(false));
            let go_thread = go.clone();
            let another_client = client.clone();
            thread::spawn(move || {
                let mut batch = DBTransaction::new();
                another_client.chain.read().insert_block(
                    &mut batch,
                    encoded::Block::new(new_block),
                    Vec::new(),
                    ExtrasInsert {
                        fork_choice: ::engines::ForkChoice::New,
                        is_finalized: false,
                    },
                );
                go_thread.store(true, Ordering::SeqCst);
            });
            go
        };

        while !go.load(Ordering::SeqCst) {
            thread::park_timeout(Duration::from_millis(5));
        }

        assert!(client.tree_route(&genesis, &new_hash).is_none());
    }

    #[test]
    fn should_return_block_receipts() {
        use client::{BlockChainClient, BlockId, TransactionId};
        use test_helpers::generate_dummy_client_with_data;

        let client = generate_dummy_client_with_data(2, 2, &[1.into(), 1.into()]);
        let receipts = client.localized_block_receipts(BlockId::Latest).unwrap();

        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].transaction_index, 0);
        assert_eq!(receipts[0].block_number, 2);
        assert_eq!(receipts[0].cumulative_gas_used, 53_000.into());
        assert_eq!(receipts[0].gas_used, 53_000.into());

        assert_eq!(receipts[1].transaction_index, 1);
        assert_eq!(receipts[1].block_number, 2);
        assert_eq!(receipts[1].cumulative_gas_used, 106_000.into());
        assert_eq!(receipts[1].gas_used, 53_000.into());

        let receipt = client.transaction_receipt(TransactionId::Hash(receipts[0].transaction_hash));
        assert_eq!(receipt, Some(receipts[0].clone()));

        let receipt = client.transaction_receipt(TransactionId::Hash(receipts[1].transaction_hash));
        assert_eq!(receipt, Some(receipts[1].clone()));
    }

    #[test]
    fn should_return_correct_log_index() {
        use super::transaction_receipt;
        use crypto::publickey::KeyPair;
        use hash::keccak;
        use types::{
            log_entry::{LocalizedLogEntry, LogEntry},
            receipt::{LegacyReceipt, LocalizedReceipt, TransactionOutcome, TypedReceipt},
            transaction::{Action, LocalizedTransaction, Transaction, TypedTransaction},
        };

        // given
        let key = KeyPair::from_secret_slice(keccak("test").as_bytes()).unwrap();
        let secret = key.secret();
        let machine = ::ethereum::new_frontier_test_machine();

        let block_number = 1;
        let block_hash = H256::from_low_u64_be(5);
        let state_root = H256::from_low_u64_be(99);
        let gas_used = 10.into();
        let raw_tx = TypedTransaction::Legacy(Transaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas: 21000.into(),
            action: Action::Call(H160::from_low_u64_be(10)),
            value: 0.into(),
            data: vec![],
        });
        let tx1 = raw_tx.clone().sign(secret, None);
        let transaction = LocalizedTransaction {
            signed: tx1.clone().into(),
            block_number: block_number,
            block_hash: block_hash,
            transaction_index: 1,
            cached_sender: Some(tx1.sender()),
        };
        let logs = vec![
            LogEntry {
                address: H160::from_low_u64_be(5),
                topics: vec![],
                data: vec![],
            },
            LogEntry {
                address: H160::from_low_u64_be(15),
                topics: vec![],
                data: vec![],
            },
        ];
        let receipt = TypedReceipt::Legacy(LegacyReceipt {
            outcome: TransactionOutcome::StateRoot(state_root),
            gas_used: gas_used,
            log_bloom: Default::default(),
            logs: logs.clone(),
        });

        // when
        let receipt = transaction_receipt(&machine, transaction, receipt, 5.into(), 1, None);

        // then
        assert_eq!(
            receipt,
            LocalizedReceipt {
                from: tx1.sender().into(),
                to: match tx1.tx().action {
                    Action::Create => None,
                    Action::Call(ref address) => Some(address.clone().into()),
                },
                transaction_hash: tx1.hash(),
                transaction_index: 1,
                transaction_type: tx1.tx_type(),
                block_hash: block_hash,
                block_number: block_number,
                cumulative_gas_used: gas_used,
                gas_used: gas_used - 5,
                contract_address: None,
                logs: vec![
                    LocalizedLogEntry {
                        entry: logs[0].clone(),
                        block_hash: block_hash,
                        block_number: block_number,
                        transaction_hash: tx1.hash(),
                        transaction_index: 1,
                        transaction_log_index: 0,
                        log_index: 1,
                    },
                    LocalizedLogEntry {
                        entry: logs[1].clone(),
                        block_hash: block_hash,
                        block_number: block_number,
                        transaction_hash: tx1.hash(),
                        transaction_index: 1,
                        transaction_log_index: 1,
                        log_index: 2,
                    }
                ],
                log_bloom: Default::default(),
                outcome: TransactionOutcome::StateRoot(state_root),
                effective_gas_price: Default::default(),
            }
        );
    }

    #[test]
    fn should_mark_finalization_correctly_for_parent() {
        let client = generate_dummy_client_with_spec_and_data(
            Spec::new_test_with_finality,
            2,
            0,
            &[],
            false,
        );
        let chain = client.chain();

        let block1_details = chain.block_hash(1).and_then(|h| chain.block_details(&h));
        assert!(block1_details.is_some());
        let block1_details = block1_details.unwrap();
        assert_eq!(block1_details.children.len(), 1);
        assert!(block1_details.is_finalized);

        let block2_details = chain.block_hash(2).and_then(|h| chain.block_details(&h));
        assert!(block2_details.is_some());
        let block2_details = block2_details.unwrap();
        assert_eq!(block2_details.children.len(), 0);
        assert!(!block2_details.is_finalized);
    }
}
