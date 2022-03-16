use std::sync::Arc;
use bytes::Bytes;
use ethereum_types::{Address, U256};
use kvdb::KeyValueDB;
use block::OpenBlock;
use client::PrepareOpenBlock;
use engines::EthEngine;
use error::Error;
use ethtrie::TrieFactory;
use evm::VMType;
use factory::{Factories, VmFactory};
use state_db::StateDB;
use trie::TrieSpec;
use types::header::Header;
use vm::LastHashes;

/// Riscv evm execution env.
pub struct RiscvEnv {
	engine: Arc<dyn EthEngine>,
	state_db: StateDB,
	last_hashes: Arc<LastHashes>,
	factories: Factories,
	parent_block_header: Header,
}

impl RiscvEnv {
	/// Create a new client with given parameters.
	pub fn new(
		engine: Arc<dyn EthEngine>,
		last_hashes: Arc<LastHashes>,
		parent_block_header: Header,
		db: Arc<dyn KeyValueDB>,
	) -> Result<RiscvEnv, Error> {
		let mb = 1024 * 1024;
		let pruning =  journaldb::Algorithm::OverlayRecent;
		let state_cache_size = 1 * mb;
		let jump_table_size =  1 * mb;
		let trie_factory = TrieFactory::new(TrieSpec::Secure);
		let factories = Factories {
			vm: VmFactory::new(VMType::Interpreter, jump_table_size),
			trie: trie_factory,
			accountdb: Default::default(),
		};

		let journal_db = journaldb::new(db, pruning, ::db::COL_STATE);
		let state_db = StateDB::new(journal_db, state_cache_size);

		Ok(RiscvEnv {
			engine,
			state_db,
			last_hashes,
			factories,
			parent_block_header,
		})
	}
}

impl PrepareOpenBlock for RiscvEnv {
	fn prepare_open_block(
		&self,
		author: Address,
		gas_range_target: (U256, U256),
		extra_data: Bytes,
	) -> Result<OpenBlock, Error> {
		let engine = &*self.engine;
		let h = self.parent_block_header.hash();

		let open_block = OpenBlock::new(
			engine,
			self.factories.clone(),
			false,
			self.state_db.boxed_clone_canon(&h),
			&self.parent_block_header,
			self.last_hashes.clone(),
			author,
			gas_range_target,
			extra_data,
		)?;

		Ok(open_block)
	}
}
