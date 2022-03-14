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

//! Traits implemented by client.

use std::{collections::BTreeMap};

use blockchain::{BlockReceipts, TreeRoute};
use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use kvdb::DBValue;
use types::{
    basic_account::BasicAccount,
    block_status::BlockStatus,
    blockchain_info::BlockChainInfo,
    call_analytics::CallAnalytics,
    encoded,
    filter::Filter,
    header::Header,
    ids::*,
    log_entry::LocalizedLogEntry,
    pruning_info::PruningInfo,
    receipt::LocalizedReceipt,
    trace_filter::Filter as TraceFilter,
    transaction::SignedTransaction,
    BlockNumber,
};
use vm::LastHashes;

use block::{OpenBlock, SealedBlock};
use engines::EthEngine;
use error::{Error, EthcoreResult};
use executed::CallError;
use executive::Executed;
use state::StateInfo;
use trace::LocalizedTrace;
use verification::queue::kind::blocks::Unverified;

/// State information to be used during client query
pub enum StateOrBlock {
    /// State to be used, may be pending
    State(Box<dyn StateInfo>),

    /// Id of an existing block from a chain to get state from
    Block(BlockId),
}

impl<S: StateInfo + 'static> From<S> for StateOrBlock {
    fn from(info: S) -> StateOrBlock {
        StateOrBlock::State(Box::new(info) as Box<_>)
    }
}

impl From<Box<dyn StateInfo>> for StateOrBlock {
    fn from(info: Box<dyn StateInfo>) -> StateOrBlock {
        StateOrBlock::State(info)
    }
}

impl From<BlockId> for StateOrBlock {
    fn from(id: BlockId) -> StateOrBlock {
        StateOrBlock::Block(id)
    }
}

/// Provides `nonce` and `latest_nonce` methods
pub trait Nonce {
    /// Attempt to get address nonce at given block.
    /// May not fail on BlockId::Latest.
    fn nonce(&self, address: &Address, id: BlockId) -> Option<U256>;

    /// Get address nonce at the latest block's state.
    fn latest_nonce(&self, address: &Address) -> U256 {
        self.nonce(address, BlockId::Latest).expect(
            "nonce will return Some when given BlockId::Latest. nonce was given BlockId::Latest. \
			Therefore nonce has returned Some; qed",
        )
    }
}

/// Provides `balance` and `latest_balance` methods
pub trait Balance {
    /// Get address balance at the given block's state.
    ///
    /// May not return None if given BlockId::Latest.
    /// Returns None if and only if the block's root hash has been pruned from the DB.
    fn balance(&self, address: &Address, state: StateOrBlock) -> Option<U256>;

    /// Get address balance at the latest block's state.
    fn latest_balance(&self, address: &Address) -> U256 {
        self.balance(address, BlockId::Latest.into()).expect(
            "balance will return Some if given BlockId::Latest. balance was given BlockId::Latest \
			Therefore balance has returned Some; qed",
        )
    }
}

/// Provides methods to access account info
pub trait AccountData: Nonce + Balance {}

/// Provides `chain_info` method
pub trait ChainInfo {
    /// Get blockchain information.
    fn chain_info(&self) -> BlockChainInfo;
}

/// Provides various information on a block by it's ID
pub trait BlockInfo {
    /// Get raw block header data by block id.
    fn block_header(&self, id: BlockId) -> Option<encoded::Header>;

    /// Get the best block header.
    fn best_block_header(&self) -> Header;

    /// Get raw block data by block header hash.
    fn block(&self, id: BlockId) -> Option<encoded::Block>;

    /// Get address code hash at given block's state.
    fn code_hash(&self, address: &Address, id: BlockId) -> Option<H256>;
}

/// Provides methods to access chain state
pub trait StateClient {
    /// Type representing chain state
    type State: StateInfo;

    /// Get a copy of the best block's state and header.
    fn latest_state_and_header(&self) -> (Self::State, Header);

    /// Attempt to get a copy of a specific block's final state.
    ///
    /// This will not fail if given BlockId::Latest.
    /// Otherwise, this can fail (but may not) if the DB prunes state or the block
    /// is unknown.
    fn state_at(&self, id: BlockId) -> Option<Self::State>;
}

/// Provides various blockchain information, like block header, chain state etc.
pub trait BlockChain: ChainInfo + BlockInfo {}

// FIXME Why these methods belong to BlockChainClient and not MiningBlockChainClient?
/// Provides methods to import block into blockchain
pub trait ImportBlock {
    /// Import a block into the blockchain.
    fn import_block(&self, block: Unverified) -> EthcoreResult<H256>;
}

/// Provides `call` and `call_many` methods
pub trait Call {
    /// Type representing chain state
    type State: StateInfo;

    /// Makes a non-persistent transaction call.
    fn call(
        &self,
        tx: &SignedTransaction,
        analytics: CallAnalytics,
        state: &mut Self::State,
        header: &Header,
    ) -> Result<Executed, CallError>;

    /// Makes multiple non-persistent but dependent transaction calls.
    /// Returns a vector of successes or a failure if any of the transaction fails.
    fn call_many(
        &self,
        txs: &[(SignedTransaction, CallAnalytics)],
        state: &mut Self::State,
        header: &Header,
    ) -> Result<Vec<Executed>, CallError>;

    /// Estimates how much gas will be necessary for a call.
    fn estimate_gas(
        &self,
        t: &SignedTransaction,
        state: &Self::State,
        header: &Header,
    ) -> Result<U256, CallError>;
}

/// Provides `engine` method
pub trait EngineInfo {
    /// Get underlying engine object
    fn engine(&self) -> &dyn EthEngine;
}

/// Blockchain database client. Owns and manages a blockchain and a block queue.
pub trait BlockChainClient:
    Sync
    + Send
    + AccountData
    + BlockChain
    + ImportBlock
{
    /// Look up the block number for the given block ID.
    fn block_number(&self, id: BlockId) -> Option<BlockNumber>;

    /// Get raw block body data by block id.
    /// Block body is an RLP list of two items: uncles and transactions.
    fn block_body(&self, id: BlockId) -> Option<encoded::Body>;

    /// Get block status by block header hash.
    fn block_status(&self, id: BlockId) -> BlockStatus;

    /// Attempt to get address storage root at given block.
    /// May not fail on BlockId::Latest.
    fn storage_root(&self, address: &Address, id: BlockId) -> Option<H256>;

    /// Get block hash.
    fn block_hash(&self, id: BlockId) -> Option<H256>;

    /// Get address code at given block's state.
    fn code(&self, address: &Address, state: StateOrBlock) -> Option<Option<Bytes>>;

    /// Get address code at the latest block's state.
    fn latest_code(&self, address: &Address) -> Option<Bytes> {
        self.code(address, BlockId::Latest.into())
            .expect("code will return Some if given BlockId::Latest; qed")
    }

    /// Get address code hash at given block's state.

    /// Get value of the storage at given position at the given block's state.
    ///
    /// May not return None if given BlockId::Latest.
    /// Returns None if and only if the block's root hash has been pruned from the DB.
    fn storage_at(&self, address: &Address, position: &H256, state: StateOrBlock) -> Option<H256>;

    /// Get value of the storage at given position at the latest block's state.
    fn latest_storage_at(&self, address: &Address, position: &H256) -> H256 {
        self.storage_at(address, position, BlockId::Latest.into())
			.expect("storage_at will return Some if given BlockId::Latest. storage_at was given BlockId::Latest. \
			Therefore storage_at has returned Some; qed")
    }

    /// Get a list of all accounts in the block `id`, if fat DB is in operation, otherwise `None`.
    /// If `after` is set the list starts with the following item.
    fn list_accounts(
        &self,
        id: BlockId,
        after: Option<&Address>,
        count: u64,
    ) -> Option<Vec<Address>>;

    /// Get a list of all storage keys in the block `id`, if fat DB is in operation, otherwise `None`.
    /// If `after` is set the list starts with the following item.
    fn list_storage(
        &self,
        id: BlockId,
        account: &Address,
        after: Option<&H256>,
        count: u64,
    ) -> Option<Vec<H256>>;

    /// Get transaction receipt with given hash.
    fn transaction_receipt(&self, id: TransactionId) -> Option<LocalizedReceipt>;

    /// Get localized receipts for all transaction in given block.
    fn localized_block_receipts(&self, id: BlockId) -> Option<Vec<LocalizedReceipt>>;

    /// Get a tree route between `from` and `to`.
    /// See `BlockChain::tree_route`.
    fn tree_route(&self, from: &H256, to: &H256) -> Option<TreeRoute>;

    /// Get latest state node
    fn state_data(&self, hash: &H256) -> Option<Bytes>;

    /// Get block receipts data by block header hash.
    fn block_receipts(&self, hash: &H256) -> Option<BlockReceipts>;

    /// Get the registrar address, if it exists.
    fn additional_params(&self) -> BTreeMap<String, String>;

    /// Returns logs matching given filter. If one of the filtering block cannot be found, returns the block id that caused the error.
    fn logs(&self, filter: Filter) -> Result<Vec<LocalizedLogEntry>, BlockId>;

    /// Returns traces matching given filter.
    fn filter_traces(&self, filter: TraceFilter) -> Option<Vec<LocalizedTrace>>;

    /// Returns trace with given id.
    fn trace(&self, trace: TraceId) -> Option<LocalizedTrace>;

    /// Returns traces created by transaction.
    fn transaction_traces(&self, trace: TransactionId) -> Option<Vec<LocalizedTrace>>;

    /// Get last hashes starting from best block.
    fn last_hashes(&self) -> LastHashes;

    /// Returns information about pruning/data availability.
    fn pruning_info(&self) -> PruningInfo;
}

/// Provides `prepare_open_block` method
pub trait PrepareOpenBlock {
    /// Returns OpenBlock prepared for closing.
    fn prepare_open_block(
        &self,
        author: Address,
        gas_range_target: (U256, U256),
        extra_data: Bytes,
    ) -> Result<OpenBlock, Error>;
}

///Provides `import_sealed_block` method
pub trait ImportSealedBlock {
    /// Import sealed block. Skips all verifications.
    fn import_sealed_block(&self, block: SealedBlock) -> EthcoreResult<H256>;
}

/// Client facilities used by internally sealing Engines.
pub trait EngineClient: Sync + Send + ChainInfo {
    /// Attempt to cast the engine client to a full client.
    fn as_full_client(&self) -> Option<&dyn BlockChainClient>;

    /// Get a block number by ID.
    fn block_number(&self, id: BlockId) -> Option<BlockNumber>;

    /// Get raw block header data by block id.
    fn block_header(&self, id: BlockId) -> Option<encoded::Header>;
}

/// Extended client interface for providing proofs of the state.
pub trait ProvingBlockChainClient: BlockChainClient {
    /// Prove account storage at a specific block id.
    ///
    /// Both provided keys assume a secure trie.
    /// Returns a vector of raw trie nodes (in order from the root) proving the storage query.
    fn prove_storage(&self, key1: H256, key2: H256, id: BlockId) -> Option<(Vec<Bytes>, H256)>;

    /// Prove account existence at a specific block id.
    /// The key is the keccak hash of the account's address.
    /// Returns a vector of raw trie nodes (in order from the root) proving the query.
    fn prove_account(&self, key1: H256, id: BlockId) -> Option<(Vec<Bytes>, BasicAccount)>;

    /// Prove execution of a transaction at the given block.
    /// Returns the output of the call and a vector of database items necessary
    /// to reproduce it.
    fn prove_transaction(
        &self,
        transaction: SignedTransaction,
        id: BlockId,
    ) -> Option<(Bytes, Vec<DBValue>)>;
}
