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

#![warn(missing_docs)]

//! Miner module
//! Keeps track of transactions and currently sealed pending block.

mod cache;
mod miner;

pub mod pool_client;

pub use self::miner::{AuthoringParams, Miner, MinerOptions, Penalization, PendingSet};
pub use ethcore_miner::{
    pool::{PendingOrdering},
};

use std::sync::Arc;

use bytes::Bytes;
use ethcore_miner::pool::{local_transactions, QueueStatus, VerifiedTransaction};
use ethereum_types::{Address, H256, U256};
use types::{
    transaction::{self, PendingTransaction, UnverifiedTransaction},
    BlockNumber,
};

use block::SealedBlock;
use client::{
    traits::ForceUpdateSealing, AccountData, BlockChain, BlockProducer, Nonce,
    ScheduleInfo, SealedBlockImporter,
};
use error::Error;
use state::StateInfo;

/// Provides methods to verify incoming external transactions
pub trait TransactionVerifierClient: Send + Sync
	// Required for verifiying transactions
	+ BlockChain + ScheduleInfo + AccountData
{}

/// Extended client interface used for mining
pub trait BlockChainClient:
    TransactionVerifierClient + BlockProducer + SealedBlockImporter
{
}

/// Miner client API
pub trait MinerService: Send + Sync {
    /// Type representing chain state
    type State: StateInfo + 'static;

    // Sealing

    /// Submit `seal` as a valid solution for the header of `pow_hash`.
    /// Will check the seal, but not actually insert the block into the chain.
    fn submit_seal(&self, pow_hash: H256, seal: Vec<Bytes>) -> Result<SealedBlock, Error>;

    /// Get the sealing work package preparing it if doesn't exist yet.
    ///
    /// Returns `None` if engine seals internally.
    fn work_package<C>(&self, chain: &C) -> Option<(H256, BlockNumber, u64, U256)>
    where
        C: BlockChain + BlockProducer + SealedBlockImporter + Nonce + Sync;

    /// Update current pending block
    fn update_sealing<C>(&self, chain: &C, force: ForceUpdateSealing)
    where
        C: BlockChain + BlockProducer + SealedBlockImporter + Nonce + Sync;

    // Notifications

    /// Called when blocks are imported to chain, updates transactions queue.
    /// `is_internal_import` indicates that the block has just been created in miner and internally sealed by the engine,
    /// so we shouldn't attempt creating new block again.
    fn chain_new_blocks<C>(
        &self,
        chain: &C,
        imported: &[H256],
        invalid: &[H256],
        enacted: &[H256],
        retracted: &[H256],
        is_internal_import: bool,
    ) where
        C: BlockChainClient;

    /// Get current authoring parameters.
    fn authoring_params(&self) -> AuthoringParams;

    /// Imports transactions to transaction queue.
    fn import_external_transactions<C>(
        &self,
        client: &C,
        transactions: Vec<UnverifiedTransaction>,
    ) -> Vec<Result<(), transaction::Error>>
    where
        C: BlockChainClient;

    /// Imports own (node owner) transaction to queue.
    fn import_own_transaction<C>(
        &self,
        chain: &C,
        transaction: PendingTransaction,
    ) -> Result<(), transaction::Error>
    where
        C: BlockChainClient;

    /// Query transaction from the pool given it's hash.
    fn transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>>;

    /// Get an unfiltered list of all ready transactions.
    fn ready_transactions<C>(
        &self,
        chain: &C,
        max_len: usize,
        ordering: PendingOrdering,
    ) -> Vec<Arc<VerifiedTransaction>>
    where
        C: BlockChain + Nonce + Sync;

    // Misc

    /// Suggested gas price.
    fn sensible_gas_price(&self) -> U256;

    /// Suggested max priority fee gas price
    fn sensible_max_priority_fee(&self) -> U256;

    /// Suggested gas limit.
    fn sensible_gas_limit(&self) -> U256;
}
