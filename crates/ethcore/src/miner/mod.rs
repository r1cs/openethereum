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
use ethcore_miner::pool::{VerifiedTransaction};
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

    /// Get an unfiltered list of all ready transactions.
    fn ready_transactions<C>(
        &self,
        chain: &C,
        max_len: usize,
        ordering: PendingOrdering,
    ) -> Vec<Arc<VerifiedTransaction>>
    where
        C: BlockChain + Nonce + Sync;
}
