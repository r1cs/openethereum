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

use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use types::blockchain_info::BlockChainInfo;
use types::header::Header;
use types::ids::*;
use types::{encoded, BlockNumber};

use crate::block::OpenBlock;
use crate::engines::EthEngine;
use crate::error::Error;
use crate::state::StateInfo;

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

/// Provides `engine` method
pub trait EngineInfo {
    /// Get underlying engine object
    fn engine(&self) -> &dyn EthEngine;
}

/// Provides `prepare_open_block` method
pub trait PrepareOpenBlock {
    /// Returns OpenBlock prepared for closing.
    fn prepare_open_block(
        &self, author: Address, gas_range_target: (U256, U256), extra_data: Bytes,
    ) -> Result<OpenBlock, Error>;
}

/// Client facilities used by internally sealing Engines.
pub trait EngineClient: Sync + Send + ChainInfo {
    /// Get a block number by ID.
    fn block_number(&self, id: BlockId) -> Option<BlockNumber>;

    /// Get raw block header data by block id.
    fn block_header(&self, id: BlockId) -> Option<encoded::Header>;
}
