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

//! Environment information for transaction execution.

use ethereum_types::{Address, H256, U256};
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

type BlockNumber = u64;

/// Simple vector of hashes, should be at most 256 items large, can be smaller if being used
/// for a block whose number is less than 257.
pub type LastHashes = Vec<H256>;

/// Information concerning the execution environment for a message-call/contract-creation.
#[derive(Debug, Clone)]
pub struct EnvInfo {
    /// The block number.
    pub number: BlockNumber,
    /// The block author.
    pub author: Address,
    /// The block timestamp.
    pub timestamp: u64,
    /// The block difficulty.
    pub difficulty: U256,
    /// The block gas limit.
    pub gas_limit: U256,
    /// The last 256 block hashes.
    pub last_hashes: Arc<LastHashes>,
    /// The gas used.
    pub gas_used: U256,
    /// Block base fee.
    pub base_fee: Option<U256>,
}

impl Default for EnvInfo {
    fn default() -> Self {
        EnvInfo {
            number: 0,
            author: Address::default(),
            timestamp: 0,
            difficulty: 0u64.into(),
            gas_limit: 0u64.into(),
            last_hashes: Arc::new(vec![]),
            gas_used: 0u64.into(),
            base_fee: None,
        }
    }
}

#[cfg(feature = "std")]
impl From<ethjson::vm::Env> for EnvInfo {
    fn from(e: ethjson::vm::Env) -> Self {
        let number = e.number.into();
        EnvInfo {
            number,
            author: e.author.into(),
            difficulty: e.difficulty.into(),
            gas_limit: e.gas_limit.into(),
            timestamp: e.timestamp.into(),
            last_hashes: Arc::new(
                (1..core::cmp::min(number + 1, 257))
                    .map(|i| hash::keccak(format!("{}", number - i).as_bytes()))
                    .collect(),
            ),
            gas_used: U256::default(),
            base_fee: e.base_fee.map(|i| i.into()),
        }
    }
}
