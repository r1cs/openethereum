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

#![warn(missing_docs, unused_extern_crates)]
//! Ethcore library
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate macros;
#[macro_use]
extern crate rlp_derive;

extern crate common_types as types;
extern crate ethcore_builtin as builtin;
extern crate keccak_hash as hash;
extern crate parity_bytes as bytes;
extern crate patricia_trie_ethereum as ethtrie;
extern crate trie_db as trie;
extern crate triehash_ethereum as triehash;

pub mod block;
pub mod client;
pub mod engines;
pub mod error;
pub mod ethereum;
pub mod executed;
pub mod executive;
pub mod machine;
pub mod miner;
pub mod pod_account;
pub mod pod_state;
pub mod spec;
pub mod state;
pub mod state_db;
pub mod trace;
pub mod transaction_ext;
pub mod verification;

mod account_db;
mod externalities;
mod factory;

#[cfg(feature = "json-tests")]
pub mod json_tests;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

extern crate alloc;
pub use evm::CreateContractAddress;
pub use executive::contract_address;
pub use trie::TrieSpec;
