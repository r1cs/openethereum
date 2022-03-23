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

extern crate common_types as types;
extern crate ethash;
extern crate ethcore_builtin as builtin;
extern crate ethcore_db as db;
extern crate ethereum_types;
extern crate ethjson;
extern crate hash_db;
extern crate itertools;
extern crate journaldb;
extern crate keccak_hash as hash;
extern crate keccak_hasher;
extern crate kvdb;
extern crate lru_cache;
extern crate maplit;
extern crate memory_cache;
extern crate memory_db;
extern crate parity_bytes as bytes;
extern crate parity_crypto as crypto;
extern crate parking_lot;
extern crate patricia_trie_ethereum as ethtrie;
#[cfg(feature = "json-tests")]
extern crate rayon;
extern crate rlp;
extern crate rustc_hex;
extern crate serde;
extern crate trie_db as trie;
extern crate triehash_ethereum as triehash;
extern crate unexpected;
extern crate vm;

#[cfg(any(test, feature = "env_logger"))]
extern crate env_logger;
#[cfg(feature = "json-tests")]
extern crate globset;
#[cfg(test)]
extern crate rlp_compress;
#[cfg(feature = "json-tests")]
extern crate walkdir;

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate macros;
#[macro_use]
extern crate rlp_derive;
#[macro_use]
extern crate serde_derive;

#[cfg_attr(test, macro_use)]
extern crate evm;

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

pub use evm::CreateContractAddress;
pub use executive::contract_address;
pub use trie::TrieSpec;
