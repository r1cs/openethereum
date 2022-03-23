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

//! DB backend wrapper for Account trie
use ethereum_types::H256;
use hash::{KECCAK_NULL_RLP};
use hash_db::{AsHashDB, HashDB};
use keccak_hasher::KeccakHasher;
use rlp::NULL_RLP;
use trie::DBValue;

/// A factory for different kinds of account dbs.
#[derive(Debug, Clone)]
pub enum Factory {
    /// Don't mangle hashes.
    Plain,
}

impl Default for Factory {
    fn default() -> Self {
        Factory::Plain
    }
}

impl Factory {
    /// Create a read-only accountdb.
    /// This will panic when write operations are called.
    pub fn readonly<'db>(
        &self,
        db: &'db dyn HashDB<KeccakHasher, DBValue>,
        _address_hash: H256,
    ) -> Box<dyn HashDB<KeccakHasher, DBValue> + 'db> {
        match *self {
            Factory::Plain => Box::new(Wrapping(db)),
        }
    }

    /// Create a new mutable hashdb.
    pub fn create<'db>(
        &self,
        db: &'db mut dyn HashDB<KeccakHasher, DBValue>,
        _address_hash: H256,
    ) -> Box<dyn HashDB<KeccakHasher, DBValue> + 'db> {
        match *self {
            Factory::Plain => Box::new(WrappingMut(db)),
        }
    }
}

struct Wrapping<'db>(&'db dyn HashDB<KeccakHasher, DBValue>);

impl<'db> AsHashDB<KeccakHasher, DBValue> for Wrapping<'db> {
    fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self
    }
    fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher, DBValue> {
        self
    }
}

impl<'db> HashDB<KeccakHasher, DBValue> for Wrapping<'db> {
    fn get(&self, key: &H256) -> Option<DBValue> {
        if key == &KECCAK_NULL_RLP {
            return Some(DBValue::from_slice(&NULL_RLP));
        }
        self.0.get(key)
    }

    fn contains(&self, key: &H256) -> bool {
        if key == &KECCAK_NULL_RLP {
            return true;
        }
        self.0.contains(key)
    }

    fn insert(&mut self, _value: &[u8]) -> H256 {
        unimplemented!()
    }

    fn emplace(&mut self, _key: H256, _value: DBValue) {
        unimplemented!()
    }

    fn remove(&mut self, _key: &H256) {
        unimplemented!()
    }
}

struct WrappingMut<'db>(&'db mut dyn HashDB<KeccakHasher, DBValue>);
impl<'db> AsHashDB<KeccakHasher, DBValue> for WrappingMut<'db> {
    fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self
    }
    fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher, DBValue> {
        self
    }
}

impl<'db> HashDB<KeccakHasher, DBValue> for WrappingMut<'db> {
    fn get(&self, key: &H256) -> Option<DBValue> {
        if key == &KECCAK_NULL_RLP {
            return Some(DBValue::from_slice(&NULL_RLP));
        }
        self.0.get(key)
    }

    fn contains(&self, key: &H256) -> bool {
        if key == &KECCAK_NULL_RLP {
            return true;
        }
        self.0.contains(key)
    }

    fn insert(&mut self, value: &[u8]) -> H256 {
        if value == &NULL_RLP {
            return KECCAK_NULL_RLP.clone();
        }
        self.0.insert(value)
    }

    fn emplace(&mut self, key: H256, value: DBValue) {
        if key == KECCAK_NULL_RLP {
            return;
        }
        self.0.emplace(key, value)
    }

    fn remove(&mut self, key: &H256) {
        if key == &KECCAK_NULL_RLP {
            return;
        }
        self.0.remove(key)
    }
}
