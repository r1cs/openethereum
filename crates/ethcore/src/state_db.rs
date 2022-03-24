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

//! State database abstraction. For more info, see the doc for `StateDB`

use std::{
    sync::Arc,
};

use ethereum_types::{Address, H256};
use hash_db::HashDB;
use keccak_hasher::KeccakHasher;
use state::{self, Account};

use trie::DBValue;

/// State database abstraction.
/// Manages shared global state cache which reflects the canonical
/// state as it is on the disk. All the entries in the cache are clean.
/// A clone of `StateDB` may be created as canonical or not.
/// For canonical clones local cache is accumulated and applied
/// in `sync_cache`
/// For non-canonical clones local cache is dropped.
///
/// Global cache propagation.
/// After a `State` object has been committed to the trie it
/// propagates its local cache into the `StateDB` local cache
/// using `add_to_account_cache` function.
/// Then, after the block has been added to the chain the local cache in the
/// `StateDB` is propagated into the global cache.
pub struct StateDB {
    /// Backing database.
	db: Box<dyn HashDB<KeccakHasher, DBValue>>,
    /// Hash of the block on top of which this instance was created or
    /// `None` if cache is disabled
    parent_hash: Option<H256>,
}

impl StateDB {
    /// Create a new instance wrapping `JournalDB` and the maximum allowed size
    /// of the LRU cache in bytes. Actual used memory may (read: will) be higher due to bookkeeping.
    // TODO: make the cache size actually accurate by moving the account storage cache
    // into the `AccountCache` structure as its own `LruCache<(Address, H256), H256>`.
    pub fn new(db: Box<dyn HashDB<KeccakHasher, DBValue>>, cache_size: usize) -> StateDB {
        StateDB {
            db: db,
            parent_hash: None,
        }
    }


    /// Conversion method to interpret self as `HashDB` reference
    pub fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self.db.as_hash_db()
    }

    /// Conversion method to interpret self as mutable `HashDB` reference
    pub fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher, DBValue> {
        self.db.as_hash_db_mut()
    }

    /// Returns underlying `JournalDB`.
    pub fn journal_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        &*self.db
    }

}

impl state::Backend for StateDB {
    fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self.db.as_hash_db()
    }

    fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher, DBValue> {
        self.db.as_hash_db_mut()
    }

    fn add_to_account_cache(&mut self, addr: Address, data: Option<Account>, modified: bool) {
        return
    }

    fn cache_code(&self, hash: H256, code: Arc<Vec<u8>>) {
       return
    }

    fn get_cached_account(&self, addr: &Address) -> Option<Option<Account>> {
       None
    }

    fn get_cached<F, U>(&self, a: &Address, f: F) -> Option<U>
    where
        F: FnOnce(Option<&mut Account>) -> U,
    {
       None
    }

    fn get_cached_code(&self, hash: &H256) -> Option<Arc<Vec<u8>>> {
        None
    }
}

/// Sync wrapper for the account.
struct SyncAccount(Option<Account>);
/// That implementation is safe because account is never modified or accessed in any way.
/// We only need `Sync` here to allow `StateDb` to be kept in a `RwLock`.
/// `Account` is `!Sync` by default because of `RefCell`s inside it.
unsafe impl Sync for SyncAccount {}
