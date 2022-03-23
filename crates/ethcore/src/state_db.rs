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
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use ethereum_types::{Address, H256};
use hash_db::HashDB;
use keccak_hasher::KeccakHasher;
use lru_cache::LruCache;
use memory_cache::MemoryLruCache;
use parking_lot::Mutex;

use state::{self, Account};
use trie::DBValue;

// The percentage of supplied cache size to go to accounts.
const ACCOUNT_CACHE_RATIO: usize = 90;

/// Shared canonical state cache.
struct AccountCache {
    /// DB Account cache. `None` indicates that account is known to be missing.
    // When changing the type of the values here, be sure to update `mem_used` and
    // `new`.
    accounts: LruCache<Address, Option<Account>>,
    /// Information on the modifications in recently committed blocks; specifically which addresses
    /// changed in which block. Ordered by block number.
    modifications: VecDeque<BlockChanges>,
}

/// Accumulates a list of accounts changed in a block.
struct BlockChanges {
    /// Block hash.
    hash: H256,
    /// Parent block hash.
    parent: H256,
    /// A set of modified account addresses.
    accounts: HashSet<Address>,
    /// Block is part of the canonical chain.
    is_canon: bool,
}

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
    /// Shared canonical state cache.
    account_cache: Arc<Mutex<AccountCache>>,
    /// DB Code cache. Maps code hashes to shared bytes.
    code_cache: Arc<Mutex<MemoryLruCache<H256, Arc<Vec<u8>>>>>,
    cache_size: usize,
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
        let acc_cache_size = cache_size * ACCOUNT_CACHE_RATIO / 100;
        let code_cache_size = cache_size - acc_cache_size;
        let cache_items = acc_cache_size / ::std::mem::size_of::<Option<Account>>();

        StateDB {
            db: db,
            account_cache: Arc::new(Mutex::new(AccountCache {
                accounts: LruCache::new(cache_items),
                modifications: VecDeque::new(),
            })),
            code_cache: Arc::new(Mutex::new(MemoryLruCache::new(code_cache_size))),
            cache_size: cache_size,
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

    /// Query how much memory is set aside for the accounts cache (in bytes).
    pub fn cache_size(&self) -> usize {
        self.cache_size
    }

    /// Check if the account can be returned from cache by matching current block parent hash against canonical
    /// state and filtering out account modified in later blocks.
    fn is_allowed(
        addr: &Address,
        parent_hash: &H256,
        modifications: &VecDeque<BlockChanges>,
    ) -> bool {
        if modifications.is_empty() {
            return true;
        }
        // Ignore all accounts modified in later blocks
        // Modifications contains block ordered by the number
        // We search for our parent in that list first and then for
        // all its parent until we hit the canonical block,
        // checking against all the intermediate modifications.
        let mut parent = parent_hash;
        for m in modifications {
            if &m.hash == parent {
                if m.is_canon {
                    return true;
                }
                parent = &m.parent;
            }
            if m.accounts.contains(addr) {
                trace!(
                    "Cache lookup skipped for {:?}: modified in a later block",
                    addr
                );
                return false;
            }
        }
        trace!(
            "Cache lookup skipped for {:?}: parent hash is unknown",
            addr
        );
        false
    }
}

impl state::Backend for StateDB {
    fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self.db.as_hash_db()
    }

    fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher, DBValue> {
        self.db.as_hash_db_mut()
    }

    fn add_to_account_cache(&mut self, addr: Address, data: Option<Account>, modified: bool) { }

    fn cache_code(&self, hash: H256, code: Arc<Vec<u8>>) {
        let mut cache = self.code_cache.lock();

        cache.insert(hash, code);
    }

    fn get_cached_account(&self, addr: &Address) -> Option<Option<Account>> {
        self.parent_hash.as_ref().and_then(|parent_hash| {
            let mut cache = self.account_cache.lock();
            if !Self::is_allowed(addr, parent_hash, &cache.modifications) {
                return None;
            }
            cache
                .accounts
                .get_mut(addr)
                .map(|a| a.as_ref().map(|a| a.clone_basic()))
        })
    }

    fn get_cached<F, U>(&self, a: &Address, f: F) -> Option<U>
    where
        F: FnOnce(Option<&mut Account>) -> U,
    {
        self.parent_hash.as_ref().and_then(|parent_hash| {
            let mut cache = self.account_cache.lock();
            if !Self::is_allowed(a, parent_hash, &cache.modifications) {
                return None;
            }
            cache.accounts.get_mut(a).map(|c| f(c.as_mut()))
        })
    }

    fn get_cached_code(&self, hash: &H256) -> Option<Arc<Vec<u8>>> {
        let mut cache = self.code_cache.lock();

        cache.get_mut(hash).map(|code| code.clone())
    }
}

/// Sync wrapper for the account.
struct SyncAccount(Option<Account>);
/// That implementation is safe because account is never modified or accessed in any way.
/// We only need `Sync` here to allow `StateDb` to be kept in a `RwLock`.
/// `Account` is `!Sync` by default because of `RefCell`s inside it.
unsafe impl Sync for SyncAccount {}
