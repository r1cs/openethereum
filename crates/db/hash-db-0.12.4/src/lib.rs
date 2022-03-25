// Copyright 2017, 2018 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
//! Database of byte-slices keyed to their hash.

use core::fmt::Debug;
use core::hash;

/// Trait describing an object that can hash a slice of bytes. Used to abstract
/// other types over the hashing algorithm. Defines a single `hash` method and an
/// `Out` associated type with the necessary bounds.
pub trait Hasher: Sync + Send {
    /// The output type of the `Hasher`
    type Out: AsRef<[u8]>
        + AsMut<[u8]>
        + Default
        + Debug
        + PartialEq
        + Eq
        + hash::Hash
        + Send
        + Sync
        + Clone
        + Copy;
    /// What to use to build `HashMap`s with this `Hasher`
    type StdHasher: Sync + Send + Default + hash::Hasher;
    /// The length in bytes of the `Hasher` output
    const LENGTH: usize;

    /// Compute the hash of the provided slice of bytes returning the `Out` type of the `Hasher`
    fn hash(x: &[u8]) -> Self::Out;
}

/// Trait modelling a plain datastore whose key is a fixed type.
/// The caller should ensure that a key only corresponds to
/// one value.
pub trait PlainDB<K, V>: Send + Sync + AsPlainDB<K, V> {
    /// Look up a given hash into the bytes that hash to it, returning None if the
    /// hash is not known.
    fn get(&self, key: &K) -> Option<V>;

    /// Check for the existance of a hash-key.
    fn contains(&self, key: &K) -> bool;

    /// Insert a datum item into the DB. Insertions are counted and the equivalent
    /// number of `remove()`s must be performed before the data is considered dead.
    /// The caller should ensure that a key only corresponds to one value.
    fn emplace(&mut self, key: K, value: V);

    /// Remove a datum previously inserted. Insertions can be "owed" such that the
    /// same number of `insert()`s may happen without the data being eventually
    /// being inserted into the DB. It can be "owed" more than once.
    /// The caller should ensure that a key only corresponds to one value.
    fn remove(&mut self, key: &K);
}

/// Trait for immutable reference of PlainDB.
pub trait PlainDBRef<K, V> {
    /// Look up a given hash into the bytes that hash to it, returning None if the
    /// hash is not known.
    fn get(&self, key: &K) -> Option<V>;

    /// Check for the existance of a hash-key.
    fn contains(&self, key: &K) -> bool;
}

impl<'a, K, V> PlainDBRef<K, V> for &'a dyn PlainDB<K, V> {
    fn get(&self, key: &K) -> Option<V> {
        PlainDB::get(*self, key)
    }
    fn contains(&self, key: &K) -> bool {
        PlainDB::contains(*self, key)
    }
}

impl<'a, K, V> PlainDBRef<K, V> for &'a mut dyn PlainDB<K, V> {
    fn get(&self, key: &K) -> Option<V> {
        PlainDB::get(*self, key)
    }
    fn contains(&self, key: &K) -> bool {
        PlainDB::contains(*self, key)
    }
}

/// Trait modelling datastore keyed by a hash defined by the `Hasher`.
pub trait HashDB<H: Hasher, T>: AsHashDB<H, T> {
    /// Look up a given hash into the bytes that hash to it, returning None if the
    /// hash is not known.
    fn get(&self, key: &H::Out) -> Option<T>;

    /// Check for the existance of a hash-key.
    fn contains(&self, key: &H::Out) -> bool;

    /// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
    /// are counted and the equivalent number of `remove()`s must be performed before the data
    /// is considered dead.
    fn insert(&mut self, value: &[u8]) -> H::Out;

    /// Like `insert()`, except you provide the key and the data is all moved.
    fn emplace(&mut self, key: H::Out, value: T);

    /// Remove a datum previously inserted. Insertions can be "owed" such that the same number of `insert()`s may
    /// happen without the data being eventually being inserted into the DB. It can be "owed" more than once.
    fn remove(&mut self, key: &H::Out);
}

/// Trait for immutable reference of HashDB.
pub trait HashDBRef<H: Hasher, T> {
    /// Look up a given hash into the bytes that hash to it, returning None if the
    /// hash is not known.
    fn get(&self, key: &H::Out) -> Option<T>;

    /// Check for the existance of a hash-key.
    fn contains(&self, key: &H::Out) -> bool;
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a dyn HashDB<H, T> {
    fn get(&self, key: &H::Out) -> Option<T> {
        HashDB::get(*self, key)
    }
    fn contains(&self, key: &H::Out) -> bool {
        HashDB::contains(*self, key)
    }
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a mut dyn HashDB<H, T> {
    fn get(&self, key: &H::Out) -> Option<T> {
        HashDB::get(*self, key)
    }
    fn contains(&self, key: &H::Out) -> bool {
        HashDB::contains(*self, key)
    }
}

/// Upcast trait for HashDB.
pub trait AsHashDB<H: Hasher, T> {
    /// Perform upcast to HashDB for anything that derives from HashDB.
    fn as_hash_db(&self) -> &dyn HashDB<H, T>;
    /// Perform mutable upcast to HashDB for anything that derives from HashDB.
    fn as_hash_db_mut<'a>(&'a mut self) -> &'a mut (dyn HashDB<H, T> + 'a);
}

/// Upcast trait for PlainDB.
pub trait AsPlainDB<K, V> {
    /// Perform upcast to PlainDB for anything that derives from PlainDB.
    fn as_plain_db(&self) -> &dyn PlainDB<K, V>;
    /// Perform mutable upcast to PlainDB for anything that derives from PlainDB.
    fn as_plain_db_mut<'a>(&'a mut self) -> &'a mut (dyn PlainDB<K, V> + 'a);
}

// NOTE: There used to be a `impl<T> AsHashDB for T` but that does not work with generics. See https://stackoverflow.com/questions/48432842/implementing-a-trait-for-reference-and-non-reference-types-causes-conflicting-im
// This means we need concrete impls of AsHashDB in several places, which somewhat defeats the point of the trait.
impl<'a, H: Hasher, T> AsHashDB<H, T> for &'a mut dyn HashDB<H, T> {
    fn as_hash_db(&self) -> &dyn HashDB<H, T> {
        &**self
    }
    fn as_hash_db_mut<'b>(&'b mut self) -> &'b mut (dyn HashDB<H, T> + 'b) {
        &mut **self
    }
}

impl<'a, K, V> AsPlainDB<K, V> for &'a mut dyn PlainDB<K, V> {
    fn as_plain_db(&self) -> &dyn PlainDB<K, V> {
        &**self
    }
    fn as_plain_db_mut<'b>(&'b mut self) -> &'b mut (dyn PlainDB<K, V> + 'b) {
        &mut **self
    }
}
