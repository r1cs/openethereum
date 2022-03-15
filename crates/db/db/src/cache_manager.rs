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

//! Database cache manager

use std::{
    collections::{HashSet, VecDeque},
    hash::Hash,
};

const COLLECTION_QUEUE_SIZE: usize = 8;

/// DB cache manager
pub struct CacheManager<T> {
    cache_usage: VecDeque<HashSet<T>>,
}

impl<T> CacheManager<T>
where
    T: Eq + Hash,
{
    /// Create new cache manager with preferred (heap) sizes.
    pub fn new(
        _pref_cache_size: usize,
        _max_cache_size: usize,
        _bytes_per_cache_entry: usize,
    ) -> Self {
        CacheManager {
            cache_usage: (0..COLLECTION_QUEUE_SIZE)
                .into_iter()
                .map(|_| Default::default())
                .collect(),
        }
    }

    /// Mark element as used.
    pub fn note_used(&mut self, id: T) {
        if !self.cache_usage[0].contains(&id) {
            if let Some(c) = self
                .cache_usage
                .iter_mut()
                .skip(1)
                .find(|e| e.contains(&id))
            {
                c.remove(&id);
            }
            self.cache_usage[0].insert(id);
        }
    }
}
