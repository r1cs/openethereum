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

//! Trace database.
use std::{collections::HashMap, sync::Arc};

use blockchain::BlockChainDB;
use db::{self, cache_manager::CacheManager, CacheUpdatePolicy, Key, Readable, Writable};
use ethereum_types::{H256, H264};
use kvdb::DBTransaction;
use parking_lot::RwLock;
use types::BlockNumber;

use trace::{
    flat::{FlatBlockTraces, FlatTrace, FlatTransactionTraces},
    Config, Database as TraceDatabase, DatabaseExtras, Filter, ImportRequest, LocalizedTrace,
};

const TRACE_DB_VER: &'static [u8] = b"1.0";

#[derive(Debug, Copy, Clone)]
enum TraceDBIndex {
    /// Block traces index.
    BlockTraces = 0,
}

impl Key<FlatBlockTraces> for H256 {
    type Target = H264;

    fn key(&self) -> H264 {
        let mut result = H264::default();
        {
            let bytes = result.as_bytes_mut();
            bytes[0] = TraceDBIndex::BlockTraces as u8;
            bytes[1..33].copy_from_slice(self.as_bytes());
        }
        result
    }
}

/// Database to store transaction execution trace.
///
/// Whenever a transaction is executed by EVM it's execution trace is stored
/// in trace database. Each trace has information, which contracts have been
/// touched, which have been created during the execution of transaction, and
/// which calls failed.
pub struct TraceDB<T>
where
    T: DatabaseExtras,
{
    /// cache
    traces: RwLock<HashMap<H256, FlatBlockTraces>>,
    /// hashes of cached traces
    cache_manager: RwLock<CacheManager<H256>>,
    /// db
    db: Arc<dyn BlockChainDB>,
    /// tracing enabled
    enabled: bool,
    /// extras
    extras: Arc<T>,
}

impl<T> TraceDB<T>
where
    T: DatabaseExtras,
{
    /// Creates new instance of `TraceDB`.
    pub fn new(config: Config, db: Arc<dyn BlockChainDB>, extras: Arc<T>) -> Self {
        let mut batch = DBTransaction::new();
        let genesis = extras
            .block_hash(0)
            .expect("Genesis block is always inserted upon extras db creation qed");
        batch.write(db::COL_TRACE, &genesis, &FlatBlockTraces::default());
        batch.put(db::COL_TRACE, b"version", TRACE_DB_VER);
        db.key_value()
            .write(batch)
            .expect("failed to update version");

        TraceDB {
            traces: RwLock::new(HashMap::new()),
            cache_manager: RwLock::new(CacheManager::new(
                config.pref_cache_size,
                config.max_cache_size,
                10 * 1024,
            )),
            db,
            enabled: config.enabled,
            extras: extras,
        }
    }

    /// Let the cache system know that a cacheable item has been used.
    fn note_trace_used(&self, trace_id: H256) {
        let mut cache_manager = self.cache_manager.write();
        cache_manager.note_used(trace_id);
    }

    /// Returns traces for block with hash.
    fn traces(&self, block_hash: &H256) -> Option<FlatBlockTraces> {
        let result = self
            .db
            .key_value()
            .read_with_cache(db::COL_TRACE, &self.traces, block_hash);
        self.note_trace_used(*block_hash);
        result
    }

    /// Returns vector of transaction traces for given block.
    fn transactions_traces(&self, block_hash: &H256) -> Option<Vec<FlatTransactionTraces>> {
        self.traces(block_hash).map(Into::into)
    }

    fn matching_block_traces(
        &self,
        filter: &Filter,
        traces: FlatBlockTraces,
        block_hash: H256,
        block_number: BlockNumber,
    ) -> Vec<LocalizedTrace> {
        let tx_traces: Vec<FlatTransactionTraces> = traces.into();
        tx_traces
            .into_iter()
            .enumerate()
            .flat_map(|(tx_number, tx_trace)| {
                self.matching_transaction_traces(
                    filter,
                    tx_trace,
                    block_hash.clone(),
                    block_number,
                    tx_number,
                )
            })
            .collect()
    }

    fn matching_transaction_traces(
        &self,
        filter: &Filter,
        traces: FlatTransactionTraces,
        block_hash: H256,
        block_number: BlockNumber,
        tx_number: usize,
    ) -> Vec<LocalizedTrace> {
        let (trace_tx_number, trace_tx_hash) =
            match self.extras.transaction_hash(block_number, tx_number) {
                Some(hash) => (Some(tx_number), Some(hash.clone())),
                //None means trace without transaction (reward)
                None => (None, None),
            };

        let flat_traces: Vec<FlatTrace> = traces.into();
        flat_traces
            .into_iter()
            .filter_map(|trace| match filter.matches(&trace) {
                true => Some(LocalizedTrace {
                    action: trace.action,
                    result: trace.result,
                    subtraces: trace.subtraces,
                    trace_address: trace.trace_address.into_iter().collect(),
                    transaction_number: trace_tx_number,
                    transaction_hash: trace_tx_hash,
                    block_number: block_number,
                    block_hash: block_hash,
                }),
                false => None,
            })
            .collect()
    }
}

impl<T> TraceDatabase for TraceDB<T>
where
    T: DatabaseExtras,
{
    fn tracing_enabled(&self) -> bool {
        self.enabled
    }

    /// Traces of import request's enacted blocks are expected to be already in database
    /// or to be the currently inserted trace.
    fn import(&self, batch: &mut DBTransaction, request: ImportRequest) {
        // valid (canon):  retracted 0, enacted 1 => false, true,
        // valid (branch): retracted 0, enacted 0 => false, false,
        // valid (bbcc):   retracted 1, enacted 1 => true, true,
        // invalid:	       retracted 1, enacted 0 => true, false,
        let ret = request.retracted != 0;
        let ena = !request.enacted.is_empty();
        assert!(!(ret && !ena));
        // fast return if tracing is disabled
        if !self.tracing_enabled() {
            return;
        }

        // now let's rebuild the blooms
        if !request.enacted.is_empty() {
            let range_start = request.block_number + 1 - request.enacted.len() as u64;
            let enacted_blooms: Vec<_> = request
                .enacted
                .iter()
                // all traces are expected to be found here. That's why `expect` has been used
                // instead of `filter_map`. If some traces haven't been found, it meens that
                // traces database is corrupted or incomplete.
                .map(|block_hash| {
                    if block_hash == &request.block_hash {
                        request.traces.bloom()
                    } else {
                        self.traces(block_hash)
                            .expect("Traces database is incomplete.")
                            .bloom()
                    }
                })
                .collect();

            self.db
                .trace_blooms()
                .insert_blooms(range_start, enacted_blooms.iter())
                .expect("Low level database error. Some issue with disk?");
        }

        // insert new block traces into the cache and the database
        {
            let mut traces = self.traces.write();
            // it's important to use overwrite here,
            // cause this value might be queried by hash later
            batch.write_with_cache(
                db::COL_TRACE,
                &mut *traces,
                request.block_hash,
                request.traces,
                CacheUpdatePolicy::Overwrite,
            );
            // note_used must be called after locking traces to avoid cache/traces deadlock on garbage collection
            self.note_trace_used(request.block_hash);
        }
    }

    fn trace(
        &self,
        block_number: BlockNumber,
        tx_position: usize,
        trace_position: Vec<usize>,
    ) -> Option<LocalizedTrace> {
        self.extras.block_hash(block_number).and_then(|block_hash| {
            self.transactions_traces(&block_hash)
                .and_then(|traces| traces.into_iter().nth(tx_position))
                .map(Into::<Vec<FlatTrace>>::into)
                // this may and should be optimized
                .and_then(|traces| {
                    traces
                        .into_iter()
                        .find(|trace| trace.trace_address == trace_position)
                })
                .map(|trace| {
                    let tx_hash = self
                        .extras
                        .transaction_hash(block_number, tx_position)
                        .expect(
                            "Expected to find transaction hash. Database is probably corrupted",
                        );

                    LocalizedTrace {
                        action: trace.action,
                        result: trace.result,
                        subtraces: trace.subtraces,
                        trace_address: trace.trace_address.into_iter().collect(),
                        transaction_number: Some(tx_position),
                        transaction_hash: Some(tx_hash),
                        block_number: block_number,
                        block_hash: block_hash,
                    }
                })
        })
    }

    fn transaction_traces(
        &self,
        block_number: BlockNumber,
        tx_position: usize,
    ) -> Option<Vec<LocalizedTrace>> {
        self.extras.block_hash(block_number).and_then(|block_hash| {
            self.transactions_traces(&block_hash)
                .and_then(|traces| traces.into_iter().nth(tx_position))
                .map(Into::<Vec<FlatTrace>>::into)
                .map(|traces| {
                    let tx_hash = self
                        .extras
                        .transaction_hash(block_number, tx_position)
                        .expect(
                            "Expected to find transaction hash. Database is probably corrupted",
                        );

                    traces
                        .into_iter()
                        .map(|trace| LocalizedTrace {
                            action: trace.action,
                            result: trace.result,
                            subtraces: trace.subtraces,
                            trace_address: trace.trace_address.into_iter().collect(),
                            transaction_number: Some(tx_position),
                            transaction_hash: Some(tx_hash.clone()),
                            block_number: block_number,
                            block_hash: block_hash,
                        })
                        .collect()
                })
        })
    }

    fn block_traces(&self, block_number: BlockNumber) -> Option<Vec<LocalizedTrace>> {
        self.extras.block_hash(block_number).and_then(|block_hash| {
            self.transactions_traces(&block_hash).map(|traces| {
                traces
                    .into_iter()
                    .map(Into::<Vec<FlatTrace>>::into)
                    .enumerate()
                    .flat_map(|(tx_position, traces)| {
                        let (trace_tx_number, trace_tx_hash) =
                            match self.extras.transaction_hash(block_number, tx_position) {
                                Some(hash) => (Some(tx_position), Some(hash.clone())),
                                //None means trace without transaction (reward)
                                None => (None, None),
                            };

                        traces
                            .into_iter()
                            .map(|trace| LocalizedTrace {
                                action: trace.action,
                                result: trace.result,
                                subtraces: trace.subtraces,
                                trace_address: trace.trace_address.into_iter().collect(),
                                transaction_number: trace_tx_number,
                                transaction_hash: trace_tx_hash,
                                block_number: block_number,
                                block_hash: block_hash,
                            })
                            .collect::<Vec<LocalizedTrace>>()
                    })
                    .collect::<Vec<LocalizedTrace>>()
            })
        })
    }

    fn filter(&self, filter: &Filter) -> Vec<LocalizedTrace> {
        let possibilities = filter.bloom_possibilities();
        let numbers = self
            .db
            .trace_blooms()
            .filter(
                filter.range.start as u64,
                filter.range.end as u64,
                &possibilities,
            )
            .expect("Low level database error. Some issue with disk?");

        numbers
            .into_iter()
            .flat_map(|n| {
                let number = n as BlockNumber;
                let hash = self
                    .extras
                    .block_hash(number)
                    .expect("Expected to find block hash. Extras db is probably corrupted");
                let traces = self
                    .traces(&hash)
                    .expect("Expected to find a trace. Db is probably corrupted.");
                self.matching_block_traces(filter, traces, hash, number)
            })
            .collect()
    }
}
