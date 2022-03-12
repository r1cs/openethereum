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

use std::{
    collections::{HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use ansi_term::Colour;
use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use miner::{
    self,
    MinerService,
};
use parking_lot::{Mutex, RwLock};
use types::{
    transaction::{self, PendingTransaction, UnverifiedTransaction},
    BlockNumber,
};
use using_queue::{GetAction, UsingQueue};

use block::{ClosedBlock, SealedBlock};
use client::{BlockChain, BlockProducer, Nonce, SealedBlockImporter};
use engines::{EthEngine, SealingState};
use error::{Error, ErrorKind};
use executed::ExecutionError;
use spec::Spec;
use state::State;
use types::transaction::SignedTransaction;

/// Pending block preparation status.
#[derive(Debug, PartialEq)]
pub enum BlockPreparationStatus {
    /// We had to prepare new pending block and the preparation succeeded.
    Succeeded,
    /// We had to prepare new pending block but the preparation failed.
    Failed,
    /// We didn't have to prepare a new block.
    NotPrepared,
}

/// Allowed number of skipped transactions when constructing pending block.
///
/// When we push transactions to pending block, some of the transactions might
/// get skipped because of block gas limit being reached.
/// This constant controls how many transactions we can skip because of that
/// before stopping attempts to push more transactions to the block.
/// This is an optimization that prevents traversing the entire pool
/// in case we have only a fraction of available block gas limit left.
const MAX_SKIPPED_TRANSACTIONS: usize = 128;

/// Configures the behaviour of the miner.
#[derive(Debug, PartialEq)]
pub struct MinerOptions {
    /// Force the miner to reseal, even when nobody has asked for work.
    pub force_sealing: bool,
    /// How many historical work packages can we store before running out?
    pub work_queue_size: usize,
    /// Can we submit two different solutions for the same block and expect both to result in an import?
    pub enable_resubmission: bool,
    /// Create a pending block with maximal possible gas limit.
    /// NOTE: Such block will contain all pending transactions but
    /// will be invalid if mined.
    pub infinite_pending_block: bool,
}

impl Default for MinerOptions {
    fn default() -> Self {
        MinerOptions {
            force_sealing: false,
            work_queue_size: 20,
            enable_resubmission: true,
            infinite_pending_block: false,
        }
    }
}

/// Configurable parameters of block authoring.
#[derive(Debug, Default, Clone)]
pub struct AuthoringParams {
    /// Lower and upper bound of block gas limit that we are targeting
    pub gas_range_target: (U256, U256),
    /// Block author
    pub author: Address,
    /// Block extra data
    pub extra_data: Bytes,
}

struct SealingWork {
    queue: UsingQueue<ClosedBlock>,
    // block number when sealing work was last requested
    last_request: Option<u64>,
}

/// Keeps track of transactions using priority queue and holds currently mined block.
/// Handles preparing work for "work sealing" or seals "internally" if Engine does not require work.
pub struct Miner {
    // NOTE [ToDr]  When locking always lock in this order!
    sealing: Mutex<SealingWork>,
    params: RwLock<AuthoringParams>,
    options: MinerOptions,
    // TODO [ToDr] Arc is only required because of price updater
    engine: Arc<dyn EthEngine>,
}

impl Miner {
    /// Creates new instance of miner Arc.
    pub fn new(
        options: MinerOptions,
        spec: &Spec,
    ) -> Self {
        let engine = spec.engine.clone();

        Miner {
            sealing: Mutex::new(SealingWork {
                queue: UsingQueue::new(options.work_queue_size),
                last_request: None,
            }),
            params: RwLock::new(AuthoringParams::default()),
            options,
            engine,
        }
    }

    /// Creates new instance of miner with given spec and accounts.
    ///
    /// NOTE This should be only used for tests.
    pub fn new_for_tests(spec: &Spec, _accounts: Option<HashSet<Address>>) -> Miner {
        let force_sealing =  false;
        Miner::new(
            MinerOptions {
                force_sealing,
                ..Default::default()
            },
            spec,
        )
    }

    /// Prepares new block for sealing including top transactions from queue.
    fn prepare_block<C>(&self, chain: &C) -> Option<(ClosedBlock, Option<H256>)>
    where
        C: BlockChain + BlockProducer + Nonce + Sync,
    {
        trace_time!("prepare_block");
        let chain_info = chain.chain_info();

        // Some engines add transactions to the block for their own purposes, e.g. AuthorityRound RANDAO.
        let (mut open_block, original_work_hash, engine_txs) = {
            let mut sealing = self.sealing.lock();
            let last_work_hash = sealing.queue.peek_last_ref().map(|pb| pb.header.hash());
            let best_hash = chain_info.best_block_hash;

            // check to see if last ClosedBlock in would_seals is actually same parent block.
            // if so
            //   duplicate, re-open and push any new transactions.
            //   if at least one was pushed successfully, close and enqueue new ClosedBlock;
            //   otherwise, leave everything alone.
            // otherwise, author a fresh block.
            match sealing
                .queue
                .get_pending_if(|b| b.header.parent_hash() == &best_hash)
            {
                Some(old_block) => {
                    trace!(target: "miner", "prepare_block: Already have previous work; updating and returning");
                    // add transactions to old_block
                    (chain.reopen_block(old_block), last_work_hash, Vec::new())
                }
                None => {
                    // block not found - create it.
                    trace!(target: "miner", "prepare_block: No existing work - making new block");
                    let params = self.params.read().clone();

                    let block = match chain.prepare_open_block(
                        params.author,
                        params.gas_range_target,
                        params.extra_data,
                    ) {
                        Ok(block) => block,
                        Err(err) => {
                            warn!(target: "miner", "Open new block failed with error {:?}. This is likely an error in \
								  chain specification or on-chain consensus smart contracts.", err);
                            return None;
                        }
                    };
					(block, last_work_hash, Vec::new())
                }
            }
        };

        if self.options.infinite_pending_block {
            open_block.remove_gas_limit();
        }

        let mut invalid_transactions = HashSet::new();
        let block_number = open_block.header.number();

        let mut tx_count = 0usize;
        let mut skipped_transactions = 0usize;

        let schedule = self.engine.schedule(block_number);
        let min_tx_gas: U256 = schedule.tx_gas.into();

		let queue_txs : Vec<SignedTransaction> = Vec::new();
        let took_ms = |elapsed: &Duration| {
            elapsed.as_secs() * 1000 + elapsed.subsec_nanos() as u64 / 1_000_000
        };

        let block_start = Instant::now();
        debug!(target: "miner", "Attempting to push {} transactions.", engine_txs.len() + queue_txs.len());

        for transaction in engine_txs.into_iter().chain(queue_txs) {
            let hash = transaction.hash();
            // Re-verify transaction again vs current state.
            let result = self.engine.machine()
				.verify_transaction_basic(&transaction, &open_block.header)
                .map_err(|e| e.into())
                .and_then(|_| open_block.push_transaction(transaction, None));

            match result {
                Err(Error(
                    ErrorKind::Execution(ExecutionError::BlockGasLimitReached {
                        gas_limit,
                        gas_used,
                        gas,
                    }),
                    _,
                )) => {
                    debug!(target: "miner", "Skipping adding transaction to block because of gas limit: {:?} (limit: {:?}, used: {:?}, gas: {:?})", hash, gas_limit, gas_used, gas);

                    // Penalize transaction if it's above current gas limit
                    if gas > gas_limit {
                        debug!(target: "txqueue", "[{:?}] Transaction above block gas limit.", hash);
                        invalid_transactions.insert(hash);
                    }

                    // Exit early if gas left is smaller then min_tx_gas
                    let gas_left = gas_limit - gas_used;
                    if gas_left < min_tx_gas {
                        debug!(target: "miner", "Remaining gas is lower than minimal gas for a transaction. Block is full.");
                        break;
                    }

                    // Avoid iterating over the entire queue in case block is almost full.
                    skipped_transactions += 1;
                    if skipped_transactions > MAX_SKIPPED_TRANSACTIONS {
                        debug!(target: "miner", "Reached skipped transactions threshold. Assuming block is full.");
                        break;
                    }
                }
                // Invalid nonce error can happen only if previous transaction is skipped because of gas limit.
                // If there is errornous state of transaction queue it will be fixed when next block is imported.
                Err(Error(
                    ErrorKind::Execution(ExecutionError::InvalidNonce { expected, got }),
                    _,
                )) => {
                    debug!(target: "miner", "Skipping adding transaction to block because of invalid nonce: {:?} (expected: {:?}, got: {:?})", hash, expected, got);
                }
                // already have transaction - ignore
                Err(Error(ErrorKind::Transaction(transaction::Error::AlreadyImported), _)) => {}
                Err(Error(ErrorKind::Transaction(transaction::Error::NotAllowed), _)) => {
                    debug!(target: "miner", "Skipping non-allowed transaction for sender {:?}", hash);
                }
                Err(e) => {
                    debug!(target: "txqueue", "[{:?}] Marking as invalid: {:?}.", hash, e);
                    debug!(
                        target: "miner", "Error adding transaction to block: number={}. transaction_hash={:?}, Error: {:?}", block_number, hash, e
                    );
                    invalid_transactions.insert(hash);
                }
                // imported ok
                _ => tx_count += 1,
            }
        }
        let elapsed = block_start.elapsed();
        debug!(target: "miner", "Pushed {} transactions in {} ms", tx_count, took_ms(&elapsed));

        let block = match open_block.close() {
            Ok(block) => block,
            Err(err) => {
                warn!(target: "miner", "Closing the block failed with error {:?}. This is likely an error in chain specificiations or on-chain consensus smart contracts.", err);
                return None;
            }
        };

        Some((block, original_work_hash))
    }

    /// Prepares work which has to be done to seal.
    fn prepare_work(&self, block: ClosedBlock, original_work_hash: Option<H256>) {
            let block_header = block.header.clone();
            let block_hash = block_header.hash();

            let mut sealing = self.sealing.lock();
            let last_work_hash = sealing.queue.peek_last_ref().map(|pb| pb.header.hash());

            trace!(
                target: "miner",
                "prepare_work: Checking whether we need to reseal: orig={:?} last={:?}, this={:?}",
                original_work_hash, last_work_hash, block_hash
            );

            let (work, is_new) = if last_work_hash.map_or(true, |h| h != block_hash) {
                trace!(
                    target: "miner",
                    "prepare_work: Pushing a new, refreshed or borrowed pending {}...",
                    block_hash
                );
                let is_new = original_work_hash.map_or(true, |h| h != block_hash);

                sealing.queue.set_pending(block);

                (
                    Some((
                        block_hash,
                        *block_header.difficulty(),
                        block_header.number(),
                    )),
                    is_new,
                )
            } else {
                (None, false)
            };
            trace!(
                target: "miner",
                "prepare_work: leaving (last={:?})",
                sealing.queue.peek_last_ref().map(|b| b.header.hash())
            );
    }

    /// Prepare a pending block. Returns the preparation status.
    fn prepare_pending_block<C>(&self, client: &C) -> BlockPreparationStatus
    where
        C: BlockChain + BlockProducer + SealedBlockImporter + Nonce + Sync,
    {
        trace!(target: "miner", "prepare_pending_block: entering");
        let prepare_new = {
            let mut sealing = self.sealing.lock();
            let have_work = sealing.queue.peek_last_ref().is_some();
            trace!(target: "miner", "prepare_pending_block: have_work={}", have_work);
            if !have_work {
                true
            } else {
                false
            }
        };

        if self.engine.sealing_state() != SealingState::External {
            trace!(target: "miner", "prepare_pending_block: engine not sealing externally; not preparing");
            return BlockPreparationStatus::NotPrepared;
        }

        let preparation_status = if prepare_new {
            // --------------------------------------------------------------------------
            // | NOTE Code below requires sealing locks.                                |
            // | Make sure to release the locks before calling that method.             |
            // --------------------------------------------------------------------------
            match self.prepare_block(client) {
                Some((block, original_work_hash)) => {
                    self.prepare_work(block, original_work_hash);
                    BlockPreparationStatus::Succeeded
                }
                None => BlockPreparationStatus::Failed,
            }
        } else {
            BlockPreparationStatus::NotPrepared
        };

        let best_number = client.chain_info().best_block_number;
        let mut sealing = self.sealing.lock();
        if sealing.last_request != Some(best_number) {
            trace!(
                target: "miner",
                "prepare_pending_block: Miner received request (was {}, now {}) - waking up.",
                sealing.last_request.unwrap_or(0), best_number
            );
            sealing.last_request = Some(best_number);
        }

        preparation_status
    }
}

impl miner::MinerService for Miner {
    type State = State<::state_db::StateDB>;

    fn work_package<C>(&self, chain: &C) -> Option<(H256, BlockNumber, u64, U256)>
    where
        C: BlockChain + BlockProducer + SealedBlockImporter + Nonce + Sync,
    {
        if self.engine.sealing_state() != SealingState::External {
            return None;
        }

        self.prepare_pending_block(chain);

        self.sealing.lock().queue.use_last_ref().map(|b| {
            let header = &b.header;
            (
                header.hash(),
                header.number(),
                header.timestamp(),
                *header.difficulty(),
            )
        })
    }

    // Note used for external submission (PoW) and internally by sealing engines.
    fn submit_seal(&self, block_hash: H256, seal: Vec<Bytes>) -> Result<SealedBlock, Error> {
        let result = if let Some(b) = self.sealing.lock().queue.get_used_if(
            if self.options.enable_resubmission {
                GetAction::Clone
            } else {
                GetAction::Take
            },
            |b| &b.header.bare_hash() == &block_hash,
        ) {
            trace!(target: "miner", "Submitted block {}={} with seal {:?}", block_hash, b.header.bare_hash(), seal);
            b.lock().try_seal(&*self.engine, seal).or_else(|e| {
                warn!(target: "miner", "Mined solution rejected: {}", e);
                Err(ErrorKind::PowInvalid.into())
            })
        } else {
            warn!(target: "miner", "Submitted solution rejected: Block unknown or out of date.");
            Err(ErrorKind::PowHashInvalid.into())
        };

        result.and_then(|sealed| {
            let n = sealed.header.number();
            let h = sealed.header.hash();
            info!(target: "miner", "Submitted block imported OK. #{}: {}", Colour::White.bold().paint(format!("{}", n)), Colour::White.bold().paint(format!("{:x}", h)));
            Ok(sealed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client::{EachBlockWith, ImportSealedBlock, TestBlockChainClient};
    use miner::{MinerService};

    #[test]
    fn should_prepare_block_to_seal() {
        // given
        let client = TestBlockChainClient::default();
        let miner = Miner::new_for_tests(&Spec::new_test(), None);

        // when
        let sealing_work = miner.work_package(&client);
        assert!(sealing_work.is_some(), "Expected closed block");
    }

    #[test]
    fn should_still_work_after_a_couple_of_blocks() {
        // given
        let client = TestBlockChainClient::default();
        let miner = Miner::new_for_tests(&Spec::new_test(), None);

        let res = miner.work_package(&client);
        let hash = res.unwrap().0;
        let block = miner.submit_seal(hash, vec![]).unwrap();
        client.import_sealed_block(block).unwrap();

        // two more blocks mined, work requested.
        client.add_blocks(1, EachBlockWith::Uncle);
        miner.work_package(&client);

        client.add_blocks(1, EachBlockWith::Uncle);
        miner.work_package(&client);

        // solution to original work submitted.
        assert!(miner.submit_seal(hash, vec![]).is_ok());
    }
}
