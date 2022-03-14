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

use bytes::Bytes;
use ethereum_types::{Address, U256};
use types::transaction;

use block::SealedBlock;
use client::PrepareOpenBlock;
use engines::EthEngine;
use error::{Error, ErrorKind};
use executed::ExecutionError;
use types::transaction::SignedTransaction;

/// Allowed number of skipped transactions when constructing pending block.
///
/// When we push transactions to pending block, some of the transactions might
/// get skipped because of block gas limit being reached.
/// This constant controls how many transactions we can skip because of that
/// before stopping attempts to push more transactions to the block.
/// This is an optimization that prevents traversing the entire pool
/// in case we have only a fraction of available block gas limit left.
const MAX_SKIPPED_TRANSACTIONS: usize = 128;

/// generate and seal new block.
pub fn generate_block(engine: &impl EthEngine, chain: &impl PrepareOpenBlock, author: Address, gas_range_target: (U256, U256),
	 extra_data: Bytes, txes: Vec<SignedTransaction>) -> Option<SealedBlock> {
	let mut open_block = chain.prepare_open_block(author, gas_range_target, extra_data).ok()?;

	let block_number = open_block.header.number();
	let mut skipped_transactions = 0usize;
	let schedule = engine.schedule(block_number);
	let min_tx_gas: U256 = schedule.tx_gas.into();

	for transaction in txes {
		let hash = transaction.hash();
		// Re-verify transaction again vs current state.
		let result = engine.machine()
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
				ErrorKind::Execution(ExecutionError::InvalidNonce {..}),
				_,
			)) => {}
			// already have transaction - ignore
			Err(Error(ErrorKind::Transaction(transaction::Error::AlreadyImported), _)) => {}
			Err(Error(ErrorKind::Transaction(transaction::Error::NotAllowed), _)) => {
				debug!(target: "miner", "Skipping non-allowed transaction for sender {:?}", hash);
			}
			Err(_e) => {}
			// imported ok
			_ => {},
		}
	}

	let closed_block = open_block.close().ok()?;
	let sealed_block = closed_block.lock().try_seal(engine, Vec::new()).expect("seal failed");
	Some(sealed_block)
}
