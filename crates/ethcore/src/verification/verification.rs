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

//! Block and transaction verification functions
//!
//! Block verification is done in 3 steps
//! 1. Quick verification upon adding to the block queue
//! 2. Signatures verification done in the queue.
//! 3. Final verification against the blockchain done before enactment.

use std::collections::HashSet;
use bytes::Bytes;
use hash::keccak;
use rlp::Rlp;
use triehash::ordered_trie_root;
use unexpected::{Mismatch, OutOfBounds};

use blockchain::*;
use client::BlockInfo;
use engines::{EthEngine, MAX_UNCLE_AGE};
use error::{BlockError, Error};
use types::{header::Header, transaction::SignedTransaction, BlockNumber};
use verification::queue::kind::blocks::Unverified;

/// Preprocessed block data gathered in `verify_block_unordered` call
pub struct PreverifiedBlock {
    /// Populated block header
    pub header: Header,
    /// Populated block transactions
    pub transactions: Vec<SignedTransaction>,
    /// Populated block uncles
    pub uncles: Vec<Header>,
    /// Block bytes
    pub bytes: Bytes,
}

/// t_nb 4.0 Phase 1 quick block verification. Only does checks that are cheap. Operates on a single block
pub fn verify_block_basic(
    block: &Unverified,
    engine: &dyn EthEngine,
    check_seal: bool,
) -> Result<(), Error> {
    // t_nb 4.1  verify header params
    verify_header_params(&block.header, engine, check_seal)?;
    // t_nb 4.2 verify header time (addded in new OE version)
    // t_nb 4.3 verify block integrity
    verify_block_integrity(block)?;

    if check_seal {
        // t_nb 4.4 Check block seal. It calls engine to verify block basic
        engine.verify_block_basic(&block.header)?;
    }

    // t_nb 4.5 for all uncled verify header and call engine to verify block basic
    for uncle in &block.uncles {
        // t_nb 4.5.1
        verify_header_params(uncle, engine, check_seal)?;
        if check_seal {
            // t_nb 4.5.2
            engine.verify_block_basic(uncle)?;
        }
    }

    // t_nb 4.6 call engine.gas_limit_override (Used only by Aura)
    if let Some(expected_gas_limit) = engine.gas_limit_override(&block.header) {
        if block.header.gas_limit() != &expected_gas_limit {
            return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
                min: Some(expected_gas_limit),
                max: Some(expected_gas_limit),
                found: *block.header.gas_limit(),
            })));
        }
    }

    // t_nb 4.7 for every transaction call engine.verify_transaction_basic
    for t in &block.transactions {
        engine.verify_transaction_basic(t, &block.header)?;
    }

    Ok(())
}

// t_nb 5.0 Phase 2 verification. Perform costly checks such as transaction signatures and block nonce for ethash.
/// Still operates on a individual block
/// Returns a `PreverifiedBlock` structure populated with transactions
pub fn verify_block_unordered(
    block: Unverified,
    engine: &dyn EthEngine,
    check_seal: bool,
) -> Result<PreverifiedBlock, Error> {
    let header = block.header;
    if check_seal {
        // t_nb 5.1
        engine.verify_block_unordered(&header)?;
        for uncle in &block.uncles {
            // t_nb 5.2
            engine.verify_block_unordered(uncle)?;
        }
    }
    // Verify transactions.
    let nonce_cap = if header.number() >= engine.params().dust_protection_transition {
        Some((engine.params().nonce_cap_increment * header.number()).into())
    } else {
        None
    };

    // t_nb 5.3 iterate over all transactions
    let transactions = block
        .transactions
        .into_iter()
        .map(|t| {
            // t_nb 5.3.1 call verify_unordered. Check signatures and calculate address
            let t = engine.verify_transaction_unordered(t, &header)?;
            // t_nb 5.3.2 check if nonce is more then max nonce (EIP-168 and EIP169)
            if let Some(max_nonce) = nonce_cap {
                if t.tx().nonce >= max_nonce {
                    return Err(BlockError::TooManyTransactions(t.sender()).into());
                }
            }
            Ok(t)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    Ok(PreverifiedBlock {
        header,
        transactions,
        uncles: block.uncles,
        bytes: block.bytes,
    })
}

/// Parameters for full verification of block family
pub struct FullFamilyParams<'a, C: BlockInfo + 'a> {
    /// Preverified block
    pub block: &'a PreverifiedBlock,

    /// Block provider to use during verification
    pub block_provider: &'a dyn BlockProvider,

    /// Engine client to use during verification
    pub client: &'a C,
}

/// t_nb 6.3 Phase 3 verification. Check block information against parent and uncles.
pub fn verify_block_family<C: BlockInfo>(
    header: &Header,
    parent: &Header,
    engine: &dyn EthEngine,
    do_full: Option<FullFamilyParams<C>>,
) -> Result<(), Error> {
    // TODO: verify timestamp
    // t_nb 6.3.1 verify parent
    verify_parent(&header, &parent, engine)?;
    engine.verify_block_family(&header, &parent)?;

    let params = match do_full {
        Some(x) => x,
        None => return Ok(()),
    };

    // t_nb 6.3.2 verify uncles
    verify_uncles(params.block, params.block_provider, engine)?;
    Ok(())
}

fn verify_uncles(
    block: &PreverifiedBlock,
    bc: &dyn BlockProvider,
    engine: &dyn EthEngine,
) -> Result<(), Error> {
    let header = &block.header;
    let num_uncles = block.uncles.len();
    let max_uncles = engine.maximum_uncle_count(header.number());
    if num_uncles != 0 {
        if num_uncles > max_uncles {
            return Err(From::from(BlockError::TooManyUncles(OutOfBounds {
                min: None,
                max: Some(max_uncles),
                found: num_uncles,
            })));
        }

        let mut excluded = HashSet::new();
        excluded.insert(header.hash());
        let mut hash = header.parent_hash().clone();
        excluded.insert(hash.clone());
        for _ in 0..MAX_UNCLE_AGE {
            match bc.block_details(&hash) {
                Some(details) => {
                    excluded.insert(details.parent);
                    let b = bc
                        .block(&hash)
                        .expect("parent already known to be stored; qed");
                    excluded.extend(b.uncle_hashes());
                    hash = details.parent;
                }
                None => break,
            }
        }

        let mut verified = HashSet::new();
        for uncle in &block.uncles {
            if excluded.contains(&uncle.hash()) {
                return Err(From::from(BlockError::UncleInChain(uncle.hash())));
            }

            if verified.contains(&uncle.hash()) {
                return Err(From::from(BlockError::DuplicateUncle(uncle.hash())));
            }

            // m_currentBlock.number() - uncle.number()		m_cB.n - uP.n()
            // 1											2
            // 2
            // 3
            // 4
            // 5
            // 6											7
            //												(8 Invalid)

            let depth = if header.number() > uncle.number() {
                header.number() - uncle.number()
            } else {
                0
            };
            if depth > MAX_UNCLE_AGE as u64 {
                return Err(From::from(BlockError::UncleTooOld(OutOfBounds {
                    min: Some(header.number() - depth),
                    max: Some(header.number() - 1),
                    found: uncle.number(),
                })));
            } else if depth < 1 {
                return Err(From::from(BlockError::UncleIsBrother(OutOfBounds {
                    min: Some(header.number() - depth),
                    max: Some(header.number() - 1),
                    found: uncle.number(),
                })));
            }

            // cB
            // cB.p^1	    1 depth, valid uncle
            // cB.p^2	---/  2
            // cB.p^3	-----/  3
            // cB.p^4	-------/  4
            // cB.p^5	---------/  5
            // cB.p^6	-----------/  6
            // cB.p^7	-------------/
            // cB.p^8
            let mut expected_uncle_parent = header.parent_hash().clone();
            let uncle_parent = bc.block_header_data(&uncle.parent_hash()).ok_or_else(|| {
                Error::from(BlockError::UnknownUncleParent(uncle.parent_hash().clone()))
            })?;
            for _ in 0..depth {
                match bc.block_details(&expected_uncle_parent) {
                    Some(details) => {
                        expected_uncle_parent = details.parent;
                    }
                    None => break,
                }
            }
            if expected_uncle_parent != uncle_parent.hash() {
                return Err(From::from(BlockError::UncleParentNotInChain(
                    uncle_parent.hash(),
                )));
            }

            let uncle_parent = uncle_parent.decode(engine.params().eip1559_transition)?;
            verify_parent(&uncle, &uncle_parent, engine)?;
            engine.verify_block_family(&uncle, &uncle_parent)?;
            verified.insert(uncle.hash());
        }
    }

    Ok(())
}

/// Phase 4 verification. Check block information against transaction enactment results,
pub fn verify_block_final(expected: &Header, got: &Header) -> Result<(), Error> {
    if expected.state_root() != got.state_root() {
        return Err(From::from(BlockError::InvalidStateRoot(Mismatch {
            expected: *expected.state_root(),
            found: *got.state_root(),
        })));
    }
    if expected.gas_used() != got.gas_used() {
        return Err(From::from(BlockError::InvalidGasUsed(Mismatch {
            expected: *expected.gas_used(),
            found: *got.gas_used(),
        })));
    }
    if expected.log_bloom() != got.log_bloom() {
        return Err(From::from(BlockError::InvalidLogBloom(Box::new(
            Mismatch {
                expected: *expected.log_bloom(),
                found: *got.log_bloom(),
            },
        ))));
    }
    if expected.receipts_root() != got.receipts_root() {
        return Err(From::from(BlockError::InvalidReceiptsRoot(Mismatch {
            expected: *expected.receipts_root(),
            found: *got.receipts_root(),
        })));
    }
    Ok(())
}

/// Check basic header parameters.
pub fn verify_header_params(
    header: &Header,
    engine: &dyn EthEngine,
    check_seal: bool,
) -> Result<(), Error> {
    if check_seal {
        let expected_seal_fields = engine.seal_fields(header);
        if header.seal().len() != expected_seal_fields {
            return Err(From::from(BlockError::InvalidSealArity(Mismatch {
                expected: expected_seal_fields,
                found: header.seal().len(),
            })));
        }
    }

    if header.number() >= From::from(BlockNumber::max_value()) {
        return Err(From::from(BlockError::RidiculousNumber(OutOfBounds {
            max: Some(From::from(BlockNumber::max_value())),
            min: None,
            found: header.number(),
        })));
    }

    // check if the block used too much gas
    if header.gas_used() > header.gas_limit() {
        return Err(From::from(BlockError::TooMuchGasUsed(OutOfBounds {
            max: Some(*header.gas_limit()),
            min: None,
            found: *header.gas_used(),
        })));
    }
    if engine.gas_limit_override(header).is_none() {
        let min_gas_limit = engine.min_gas_limit();
        if header.gas_limit() < &min_gas_limit {
            return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
                min: Some(min_gas_limit),
                max: None,
                found: *header.gas_limit(),
            })));
        }
        if let Some(limit) = engine.maximum_gas_limit() {
            if header.gas_limit() > &limit {
                return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
                    min: None,
                    max: Some(limit),
                    found: *header.gas_limit(),
                })));
            }
        }
    }

    let maximum_extra_data_size = engine.maximum_extra_data_size();
    if header.number() != 0 && header.extra_data().len() > maximum_extra_data_size {
        return Err(From::from(BlockError::ExtraDataOutOfBounds(OutOfBounds {
            min: None,
            max: Some(maximum_extra_data_size),
            found: header.extra_data().len(),
        })));
    }

    if let Some(ref ext) = engine.machine().ethash_extensions() {
        if header.number() >= ext.dao_hardfork_transition
            && header.number() <= ext.dao_hardfork_transition + 9
            && header.extra_data()[..] != b"dao-hard-fork"[..]
        {
            return Err(From::from(BlockError::ExtraDataOutOfBounds(OutOfBounds {
                min: None,
                max: None,
                found: 0,
            })));
        }
    }

    Ok(())
}

/// Check header parameters agains parent header.
fn verify_parent(header: &Header, parent: &Header, engine: &dyn EthEngine) -> Result<(), Error> {
    assert!(
        header.parent_hash().is_zero() || &parent.hash() == header.parent_hash(),
        "Parent hash should already have been verified; qed"
    );

    if !engine.is_timestamp_valid(header.timestamp(), parent.timestamp()) {
		let min = parent.timestamp().saturating_add(1);
        let found = header.timestamp();
        return Err(From::from(BlockError::InvalidTimestamp(OutOfBounds {
            max: None,
            min: Some(min),
            found,
        })));
    }
    if header.number() != parent.number() + 1 {
        return Err(From::from(BlockError::InvalidNumber(Mismatch {
            expected: parent.number() + 1,
            found: header.number(),
        })));
    }

    if header.number() == 0 {
        return Err(BlockError::RidiculousNumber(OutOfBounds {
            min: Some(1),
            max: None,
            found: header.number(),
        })
        .into());
    }

    // check if the block changed the gas limit too much
    if engine.gas_limit_override(header).is_none() {
        let gas_limit_divisor = engine.params().gas_limit_bound_divisor;
        let parent_gas_limit =
            parent.gas_limit() * engine.schedule(header.number()).eip1559_gas_limit_bump;
        let min_gas = parent_gas_limit - parent_gas_limit / gas_limit_divisor;
        let max_gas = parent_gas_limit + parent_gas_limit / gas_limit_divisor;
        if header.gas_limit() <= &min_gas || header.gas_limit() >= &max_gas {
            return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
                min: Some(min_gas),
                max: Some(max_gas),
                found: *header.gas_limit(),
            })));
        }
    }

    // check if the base fee is correct
    let expected_base_fee = engine.calculate_base_fee(parent);
    if expected_base_fee != header.base_fee() {
        return Err(From::from(BlockError::IncorrectBaseFee(Mismatch {
            expected: expected_base_fee.unwrap_or_default(),
            found: header.base_fee().unwrap_or_default(),
        })));
    };

    Ok(())
}

/// Verify block data against header: transactions root and uncles hash.
fn verify_block_integrity(block: &Unverified) -> Result<(), Error> {
    let block_rlp = Rlp::new(&block.bytes);
    let tx = block_rlp.at(1)?;
    let expected_root = ordered_trie_root(tx.iter().map(|r| {
        if r.is_list() {
            r.as_raw()
        } else {
            // This is already checked in Unverified structure and that is why we are okay to asume that data is valid.
            r.data().expect(
                "Unverified block should already check if raw list of transactions is valid",
            )
        }
    }));
    if &expected_root != block.header.transactions_root() {
        bail!(BlockError::InvalidTransactionsRoot(Mismatch {
            expected: expected_root,
            found: *block.header.transactions_root(),
        }));
    }
    let expected_uncles = keccak(block_rlp.at(2)?.as_raw());
    if &expected_uncles != block.header.uncles_hash() {
        bail!(BlockError::InvalidUnclesHash(Mismatch {
            expected: expected_uncles,
            found: *block.header.uncles_hash(),
        }));
    }
    Ok(())
}
