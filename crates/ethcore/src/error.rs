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

//! General error types for use in ethcore.

// Silence: `use of deprecated item 'std::error::Error::cause': replaced by Error::source, which can support downcasting`
// https://github.com/openethereum/openethereum/issues/10302
#![allow(deprecated)]

use std::error;
use std::fmt::{self, Display};

use ethereum_types::{Address, Bloom, H256, U256};
use ethtrie::TrieError;
use rlp;
use types::transaction::Error as TransactionError;
use types::BlockNumber;
use unexpected::{Mismatch, OutOfBounds};

use crate::engines::EngineError;

pub use crate::executed::ExecutionError;

#[derive(Debug, PartialEq, Clone, Eq)]
/// Errors concerning block processing.
pub enum BlockError {
    /// Block has too many uncles.
    TooManyUncles(OutOfBounds<usize>),
    /// Extra data is of an invalid length.
    ExtraDataOutOfBounds(OutOfBounds<usize>),
    /// Seal is incorrect format.
    InvalidSealArity(Mismatch<usize>),
    /// Block has too much gas used.
    TooMuchGasUsed(OutOfBounds<U256>),
    /// Gas target increased too much from previous block
    GasTargetTooBig(OutOfBounds<U256>),
    /// Gas target decreased too much from previous block
    GasTargetTooSmall(OutOfBounds<U256>),
    /// Uncles hash in header is invalid.
    InvalidUnclesHash(Mismatch<H256>),
    /// An uncle is from a generation too old.
    UncleTooOld(OutOfBounds<BlockNumber>),
    /// An uncle is from the same generation as the block.
    UncleIsBrother(OutOfBounds<BlockNumber>),
    /// An uncle is already in the chain.
    UncleInChain(H256),
    /// An uncle is included twice.
    DuplicateUncle(H256),
    /// An uncle has a parent not in the chain.
    UncleParentNotInChain(H256),
    /// State root header field is invalid.
    InvalidStateRoot(Mismatch<H256>),
    /// Gas used header field is invalid.
    InvalidGasUsed(Mismatch<U256>),
    /// Transactions root header field is invalid.
    InvalidTransactionsRoot(Mismatch<H256>),
    /// Difficulty is out of range; this can be used as an looser error prior to getting a definitive
    /// value for difficulty. This error needs only provide bounds of which it is out.
    DifficultyOutOfBounds(OutOfBounds<U256>),
    /// Difficulty header field is invalid; this is a strong error used after getting a definitive
    /// value for difficulty (which is provided).
    InvalidDifficulty(Mismatch<U256>),
    /// Seal element of type H256 (max_hash for Ethash, but could be something else for
    /// other seal engines) is out of bounds.
    MismatchedH256SealElement(Mismatch<H256>),
    /// Proof-of-work aspect of seal, which we assume is a 256-bit value, is invalid.
    InvalidProofOfWork(OutOfBounds<U256>),
    /// Some low-level aspect of the seal is incorrect.
    InvalidSeal,
    /// Gas limit header field is invalid.
    InvalidGasLimit(OutOfBounds<U256>),
    /// Base fee is incorrect; base fee is different from the expected calculated value.
    IncorrectBaseFee(Mismatch<U256>),
    /// Receipts trie root header field is invalid.
    InvalidReceiptsRoot(Mismatch<H256>),
    /// Timestamp header field is invalid.
    InvalidTimestamp(OutOfBounds<u64>),
    /// Timestamp header field is too far in future.
    TemporarilyInvalid(OutOfBounds<u64>),
    /// Log bloom header field is invalid.
    InvalidLogBloom(Box<Mismatch<Bloom>>),
    /// Number field of header is invalid.
    InvalidNumber(Mismatch<BlockNumber>),
    /// Block number isn't sensible.
    RidiculousNumber(OutOfBounds<BlockNumber>),
    /// Timestamp header overflowed
    TimestampOverflow,
    /// Too many transactions from a particular address.
    TooManyTransactions(Address),
    /// Parent given is unknown.
    UnknownParent(H256),
    /// Uncle parent given is unknown.
    UnknownUncleParent(H256),
    /// No transition to epoch number.
    UnknownEpochTransition(u64),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BlockError::*;

        let msg = match *self {
            TooManyUncles(ref oob) => format!("Block has too many uncles. {}", oob),
            ExtraDataOutOfBounds(ref oob) => format!("Extra block data too long. {}", oob),
            InvalidSealArity(ref mis) => format!("Block seal in incorrect format: {}", mis),
            TooMuchGasUsed(ref oob) => format!("Block has too much gas used. {}", oob),
            GasTargetTooBig(ref oob) => format!("Gas target is bigger then expected. {}", oob),
            GasTargetTooSmall(ref oob) => format!("Gas target is smaller then expected. {}", oob),
            InvalidUnclesHash(ref mis) => format!("Block has invalid uncles hash: {}", mis),
            UncleTooOld(ref oob) => format!("Uncle block is too old. {}", oob),
            UncleIsBrother(ref oob) => format!("Uncle from same generation as block. {}", oob),
            UncleInChain(ref hash) => format!("Uncle {} already in chain", hash),
            DuplicateUncle(ref hash) => format!("Uncle {} already in the header", hash),
            UncleParentNotInChain(ref hash) => {
                format!("Uncle {} has a parent not in the chain", hash)
            }
            InvalidStateRoot(ref mis) => format!("Invalid state root in header: {}", mis),
            InvalidGasUsed(ref mis) => format!("Invalid gas used in header: {}", mis),
            InvalidTransactionsRoot(ref mis) => {
                format!("Invalid transactions root in header: {}", mis)
            }
            DifficultyOutOfBounds(ref oob) => format!("Invalid block difficulty: {}", oob),
            InvalidDifficulty(ref mis) => format!("Invalid block difficulty: {}", mis),
            MismatchedH256SealElement(ref mis) => format!("Seal element out of bounds: {}", mis),
            InvalidProofOfWork(ref oob) => format!("Block has invalid PoW: {}", oob),
            InvalidSeal => "Block has invalid seal.".into(),
            InvalidGasLimit(ref oob) => format!("Invalid gas limit: {}", oob),
            IncorrectBaseFee(ref mis) => format!("Incorrect base fee: {}", mis),
            InvalidReceiptsRoot(ref mis) => {
                format!("Invalid receipts trie root in header: {}", mis)
            }
            InvalidTimestamp(ref oob) => {
                format!("Invalid timestamp in header: {}", oob)
            }
            TemporarilyInvalid(ref oob) => {
                format!("Future timestamp in header: {}", oob)
            }
            InvalidLogBloom(ref oob) => format!("Invalid log bloom in header: {}", oob),
            InvalidNumber(ref mis) => format!("Invalid number in header: {}", mis),
            RidiculousNumber(ref oob) => format!("Implausible block number. {}", oob),
            UnknownParent(ref hash) => format!("Unknown parent: {}", hash),
            UnknownUncleParent(ref hash) => format!("Unknown uncle parent: {}", hash),
            UnknownEpochTransition(ref num) => {
                format!("Unknown transition to epoch number: {}", num)
            }
            TimestampOverflow => format!("Timestamp overflow"),
            TooManyTransactions(ref address) => format!("Too many transactions from: {}", address),
        };

        f.write_fmt(format_args!("Block error ({})", msg))
    }
}

impl error::Error for BlockError {}

impl<E> From<Box<E>> for Error
where
    Error: From<E>,
{
    fn from(err: Box<E>) -> Error {
        Error::from(*err)
    }
}

impl ::std::error::Error for Error {}

///Error concerning TrieDBs.
impl From<TrieError> for Error {
    fn from(e: TrieError) -> Self {
        Error::Trie(e)
    }
}

///Error concerning EVM code execution.
impl From<ExecutionError> for Error {
    fn from(e: ExecutionError) -> Self {
        Error::Execution(e)
    }
}

///Error concerning block processing.
impl From<BlockError> for Error {
    fn from(e: BlockError) -> Self {
        Error::Block(e)
    }
}

///Error concerning transaction processing.
impl From<TransactionError> for Error {
    fn from(e: TransactionError) -> Self {
        Error::Transaction(e)
    }
}

///Consensus vote error.
impl From<EngineError> for Error {
    fn from(e: EngineError) -> Self {
        Error::Engine(e)
    }
}

///RLP decoding errors
impl From<rlp::DecoderError> for Error {
    fn from(e: rlp::DecoderError) -> Self {
        Error::Decoder(e)
    }
}

/// The kind of an error.
#[derive(Debug)]
pub enum Error {
    /// A convenient variant for String.
    Msg(String),
    ///Error concerning TrieDBs.
    Trie(TrieError),
    ///Error concerning EVM code execution.
    Execution(ExecutionError),
    ///Error concerning block processing.
    Block(BlockError),
    ///Error concerning transaction processing.
    Transaction(TransactionError),
    ///Consensus vote error.
    Engine(EngineError),
    ///RLP decoding errors
    Decoder(rlp::DecoderError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        let msg = match self {
            Msg(s) => format!("err: {}", s),
            Trie(trie) => format!("trie err: {}", trie),
            Execution(e) => format!("exec err: {}", e),
            Block(e) => format!("block err: {}", e),
            Transaction(e) => format!("transaction err: {}", e),
            Engine(e) => format!("consensus err: {}", e),
            Decoder(e) => format!("rlp err: {}", e),
        };
        f.write_fmt(format_args!("Block error ({})", msg))
    }
}

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Self {
        Error::Msg(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Msg(s)
    }
}
