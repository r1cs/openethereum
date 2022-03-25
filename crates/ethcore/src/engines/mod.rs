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

//! Consensus engine specification and basic implementations.

mod instant_seal;
mod null_engine;

pub mod block_reward;

pub use self::instant_seal::{InstantSeal, InstantSealParams};
pub use self::null_engine::NullEngine;

pub use types::engines::ForkChoice;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::{error, fmt};

use builtin::Builtin;
use error::Error;
use spec::CommonParams;
use types::header::{ExtendedHeader, Header};
use types::transaction::{self, SignedTransaction, UnverifiedTransaction};
use types::BlockNumber;
use vm::{CreateContractAddress, EnvInfo, Schedule};

use block::ExecutedBlock;
use bytes::Bytes;
use crypto::publickey::Signature;
use ethereum_types::{Address, H256, H64, U256};
use machine::{self, Machine};
use types::ancestry_action::AncestryAction;
use unexpected::{Mismatch, OutOfBounds};

/// The number of generations back that uncles can be.
pub const MAX_UNCLE_AGE: usize = 6;

/// Voting errors.
#[derive(Debug)]
pub enum EngineError {
    /// Signature or author field does not belong to an authority.
    NotAuthorized(Address),
    /// The same author issued different votes at the same step.
    DoubleVote(Address),
    /// The received block is from an incorrect proposer.
    NotProposer(Mismatch<Address>),
    /// Message was not expected.
    UnexpectedMessage,
    /// Seal field has an unexpected size.
    BadSealFieldSize(OutOfBounds<usize>),
    /// Validation proof insufficient.
    InsufficientProof(String),
    /// Failed system call.
    FailedSystemCall(String),
    /// Failed to decode the result of a system call.
    SystemCallResultDecoding(String),
    /// The result of a system call is invalid.
    SystemCallResultInvalid(String),
    /// Malformed consensus message.
    MalformedMessage(String),
    /// Requires client ref, but none registered.
    RequiresClient,
    /// Invalid engine specification or implementation.
    InvalidEngine,
    /// Requires signer ref, but none registered.
    RequiresSigner,
    /// Checkpoint is missing
    CliqueMissingCheckpoint(H256),
    /// Missing vanity data
    CliqueMissingVanity,
    /// Missing signature
    CliqueMissingSignature,
    /// Missing signers
    CliqueCheckpointNoSigner,
    /// List of signers is invalid
    CliqueCheckpointInvalidSigners(usize),
    /// Wrong author on a checkpoint
    CliqueWrongAuthorCheckpoint(Mismatch<Address>),
    /// Wrong checkpoint authors recovered
    CliqueFaultyRecoveredSigners(Vec<String>),
    /// Invalid nonce (should contain vote)
    CliqueInvalidNonce(H64),
    /// The signer signed a block to recently
    CliqueTooRecentlySigned(Address),
    /// Custom
    Custom(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EngineError::*;
        let msg = match *self {
            CliqueMissingCheckpoint(ref hash) => format!("Missing checkpoint block: {}", hash),
            CliqueMissingVanity => format!("Extra data is missing vanity data"),
            CliqueMissingSignature => format!("Extra data is missing signature"),
            CliqueCheckpointInvalidSigners(len) => format!(
                "Checkpoint block list was of length: {} of checkpoint but
															it needs to be bigger than zero and a divisible by 20",
                len
            ),
            CliqueCheckpointNoSigner => format!("Checkpoint block list of signers was empty"),
            CliqueInvalidNonce(ref mis) => {
                format!("Unexpected nonce {} expected {} or {}", mis, 0_u64, u64::max_value())
            }
            CliqueWrongAuthorCheckpoint(ref oob) => {
                format!("Unexpected checkpoint author: {}", oob)
            }
            CliqueFaultyRecoveredSigners(ref mis) => format!("Faulty recovered signers {:?}", mis),
            CliqueTooRecentlySigned(ref address) => {
                format!("The signer: {} has signed a block too recently", address)
            }
            Custom(ref s) => s.clone(),
            DoubleVote(ref address) => format!("Author {} issued too many blocks.", address),
            NotProposer(ref mis) => format!("Author is not a current proposer: {}", mis),
            NotAuthorized(ref address) => format!("Signer {} is not authorized.", address),
            UnexpectedMessage => "This Engine should not be fed messages.".into(),
            BadSealFieldSize(ref oob) => format!("Seal field has an unexpected length: {}", oob),
            InsufficientProof(ref msg) => format!("Insufficient validation proof: {}", msg),
            FailedSystemCall(ref msg) => format!("Failed to make system call: {}", msg),
            SystemCallResultDecoding(ref msg) => {
                format!("Failed to decode the result of a system call: {}", msg)
            }
            SystemCallResultInvalid(ref msg) => {
                format!("The result of a system call is invalid: {}", msg)
            }
            MalformedMessage(ref msg) => format!("Received malformed consensus message: {}", msg),
            RequiresClient => format!("Call requires client but none registered"),
            RequiresSigner => format!("Call requires signer but none registered"),
            InvalidEngine => format!("Invalid engine specification or implementation"),
        };

        f.write_fmt(format_args!("Engine error ({})", msg))
    }
}

impl error::Error for EngineError {
    fn description(&self) -> &str {
        "Engine error"
    }
}

/// Seal type.
#[derive(Debug, PartialEq, Eq)]
pub enum Seal {
    /// Proposal seal; should be broadcasted, but not inserted into blockchain.
    Proposal(Vec<Bytes>),
    /// Regular block seal; should be part of the blockchain.
    Regular(Vec<Bytes>),
    /// Engine does not generate seal for this block right now.
    None,
}

/// The type of sealing the engine is currently able to perform.
#[derive(Debug, PartialEq, Eq)]
pub enum SealingState {
    /// The engine is ready to seal a block.
    Ready,
    /// The engine can't seal at the moment, and no block should be prepared and queued.
    NotReady,
    /// The engine does not seal internally.
    External,
}

/// Type alias for a function we can get headers by hash through.
pub type Headers<'a, H> = dyn Fn(H256) -> Option<H> + 'a;

/// Proof dependent on state.
pub trait StateDependentProof<M: Machine>: Send + Sync {
    /// Generate a proof, given the state.
    fn generate_proof<'a>(&self, state: &machine::Call) -> Result<Vec<u8>, String>;
    /// Check a proof generated elsewhere (potentially by a peer).
    // `engine` needed to check state proofs, while really this should
    // just be state machine params.
    fn check_proof(&self, machine: &M, proof: &[u8]) -> Result<(), String>;
}

/// Proof generated on epoch change.
pub enum Proof<M: Machine> {
    /// Known proof (extracted from signal)
    Known(Vec<u8>),
    /// State dependent proof.
    WithState(Arc<dyn StateDependentProof<M>>),
}

/// A consensus mechanism for the chain. Generally either proof-of-work or proof-of-stake-based.
/// Provides hooks into each of the major parts of block import.
pub trait Engine<M: Machine>: Sync + Send {
    /// The name of this engine.
    fn name(&self) -> &str;

    /// Get access to the underlying state machine.
    // TODO: decouple.
    fn machine(&self) -> &M;

    /// The number of additional header fields required for this engine.
    fn seal_fields(&self, _header: &Header) -> usize {
        0
    }

    /// Additional engine-specific information for the user/developer concerning `header`.
    fn extra_info(&self, _header: &Header) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// Maximum number of uncles a block is allowed to declare.
    fn maximum_uncle_count(&self, _block: BlockNumber) -> usize {
        0
    }

    /// Optional maximum gas limit.
    fn maximum_gas_limit(&self) -> Option<U256> {
        None
    }

    /// Block transformation functions, after the transactions.
    fn on_close_block(&self, _block: &mut ExecutedBlock) -> Result<(), M::Error> {
        Ok(())
    }

    /// Allow mutating the header during seal generation. Currently only used by Clique.
    fn on_seal_block(&self, _block: &mut ExecutedBlock) -> Result<(), Error> {
        Ok(())
    }

    /// Returns the engine's current sealing state.
    fn sealing_state(&self) -> SealingState {
        SealingState::External
    }

    /// Called in `miner.chain_new_blocks` if the engine wishes to `update_sealing`
    /// after a block was recently sealed.
    ///
    /// returns false by default
    fn should_reseal_on_update(&self) -> bool {
        false
    }

    /// Attempt to seal the block internally.
    ///
    /// If `Some` is returned, then you get a valid seal.
    ///
    /// This operation is synchronous and may (quite reasonably) not be available, in which None will
    /// be returned.
    ///
    /// It is fine to require access to state or a full client for this function, since
    /// light clients do not generate seals.
    fn generate_seal(&self, _block: &ExecutedBlock, _parent: &Header) -> Seal {
        Seal::None
    }

    /// Verify a locally-generated seal of a header.
    ///
    /// If this engine seals internally,
    /// no checks have to be done here, since all internally generated seals
    /// should be valid.
    ///
    /// Externally-generated seals (e.g. PoW) will need to be checked for validity.
    ///
    /// It is fine to require access to state or a full client for this function, since
    /// light clients do not generate seals.
    fn verify_local_seal(&self, header: &Header) -> Result<(), M::Error>;

    /// Phase 1 quick block verification. Only does checks that are cheap. Returns either a null `Ok` or a general error detailing the problem with import.
    /// The verification module can optionally avoid checking the seal (`check_seal`), if seal verification is disabled this method won't be called.
    fn verify_block_basic(&self, _header: &Header) -> Result<(), M::Error> {
        Ok(())
    }

    /// Phase 2 verification. Perform costly checks such as transaction signatures. Returns either a null `Ok` or a general error detailing the problem with import.
    /// The verification module can optionally avoid checking the seal (`check_seal`), if seal verification is disabled this method won't be called.
    fn verify_block_unordered(&self, _header: &Header) -> Result<(), M::Error> {
        Ok(())
    }

    /// Phase 3 verification. Check block information against parent. Returns either a null `Ok` or a general error detailing the problem with import.
    fn verify_block_family(&self, _header: &Header, _parent: &Header) -> Result<(), M::Error> {
        Ok(())
    }

    /// Phase 4 verification. Verify block header against potentially external data.
    /// Should only be called when `register_client` has been called previously.
    fn verify_block_external(&self, _header: &Header) -> Result<(), M::Error> {
        Ok(())
    }

    /// Populate a header's fields based on its parent's header.
    /// Usually implements the chain scoring rule based on weight.
    fn populate_from_parent(&self, _header: &mut Header, _parent: &Header) {}

    /// Handle any potential consensus messages;
    /// updating consensus state and potentially issuing a new one.
    fn handle_message(&self, _message: &[u8]) -> Result<(), EngineError> {
        Err(EngineError::UnexpectedMessage)
    }

    /// Returns whether the current node is a validator and
    /// actually may seal a block if AuRa engine is used.
    ///
    /// Used by `eth_mining` rpc call.
    fn is_allowed_to_seal(&self) -> bool {
        true
    }

    /// Sign using the EngineSigner, to be used for consensus tx signing.
    fn sign(&self, _hash: H256) -> Result<Signature, M::Error> {
        unimplemented!()
    }

    /// Add Client which can be used for sealing, potentially querying the state and sending messages.
    fn register_client(&self, _client: Weak<M::EngineClient>) {}

    /// Return a new open block header timestamp based on the parent timestamp.
    fn open_block_header_timestamp(&self, parent_timestamp: u64) -> u64 {
        use std::{cmp, time};

        let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap_or_default();
        cmp::max(now.as_secs() as u64, parent_timestamp + 1)
    }

    /// Check whether the parent timestamp is valid.
    fn is_timestamp_valid(&self, header_timestamp: u64, parent_timestamp: u64) -> bool {
        header_timestamp > parent_timestamp
    }

    // t_nb 9.1 Gather all ancestry actions. Called at the last stage when a block is committed. The Engine must guarantee that
    /// the ancestry exists.
    fn ancestry_actions(
        &self, _header: &Header, _ancestry: &mut dyn Iterator<Item = ExtendedHeader>,
    ) -> Vec<AncestryAction> {
        Vec::new()
    }

    /// Check whether the given new block is the best block, after finalization check.
    fn fork_choice(&self, new: &ExtendedHeader, best: &ExtendedHeader) -> ForkChoice;

    /// Returns author should used when executing tx's for this block.
    fn executive_author(&self, header: &Header) -> Result<Address, Error> {
        Ok(*header.author())
    }

    /// Overrides the block gas limit. Whenever this returns `Some` for a header, the next block's gas limit must be
    /// exactly that value. used by AuRa engine.
    fn gas_limit_override(&self, _header: &Header) -> Option<U256> {
        None
    }
}

/// t_nb 9.3 Check whether a given block is the best block based on the default total difficulty rule.
pub fn total_difficulty_fork_choice(new: &ExtendedHeader, best: &ExtendedHeader) -> ForkChoice {
    if new.total_score() > best.total_score() {
        ForkChoice::New
    } else {
        ForkChoice::Old
    }
}

/// Common type alias for an engine coupled with an Ethereum-like state machine.
// TODO: make this a _trait_ alias when those exist.
// fortunately the effect is largely the same since engines are mostly used
// via trait objects.
pub trait EthEngine: Engine<::machine::EthereumMachine> {
    /// Get the general parameters of the chain.
    fn params(&self) -> &CommonParams {
        self.machine().params()
    }

    /// Get the EVM schedule for the given block number.
    fn schedule(&self, block_number: BlockNumber) -> Schedule {
        self.machine().schedule(block_number)
    }

    /// Builtin-contracts for the chain..
    fn builtins(&self) -> &BTreeMap<Address, Builtin> {
        self.machine().builtins()
    }

    /// Attempt to get a handle to a built-in contract.
    /// Only returns references to activated built-ins.
    fn builtin(&self, a: &Address, block_number: BlockNumber) -> Option<&Builtin> {
        self.machine().builtin(a, block_number)
    }

    /// Some intrinsic operation parameters; by default they take their value from the `spec()`'s `engine_params`.
    fn maximum_extra_data_size(&self) -> usize {
        self.machine().maximum_extra_data_size()
    }

    /// The nonce with which accounts begin at given block.
    fn account_start_nonce(&self, block: BlockNumber) -> U256 {
        self.machine().account_start_nonce(block)
    }

    /// The network ID that transactions should be signed with.
    fn signing_chain_id(&self, env_info: &EnvInfo) -> Option<u64> {
        self.machine().signing_chain_id(env_info)
    }

    /// Returns new contract address generation scheme at given block number.
    fn create_address_scheme(&self, number: BlockNumber) -> CreateContractAddress {
        self.machine().create_address_scheme(number)
    }

    // t_nb 5.3.1 Verify a particular transaction is valid.
    ///
    /// Unordered verification doesn't rely on the transaction execution order,
    /// i.e. it should only verify stuff that doesn't assume any previous transactions
    /// has already been verified and executed.
    ///
    /// NOTE This function consumes an `UnverifiedTransaction` and produces `SignedTransaction`
    /// which implies that a heavy check of the signature is performed here.
    fn verify_transaction_unordered(
        &self, t: UnverifiedTransaction, header: &Header,
    ) -> Result<SignedTransaction, transaction::Error> {
        self.machine().verify_transaction_unordered(t, header)
    }

    /// Perform basic/cheap transaction verification.
    ///
    /// This should include all cheap checks that can be done before
    /// actually checking the signature, like chain-replay protection.
    ///
    /// NOTE This is done before the signature is recovered so avoid
    /// doing any state-touching checks that might be expensive.
    ///
    /// TODO: Add flags for which bits of the transaction to check.
    /// TODO: consider including State in the params.
    fn verify_transaction_basic(
        &self, t: &UnverifiedTransaction, header: &Header,
    ) -> Result<(), transaction::Error> {
        self.machine().verify_transaction_basic(t, header)
    }

    /// Additional information.
    fn additional_params(&self) -> HashMap<String, String> {
        self.machine().additional_params()
    }

    /// Performs pre-validation of RLP decoded transaction before other processing
    fn decode_transaction(
        &self, transaction: &[u8], best_block_number: BlockNumber,
    ) -> Result<UnverifiedTransaction, transaction::Error> {
        let schedule = self.schedule(best_block_number);
        self.machine().decode_transaction(transaction, &schedule)
    }

    /// Calculates base fee for the block that should be mined next.
    /// This base fee is calculated based on the parent header (last block in blockchain / best block).
    ///
    /// Introduced by EIP1559 to support new market fee mechanism.
    fn calculate_base_fee(&self, parent: &Header) -> Option<U256> {
        self.machine().calc_base_fee(parent)
    }

    /// The configured minimum gas limit. Used by AuRa Engine.
    fn min_gas_limit(&self) -> U256 {
        self.params().min_gas_limit
    }

    /// Returns whether transactions from non externally owned accounts (EOA)
    /// are allowed in the given block number (see EIP-3607).
    ///
    /// That is only possible if EIP-3607 is still not activated.
    fn allow_non_eoa_sender(&self, best_block_number: BlockNumber) -> bool {
        self.params().eip3607_transition > best_block_number
    }
}

// convenience wrappers for existing functions.
impl<T> EthEngine for T where T: Engine<::machine::EthereumMachine> {}
