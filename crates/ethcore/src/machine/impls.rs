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

//! Ethereum-like state machine definition.

use std::{
    cmp::{self, max},
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use ethereum_types::{Address, U256};
use types::{
    header::Header,
    transaction::{self, SignedTransaction, TypedTransaction, UnverifiedTransaction},
    BlockNumber,
};
use vm::{CreateContractAddress, EnvInfo, Schedule};

use block::ExecutedBlock;
use builtin::Builtin;
use error::Error;
use spec::CommonParams;
use state::CleanupMode;

/// Ethash-specific extensions.
#[derive(Debug, Clone)]
pub struct EthashExtensions {
    /// Homestead transition block number.
    pub homestead_transition: BlockNumber,
    /// DAO hard-fork transition block (X).
    pub dao_hardfork_transition: u64,
    /// DAO hard-fork refund contract address (C).
    pub dao_hardfork_beneficiary: Address,
    /// DAO hard-fork DAO accounts list (L)
    pub dao_hardfork_accounts: Vec<Address>,
}

impl From<::ethjson::spec::EthashParams> for EthashExtensions {
    fn from(p: ::ethjson::spec::EthashParams) -> Self {
        EthashExtensions {
            homestead_transition: p.homestead_transition.map_or(0, Into::into),
            dao_hardfork_transition: p
                .dao_hardfork_transition
                .map_or(u64::max_value(), Into::into),
            dao_hardfork_beneficiary: p
                .dao_hardfork_beneficiary
                .map_or_else(Address::default, Into::into),
            dao_hardfork_accounts: p
                .dao_hardfork_accounts
                .unwrap_or_else(Vec::new)
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// Special rules to be applied to the schedule.
pub type ScheduleCreationRules = dyn Fn(&mut Schedule, BlockNumber) + Sync + Send;

/// An ethereum-like state machine.
pub struct EthereumMachine {
    params: CommonParams,
    builtins: Arc<BTreeMap<Address, Builtin>>,
    ethash_extensions: Option<EthashExtensions>,
    schedule_rules: Option<Box<ScheduleCreationRules>>,
}

impl EthereumMachine {
    /// Regular ethereum machine.
    pub fn regular(params: CommonParams, builtins: BTreeMap<Address, Builtin>) -> EthereumMachine {
        EthereumMachine {
            params,
            builtins: Arc::new(builtins),
            ethash_extensions: None,
            schedule_rules: None,
        }
    }

    /// Ethereum machine with ethash extensions.
    // TODO: either unify or specify to mainnet specifically and include other specific-chain HFs?
    pub fn with_ethash_extensions(
        params: CommonParams,
        builtins: BTreeMap<Address, Builtin>,
        extensions: EthashExtensions,
    ) -> EthereumMachine {
        let mut machine = EthereumMachine::regular(params, builtins);
        machine.ethash_extensions = Some(extensions);
        machine
    }

    /// Attach special rules to the creation of schedule.
    pub fn set_schedule_creation_rules(&mut self, rules: Box<ScheduleCreationRules>) {
        self.schedule_rules = Some(rules);
    }

    /// Get a reference to the ethash-specific extensions.
    pub fn ethash_extensions(&self) -> Option<&EthashExtensions> {
        self.ethash_extensions.as_ref()
    }
}

impl EthereumMachine {
    // t_nb 8.1.3 Logic to perform on a new block: updating last hashes and the DAO
    /// fork, for ethash.
    pub fn on_new_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        if let Some(ref ethash_params) = self.ethash_extensions {
            if block.header.number() == ethash_params.dao_hardfork_transition {
                let state = block.state_mut();
                for child in &ethash_params.dao_hardfork_accounts {
                    let beneficiary = &ethash_params.dao_hardfork_beneficiary;
                    state.balance(child).and_then(|b| {
                        state.transfer_balance(child, beneficiary, &b, CleanupMode::NoEmpty)
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Populate a header's fields based on its parent's header.
    /// Usually implements the chain scoring rule based on weight.
    /// The gas floor target must not be lower than the engine's minimum gas limit.
    pub fn populate_from_parent(
        &self,
        header: &mut Header,
        parent: &Header,
        gas_floor_target: U256,
        gas_ceil_target: U256,
    ) {
        header.set_difficulty(parent.difficulty().clone());
        let gas_limit = parent.gas_limit() * self.schedule(header.number()).eip1559_gas_limit_bump;
        assert!(!gas_limit.is_zero(), "Gas limit should be > 0");

        let gas_limit_target = if self.schedule(header.number()).eip1559 {
            gas_ceil_target
        } else {
            gas_floor_target
        };

        header.set_gas_limit({
            let bound_divisor = self.params().gas_limit_bound_divisor;
            if gas_limit < gas_limit_target {
                cmp::min(gas_limit_target, gas_limit + gas_limit / bound_divisor - 1)
            } else {
                cmp::max(gas_limit_target, gas_limit - gas_limit / bound_divisor + 1)
            }
        });

        if let Some(ref ethash_params) = self.ethash_extensions {
            if header.number() >= ethash_params.dao_hardfork_transition
                && header.number() <= ethash_params.dao_hardfork_transition + 9
            {
                header.set_extra_data(b"dao-hard-fork"[..].to_owned());
            }
        }
    }

    /// Get the general parameters of the chain.
    pub fn params(&self) -> &CommonParams {
        &self.params
    }

    /// Get the EVM schedule for the given block number.
    pub fn schedule(&self, block_number: BlockNumber) -> Schedule {
        let mut schedule = match self.ethash_extensions {
            None => self.params.schedule(block_number),
            Some(ref ext) => {
                if block_number < ext.homestead_transition {
                    Schedule::new_frontier()
                } else {
                    self.params.schedule(block_number)
                }
            }
        };

        if let Some(ref rules) = self.schedule_rules {
            (rules)(&mut schedule, block_number)
        }

        schedule
    }

    /// Builtin-contracts for the chain..
    pub fn builtins(&self) -> &BTreeMap<Address, Builtin> {
        &*self.builtins
    }

    /// Attempt to get a handle to a built-in contract.
    /// Only returns references to activated built-ins.
    // TODO: builtin contract routing - to do this properly, it will require removing the built-in configuration-reading logic
    // from Spec into here and removing the Spec::builtins field.
    pub fn builtin(&self, a: &Address, block_number: BlockNumber) -> Option<&Builtin> {
        self.builtins().get(a).and_then(|b| {
            if b.is_active(block_number) {
                Some(b)
            } else {
                None
            }
        })
    }

    /// Some intrinsic operation parameters; by default they take their value from the `spec()`'s `engine_params`.
    pub fn maximum_extra_data_size(&self) -> usize {
        self.params().maximum_extra_data_size
    }

    /// The nonce with which accounts begin at given block.
    pub fn account_start_nonce(&self, block: u64) -> U256 {
        let params = self.params();

        if block >= params.dust_protection_transition {
            U256::from(params.nonce_cap_increment) * U256::from(block)
        } else {
            params.account_start_nonce
        }
    }

    /// The network ID that transactions should be signed with.
    pub fn signing_chain_id(&self, env_info: &EnvInfo) -> Option<u64> {
        let params = self.params();

        if env_info.number >= params.eip155_transition {
            Some(params.chain_id)
        } else {
            None
        }
    }

    /// Returns new contract address generation scheme at given block number.
    pub fn create_address_scheme(&self, _number: BlockNumber) -> CreateContractAddress {
        CreateContractAddress::FromSenderAndNonce
    }

    /// Verify a particular transaction is valid, regardless of order.
    pub fn verify_transaction_unordered(
        &self,
        t: UnverifiedTransaction,
        header: &Header,
    ) -> Result<SignedTransaction, transaction::Error> {
        // ensure that the user was willing to at least pay the base fee
        if t.tx().gas_price < header.base_fee().unwrap_or_default() && !t.has_zero_gas_price() {
            return Err(transaction::Error::GasPriceLowerThanBaseFee {
                gas_price: t.tx().gas_price,
                base_fee: header.base_fee().unwrap_or_default(),
            });
        }

        Ok(SignedTransaction::new(t)?)
    }

    /// Does basic verification of the transaction.
    pub fn verify_transaction_basic(
        &self,
        t: &UnverifiedTransaction,
        header: &Header,
    ) -> Result<(), transaction::Error> {
        let check_low_s = match self.ethash_extensions {
            Some(ref ext) => header.number() >= ext.homestead_transition,
            None => true,
        };

        let chain_id = if header.number() < self.params().validate_chain_id_transition {
            t.chain_id()
        } else if header.number() >= self.params().eip155_transition {
            Some(self.params().chain_id)
        } else {
            None
        };
        t.verify_basic(check_low_s, chain_id)?;

        Ok(())
    }

    /// Additional params.
    pub fn additional_params(&self) -> HashMap<String, String> {
        hash_map![
            "registrar".to_owned() => format!("{:x}", self.params.registrar)
        ]
    }

    /// Performs pre-validation of RLP decoded transaction before other processing
    pub fn decode_transaction(
        &self,
        transaction: &[u8],
        schedule: &Schedule,
    ) -> Result<UnverifiedTransaction, transaction::Error> {
        if transaction.len() > self.params().max_transaction_size {
            debug!(
                "Rejected oversized transaction of {} bytes",
                transaction.len()
            );
            return Err(transaction::Error::TooBig);
        }

        let tx = TypedTransaction::decode(transaction)
            .map_err(|e| transaction::Error::InvalidRlp(e.to_string()))?;

        match tx.tx_type() {
            transaction::TypedTxId::AccessList if !schedule.eip2930 => {
                return Err(transaction::Error::TransactionTypeNotEnabled)
            }
            transaction::TypedTxId::EIP1559Transaction if !schedule.eip1559 => {
                return Err(transaction::Error::TransactionTypeNotEnabled)
            }
            _ => (),
        };

        Ok(tx)
    }

    /// Calculates base fee for the block that should be mined next.
    /// Base fee is calculated based on the parent header (last block in blockchain / best block).
    ///
    /// Introduced by EIP1559 to support new market fee mechanism.
    ///
    /// Modified for xDai chain to have an ability to set min base fee
    /// through eip1559BaseFeeMinValue spec option. The modification made
    /// in v3.3.0-rc.14
    pub fn calc_base_fee(&self, parent: &Header) -> Option<U256> {
        // Block eip1559_transition - 1 has base_fee = None
        if parent.number() + 1 < self.params().eip1559_transition {
            return None;
        }

        let base_fee_min_value =
            if parent.number() + 1 >= self.params().eip1559_base_fee_min_value_transition {
                match self.params().eip1559_base_fee_min_value {
                    None => panic!("Base fee min value must be set in spec."),
                    Some(min_value) => min_value,
                }
            } else {
                U256::zero()
            };

        // Block eip1559_transition has base_fee = self.params().eip1559_base_fee_initial_value
        if parent.number() + 1 == self.params().eip1559_transition {
            return Some(max(
                self.params().eip1559_base_fee_initial_value,
                base_fee_min_value,
            ));
        }

        // Block eip1559_transition + 1 has base_fee = calculated
        let base_fee_denominator = match self.params().eip1559_base_fee_max_change_denominator {
            None => panic!("Can't calculate base fee if base fee denominator does not exist."),
            Some(denominator) if denominator == U256::from(0) => {
                panic!("Can't calculate base fee if base fee denominator is zero.")
            }
            Some(denominator) => denominator,
        };

        let parent_base_fee = parent.base_fee().unwrap_or_default();
        let parent_gas_target = parent.gas_limit() / self.params().eip1559_elasticity_multiplier;
        if parent_gas_target == U256::zero() {
            panic!("Can't calculate base fee if parent gas target is zero.");
        }

        let result = if parent.gas_used() == &parent_gas_target {
            parent_base_fee
        } else if parent.gas_used() > &parent_gas_target {
            let gas_used_delta = parent.gas_used() - parent_gas_target;
            let base_fee_per_gas_delta = max(
                parent_base_fee * gas_used_delta / parent_gas_target / base_fee_denominator,
                U256::from(1),
            );
            parent_base_fee + base_fee_per_gas_delta
        } else {
            let gas_used_delta = parent_gas_target - parent.gas_used();
            let base_fee_per_gas_delta =
                parent_base_fee * gas_used_delta / parent_gas_target / base_fee_denominator;
            max(parent_base_fee - base_fee_per_gas_delta, U256::zero())
        };

        Some(max(result, base_fee_min_value))
    }
}

/// Auxiliary data fetcher for an Ethereum machine. In Ethereum-like machines
/// there are two kinds of auxiliary data: bodies and receipts.
#[derive(Default, Clone)]
pub struct AuxiliaryData<'a> {
    /// The full block bytes, including the header.
    pub bytes: Option<&'a [u8]>,
    /// The block receipts.
    pub receipts: Option<&'a [::types::receipt::TypedReceipt]>,
}

/// Type alias for a function we can make calls through synchronously.
/// Returns the call result and state proof for each call.
pub type Call<'a> = dyn Fn(Address, Vec<u8>) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> + 'a;

/// Request for auxiliary data of a block.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuxiliaryRequest {
    /// Needs the body.
    Body,
    /// Needs the receipts.
    Receipts,
    /// Needs both body and receipts.
    Both,
}

impl super::Machine for EthereumMachine {
    type EngineClient = dyn crate::client::EngineClient;

    type Error = Error;

    fn balance(&self, live: &ExecutedBlock, address: &Address) -> Result<U256, Error> {
        live.state.balance(address).map_err(Into::into)
    }

    fn add_balance(
        &self,
        live: &mut ExecutedBlock,
        address: &Address,
        amount: &U256,
    ) -> Result<(), Error> {
        live.state_mut()
            .add_balance(address, amount, CleanupMode::NoEmpty)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum::new_london_test_machine;
    use ethereum_types::H160;
    use std::str::FromStr;

    fn get_default_ethash_extensions() -> EthashExtensions {
        EthashExtensions {
            homestead_transition: 1150000,
            dao_hardfork_transition: u64::max_value(),
            dao_hardfork_beneficiary: H160::from_str("0000000000000000000000000000000000000001")
                .unwrap(),
            dao_hardfork_accounts: Vec::new(),
        }
    }

    #[test]
    fn should_disallow_unsigned_transactions() {
        let rlp = "ea80843b9aca0083015f90948921ebb5f79e9e3920abe571004d0b1d5119c154865af3107a400080038080";
		let raw_tx: Vec<u8> = ::rustc_hex::FromHex::from_hex(rlp).unwrap();
		let transaction: UnverifiedTransaction = TypedTransaction::decode(&raw_tx).unwrap();
        let spec = ::ethereum::new_ropsten_test();
        let ethparams = get_default_ethash_extensions();

        let machine = EthereumMachine::with_ethash_extensions(
            spec.params().clone(),
            Default::default(),
            ethparams,
        );
        let mut header = ::types::header::Header::new();
        header.set_number(15);

        let res = machine.verify_transaction_basic(&transaction, &header);
        assert_eq!(
            res,
            Err(transaction::Error::InvalidSignature(
                "invalid EC signature".into()
            ))
        );
    }

    #[test]
    fn calculate_base_fee_success() {
        let machine = new_london_test_machine();
        let parent_base_fees = [
            U256::from(1000000000),
            U256::from(1000000000),
            U256::from(1000000000),
            U256::from(1072671875),
            U256::from(1059263476),
            U256::from(1049238967),
            U256::from(1049238967),
            U256::from(0),
            U256::from(1),
            U256::from(2),
        ];
        let parent_gas_used = [
            U256::from(10000000),
            U256::from(10000000),
            U256::from(10000000),
            U256::from(9000000),
            U256::from(10001000),
            U256::from(0),
            U256::from(10000000),
            U256::from(10000000),
            U256::from(10000000),
            U256::from(10000000),
        ];
        let parent_gas_limit = [
            U256::from(10000000),
            U256::from(12000000),
            U256::from(14000000),
            U256::from(10000000),
            U256::from(14000000),
            U256::from(2000000),
            U256::from(18000000),
            U256::from(18000000),
            U256::from(18000000),
            U256::from(18000000),
        ];
        let expected_base_fee = [
            U256::from(1125000000),
            U256::from(1083333333),
            U256::from(1053571428),
            U256::from(1179939062),
            U256::from(1116028649),
            U256::from(918084097),
            U256::from(1063811730),
            U256::from(1),
            U256::from(2),
            U256::from(3),
        ];

        for i in 0..parent_base_fees.len() {
            let mut parent_header = Header::default();
            parent_header.set_base_fee(Some(parent_base_fees[i]));
            parent_header.set_gas_used(parent_gas_used[i]);
            parent_header.set_gas_limit(parent_gas_limit[i]);

            let base_fee = machine.calc_base_fee(&parent_header);
            assert_eq!(expected_base_fee[i], base_fee.unwrap());
        }
    }
}
