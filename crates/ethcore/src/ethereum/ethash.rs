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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cmp::{self};

use ethereum_types::{H256, H64, U256};
use hash::KECCAK_EMPTY_LIST_RLP;
use rlp::Rlp;
use types::header::Header;
use types::BlockNumber;
use unexpected::{Mismatch, OutOfBounds};

use crate::block::ExecutedBlock;
use crate::engines::block_reward::{self, RewardKind};
use crate::engines::Engine;
use crate::error::{BlockError, Error};
use crate::machine::EthereumMachine;
use ethash::{boundary_to_difficulty, quick_get_difficulty};

use crate::alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use ethjson;
#[cfg(feature = "std")]
use ethjson::uint::Uint;

/// Ethash specific seal
#[derive(Debug, PartialEq)]
pub struct Seal {
    /// Ethash seal mix_hash
    pub mix_hash: H256,
    /// Ethash seal nonce
    pub nonce: H64,
}

impl Seal {
    /// Tries to parse rlp as ethash seal.
    pub fn parse_seal<T: AsRef<[u8]>>(seal: &[T]) -> Result<Self, Error> {
        if seal.len() != 2 {
            return Err(
                BlockError::InvalidSealArity(Mismatch { expected: 2, found: seal.len() }).into()
            );
        }

        let mix_hash = Rlp::new(seal[0].as_ref()).as_val::<H256>()?;
        let nonce = Rlp::new(seal[1].as_ref()).as_val::<H64>()?;
        let seal = Seal { mix_hash, nonce };

        Ok(seal)
    }
}

/// Ethash params.
#[derive(Debug, PartialEq)]
pub struct EthashParams {
    /// Minimum difficulty.
    pub minimum_difficulty: U256,
    /// Difficulty bound divisor.
    pub difficulty_bound_divisor: U256,
    /// Difficulty increment divisor.
    pub difficulty_increment_divisor: u64,
    /// Metropolis difficulty increment divisor.
    pub metropolis_difficulty_increment_divisor: u64,
    /// Block duration.
    pub duration_limit: u64,
    /// Homestead transition block number.
    pub homestead_transition: u64,
    /// Transition block for a change of difficulty params (currently just bound_divisor).
    pub difficulty_hardfork_transition: u64,
    /// Difficulty param after the difficulty transition.
    pub difficulty_hardfork_bound_divisor: U256,
    /// Block on which there is no additional difficulty from the exponential bomb.
    pub bomb_defuse_transition: u64,
    /// Number of first block where EIP-100 rules begin.
    pub eip100b_transition: u64,
    /// Total block number for one ECIP-1017 era.
    pub ecip1017_era_rounds: u64,
    /// Block reward in base units.
    pub block_reward: BTreeMap<BlockNumber, U256>,
    /// EXPIP-2 block height
    pub expip2_transition: u64,
    /// EXPIP-2 duration limit
    pub expip2_duration_limit: u64,
    /// Difficulty bomb delays.
    pub difficulty_bomb_delays: BTreeMap<BlockNumber, BlockNumber>,
    /// Block to transition to progpow
    pub progpow_transition: u64,
}

#[cfg(feature = "std")]
impl From<ethjson::spec::EthashParams> for EthashParams {
    fn from(p: ethjson::spec::EthashParams) -> Self {
        EthashParams {
            minimum_difficulty: p.minimum_difficulty.into(),
            difficulty_bound_divisor: p.difficulty_bound_divisor.into(),
            difficulty_increment_divisor: p.difficulty_increment_divisor.map_or(10, Into::into),
            metropolis_difficulty_increment_divisor: p
                .metropolis_difficulty_increment_divisor
                .map_or(9, Into::into),
            duration_limit: p.duration_limit.map_or(0, Into::into),
            homestead_transition: p.homestead_transition.map_or(0, Into::into),
            difficulty_hardfork_transition: p
                .difficulty_hardfork_transition
                .map_or(u64::max_value(), Into::into),
            difficulty_hardfork_bound_divisor: p
                .difficulty_hardfork_bound_divisor
                .map_or(p.difficulty_bound_divisor.into(), Into::into),
            bomb_defuse_transition: p.bomb_defuse_transition.map_or(u64::max_value(), Into::into),
            eip100b_transition: p.eip100b_transition.map_or(u64::max_value(), Into::into),
            ecip1017_era_rounds: p.ecip1017_era_rounds.map_or(u64::max_value(), Into::into),
            block_reward: p.block_reward.map_or_else(
                || {
                    let mut ret = BTreeMap::new();
                    ret.insert(0, U256::zero());
                    ret
                },
                |reward| match reward {
                    ethjson::spec::BlockReward::Single(reward) => {
                        let mut ret = BTreeMap::new();
                        ret.insert(0, reward.into());
                        ret
                    }
                    ethjson::spec::BlockReward::Multi(mut multi) => {
                        if multi.is_empty() {
                            panic!("No block rewards are found in config");
                        }
                        // add block reward from genesis and put reward to zero.
                        multi.entry(Uint(U256::from(0u32))).or_insert(Uint(U256::from(0u32)));
                        multi
                            .into_iter()
                            .map(|(block, reward)| (block.into(), reward.into()))
                            .collect()
                    }
                },
            ),
            expip2_transition: p.expip2_transition.map_or(u64::max_value(), Into::into),
            expip2_duration_limit: p.expip2_duration_limit.map_or(30, Into::into),
            progpow_transition: p.progpow_transition.map_or(u64::max_value(), Into::into),
            difficulty_bomb_delays: p
                .difficulty_bomb_delays
                .unwrap_or_default()
                .into_iter()
                .map(|(block, delay)| (block.into(), delay.into()))
                .collect(),
        }
    }
}

/// Engine using Ethash proof-of-work consensus algorithm, suitable for Ethereum
/// mainnet chains in the Olympic, Frontier and Homestead eras.
pub struct Ethash {
    ethash_params: EthashParams,
    machine: EthereumMachine,
}

impl Ethash {
    /// Create a new instance of Ethash engine
    pub fn new(ethash_params: EthashParams, machine: EthereumMachine) -> Arc<Self> {
        Arc::new(Ethash { ethash_params, machine })
    }
}

impl Engine<EthereumMachine> for Arc<Ethash> {
    fn name(&self) -> &str {
        "Ethash"
    }
    fn machine(&self) -> &EthereumMachine {
        &self.machine
    }

    // Two fields - nonce and mix.
    fn seal_fields(&self, _header: &Header) -> usize {
        2
    }

    /// Additional engine-specific information for the user/developer concerning `header`.
    fn extra_info(&self, header: &Header) -> BTreeMap<String, String> {
        match Seal::parse_seal(header.seal()) {
            Ok(seal) => map![
                "nonce".to_owned() => format!("0x{:x}", seal.nonce),
                "mixHash".to_owned() => format!("0x{:x}", seal.mix_hash)
            ],
            _ => BTreeMap::default(),
        }
    }

    fn maximum_uncle_count(&self, _block: BlockNumber) -> usize {
        2
    }

    fn populate_from_parent(&self, header: &mut Header, parent: &Header) {
        let difficulty = self.calculate_difficulty(header, parent);
        header.set_difficulty(difficulty);
    }

    /// Apply the block reward on finalisation of the block.
    /// This assumes that all uncles are valid uncles (i.e. of at least one generation before the current).
    fn on_close_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        use core::ops::Shr;

        let author = *block.header.author();
        let number = block.header.number();

        let rewards =
            {
                let mut rewards = Vec::new();

                let (_, reward) = self.ethash_params.block_reward.iter()
					.rev()
					.find(|&(block, _)| *block <= number)
					.expect("Current block's reward is not found; this indicates a chain config error; qed");
                let reward = *reward;

                // Applies ECIP-1017 eras.
                let eras_rounds = self.ethash_params.ecip1017_era_rounds;
                let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, reward, number);

                //let n_uncles = LiveBlock::uncles(&*block).len();
                let n_uncles = block.uncles.len();

                // Bestow block rewards.
                let result_block_reward = reward + reward.shr(5) * U256::from(n_uncles);

                rewards.push((author, RewardKind::Author, result_block_reward));

                // Bestow uncle rewards.
                for u in &block.uncles {
                    let uncle_author = u.author();
                    let result_uncle_reward = if eras == 0 {
                        (reward * U256::from(8 + u.number() - number)).shr(3)
                    } else {
                        reward.shr(5)
                    };

                    rewards.push((
                        *uncle_author,
                        RewardKind::uncle(number, u.number()),
                        result_uncle_reward,
                    ));
                }

                rewards
            };

        block_reward::apply_block_rewards(&rewards, block, &self.machine)
    }

    #[cfg(not(feature = "miner-debug"))]
    fn verify_local_seal(&self, header: &Header) -> Result<(), Error> {
        self.verify_block_basic(header).and_then(|_| self.verify_block_unordered(header))
    }

    #[cfg(feature = "miner-debug")]
    fn verify_local_seal(&self, _header: &Header) -> Result<(), Error> {
        //warn!("Skipping seal verification, running in miner testing mode.");
        Ok(())
    }

    fn verify_block_basic(&self, header: &Header) -> Result<(), Error> {
        // check the seal fields.
        let seal = Seal::parse_seal(header.seal())?;

        // TODO: consider removing these lines.
        let min_difficulty = self.ethash_params.minimum_difficulty;
        if header.difficulty() < &min_difficulty {
            return Err(From::from(BlockError::DifficultyOutOfBounds(OutOfBounds {
                min: Some(min_difficulty),
                max: None,
                found: header.difficulty().clone(),
            })));
        }

        let difficulty = boundary_to_difficulty(&H256(quick_get_difficulty(
            &header.bare_hash().0,
            seal.nonce.to_low_u64_be(),
            &seal.mix_hash.0,
            header.number() >= self.ethash_params.progpow_transition,
        )));

        if &difficulty < header.difficulty() {
            return Err(From::from(BlockError::InvalidProofOfWork(OutOfBounds {
                min: Some(header.difficulty().clone()),
                max: None,
                found: difficulty,
            })));
        }

        Ok(())
    }

    fn verify_block_unordered(&self, _header: &Header) -> Result<(), Error> {
        return Ok(());
    }

    fn verify_block_family(&self, header: &Header, parent: &Header) -> Result<(), Error> {
        // we should not calculate difficulty for genesis blocks
        if header.number() == 0 {
            return Err(From::from(BlockError::RidiculousNumber(OutOfBounds {
                min: Some(1),
                max: None,
                found: header.number(),
            })));
        }

        // Check difficulty is correct given the two timestamps.
        let expected_difficulty = self.calculate_difficulty(header, parent);
        if header.difficulty() != &expected_difficulty {
            return Err(From::from(BlockError::InvalidDifficulty(Mismatch {
                expected: expected_difficulty,
                found: header.difficulty().clone(),
            })));
        }

        Ok(())
    }
}

impl Ethash {
    fn calculate_difficulty(&self, header: &Header, parent: &Header) -> U256 {
        const EXP_DIFF_PERIOD: u64 = 100_000;
        if header.number() == 0 {
            panic!("Can't calculate genesis block difficulty");
        }

        let parent_has_uncles = parent.uncles_hash() != &KECCAK_EMPTY_LIST_RLP;

        let min_difficulty = self.ethash_params.minimum_difficulty;

        let difficulty_hardfork =
            header.number() >= self.ethash_params.difficulty_hardfork_transition;
        let difficulty_bound_divisor = if difficulty_hardfork {
            self.ethash_params.difficulty_hardfork_bound_divisor
        } else {
            self.ethash_params.difficulty_bound_divisor
        };

        let expip2_hardfork = header.number() >= self.ethash_params.expip2_transition;
        let duration_limit = if expip2_hardfork {
            self.ethash_params.expip2_duration_limit
        } else {
            self.ethash_params.duration_limit
        };

        let frontier_limit = self.ethash_params.homestead_transition;

        let mut target = if header.number() < frontier_limit {
            if header.timestamp() >= parent.timestamp() + duration_limit {
                *parent.difficulty() - (*parent.difficulty() / difficulty_bound_divisor)
            } else {
                *parent.difficulty() + (*parent.difficulty() / difficulty_bound_divisor)
            }
        } else {
            //trace!(target: "ethash", "Calculating difficulty parent.difficulty={}, header.timestamp={}, parent.timestamp={}", parent.difficulty(), header.timestamp(), parent.timestamp());
            //block_diff = parent_diff + parent_diff // 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99)
            let (increment_divisor, threshold) =
                if header.number() < self.ethash_params.eip100b_transition {
                    (self.ethash_params.difficulty_increment_divisor, 1)
                } else if parent_has_uncles {
                    (self.ethash_params.metropolis_difficulty_increment_divisor, 2)
                } else {
                    (self.ethash_params.metropolis_difficulty_increment_divisor, 1)
                };

            let diff_inc = (header.timestamp() - parent.timestamp()) / increment_divisor;
            if diff_inc <= threshold {
                *parent.difficulty()
                    + *parent.difficulty() / difficulty_bound_divisor
                        * U256::from(threshold - diff_inc)
            } else {
                let multiplier: U256 = cmp::min(diff_inc - threshold, 99).into();
                parent
                    .difficulty()
                    .saturating_sub(*parent.difficulty() / difficulty_bound_divisor * multiplier)
            }
        };
        target = cmp::max(min_difficulty, target);
        if header.number() < self.ethash_params.bomb_defuse_transition {
            let mut number = header.number();
            let original_number = number;
            for (block, delay) in &self.ethash_params.difficulty_bomb_delays {
                if original_number >= *block {
                    number = number.saturating_sub(*delay);
                }
            }
            let period = (number / EXP_DIFF_PERIOD) as usize;
            if period > 1 {
                target = cmp::max(min_difficulty, target + (U256::from(1u32) << (period - 2)));
            }
        }
        target
    }
}

fn ecip1017_eras_block_reward(era_rounds: u64, mut reward: U256, block_number: u64) -> (u64, U256) {
    let eras = if block_number != 0 && block_number % era_rounds == 0 {
        block_number / era_rounds - 1
    } else {
        block_number / era_rounds
    };
    let mut divi = U256::from(1u32);
    for _ in 0..eras {
        reward = reward * U256::from(4u32);
        divi = divi * U256::from(5u32);
    }
    reward = reward / divi;
    (eras, reward)
}

#[cfg(test)]
mod tests {
    use super::super::{new_homestead_test_machine, new_morden};
    use super::{ecip1017_eras_block_reward, Ethash, EthashParams};
    use crate::block::*;
    use crate::engines::Engine;
    use crate::error::{BlockError, Error};
    use crate::spec::Spec;
    use crate::test_helpers::get_temp_state_db;
    use ethereum_types::{Address, H256, H64, U256};
    use rlp;
    use std::collections::BTreeMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use types::header::Header;

    fn test_spec() -> Spec {
        new_morden()
    }

    fn get_default_ethash_params() -> EthashParams {
        EthashParams {
            minimum_difficulty: U256::from(131072u32),
            difficulty_bound_divisor: U256::from(2048u32),
            difficulty_increment_divisor: 10,
            metropolis_difficulty_increment_divisor: 9,
            homestead_transition: 1150000,
            duration_limit: 13,
            block_reward: {
                let mut ret = BTreeMap::new();
                ret.insert(0, 0.into());
                ret
            },
            difficulty_hardfork_transition: u64::max_value(),
            difficulty_hardfork_bound_divisor: U256::from(0u32),
            bomb_defuse_transition: u64::max_value(),
            eip100b_transition: u64::max_value(),
            ecip1017_era_rounds: u64::max_value(),
            expip2_transition: u64::max_value(),
            expip2_duration_limit: 30,
            difficulty_bomb_delays: BTreeMap::new(),
            progpow_transition: u64::max_value(),
        }
    }

    #[test]
    fn on_close_block() {
        let spec = test_spec();
        let engine = &*spec.engine;
        let genesis_header = spec.genesis_header();
        let db = spec.ensure_db_good(get_temp_state_db(), &Default::default()).unwrap();
        let last_hashes = Arc::new(vec![genesis_header.hash()]);
        let b = OpenBlock::new(
            engine,
            Default::default(),
            false,
            db,
            &genesis_header,
            last_hashes,
            Address::zero(),
            (3141562.into(), 31415620.into()),
            vec![],
        )
        .unwrap();
        let b = b.close().unwrap();
        assert_eq!(
            b.state.balance(&Address::zero()).unwrap(),
            U256::from_str("4563918244f40000").unwrap()
        );
    }

    #[test]
    fn has_valid_ecip1017_eras_block_reward() {
        let eras_rounds = 5000000;

        let start_reward: U256 = "4563918244F40000".parse().unwrap();

        let block_number = 0;
        let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, start_reward, block_number);
        assert_eq!(0, eras);
        assert_eq!(U256::from_str("4563918244F40000").unwrap(), reward);

        let block_number = 5000000;
        let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, start_reward, block_number);
        assert_eq!(0, eras);
        assert_eq!(U256::from_str("4563918244F40000").unwrap(), reward);

        let block_number = 10000000;
        let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, start_reward, block_number);
        assert_eq!(1, eras);
        assert_eq!(U256::from_str("3782DACE9D900000").unwrap(), reward);

        let block_number = 20000000;
        let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, start_reward, block_number);
        assert_eq!(3, eras);
        assert_eq!(U256::from_str("2386F26FC1000000").unwrap(), reward);

        let block_number = 80000000;
        let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, start_reward, block_number);
        assert_eq!(15, eras);
        assert_eq!(U256::from_str("271000000000000").unwrap(), reward);

        let block_number = 250000000;
        let (eras, reward) = ecip1017_eras_block_reward(eras_rounds, start_reward, block_number);
        assert_eq!(49, eras);
        assert_eq!(U256::from_str("51212FFBAF0A").unwrap(), reward);
    }

    #[test]
    fn on_close_block_with_uncle() {
        let spec = test_spec();
        let engine = &*spec.engine;
        let genesis_header = spec.genesis_header();
        let db = spec.ensure_db_good(get_temp_state_db(), &Default::default()).unwrap();
        let last_hashes = Arc::new(vec![genesis_header.hash()]);
        let mut b = OpenBlock::new(
            engine,
            Default::default(),
            false,
            db,
            &genesis_header,
            last_hashes,
            Address::zero(),
            (3141562.into(), 31415620.into()),
            vec![],
        )
        .unwrap();
        let mut uncle = Header::new();
        let uncle_author = Address::from_str("ef2d6d194084c2de36e0dabfce45d046b37d1106").unwrap();
        uncle.set_author(uncle_author);
        b.push_uncle(uncle).unwrap();

        let b = b.close().unwrap();
        assert_eq!(b.state.balance(&Address::zero()).unwrap(), "478eae0e571ba000".into());
        assert_eq!(b.state.balance(&uncle_author).unwrap(), "3cb71f51fc558000".into());
    }

    #[test]
    fn has_valid_metadata() {
        let engine = test_spec().engine;
        assert!(!engine.name().is_empty());
    }

    #[test]
    fn can_return_schedule() {
        let engine = test_spec().engine;
        let schedule = engine.schedule(10000000);
        assert!(schedule.stack_limit > 0);

        let schedule = engine.schedule(100);
        assert!(!schedule.have_delegate_call);
    }

    #[test]
    fn can_do_seal_verification_fail() {
        let engine = test_spec().engine;
        let header: Header = Header::default();

        let verify_result = engine.verify_block_basic(&header);

        match verify_result {
            Err(Error::Block(BlockError::InvalidSealArity(_))) => {}
            Err(_) => {
                panic!("should be block seal-arity mismatch error (got {:?})", verify_result);
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_difficulty_verification_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_seal(vec![rlp::encode(&H256::zero()), rlp::encode(&H64::zero())]);

        let verify_result = engine.verify_block_basic(&header);

        match verify_result {
            Err(Error::Block(BlockError::DifficultyOutOfBounds(_))) => {}
            Err(_) => {
                panic!("should be block difficulty error (got {:?})", verify_result);
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_proof_of_work_verification_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_seal(vec![rlp::encode(&H256::zero()), rlp::encode(&H64::zero())]);
        header.set_difficulty(
            U256::from_str("ffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        );

        let verify_result = engine.verify_block_basic(&header);

        match verify_result {
            Err(Error::Block(BlockError::InvalidProofOfWork(_))) => {}
            Err(_) => {
                panic!("should be invalid proof of work error (got {:?})", verify_result);
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_verify_block_family_genesis_fail() {
        let engine = test_spec().engine;
        let header: Header = Header::default();
        let parent_header: Header = Header::default();

        let verify_result = engine.verify_block_family(&header, &parent_header);

        match verify_result {
            Err(Error::Block(BlockError::RidiculousNumber(_))) => {}
            Err(_) => {
                panic!("should be invalid block number fail (got {:?})", verify_result);
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_verify_block_family_difficulty_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_number(2);
        let mut parent_header: Header = Header::default();
        parent_header.set_number(1);

        let verify_result = engine.verify_block_family(&header, &parent_header);

        match verify_result {
            Err(Error::Block(BlockError::InvalidDifficulty(_))) => {}
            Err(_) => {
                panic!("should be invalid difficulty fail (got {:?})", verify_result);
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn difficulty_frontier() {
        let machine = new_homestead_test_machine();
        let ethparams = get_default_ethash_params();
        let ethash = Ethash::new(ethparams, machine);

        let mut parent_header = Header::default();
        parent_header.set_number(1000000);
        parent_header.set_difficulty(U256::from_str("b69de81a22b").unwrap());
        parent_header.set_timestamp(1455404053);
        let mut header = Header::default();
        header.set_number(parent_header.number() + 1);
        header.set_timestamp(1455404058);

        let difficulty = ethash.calculate_difficulty(&header, &parent_header);
        assert_eq!(U256::from_str("b6b4bbd735f").unwrap(), difficulty);
    }

    #[test]
    fn difficulty_homestead() {
        let machine = new_homestead_test_machine();
        let ethparams = get_default_ethash_params();
        let ethash = Ethash::new(ethparams, machine);

        let mut parent_header = Header::default();
        parent_header.set_number(1500000);
        parent_header.set_difficulty(U256::from_str("1fd0fd70792b").unwrap());
        parent_header.set_timestamp(1463003133);
        let mut header = Header::default();
        header.set_number(parent_header.number() + 1);
        header.set_timestamp(1463003177);

        let difficulty = ethash.calculate_difficulty(&header, &parent_header);
        assert_eq!(U256::from_str("1fc50f118efe").unwrap(), difficulty);
    }

    #[test]
    fn difficulty_max_timestamp() {
        let machine = new_homestead_test_machine();
        let ethparams = get_default_ethash_params();
        let ethash = Ethash::new(ethparams, machine);

        let mut parent_header = Header::default();
        parent_header.set_number(1000000);
        parent_header.set_difficulty(U256::from_str("b69de81a22b").unwrap());
        parent_header.set_timestamp(1455404053);
        let mut header = Header::default();
        header.set_number(parent_header.number() + 1);
        header.set_timestamp(u64::max_value());

        let difficulty = ethash.calculate_difficulty(&header, &parent_header);
        assert_eq!(U256::from(12543204905719u64), difficulty);
    }

    #[test]
    fn test_extra_info() {
        let machine = new_homestead_test_machine();
        let ethparams = get_default_ethash_params();
        let ethash = Ethash::new(ethparams, machine);
        let mut header = Header::default();
        header.set_seal(vec![
            rlp::encode(
                &H256::from_str("b251bd2e0283d0658f2cadfdc8ca619b5de94eca5742725e2e757dd13ed7503d")
                    .unwrap(),
            ),
            rlp::encode(&H64::zero()),
        ]);
        let info = ethash.extra_info(&header);
        assert_eq!(info["nonce"], "0x0000000000000000");
        assert_eq!(
            info["mixHash"],
            "0xb251bd2e0283d0658f2cadfdc8ca619b5de94eca5742725e2e757dd13ed7503d"
        );
    }
}
