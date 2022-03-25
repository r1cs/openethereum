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

//! A module with types for declaring block rewards and a client interface for interacting with a
//! block reward contract.

use ethereum_types::{Address, U256};

use block::ExecutedBlock;
use machine::Machine;
use trace::{self, ExecutiveTracer, Tracer, Tracing};
use types::BlockNumber;

/// The kind of block reward.
/// Depending on the consensus engine the allocated block reward might have
/// different semantics which could lead e.g. to different reward values.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum RewardKind {
    /// Reward attributed to the block author.
    Author,
    /// Reward attributed to the author(s) of empty step(s) included in the block (AuthorityRound engine).
    EmptyStep,
    /// Reward attributed by an external protocol (e.g. block reward contract).
    External,
    /// Reward attributed to the block uncle(s) with given difference.
    Uncle(u8),
}

impl RewardKind {
    /// Create `RewardKind::Uncle` from given current block number and uncle block number.
    pub fn uncle(number: BlockNumber, uncle: BlockNumber) -> Self {
        RewardKind::Uncle(if number > uncle && number - uncle <= u8::max_value().into() {
            (number - uncle) as u8
        } else {
            0
        })
    }
}

impl From<RewardKind> for u16 {
    fn from(reward_kind: RewardKind) -> Self {
        match reward_kind {
            RewardKind::Author => 0,
            RewardKind::EmptyStep => 2,
            RewardKind::External => 3,

            RewardKind::Uncle(depth) => 100 + depth as u16,
        }
    }
}

impl Into<trace::RewardType> for RewardKind {
    fn into(self) -> trace::RewardType {
        match self {
            RewardKind::Author => trace::RewardType::Block,
            RewardKind::Uncle(_) => trace::RewardType::Uncle,
            RewardKind::EmptyStep => trace::RewardType::EmptyStep,
            RewardKind::External => trace::RewardType::External,
        }
    }
}

/// Applies the given block rewards, i.e. adds the given balance to each beneficiary' address.
/// If tracing is enabled the operations are recorded.
pub fn apply_block_rewards<M: Machine>(
    rewards: &[(Address, RewardKind, U256)], block: &mut ExecutedBlock, machine: &M,
) -> Result<(), M::Error> {
    for &(ref author, _, ref block_reward) in rewards {
        machine.add_balance(block, author, block_reward)?;
    }

    if let Tracing::Enabled(ref mut traces) = *block.traces_mut() {
        let mut tracer = ExecutiveTracer::default();

        for &(address, reward_kind, amount) in rewards {
            tracer.trace_reward(address, amount, reward_kind.into());
        }

        traces.push(tracer.drain().into());
    }

    Ok(())
}
