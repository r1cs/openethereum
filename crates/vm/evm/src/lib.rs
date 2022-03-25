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

//! Ethereum virtual machine.

#![cfg_attr(not(test), no_std)]

extern crate alloc;
extern crate ethcore_builtin as builtin;
extern crate keccak_hash as hash;
extern crate parity_bytes as bytes;
pub mod evm;
pub mod interpreter;

#[macro_use]
pub mod factory;
mod instructions;
mod vmtype;

#[cfg(test)]
mod tests;

pub use self::evm::{CostType, FinalizationResult, Finalize};
pub use self::factory::Factory;
pub use self::instructions::{Instruction, InstructionInfo};
pub use self::vmtype::VMType;
pub use vm::{
    ActionParams, CallType, CleanDustMode, ContractCreateResult, CreateContractAddress, EnvInfo,
    Ext, GasLeft, MessageCallResult, ReturnData, Schedule,
};
