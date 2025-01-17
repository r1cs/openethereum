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

//! Tracing

mod config;
mod executive_tracer;
mod import;
mod noop_tracer;
mod types;

pub use self::config::Config;
pub use self::executive_tracer::{ExecutiveTracer, ExecutiveVMTracer};
pub use self::import::ImportRequest;
pub use self::localized::LocalizedTrace;
pub use self::noop_tracer::{NoopTracer, NoopVMTracer};

pub use self::types::error::Error as TraceError;
pub use self::types::filter::{AddressesFilter, Filter};
pub use self::types::flat::{FlatBlockTraces, FlatTrace, FlatTransactionTraces};
pub use self::types::trace::{
    MemoryDiff, RewardType, StorageDiff, VMExecutedOperation, VMOperation, VMTrace
};
pub use self::types::{filter, flat, localized, trace, Tracing};

use common_types::BlockNumber;
use ethereum_types::{Address, H256, U256};
use vm::{ActionParams, Error as VmError};

/// This trait is used by executive to build traces.
pub trait Tracer: Send {
    /// Data returned when draining the Tracer.
    type Output;

    /// Prepares call trace for given params. Would panic if prepare/done_trace are not balanced.
    fn prepare_trace_call(&mut self, params: &ActionParams, depth: usize, is_builtin: bool);

    /// Prepares create trace for given params. Would panic if prepare/done_trace are not balanced.
    fn prepare_trace_create(&mut self, params: &ActionParams);

    /// Finishes a successful call trace. Would panic if prepare/done_trace are not balanced.
    fn done_trace_call(&mut self, gas_used: U256, output: &[u8]);

    /// Finishes a successful create trace. Would panic if prepare/done_trace are not balanced.
    fn done_trace_create(&mut self, gas_used: U256, code: &[u8], address: Address);

    /// Finishes a failed trace. Would panic if prepare/done_trace are not balanced.
    fn done_trace_failed(&mut self, error: &VmError);

    /// Stores suicide info.
    fn trace_suicide(&mut self, address: Address, balance: U256, refund_address: Address);

    /// Stores reward info.
    fn trace_reward(&mut self, author: Address, value: U256, reward_type: RewardType);

    /// Consumes self and returns all traces.
    fn drain(self) -> Vec<Self::Output>;
}

/// Used by executive to build VM traces.
pub trait VMTracer: Send {
    /// Data returned when draining the VMTracer.
    type Output;

    /// Trace the progression of interpreter to next instruction.
    /// If tracer returns `false` it won't be called again.
    /// @returns true if `trace_prepare_execute` and `trace_executed` should be called.
    fn trace_next_instruction(&mut self, _pc: usize, _instruction: u8, _current_gas: U256) -> bool {
        false
    }

    /// Trace the preparation to execute a single valid instruction.
    fn trace_prepare_execute(
        &mut self, _pc: usize, _instruction: u8, _gas_cost: U256,
        _mem_written: Option<(usize, usize)>, _store_written: Option<(U256, U256)>,
    ) {
    }

    /// Trace the execution failure of a single instruction.
    fn trace_failed(&mut self) {}

    /// Trace the finalised execution of a single valid instruction.
    fn trace_executed(&mut self, _gas_used: U256, _stack_push: &[U256], _mem: &[u8]) {}

    /// Spawn subtracer which will be used to trace deeper levels of execution.
    fn prepare_subtrace(&mut self, _code: &[u8]) {}

    /// Finalize subtracer.
    fn done_subtrace(&mut self) {}

    /// Consumes self and returns the VM trace.
    fn drain(self) -> Option<Self::Output>;
}

/// `DbExtras` provides an interface to query extra data which is not stored in tracesdb,
/// but necessary to work correctly.
pub trait DatabaseExtras {
    /// Returns hash of given block number.
    fn block_hash(&self, block_number: BlockNumber) -> Option<H256>;

    /// Returns hash of transaction at given position.
    fn transaction_hash(&self, block_number: BlockNumber, tx_position: usize) -> Option<H256>;
}
