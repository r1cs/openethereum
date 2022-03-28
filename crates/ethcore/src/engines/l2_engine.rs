use crate::engines::Engine;
use crate::machine::Machine;
use std::cmp::max;
use types::header::Header;

/// An engine which does not provide any consensus mechanism, just seals blocks internally.
pub struct L2Seal<M> {
    timestamp: u64,
    machine: M,
}

impl<M> L2Seal<M> {
    /// Returns new instance of L2Seal over the given state machine.
    pub fn new(timestamp: u64, machine: M) -> Self {
        L2Seal { timestamp, machine }
    }
}

impl<M: Machine> Engine<M> for L2Seal<M> {
    fn name(&self) -> &str {
        "L2Seal"
    }

    fn machine(&self) -> &M {
        &self.machine
    }

    fn verify_local_seal(&self, _header: &Header) -> Result<(), M::Error> {
        Ok(())
    }

    fn open_block_header_timestamp(&self, parent_timestamp: u64) -> u64 {
        max(parent_timestamp, self.timestamp)
    }

    fn is_timestamp_valid(&self, header_timestamp: u64, parent_timestamp: u64) -> bool {
        header_timestamp >= parent_timestamp
    }
}
