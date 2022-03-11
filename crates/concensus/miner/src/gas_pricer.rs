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

//! Auto-updates minimal gas price requirement.

use ethereum_types::U256;

/// Struct to look after updating the acceptable gas price of a miner.
#[derive(Debug, PartialEq)]
pub enum GasPricer {
	/// fixed
    Fixed(U256),
}

impl GasPricer {
    /// Create a new Fixed `GasPricer`.
    pub fn new_fixed(gas_price: U256) -> GasPricer {
        GasPricer::Fixed(gas_price)
    }

    /// Recalibrate current gas price.
    pub fn recalibrate<F: FnOnce(U256) + Sync + Send + 'static>(&mut self, set_price: F) {
        match *self {
            GasPricer::Fixed(ref curr) => set_price(curr.clone()),
        }
    }
}
