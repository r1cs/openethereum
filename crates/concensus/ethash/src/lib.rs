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

#![no_std]

mod compute;
mod keccak;
mod progpow;

pub use compute::quick_get_difficulty;
use core::convert::TryFrom;
use ethereum_types::{BigEndianHash, U256, U512};

/// Convert an Ethash boundary to its original difficulty. Basically just `f(x) = 2^256 / x`.
pub fn boundary_to_difficulty(boundary: &ethereum_types::H256) -> U256 {
    difficulty_to_boundary_aux(&boundary.into_uint())
}

/// Convert an Ethash difficulty to the target boundary. Basically just `f(x) = 2^256 / x`.
pub fn difficulty_to_boundary(difficulty: &U256) -> ethereum_types::H256 {
    BigEndianHash::from_uint(&difficulty_to_boundary_aux(difficulty))
}

fn difficulty_to_boundary_aux<T: Into<U512>>(difficulty: T) -> ethereum_types::U256 {
    let difficulty = difficulty.into();

    assert!(!difficulty.is_zero());

    if difficulty == U512::one() {
        U256::max_value()
    } else {
        const PROOF: &str = "difficulty > 1, so result never overflows 256 bits; qed";
        U256::try_from((U512::one() << 256) / difficulty).expect(PROOF)
    }
}
