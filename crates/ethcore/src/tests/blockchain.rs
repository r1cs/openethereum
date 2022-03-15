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

use test_helpers::{
    generate_dummy_blockchain, generate_dummy_blockchain_with_extra,
    generate_dummy_empty_blockchain,
};

#[test]
fn can_contain_arbitrary_block_sequence() {
    let bc = generate_dummy_blockchain(50);
    assert_eq!(bc.best_block_number(), 49);
}

#[test]
fn can_contain_arbitrary_block_sequence_with_extra() {
    let bc = generate_dummy_blockchain_with_extra(25);
    assert_eq!(bc.best_block_number(), 24);
}

#[test]
fn can_contain_only_genesis_block() {
    let bc = generate_dummy_empty_blockchain();
    assert_eq!(bc.best_block_number(), 0);
}
