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

//! Set of different helpers for client tests

use std::sync::Arc;

use ethereum_types::U256;
use evm::Factory as EvmFactory;

use factory::Factories;
use state::*;
use state_db::StateDB;

/// Returns temp state
pub fn get_temp_state() -> State<::state_db::StateDB> {
    let journal_db = get_temp_state_db();
    State::new(journal_db, U256::from(0), Default::default())
}

/// Returns temp state using coresponding factory
pub fn get_temp_state_with_factory(factory: EvmFactory) -> State<::state_db::StateDB> {
    let journal_db = get_temp_state_db();
    let mut factories = Factories::default();
    factories.vm = factory.into();
    State::new(journal_db, U256::from(0), factories)
}

/// Returns temp state db
pub fn get_temp_state_db() -> StateDB {
	let key_value = Arc::new(ethcore_db::InMemory::create(
		::db::NUM_COLUMNS.unwrap(),
	));
	let journal_db = ::journaldb::new(
        key_value,
        ::journaldb::Algorithm::EarlyMerge,
        ::db::COL_STATE,
    );
    StateDB::new(journal_db, 5 * 1024 * 1024)
}
