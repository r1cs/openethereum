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

use blockchain::BlockChainDB;
use blooms_db;
use db::KeyValueDB;
use ethereum_types::U256;
use evm::Factory as EvmFactory;
use tempdir::TempDir;

use factory::Factories;
use state::*;
use state_db::StateDB;

struct TestBlockChainDB {
    blooms: blooms_db::Database,
    trace_blooms: blooms_db::Database,
    key_value: Arc<dyn KeyValueDB>,
}

impl BlockChainDB for TestBlockChainDB {
    fn key_value(&self) -> &Arc<dyn KeyValueDB> {
        &self.key_value
    }

    fn blooms(&self) -> &blooms_db::Database {
        &self.blooms
    }

    fn trace_blooms(&self) -> &blooms_db::Database {
        &self.trace_blooms
    }
}

/// Creates new test instance of `BlockChainDB`
pub fn new_db() -> Arc<dyn BlockChainDB> {
    let blooms_dir = TempDir::new("").unwrap();
    let trace_blooms_dir = TempDir::new("").unwrap();

    let db = TestBlockChainDB {
        blooms: blooms_db::Database::open(blooms_dir.path()).unwrap(),
        trace_blooms: blooms_db::Database::open(trace_blooms_dir.path()).unwrap(),
        key_value: Arc::new(ethcore_db::InMemory::create(
            ::db::NUM_COLUMNS.unwrap(),
        )),
    };

    Arc::new(db)
}

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
    let db = new_db();
    let journal_db = ::journaldb::new(
        db.key_value().clone(),
        ::journaldb::Algorithm::EarlyMerge,
        ::db::COL_STATE,
    );
    StateDB::new(journal_db, 5 * 1024 * 1024)
}
