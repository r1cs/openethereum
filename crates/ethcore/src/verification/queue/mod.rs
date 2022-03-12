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

//! A queue of blocks. Sits between network or other I/O and the `BlockChain`.
//! Sorts them ready for blockchain insertion.

use engines::EthEngine;
use error::Error;
use std::{
    sync::Arc,
};
use std::marker::PhantomData;

use self::kind::{Kind};
pub use types::verification_queue_info::VerificationQueueInfo as QueueInfo;

pub mod kind;

pub type BlockVerifier = Verifier<self::kind::Blocks>;
pub type HeaderVerifier = Verifier<self::kind::Headers>;

/// A queue of items to be verified. Sits between network or other I/O and the `BlockChain`.
/// Keeps them in the same order as inserted, minus invalid items.
pub struct Verifier<K: Kind> {
	engine: Arc<dyn EthEngine>,
	check_seal: bool,
	_maker : PhantomData<K>,
}

impl<K:Kind> Verifier<K> {
	pub fn new(engine: Arc<dyn EthEngine>, check_seal: bool) -> Self {
		Self { engine, check_seal, _maker: PhantomData }
	}

	pub fn verify(&self, input: K::Input) -> Result<K::Verified, Error> {
		let item = K::create(input, &*self.engine, self.check_seal).map_err(|(_input, e)| e)?;
		// t_nb 5.0 verify standalone block (this verification is done in VerificationQueue thread pool)
		K::verify(item, &*self.engine, self.check_seal)
	}
}
