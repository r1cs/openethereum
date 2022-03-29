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

//! Definition of valid items for the verification queue.

/// The blocks verification module.
pub mod blocks {
    use types::header::Header;
    use types::transaction::{TypedTransaction, UnverifiedTransaction};
    use types::BlockNumber;

    use alloc::vec::Vec;
    use bytes::Bytes;

    /// An unverified block.
    #[derive(PartialEq, Debug)]
    pub struct Unverified {
        /// Unverified block header.
        pub header: Header,
        /// Unverified block transactions.
        pub transactions: Vec<UnverifiedTransaction>,
        /// Unverified block uncles.
        pub uncles: Vec<Header>,
        /// Raw block bytes.
        pub bytes: Bytes,
    }

    impl Unverified {
        /// Create an `Unverified` from raw bytes.
        pub fn from_rlp(
            bytes: Bytes, eip1559_transition: BlockNumber,
        ) -> Result<Self, ::rlp::DecoderError> {
            use rlp::Rlp;
            let (header, transactions, uncles) = {
                let rlp = Rlp::new(&bytes);
                let header = Header::decode_rlp(&rlp.at(0)?, eip1559_transition)?;
                let transactions = TypedTransaction::decode_rlp_list(&rlp.at(1)?)?;
                let uncles = Header::decode_rlp_list(&rlp.at(2)?, eip1559_transition)?;
                (header, transactions, uncles)
            };

            Ok(Unverified { header, transactions, uncles, bytes })
        }
    }
}
