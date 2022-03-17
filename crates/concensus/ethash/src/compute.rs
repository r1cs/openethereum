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

//! Ethash implementation
//! See https://github.com/ethereum/wiki/wiki/Ethash

// TODO: fix endianess for big endian

use crate::keccak::{keccak_256, keccak_512, H256};
use crate::progpow::{keccak_f800_long, keccak_f800_short};

use core::mem;

/// Difficulty quick check for POW preverification
///
/// `header_hash`      The hash of the header
/// `nonce`            The block's nonce
/// `mix_hash`         The mix digest hash
/// Boundary recovered from mix hash
pub fn quick_get_difficulty(
    header_hash: &H256,
    nonce: u64,
    mix_hash: &H256,
    progpow: bool,
) -> H256 {
    if progpow {
        let seed = keccak_f800_short(*header_hash, nonce, [0u32; 8]);
        keccak_f800_long(*header_hash, seed, unsafe { mem::transmute(*mix_hash) })
    } else {
        let mut buf = [0u8; 64 + 32];

        let hash_len = header_hash.len();
        buf[..hash_len].copy_from_slice(header_hash);
        let end = hash_len + mem::size_of::<u64>();
        buf[hash_len..end].copy_from_slice(&nonce.to_ne_bytes());

        keccak_512::inplace_range(&mut buf, 0..end);
        buf[64..].copy_from_slice(mix_hash);

        let mut hash = [0u8; 32];
        keccak_256::write(&buf, &mut hash);

        hash
    }
}
