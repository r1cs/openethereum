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

use crate::keccak::H256;

const KECCAKF_RNDC: [u32; 24] = [
    0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
    0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
    0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
];

const KECCAKF_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f800_round(st: &mut [u32; 25], r: usize) {
    // Theta
    let mut bc = [0u32; 5];
    for i in 0..bc.len() {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    }

    for i in 0..bc.len() {
        let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
        for j in (0..st.len()).step_by(5) {
            st[j + i] ^= t;
        }
    }

    // Rho Pi
    let mut t = st[1];

    debug_assert_eq!(KECCAKF_ROTC.len(), 24);
    for i in 0..24 {
        let j = KECCAKF_PILN[i];
        bc[0] = st[j];
        st[j] = t.rotate_left(KECCAKF_ROTC[i]);
        t = bc[0];
    }

    // Chi
    for j in (0..st.len()).step_by(5) {
        for i in 0..bc.len() {
            bc[i] = st[j + i];
        }
        for i in 0..bc.len() {
            st[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
    }

    // Iota
    debug_assert!(r < KECCAKF_RNDC.len());
    st[0] ^= KECCAKF_RNDC[r];
}

fn keccak_f800(header_hash: H256, nonce: u64, result: [u32; 8], st: &mut [u32; 25]) {
    for i in 0..8 {
        st[i] = (header_hash[4 * i] as u32)
            + ((header_hash[4 * i + 1] as u32) << 8)
            + ((header_hash[4 * i + 2] as u32) << 16)
            + ((header_hash[4 * i + 3] as u32) << 24);
    }

    st[8] = nonce as u32;
    st[9] = (nonce >> 32) as u32;

    for i in 0..8 {
        st[10 + i] = result[i];
    }

    for r in 0..22 {
        keccak_f800_round(st, r);
    }
}

pub fn keccak_f800_short(header_hash: H256, nonce: u64, result: [u32; 8]) -> u64 {
    let mut st = [0u32; 25];
    keccak_f800(header_hash, nonce, result, &mut st);
    (st[0].swap_bytes() as u64) << 32 | st[1].swap_bytes() as u64
}

pub fn keccak_f800_long(header_hash: H256, nonce: u64, result: [u32; 8]) -> H256 {
    let mut st = [0u32; 25];
    keccak_f800(header_hash, nonce, result, &mut st);

    // NOTE: transmute from `[u32; 8]` to `[u8; 32]`
    unsafe { core::mem::transmute([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]) }
}
