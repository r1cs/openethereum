extern crate alloc;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;
use core::ops::{Deref, DerefMut};
use core::hash::{Hash, Hasher};
use ethereum_types::{Address, H256, H520};
use rustc_hex::ToHex;
use crate::publickey::Message;

/// Signature encoded as RSV components
#[repr(C)]
pub struct Signature([u8; 65]);

impl Signature {
	/// Get a slice into the 'r' portion of the data.
	pub fn r(&self) -> &[u8] {
		&self.0[0..32]
	}

	/// Get a slice into the 's' portion of the data.
	pub fn s(&self) -> &[u8] {
		&self.0[32..64]
	}

	/// Get the recovery byte.
	pub fn v(&self) -> u8 {
		self.0[64]
	}

	/// Encode the signature into RSV array (V altered to be in "Electrum" notation).
	pub fn into_electrum(mut self) -> [u8; 65] {
		self.0[64] += 27;
		self.0
	}

	/// Parse bytes as a signature encoded as RSV (V in "Electrum" notation).
	/// May return empty (invalid) signature if given data has invalid length.
	pub fn from_electrum(data: &[u8]) -> Self {
		if data.len() != 65 || data[64] < 27 {
			// fallback to empty (invalid) signature
			return Signature::default();
		}

		let mut sig = [0u8; 65];
		sig.copy_from_slice(data);
		sig[64] -= 27;
		Signature(sig)
	}

	/// Create a signature object from the RSV triple.
	pub fn from_rsv(r: &H256, s: &H256, v: u8) -> Self {
		let mut sig = [0u8; 65];
		sig[0..32].copy_from_slice(r.as_ref());
		sig[32..64].copy_from_slice(s.as_ref());
		sig[64] = v;
		Signature(sig)
	}

	/// Check if this is a "low" signature (that s part of the signature is in range
	/// 0x1 and 0x7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0 (inclusive)).
	/// This condition may be required by some verification algorithms
	pub fn is_low_s(&self) -> bool {
		const LOW_SIG_THRESHOLD: H256 = H256([
			0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57,
			0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
		]);
		H256::from_slice(self.s()) <= LOW_SIG_THRESHOLD
	}

	/// Check if each component of the signature is in valid range.
	/// r is in range 0x1 and 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 (inclusive)
	/// s is in range 0x1 and fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 (inclusive)
	/// v is 0 or 1
	/// Group order for secp256k1 defined as 'n' in "Standards for Efficient Cryptography" (SEC2) 2.7.1;
	/// used here as the upper bound for a valid (r, s, v) tuple
	pub fn is_valid(&self) -> bool {
		const UPPER_BOUND: H256 = H256([
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae,
			0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
		]);
		const ONE: H256 = H256([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		]);
		let r = H256::from_slice(self.r());
		let s = H256::from_slice(self.s());
		self.v() <= 1 && r < UPPER_BOUND && r >= ONE && s < UPPER_BOUND && s >= ONE
	}
}

// manual implementation large arrays don't have trait impls by default.
// TODO[grbIzl] remove when integer generics exist
impl PartialEq for Signature {
	fn eq(&self, other: &Self) -> bool {
		&self.0[..] == &other.0[..]
	}
}

// manual implementation required in Rust 1.13+, see `std::cmp::AssertParamIsEq`.
impl Eq for Signature {}

// also manual for the same reason, but the pretty printing might be useful.
impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		f.debug_struct("Signature")
			.field("r", &self.0[0..32].to_hex::<String>())
			.field("s", &self.0[32..64].to_hex::<String>())
			.field("v", &self.0[64..65].to_hex::<String>())
			.finish()
	}
}

impl fmt::Display for Signature {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "{}", self.to_hex::<String>())
	}
}

impl Default for Signature {
	fn default() -> Self {
		Signature([0; 65])
	}
}

impl Hash for Signature {
	fn hash<H: Hasher>(&self, state: &mut H) {
		H520::from(self.0).hash(state);
	}
}

impl Clone for Signature {
	fn clone(&self) -> Self {
		Signature(self.0.clone())
	}
}

impl From<[u8; 65]> for Signature {
	fn from(s: [u8; 65]) -> Self {
		Signature(s)
	}
}

impl Into<[u8; 65]> for Signature {
	fn into(self) -> [u8; 65] {
		self.0
	}
}

impl From<Signature> for H520 {
	fn from(s: Signature) -> Self {
		H520::from(s.0)
	}
}

impl From<H520> for Signature {
	fn from(bytes: H520) -> Self {
		Signature(bytes.into())
	}
}

impl Deref for Signature {
	type Target = [u8; 65];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DerefMut for Signature {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

pub fn recover(signature: &Signature, message: &Message) -> Option<Address> {
	todo!("use riscv syscall")
}
