#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
mod signature;

pub mod hash {
	use ethereum_types::{H160, H256};
	pub use keccak_hash::{keccak, keccak256};
	use digest::Digest;

	pub fn sha256<T: AsRef<[u8]>>(s: T) -> H256 {
		let mut d   =sha2::Sha256::default();
		let ref mut f=d;
		f.input(s);
		return H256::from_slice(d.result().as_slice()) ;
	}

	pub fn ripemd160<T: AsRef<[u8]>>(data: T) -> H160 {
		let mut d = ripemd160::Ripemd160::default();
		let ref mut f = d;
		f.input(data);
		return H160::from_slice(d.result().as_slice()) ;
	}
}

pub mod publickey {
	pub use ethereum_types::{Address, Public};
	use ethereum_types::H256;
	pub type Message = H256;

	pub fn public_to_address(public: &Public) -> Address {
		let hash = crate::hash::keccak(public);
		let mut result = Address::zero();
		result.as_bytes_mut().copy_from_slice(&hash[12..]);
		result
	}

	#[cfg(not(feature = "std"))]
	pub use crate::signature::{Signature, recover};
	#[cfg(feature = "std")]
	pub use parity_crypto::publickey::{sign, Signature, Generator, Random, Secret};
	#[cfg(feature = "std")]
	pub fn recover(signature: &Signature, message: &Message) -> Option<Address> {
		let public = parity_crypto::publickey::recover(signature, message).ok()?;
		Some(public_to_address(&public))
	}
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
