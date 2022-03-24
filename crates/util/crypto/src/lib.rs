
#![no_std]
use sha2;
use digest::Digest;
use sha2::Sha256;
use digest::generic_array::{
	typenum:: {U32,U20},
	GenericArray,
};
use ripemd160;

pub fn sha256(data: &[u8]) -> GenericArray<u8, U32> {
	let mut d   =sha2::Sha256::default();
	let ref mut f=d;
	f.input(data);
	return d.result();
}


pub fn getRipemd160(data: &[u8]) -> GenericArray<u8, U20> {

	let mut d = ripemd160::Ripemd160::default();
	let ref mut f = d;
	f.input(data);
	return d.result();
}
