

/// Single-step sha256 digest computation.
pub fn sha256(data: &[u8]) -> Vec<u8> {
	let  d=sha2::Sha256::default();
	d.input(data);
	return d.result().into_vec();
}
