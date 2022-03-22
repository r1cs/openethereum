use client::RiscvEnv;
use ethereum_types::{Address, H256, U256};
use ethjson::types::transaction::SignedTransaction;
use evm::VMType;
use factory::{Factories, VmFactory};
use hash_db::{AsHashDB, Hasher};
use journaldb::oracle::Oracle;
use keccak_hasher::KeccakHasher;
use miner::generate_block;
use spec::Spec;
use state_db::StateDB;
use std::sync::Arc;
use types::header::Header;
use TrieSpec;
use ethtrie::TrieFactory;
use engines::{InstantSeal, InstantSealParams};
use rlp::DecoderError;

#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable)]
struct Input {
    pub last_hashes: Vec<H256>,
    pub header: Header,
    pub author: Address,
    pub gas_range_target_start: U256,
	pub gas_range_targe_end: U256,
    pub tx: SignedTransaction,
}


fn start() {
    let oracleDB = Box::new(Oracle::new());
    let machine = Spec::load_machine(include_bytes!("../res/chainspec/test/frontier_test.json")).expect("riscv open test json failed");
	let engine = InstantSeal::new(InstantSealParams{millisecond_timestamp:false}, machine);
	let input_hash=oracleDB.as_ref().inputHash();
	let input_code =match oracleDB.oracle_preimage(&input_hash){
		Some(t)=>t,
		None=>oracleDB.as_ref().panic("cant get input"),
	};
    let input: Input = rlp::decode(input_code.as_slice()).unwrap();

    let riscvClient = RiscvEnv {
        engine: Arc::new(engine),
        state_db: StateDB::new(oracleDB, 1024),
        last_hashes: Arc::new(input.last_hashes.clone()),
        factories: Factories {
            vm: VmFactory::new(VMType::Interpreter, 1024),
            trie: TrieFactory::new(TrieSpec::Secure),
            accountdb: Default::default(),
        },
        parent_block_header: input.header.clone(),
    };

    let sealBlock = generate_block(
        &engine,
        &riscvClient,
        input.author,
        (input.gas_range_target_start,input.gas_range_targe_end),
        vec![],
        vec![input.tx],
    );
    match sealBlock {
        Some(b) =>{
			let rlpCode = b.rlp_bytes();
			oracleDB.as_ref().output_return(KeccakHasher::hash(&rlpCode));
		},
        None => oracleDB.as_ref().panic("generate block failed"),
    };
}
