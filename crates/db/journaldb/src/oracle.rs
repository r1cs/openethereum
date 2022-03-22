use alloc::{collections::BTreeMap, sync::Arc};
use ethereum_types::H256;
use hash_db::{AsHashDB, HashDB, Hasher};
use keccak_hasher::KeccakHasher;
use kvdb::{DBTransaction, DBValue, KeyValueDB};

use JournalDB;
use traits::FakeJournalDB;

#[derive(Clone, PartialEq)]
pub struct Oracle;

impl Oracle {
    pub fn new() -> Oracle {
        Oracle {}
    }
  pub  fn preimage<'a, T>(&self, hash: &H256) -> DBValue where T: From<&'a [u8]>  {
        let v = match self.oracle_preimage(hash) {
            Some(value) => value,
            None => panic!("can't get hash in oracle"), //may be should panic,so consider hash=keccake256(""),do not get preimage
        };
		v.as_slice().into()
    }

   pub fn oracle_preimage(&self, preimage: &H256) -> Option<Vec<u8>> {
        panic!("should use system call");
    }

  pub  fn inputHash(&self) -> H256 {
        panic!("syscall inputHash")
    }

   pub  fn output_return(&self,outputHash: H256) {
        panic!("syscall outputHash then return")
    }

   pub fn panic(&self,s: &str) {
        panic!("should use panic sys call")
    }
}

impl HashDB<KeccakHasher, DBValue> for Oracle {
    fn get(&self, key: &H256) -> Option<DBValue> {
        Some(self.preimage::<DBValue>(key))
    }

    fn contains(&self, key: &H256) -> bool {
        self.get(key).is_some()
    }

    fn insert(&mut self, value: &[u8]) -> H256 {
        //do not need to insert in riscv, casue it only need to get oracle from outside
        KeccakHasher::hash(value)
    }

    fn emplace(&mut self, key: H256, value:DBValue) {}

    fn remove(&mut self, key: &H256) {}
}

impl AsHashDB<KeccakHasher, DBValue> for Oracle {
    fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self
    }
    fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher,DBValue> {
        self
    }
}

impl FakeJournalDB for Oracle {
    fn boxed_clone(&self) -> Box<dyn FakeJournalDB> {
        return Box::new(self.clone());
    }

    fn journal_under(&mut self, batch: &mut DBTransaction, now: u64, id: &H256) -> u32 {
        //do not write
        0
    }

    fn mark_canonical(&mut self, batch: &mut DBTransaction, era: u64, id: &H256) -> Option<u32> {
        Some(0)
    }

    fn is_pruned(&self) -> bool {
        false
    }
}
