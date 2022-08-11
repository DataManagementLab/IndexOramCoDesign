use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

use oblivious_data_structures::page::Slot;

#[derive(Serialize, Deserialize, Clone)]
pub struct SlotCache {
    map: HashMap<u128, Slot>,
}

impl SlotCache {
    pub fn new_empty() -> Self {
        SlotCache {
            map: HashMap::new(),
        }
    }
    fn map(&self) -> &HashMap<u128, Slot> {
        &self.map
    }
    fn mut_map(&mut self) -> &mut HashMap<u128, Slot> {
        &mut self.map
    }
    pub fn get_slot(&self, key: &u128) -> Option<&Slot> {
        self.map().get(key)
    }
    pub fn mut_slot(&mut self, key: &u128) -> Option<&mut Slot> {
        self.mut_map().get_mut(key)
    }
    pub fn insert_slot(&mut self, key: u128, slot: Slot) {
        assert!(self.mut_map().insert(key, slot).is_none());
    }
    pub fn remove_slot(&mut self, key: &u128) -> Option<Slot> {
        self.mut_map().remove(key)
    }
    pub fn size(&self) -> usize {
        self.map().len()
    }
    pub fn byte_size(&self) -> u64 {
        let mut byte_size: u64 = 0;
        for (_, slot) in self.map.iter() {
            byte_size += bincode::serialized_size(slot).unwrap();
        }
        byte_size
    }
    pub fn is_empty(&self) -> bool {
        return self.size() == 0;
    }
}
