use oblivious_data_structures::page::SlotContent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Serialize, Deserialize, Clone)]
pub struct QueryResponseCache {
    cache: HashMap<u128, Vec<SlotContent>>,
}

impl QueryResponseCache {
    pub fn new_empty() -> Self {
        QueryResponseCache {
            cache: HashMap::new(),
        }
    }
    pub fn insert(&mut self, query_id: u128, response: Vec<SlotContent>) {
        self.cache.insert(query_id, response);
    }
    #[allow(dead_code)]
    pub fn remove(&mut self, query_id: &u128) -> Option<Vec<SlotContent>> {
        self.cache.remove(query_id)
    }
    #[allow(dead_code)]
    pub fn get(&self, query_id: &u128) -> Option<&Vec<SlotContent>> {
        self.cache.get(query_id)
    }
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.cache.len()
    }
    pub fn flush(&mut self) {
        self.cache = HashMap::new()
    }
}
