use serde::{Deserialize, Serialize};
use std::collections::hash_map::Values;
use std::collections::HashMap;
use std::vec::Vec;

use crate::oblivious_data_structures::ob_tree::components::ObTreeNode;

#[derive(Serialize, Deserialize, Clone)]
pub struct ObTreeNodeCache {
    map: HashMap<u128, ObTreeNode>,
}

impl ObTreeNodeCache {
    pub fn new_empty() -> Self {
        ObTreeNodeCache {
            map: HashMap::new(),
        }
    }
    pub fn shrink_to_fit(&mut self) {
        self.map.shrink_to_fit();
    }
    fn map(&self) -> &HashMap<u128, ObTreeNode> {
        &self.map
    }
    fn mut_map(&mut self) -> &mut HashMap<u128, ObTreeNode> {
        &mut self.map
    }
    pub fn get_node(&self, key: &u128) -> Option<&ObTreeNode> {
        self.map().get(key)
    }
    pub fn mut_node(&mut self, key: &u128) -> Option<&mut ObTreeNode> {
        self.mut_map().get_mut(key)
    }
    pub fn insert_node(&mut self, key: u128, node: ObTreeNode) {
        assert!(self.mut_map().insert(key, node).is_none());
    }
    pub fn remove_node(&mut self, key: &u128) -> Option<ObTreeNode> {
        self.mut_map().remove(key)
    }
    pub fn size(&self) -> usize {
        self.map().len()
    }
    pub fn byte_size(&self) -> u64 {
        let mut byte_size: u64 = 0;
        for (_, node) in self.map.iter() {
            byte_size += bincode::serialized_size(node).unwrap();
        }
        byte_size
    }
    pub fn is_empty(&self) -> bool {
        self.map().is_empty()
    }
    pub fn nodes(&self) -> Values<u128, ObTreeNode> {
        self.map.values()
    }
    pub fn keys(&self) -> Vec<u128> {
        self.map.iter().map(|(key, _)| *key).collect()
    }
}
