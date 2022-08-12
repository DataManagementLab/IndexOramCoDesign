use oblivious_data_structures::ob_tree::components::ObTreeDirectory;
use oblivious_data_structures::page::SlotContent;
use packet_stash::PacketStash;
use serde::{Deserialize, Serialize};
use slot_cache::SlotCache;
use std::collections::hash_map::Values;
use std::collections::HashMap;
use std::string::String;
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

pub mod functions {
    use std::string::String;
    use std::time::Instant;
    use std::untrusted::time::InstantEx;
    use std::vec::Vec;

    use helpers::range::Range;
    use sql_engine::sql_data_types::components::SqlDataType;
    use sql_engine::sql_database::components::SqlAttribute;

    use crate::enclave_state::EnclaveState;
    use crate::oblivious_data_structures::ob_tree::components::ObTreeNode;
    use crate::oblivious_data_structures::position_tag::PositionTag;

    /*
    pub fn transform_fragments_to_obt_node(
        enclave_state: &EnclaveState,
        fragments: Vec<u8>,
        pos_tag_string: &str,
    ) {
        let node: ObTreeNode = bincode::deserialize(&fragments[..])
            .expect("transform_fragments_to_obt_node has not worked!");
        enclave_state
            .lock_obt_node_cache()
            .insert_node(String::from(pos_tag_string), node);
    }

    pub fn assure_obt_node_is_in_cache(
        enclave_state: &EnclaveState,
        position_tag: &PositionTag,
        queried_value_range: Option<&Range<&SqlDataType>>,
        value_config: Option<&SqlAttribute>,
        index_id: u16,
    ) -> String {
        let pos_tag_string = position_tag.as_string();
        if enclave_state
            .lock_obt_node_cache()
            .get_node(&pos_tag_string)
            .is_none()
        {
            let fragments: Vec<u8> = get_fragments_of_one_packet_in_oram_and_evict_others(
                enclave_state,
                position_tag,
                queried_value_range,
                value_config,
                index_id,
            );
            let time_transform_fragments_to_obt_node: Instant = Instant::now();
            transform_fragments_to_obt_node(enclave_state, fragments, &pos_tag_string);
            enclave_state
                .lock_statistics()
                .inc_time_transform_fragments_to_obt_node(
                    time_transform_fragments_to_obt_node.elapsed().as_nanos(),
                );
            assert!(enclave_state
                .lock_obt_node_cache()
                .get_node(&pos_tag_string)
                .is_some());
        }
        pos_tag_string
    }
     */
}
