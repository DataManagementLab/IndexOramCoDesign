use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::vec::Vec;

use enclave_state::EnclaveState;
use oblivious_data_structures::ob_tree::components::Origin;
use oblivious_ram::functions::{transform_oram_fragments_to_logical_object, Object};
use oblivious_ram::packaging::Packet;
use oram_interface::EnclaveStatistics;
use packet_stash::PacketStash;
use query_state::ObjectType;

#[derive(Serialize, Deserialize, Clone)]
pub struct IndexLocalityCache {
    cache: HashMap<u128, (Packet, u128)>,
}

impl IndexLocalityCache {
    pub fn new_empty() -> Self {
        IndexLocalityCache {
            cache: HashMap::new(),
        }
    }
    pub fn size(&self) -> usize {
        self.cache.len()
    }
    pub fn byte_size(&self) -> u64 {
        let mut byte_size: u64 = 0;
        for (_, (packet, _)) in self.cache.iter() {
            byte_size += packet.byte_size() as u64;
        }
        byte_size
    }
    pub fn pop_all_packets_to_stash(&mut self, stash: &mut PacketStash) {
        let number_of_packets = self.size();
        let mut keys: Vec<u128> = Vec::with_capacity(number_of_packets);
        for (key, _) in self.cache.iter() {
            keys.push(*key);
        }
        for key in keys {
            let packet = self.cache.remove(&key).unwrap().0;
            let packet_size = packet.byte_size();
            stash.add_packet(packet, packet_size);
        }
        self.cache.clear();
    }
    pub fn flush_packets_of_query_id_to_stash(
        &mut self,
        stash: &mut PacketStash,
        query_id: &u128,
        stats: &mut EnclaveStatistics,
    ) {
        let time = Instant::now();
        let mut keys: Vec<u128> = Vec::new();
        for (key, (_, query_id_iter)) in self.cache.iter() {
            if query_id_iter.eq(query_id) {
                keys.push(*key);
            }
        }
        for key in keys {
            let packet = self.cache.remove(&key).unwrap().0;
            let packet_size = packet.byte_size();
            stash.add_packet(packet, packet_size);
        }
        stats.inc_time_flush_packets_of_query_id_to_stash(time.elapsed().as_nanos());
    }
    pub fn insert(&mut self, packet: Packet, query_id: u128) {
        self.cache
            .insert(packet.position().copy_packet_id(), (packet, query_id));
    }
    pub fn remove_and_get_object(
        &mut self,
        enclave_state: &EnclaveState,
        packet_id: &u128,
        object_type: &ObjectType,
    ) -> bool {
        match self.cache.remove(packet_id) {
            None => {}
            Some(packet) => {
                let object = transform_oram_fragments_to_logical_object(
                    &mut enclave_state.lock_statistics(),
                    packet.0.content(),
                    object_type,
                    Origin::IndexLocalityCache,
                );
                match object {
                    Object::SlotObject(slot) => {
                        enclave_state
                            .lock_statistics()
                            .inc_times_slot_found_in_locality_cache();
                        enclave_state
                            .lock_slot_cache()
                            .insert_slot(*packet_id, slot);
                    }
                    Object::NodeObject(node) => {
                        enclave_state
                            .lock_statistics()
                            .inc_times_node_found_in_locality_cache();
                        enclave_state
                            .lock_obt_node_cache()
                            .insert_node(*packet_id, node);
                    }
                }
                return true;
            }
        }
        false
    }
}

pub fn clear_index_locality_cache_to_packet_stash(app_state: &EnclaveState) {
    println!("clear_index_locality_cache_to_packet_stash");
    let time: Instant = Instant::now();
    let mut packet_stash = app_state.lock_packet_stash();
    {
        let mut index_locality_cache = app_state.lock_index_locality_cache();
        match index_locality_cache.as_mut() {
            None => {}
            Some(some_index_locality_cache) => {
                some_index_locality_cache.pop_all_packets_to_stash(&mut packet_stash);
            }
        }
    }
    app_state
        .lock_statistics()
        .inc_time_clear_index_locality_cache_to_packet_stash(time.elapsed().as_nanos());
}
