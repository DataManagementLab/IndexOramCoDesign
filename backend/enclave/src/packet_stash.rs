use serde::{Deserialize, Serialize};
use std::collections::{HashMap};
use std::vec::Vec;
use oblivious_data_structures::ob_tree::components::Origin;
use oblivious_ram::components::{BucketContentForLocal};
use oblivious_ram::functions::{
    read_process_and_evict_oram_request_batch,
    transform_oram_fragments_to_logical_object, Object,
};
use oblivious_ram::packaging::Packet;
use query_state::ObjectType;
use {PRINT_PACKET_EVICTIONS};
use crate::enclave_state::EnclaveState;
use crate::helpers::oram_helper::get_number_of_leaves;
use crate::oblivious_data_structures::position_tag::PositionTag;


#[derive(Serialize, Deserialize, Clone)]
pub struct PacketStash {
    stash: HashMap<u32, HashMap<u32, Vec<Packet>>>,
    current_size: HashMap<u32, usize>,
}

impl PacketStash {
    pub fn new_empty() -> Self {
        PacketStash {
            stash: HashMap::new(),
            current_size: HashMap::new(),
        }
    }
    pub fn shrink_to_fit(&mut self) {
        self.stash.shrink_to_fit();
    }
    pub fn mut_oram(&mut self, oram_id: u32) -> Option<&mut HashMap<u32, Vec<Packet>>> {
        return match self.stash.get_mut(&oram_id) {
            None => None,
            Some(oram) => Some(oram),
        };
    }
    pub fn oram(&self, oram_id: u32) -> Option<&HashMap<u32, Vec<Packet>>> {
        return match self.stash.get(&oram_id) {
            None => None,
            Some(oram) => Some(oram),
        };
    }
    #[allow(dead_code)]
    pub fn path_of_oram(&self, oram_id: u32, path_id: u32) -> Option<&Vec<Packet>> {
        match self.stash.get(&oram_id) {
            None => {
                return None;
            }
            Some(oram) => match oram.get(&path_id) {
                None => {
                    return None;
                }
                Some(path) => {
                    return Some(path);
                }
            },
        }
    }
    pub fn contains_packet(&self, packet_position: &PositionTag) -> bool {
        match self.stash.get(&packet_position.oram_id()) {
            None => {}
            Some(oram) => match oram.get(&packet_position.path()) {
                None => {}
                Some(path) => {
                    for packet in path.iter() {
                        if packet
                            .position()
                            .packet_id()
                            .eq(packet_position.packet_id())
                        {
                            return true;
                        }
                    }
                }
            },
        }
        false
    }
    pub fn mut_path_of_oram(&mut self, oram_id: u32, path_id: u32) -> Option<&mut Vec<Packet>> {
        match self.stash.get_mut(&oram_id) {
            None => {
                return None;
            }
            Some(oram) => match oram.get_mut(&path_id) {
                None => {
                    return None;
                }
                Some(path) => {
                    return Some(path);
                }
            },
        }
    }
    pub fn get_keys(&self, instance: u32) -> Vec<u32> {
        let keys = match self.oram(instance) {
            None => Vec::new(),
            Some(some_oram) => some_oram
                .iter()
                .filter_map(|(key, packets)| {
                    if !packets.is_empty() {
                        Some(*key)
                    } else {
                        None
                    }
                })
                .collect(),
        };
        keys
    }
    pub fn evict_into_oram_bucket(
        &mut self,
        min_packet_size: usize,
        oram_id: u32,
        oram_bucket: &mut BucketContentForLocal,
        keys: &Vec<u32>,
    ) -> usize {
        let mut evicted_packets: usize = 0;
        let mut current_oram_size = self.current_oram_size(&oram_id);
        if current_oram_size == 0 {
            return 0;
        }
        let poss_positions = oram_bucket.poss_positions();
        for current_pos in keys
            .iter()
            .filter(|pos| (pos >= &&poss_positions.0) && (pos <= &&poss_positions.1))
        {
            if oram_bucket.free_space() >= min_packet_size && current_oram_size > 0 {
                let mut is_empty: bool = false;
                match self.mut_path_of_oram(oram_id, *current_pos) {
                    None => {}
                    Some(some_path) => {
                        for i_packet in (0..some_path.len()).rev() {
                            let packet_size = some_path.get(i_packet).unwrap().byte_size();
                            if packet_size <= oram_bucket.free_space() {
                                let packet_to_evict = some_path.remove(i_packet);
                                current_oram_size -= 1;
                                if PRINT_PACKET_EVICTIONS {
                                    println!(
                                            "Evicted packet at index {} inserted into bucket ({}..{}): ID {}, Leaf: {}",
                                            i_packet,
                                            oram_bucket.poss_positions().0,
                                            oram_bucket.poss_positions().1,
                                            packet_to_evict.position().packet_id(),
                                            current_pos
                                        );
                                }
                                /*
                                inserted_packets
                                    .insert(packet_to_evict.position().copy_packet_id());
                                 */
                                oram_bucket.insert_packet_with_size(packet_to_evict, packet_size);
                                evicted_packets += 1;
                            }
                        }
                        is_empty = some_path.is_empty();
                    }
                }
                if is_empty {
                    self.mut_oram(oram_id).unwrap().remove(current_pos);
                }
            } else {
                break;
            }
        }
        self.set_current_oram_size(oram_id, current_oram_size);
        evicted_packets
    }

    pub fn number_of_packets(&self) -> usize {
        let mut number: usize = 0;
        for (_oram_id, oram) in self.stash.iter() {
            for (_path, packets) in oram.iter() {
                number += packets.len();
            }
        }
        let mut number2: usize = 0;
        for val in self.current_size.values() {
            number2 += *val;
        }
        assert_eq!(number, number2);
        number
    }

    pub fn resource_usage(&self) -> (u64, u64, u64, f64) {
        let mut number: usize = 0;
        let mut total_byte_size: u64 = 0;
        let mut max_byte_size: u64 = 0;
        for (_oram_id, oram) in self.stash.iter() {
            for (_path, packets) in oram.iter() {
                number += packets.len();
                for packet in packets.iter() {
                    let packet_byte_size = packet.byte_size() as u64;
                    total_byte_size += packet_byte_size;
                    if packet_byte_size > max_byte_size {
                        max_byte_size = packet_byte_size;
                    }
                }
            }
        }
        let average_byte_size: f64 = (total_byte_size as f64) / (number as f64);
        (
            number as u64,
            total_byte_size,
            max_byte_size,
            average_byte_size,
        )
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.number_of_packets() == 0
        /*
        let mut is_empty = true;
        for (_oram_id, oram) in self.stash.iter() {
            if !oram.is_empty() {
                is_empty = false;
                break;
            }
        }
        is_empty
         */
    }

    pub fn add_packet(&mut self, packet: Packet, packet_size: usize) -> bool {
        if self.stash.get_mut(&packet.position().oram_id()).is_none() {
            self.stash
                .insert(packet.position().oram_id(), HashMap::new());
        }
        self.inc_current_size(packet.position().oram_id());

        return match self.stash.get_mut(&packet.position().oram_id()) {
            None => false,
            Some(oram) => match oram.get_mut(&packet.position().path()) {
                None => {
                    oram.insert(packet.position().path(), vec![packet]);
                    true
                }
                Some(path) => {
                    /*
                    path.push(packet);
                    true
                     */

                    let mut best_index = path.len();

                    for index in 0..path.len() {
                        if packet_size >= path[index].byte_size() {
                            best_index = index;
                            break;
                        }
                    }
                    path.insert(best_index, packet);
                    //path.push(packet);
                    //path.par_sort_by(|a, b| a.byte_size().cmp(&b.byte_size()));
                    //assert!(path[0].byte_size() >= path[1].byte_size());
                    true

                    /*
                    let mut best_index = path.len();
                    let packet_size = packet.byte_size();
                    for (index, packet_iter) in path.iter().enumerate() {
                        if packet_iter.byte_size() >= packet_size {
                            best_index = index;
                            break;
                        }
                    }
                    path.insert(best_index, packet);
                    //path.push(packet);
                    //path.par_sort_by(|a, b| a.byte_size().cmp(&b.byte_size()));
                    assert!(path[0].byte_size() <= path[1].byte_size());
                    true
                     */
                }
            },
        };
    }

    pub fn lookup_stash_for_requested_packets(
        &mut self,
        enclave_state: &EnclaveState,
        oram_instance: &u32,
        leaves: &Vec<u32>,
        needed_objects: &mut HashMap<u128, ObjectType>,
    ) {
        let mut current_oram_size = self.current_oram_size(oram_instance);
        if current_oram_size == 0 {
            return;
        }
        match self.stash.get_mut(oram_instance) {
            None => {}
            Some(oram) => {
                for leaf in leaves {
                    let mut empty_path: bool = false;
                    match oram.get_mut(leaf) {
                        None => {}
                        Some(path) => {
                            for curr_packet_index in (0..path.len()).rev() {
                                match needed_objects.remove(
                                    path.get(curr_packet_index).unwrap().position().packet_id(),
                                ) {
                                    None => {}
                                    Some(object_type) => {
                                        let packet = path.remove(curr_packet_index);
                                        current_oram_size -= 1;

                                        let packet_id = packet.position().copy_packet_id();
                                        if PRINT_PACKET_EVICTIONS {
                                            println!(
                                                "Got packet from stash: {}, Leaf: {}",
                                                packet_id, leaf
                                            );
                                        }
                                        let object = transform_oram_fragments_to_logical_object(
                                            &mut enclave_state.lock_statistics(),
                                            packet.content(),
                                            &object_type,
                                            Origin::Stash,
                                        );
                                        match object {
                                            Object::SlotObject(slot) => {
                                                enclave_state
                                                    .lock_slot_cache()
                                                    .insert_slot(packet_id, slot);
                                            }
                                            Object::NodeObject(node) => {
                                                enclave_state
                                                    .lock_obt_node_cache()
                                                    .insert_node(packet_id, node);
                                            }
                                        }
                                    }
                                }
                            }
                            empty_path = path.is_empty();
                        }
                    }
                    if empty_path {
                        oram.remove(leaf);
                    }
                }
            }
        }
        self.set_current_oram_size(*oram_instance, current_oram_size);
    }
    pub fn inc_current_size(&mut self, oram_id: u32) {
        self.current_size
            .entry(oram_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }
    pub fn current_oram_size(&self, oram_id: &u32) -> usize {
        return match self.current_size.get(oram_id) {
            None => 0,
            Some(size) => *size,
        };
    }
    pub fn set_current_oram_size(&mut self, oram_id: u32, new_val: usize) {
        self.current_size
            .entry(oram_id)
            .and_modify(|count| {
                *count = new_val;
            })
            .or_insert(new_val);
    }
}

/// Should not be used in production
pub fn clear_to_oram(enclave_state: &EnclaveState) {
    let (bounded_locality_cache_before, keep_not_requested_in_buckets_before) = {
        let mut dynamic_config = enclave_state.lock_dynamic_config();
        let bounded_locality_cache = dynamic_config.bounded_locality_cache();
        let keep_not_requested_in_buckets = dynamic_config.keep_not_requested_in_buckets();
        dynamic_config.set_keep_not_requested_in_buckets(0.7f64);
        dynamic_config.set_bounded_locality_cache(0);
        (bounded_locality_cache, keep_not_requested_in_buckets)
    };

    {
        let packet_stash = enclave_state.lock_packet_stash();
        println!(
            "clear_to_oram: packet_stash has size of {} before",
            packet_stash.number_of_packets()
        );
    }

    let (number_of_oram, oram_degree, oram_tree_height) = {
        let oram_config = enclave_state.lock_oram_config();
        (
            oram_config.number_of_oram(),
            oram_config.oram_degree(),
            oram_config.tree_height(),
        )
    };
    for oram_instance in 0..number_of_oram {
        for pos in 1..(get_number_of_leaves(oram_degree, oram_tree_height) + 1) {
            let oram_instance = oram_instance as u32;
            let pos = pos as u32;

            let mut packet_stash = enclave_state.lock_packet_stash();
            match packet_stash.mut_oram(oram_instance) {
                None => {}
                Some(some_oram) => match some_oram.get(&pos) {
                    None => {}
                    Some(some_path) => {
                        if !some_path.is_empty() {
                            drop(packet_stash);
                            read_process_and_evict_oram_request_batch(
                                enclave_state,
                                oram_instance as u32,
                                vec![pos as u32],
                                HashMap::new(),
                            );
                        } else {
                            drop(some_path);
                            some_oram.remove(&pos);
                        }
                    }
                },
            }
        }
        //assert!(packet_stash.oram(oram_instance as u32).unwrap().is_empty());
    }

    {
        let mut dynamic_config = enclave_state.lock_dynamic_config();
        let mut packet_stash = enclave_state.lock_packet_stash();
        dynamic_config.set_bounded_locality_cache(bounded_locality_cache_before);
        dynamic_config.set_keep_not_requested_in_buckets(keep_not_requested_in_buckets_before);
        println!(
            "clear_to_oram: packet_stash has size of {} now",
            packet_stash.number_of_packets()
        );
        packet_stash.shrink_to_fit();
    }
}
