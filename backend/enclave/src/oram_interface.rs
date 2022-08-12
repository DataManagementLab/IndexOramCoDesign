use core::ops::Add;
use serde::{Deserialize, Serialize};
use std::string::{String, ToString};
use std::vec::Vec;

#[derive(Serialize, Deserialize)]
pub enum GenericRequestToServer {
    TestMsg(String),
    EnvironmentVariables(EnvironmentVariables),
    Statistics(EnclaveStatistics),
    ResourceUsageReport(ResourceUsageReport),
    EnclaveStateBackup(ByteObject),
    Signal(u8),
    Shutdown(u8),
}

impl GenericRequestToServer {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serializing the request has not worked out.")
    }
}

#[derive(Serialize, Deserialize)]
pub struct ByteObject {
    header: String,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    complete: bool,
}

impl ByteObject {
    pub fn new(header: String, data: Vec<u8>, complete: bool) -> Self {
        ByteObject {
            header,
            data,
            complete,
        }
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Serialize, Deserialize)]
pub enum GenericRequestToEnclave {
    InitEnclave(InitEnclaveConfig),
    ExperimentWorkloadRequest(ExperimentWorkloadRequest),
    EnclaveStateBackupRequest(String),
    EnclaveStateRestoreBackupRequest(ByteObject),
    ClearIndexLocalityCache,
    ClearPacketStash,
    ORAMBenchmark,
}

impl GenericRequestToEnclave {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serializing the request has not worked out.")
    }
}

#[derive(Serialize, Deserialize)]
pub struct InitEnclaveConfig {
    number_of_oram: usize,
    tree_height: usize,
    oram_degree: usize,
    bucket_size: usize,
    index_locality_cache: u8,
    fill_grade: u32,
}

impl InitEnclaveConfig {
    pub fn number_of_oram(&self) -> usize {
        self.number_of_oram
    }
    pub fn tree_height(&self) -> usize {
        self.tree_height
    }
    pub fn oram_degree(&self) -> usize {
        self.oram_degree
    }
    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }
    pub fn index_locality_cache(&self) -> u8 {
        self.index_locality_cache
    }
    pub fn fill_grade(&self) -> u32 {
        self.fill_grade
    }
}

#[derive(Serialize, Deserialize)]
pub struct ResourceUsageReport {
    stash_number_of_packets: u64,
    stash_total_byte_size: u64,
    stash_max_byte_size: u64,
    stash_average_byte_size: f64,
    node_cache_amount: u64,
    node_cache_byte_size: u64,
    slot_cache_amount: u64,
    slot_cache_byte_size: u64,
    locality_cache_amount: u64,
    locality_cache_byte_size: u64,
    free_oram_space_after: f64,
    evicted_packets_in_batch: u64,
}

impl ResourceUsageReport {
    pub fn new(
        stash_number_of_packets: u64,
        stash_total_byte_size: u64,
        stash_max_byte_size: u64,
        stash_average_byte_size: f64,
        node_cache_amount: u64,
        node_cache_byte_size: u64,
        slot_cache_amount: u64,
        slot_cache_byte_size: u64,
        locality_cache_amount: u64,
        locality_cache_byte_size: u64,
        free_oram_space_after: f64,
        evicted_packets_in_batch: u64,
    ) -> Self {
        ResourceUsageReport {
            stash_number_of_packets,
            stash_total_byte_size,
            stash_max_byte_size,
            stash_average_byte_size,
            node_cache_amount,
            node_cache_byte_size,
            slot_cache_amount,
            slot_cache_byte_size,
            locality_cache_amount,
            locality_cache_byte_size,
            free_oram_space_after,
            evicted_packets_in_batch,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EnvironmentVariables {
    number_of_oram: usize,
    tree_height: usize,
    oram_degree: usize,
    max_bucket_size: usize,
    bucket_serialized_size: usize,
    bucket_ciphertext_len: usize,
}

impl EnvironmentVariables {
    pub fn new(
        number_of_oram: usize,
        tree_height: usize,
        oram_degree: usize,
        max_bucket_size: usize,
        bucket_serialized_size: usize,
        bucket_ciphertext_len: usize,
    ) -> Self {
        EnvironmentVariables {
            number_of_oram,
            tree_height,
            oram_degree,
            max_bucket_size,
            bucket_serialized_size,
            bucket_ciphertext_len,
        }
    }
    pub fn number_of_oram(&self) -> usize {
        self.number_of_oram
    }
    pub fn tree_height(&self) -> usize {
        self.tree_height
    }
    pub fn oram_degree(&self) -> usize {
        self.oram_degree
    }
    pub fn max_bucket_size(&self) -> usize {
        self.max_bucket_size
    }
    pub fn bucket_serialized_size(&self) -> usize {
        self.bucket_serialized_size
    }
    pub fn bucket_ciphertext_len(&self) -> usize {
        self.bucket_ciphertext_len
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExperimentWorkloadRequest {
    experiment_id: u64,
    experiment_name: String,
    clear_stash_afterwards: bool,
    index: usize,
    query_amount: usize,
    query_batch_size: usize,
    query_type: String,
    oram_access_batch_size: usize,
    aggressive_caching: bool,
    skew: bool,
    pre_data_volume: usize,
    direct_eviction: bool,
    locality_cache_direct_flush: bool,
    min_matching_prefix_level: u32,
    oram_random_batch_size: bool,
    bounded_locality_cache: usize,
    dummy_fill_oram_access_batch: bool,
    keep_not_requested_in_buckets: f64,
}

impl ExperimentWorkloadRequest {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serializing the request has not worked out.")
    }
    pub fn experiment_name(&self) -> &str {
        &self.experiment_name
    }
    pub fn clear_stash_afterwards(&self) -> bool {
        self.clear_stash_afterwards
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn query_amount(&self) -> usize {
        self.query_amount
    }
    pub fn query_batch_size(&self) -> usize {
        self.query_batch_size
    }
    pub fn query_type(&self) -> &str {
        &self.query_type
    }
    pub fn oram_access_batch_size(&self) -> usize {
        self.oram_access_batch_size
    }
    pub fn experiment_id(&self) -> u64 {
        self.experiment_id
    }
    pub fn aggressive_caching(&self) -> bool {
        self.aggressive_caching
    }
    pub fn skew(&self) -> bool {
        self.skew
    }
    pub fn pre_data_volume(&self) -> usize {
        self.pre_data_volume
    }
    pub fn direct_eviction(&self) -> bool {
        self.direct_eviction
    }
    pub fn locality_cache_direct_flush(&self) -> bool {
        self.locality_cache_direct_flush
    }
    pub fn min_matching_prefix_level(&self) -> u32 {
        self.min_matching_prefix_level
    }
    pub fn oram_random_batch_size(&self) -> bool {
        self.oram_random_batch_size
    }
    pub fn bounded_locality_cache(&self) -> usize {
        self.bounded_locality_cache
    }
    pub fn dummy_fill_oram_access_batch(&self) -> bool {
        self.dummy_fill_oram_access_batch
    }
    pub fn keep_not_requested_in_buckets(&self) -> f64 {
        self.keep_not_requested_in_buckets
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EnclaveStatistics {
    experiment_id: u64,

    index_locality_cache: bool,
    obt_fill_grade: u32,

    oram_reads: u64,
    oram_read_time: u128,
    oram_writes: u64,
    oram_write_time: u128,
    time_evict_into_oram_batch_from_packet_stash: u128,

    workload_time: u128,

    time_evict_bottom_up: u128,
    time_split_node: u128,
    time_cast_split_to_parent: u128,

    times_node_found_in_locality_cache: u64,
    times_slot_found_in_locality_cache: u64,
    times_node_originally_from_locality_cache: u64,
    times_slot_originally_from_locality_cache: u64,

    times_more_than_one_packet: u64,
    evicted_packets: usize,
    total_node_evictions: u64,
    total_node_traversal_visits: u64,
    requested_oram_leaves: u64,

    number_packets_requested_from_oram: u64,
    number_packets_found_in_stash: u64,
    number_nodes_found_in_node_cache: u64,
    number_slots_found_in_slot_cache: u64,

    insert_packet_to_stash_time: u128,
    insert_packet_of_bucket_to_stash_time: u128,
    iter_buckets_from_oram_time: u128,
    time_clear_index_locality_cache_to_packet_stash: u128,
    time_flush_packets_of_query_id_to_stash: u128,
    time_iterate_buckets_for_locality_cache: u128,

    time_transform_fragments_to_obt_node: u128,
    time_transform_fragments_to_obt_slot: u128,

    time_serialize_obtree_node: u128,
    time_decompress_sql_data_type: u128,
    time_transform_bytes_to_oram_packets: u128,
    time_transform_buckets_to_bucket_contents: u128,
    time_transform_bucket_contents_to_buckets: u128,
    time_byte_range_to_sql_data_types: u128,

    generated_data_byte_size: usize,
}

impl EnclaveStatistics {
    pub fn new(index_locality_cache: bool, obt_fill_grade: u32) -> Self {
        EnclaveStatistics {
            experiment_id: 0,

            index_locality_cache,
            obt_fill_grade,

            oram_reads: 0,
            oram_read_time: 0,
            oram_writes: 0,
            oram_write_time: 0,
            time_evict_into_oram_batch_from_packet_stash: 0,

            workload_time: 0,

            time_evict_bottom_up: 0,
            time_split_node: 0,
            time_cast_split_to_parent: 0,

            times_node_found_in_locality_cache: 0,
            times_slot_found_in_locality_cache: 0,
            times_node_originally_from_locality_cache: 0,
            times_slot_originally_from_locality_cache: 0,

            times_more_than_one_packet: 0,
            evicted_packets: 0,
            total_node_evictions: 0,
            total_node_traversal_visits: 0,
            requested_oram_leaves: 0,

            number_packets_requested_from_oram: 0,
            number_packets_found_in_stash: 0,
            number_nodes_found_in_node_cache: 0,
            number_slots_found_in_slot_cache: 0,

            insert_packet_to_stash_time: 0,
            insert_packet_of_bucket_to_stash_time: 0,
            iter_buckets_from_oram_time: 0,
            time_clear_index_locality_cache_to_packet_stash: 0,
            time_flush_packets_of_query_id_to_stash: 0,
            time_iterate_buckets_for_locality_cache: 0,

            time_transform_fragments_to_obt_node: 0,
            time_transform_fragments_to_obt_slot: 0,

            time_serialize_obtree_node: 0,
            time_decompress_sql_data_type: 0,
            time_transform_bytes_to_oram_packets: 0,
            time_transform_buckets_to_bucket_contents: 0,
            time_transform_bucket_contents_to_buckets: 0,
            time_byte_range_to_sql_data_types: 0,

            generated_data_byte_size: 0,
        }
    }
    pub fn inc_oram_reads(&mut self) {
        self.oram_reads += 1;
    }
    pub fn inc_oram_read_time(&mut self, time: u128) {
        self.oram_read_time += time;
    }
    pub fn oram_write_time(&self) -> f64 {
        (self.oram_write_time as f64) / 1000000.0
    }
    pub fn inc_oram_write_time(&mut self, time: u128) {
        self.oram_write_time += time;
    }
    pub fn reset(&mut self, index_locality_cache: bool, obt_fill_grade: u32) {
        self.experiment_id = 0;

        self.index_locality_cache = index_locality_cache;
        self.obt_fill_grade = obt_fill_grade;

        self.oram_reads = 0;
        self.oram_read_time = 0;
        self.oram_writes = 0;
        self.oram_write_time = 0;
        self.time_evict_into_oram_batch_from_packet_stash = 0;

        self.workload_time = 0;

        self.time_evict_bottom_up = 0;
        self.time_split_node = 0;
        self.time_cast_split_to_parent = 0;

        self.times_node_found_in_locality_cache = 0;
        self.times_slot_found_in_locality_cache = 0;
        self.times_node_originally_from_locality_cache = 0;
        self.times_slot_originally_from_locality_cache = 0;

        self.times_more_than_one_packet = 0;
        self.evicted_packets = 0;
        self.total_node_evictions = 0;
        self.total_node_traversal_visits = 0;
        self.requested_oram_leaves = 0;

        self.number_packets_requested_from_oram = 0;
        self.number_packets_found_in_stash = 0;
        self.number_nodes_found_in_node_cache = 0;
        self.number_slots_found_in_slot_cache = 0;

        self.insert_packet_to_stash_time = 0;
        self.insert_packet_of_bucket_to_stash_time = 0;
        self.iter_buckets_from_oram_time = 0;
        self.time_clear_index_locality_cache_to_packet_stash = 0;
        self.time_flush_packets_of_query_id_to_stash = 0;
        self.time_iterate_buckets_for_locality_cache = 0;

        self.time_transform_fragments_to_obt_node = 0;
        self.time_transform_fragments_to_obt_slot = 0;

        self.time_serialize_obtree_node = 0;
        self.time_decompress_sql_data_type = 0;
        self.time_transform_bytes_to_oram_packets = 0;
        self.time_transform_buckets_to_bucket_contents = 0;
        self.time_transform_bucket_contents_to_buckets = 0;
        self.time_byte_range_to_sql_data_types = 0;

        self.generated_data_byte_size = 0;
    }
    pub fn inc_iter_buckets_from_oram_time(&mut self, time: u128) {
        self.iter_buckets_from_oram_time += time;
    }
    pub fn to_json(&self) -> String {
        match serde_json::to_string(self) {
            Ok(json) => json,
            Err(err) => {
                panic!("Error happened: {}", err.to_string());
            }
        }
    }
    pub fn inc_workload_time(&mut self, time: u128) {
        self.workload_time += time;
    }
    pub fn inc_oram_writes(&mut self) {
        self.oram_writes += 1;
    }
    pub fn inc_times_node_found_in_locality_cache(&mut self) {
        self.times_node_found_in_locality_cache += 1;
    }
    pub fn inc_times_slot_found_in_locality_cache(&mut self) {
        self.times_slot_found_in_locality_cache += 1;
    }
    pub fn inc_times_node_originally_from_locality_cache(&mut self) {
        self.times_node_originally_from_locality_cache += 1;
    }
    pub fn inc_times_slot_originally_from_locality_cache(&mut self) {
        self.times_slot_originally_from_locality_cache += 1;
    }
    pub fn inc_time_evict_bottom_up(&mut self, time: u128) {
        self.time_evict_bottom_up += time;
    }
    pub fn inc_time_transform_bytes_to_oram_packets(&mut self, time: u128) {
        self.time_transform_bytes_to_oram_packets += time;
    }
    pub fn inc_times_more_than_one_packet(&mut self) {
        self.times_more_than_one_packet += 1;
    }
    pub fn inc_time_serialize_obtree_node(&mut self, time: u128) {
        self.time_serialize_obtree_node += time;
    }
    pub fn inc_time_transform_fragments_to_obt_node(&mut self, time: u128) {
        self.time_transform_fragments_to_obt_node += time;
    }
    pub fn inc_time_transform_fragments_to_obt_slot(&mut self, time: u128) {
        self.time_transform_fragments_to_obt_slot += time;
    }
    pub fn inc_insert_packet_to_stash_time(&mut self, time: u128) {
        self.insert_packet_to_stash_time += time;
    }
    pub fn inc_insert_packet_of_bucket_to_stash_time(&mut self, time: u128) {
        self.insert_packet_of_bucket_to_stash_time += time;
    }
    pub fn inc_time_decompress_sql_data_type(&mut self, time: u128) {
        self.time_decompress_sql_data_type += time;
    }
    pub fn inc_time_clear_index_locality_cache_to_packet_stash(&mut self, time: u128) {
        self.time_clear_index_locality_cache_to_packet_stash += time;
    }
    pub fn inc_time_flush_packets_of_query_id_to_stash(&mut self, time: u128) {
        self.time_flush_packets_of_query_id_to_stash += time;
    }
    pub fn inc_time_iterate_buckets_for_locality_cache(&mut self, time: u128) {
        self.time_iterate_buckets_for_locality_cache += time;
    }
    pub fn inc_time_transform_buckets_to_bucket_contents(&mut self, time: u128) {
        self.time_transform_buckets_to_bucket_contents += time;
    }
    pub fn inc_time_transform_bucket_contents_to_buckets(&mut self, time: u128) {
        self.time_transform_bucket_contents_to_buckets += time;
    }
    pub fn inc_evicted_packets(&mut self, evicted_packets: usize) {
        self.evicted_packets += evicted_packets;
    }
    pub fn inc_total_node_evictions(&mut self) {
        self.total_node_evictions += 1;
    }
    pub fn inc_total_node_traversal_visits(&mut self, total_node_traversal_visits: u64) {
        self.total_node_traversal_visits += total_node_traversal_visits;
    }
    pub fn clone_me(&self) -> EnclaveStatistics {
        self.clone()
    }
    pub fn set_experiment_id(&mut self, experiment_id: u64) {
        self.experiment_id = experiment_id;
    }
    pub fn inc_time_split_node(&mut self, time_split_node: u128) {
        self.time_split_node += time_split_node;
    }
    pub fn inc_time_cast_split_to_parent(&mut self, time_cast_split_to_parent: u128) {
        self.time_cast_split_to_parent += time_cast_split_to_parent;
    }
    pub fn inc_time_evict_into_oram_batch_from_packet_stash(&mut self, time: u128) {
        self.time_evict_into_oram_batch_from_packet_stash += time;
    }
    pub fn inc_number_packets_requested_from_oram(&mut self, number: u64) {
        self.number_packets_requested_from_oram += number;
    }
    pub fn inc_number_packets_found_in_stash(&mut self, number: u64) {
        self.number_packets_found_in_stash += number;
    }
    pub fn inc_number_nodes_found_in_node_cache(&mut self) {
        self.number_nodes_found_in_node_cache += 1;
    }
    pub fn inc_number_slots_found_in_slot_cache(&mut self) {
        self.number_slots_found_in_slot_cache += 1;
    }
    pub fn inc_requested_oram_leaves(&mut self, number: u64) {
        self.requested_oram_leaves += number;
    }
    pub fn inc_generated_data_byte_size(&mut self, generated_data_byte_size: usize) {
        self.generated_data_byte_size += generated_data_byte_size;
    }
    pub fn inc_time_byte_range_to_sql_data_types(&mut self, time: u128) {
        self.time_byte_range_to_sql_data_types += time;
    }
}
