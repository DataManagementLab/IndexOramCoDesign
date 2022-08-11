use serde::{Deserialize, Serialize};

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
    pub fn header(&self) -> &str {
        &self.header
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
    pub fn destroy(self) -> (String, Vec<u8>, bool) {
        (self.header, self.data, self.complete)
    }
    pub fn new(header: String, data: Vec<u8>, complete: bool) -> Self {
        ByteObject {
            header,
            data,
            complete,
        }
    }
    pub fn complete(&self) -> bool {
        self.complete
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
    pub fn new(
        number_of_oram: usize,
        tree_height: usize,
        oram_degree: usize,
        bucket_size: usize,
        index_locality_cache: u8,
        fill_grade: u32,
    ) -> Self {
        InitEnclaveConfig {
            number_of_oram,
            tree_height,
            oram_degree,
            bucket_size,
            index_locality_cache,
            fill_grade,
        }
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
    pub fn node_cache_amount(&self) -> u64 {
        self.node_cache_amount
    }
    pub fn node_cache_byte_size(&self) -> u64 {
        self.node_cache_byte_size
    }
    pub fn slot_cache_amount(&self) -> u64 {
        self.slot_cache_amount
    }
    pub fn slot_cache_byte_size(&self) -> u64 {
        self.slot_cache_byte_size
    }
    pub fn locality_cache_amount(&self) -> u64 {
        self.locality_cache_amount
    }
    pub fn locality_cache_byte_size(&self) -> u64 {
        self.locality_cache_byte_size
    }
    pub fn free_oram_space_after(&self) -> f64 {
        self.free_oram_space_after
    }
    pub fn evicted_packets_in_batch(&self) -> u64 {
        self.evicted_packets_in_batch
    }
    pub fn stash_number_of_packets(&self) -> u64 {
        self.stash_number_of_packets
    }
    pub fn stash_total_byte_size(&self) -> u64 {
        self.stash_total_byte_size
    }
    pub fn stash_max_byte_size(&self) -> u64 {
        self.stash_max_byte_size
    }
    pub fn stash_average_byte_size(&self) -> f64 {
        self.stash_average_byte_size
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

#[derive(Serialize, Deserialize, Clone)]
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
    pub fn set_experiment_id(&mut self, experiment_id: u64) {
        self.experiment_id = experiment_id;
    }
    pub fn experiment_id(&self) -> u64 {
        self.experiment_id
    }
}

#[derive(Serialize, Deserialize)]
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
    pub fn experiment_id(&self) -> u64 {
        self.experiment_id
    }
}
