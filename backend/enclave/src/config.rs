use serde::{Deserialize, Serialize};
use AES_TAG_LEN;
use {log_runtime, NONCE_SIZE};
//use serde::{Deserialize, Serialize};

/*
#[derive(Serialize, Deserialize, Clone)]
pub struct ExperimentConfig {
    rids_per_slot: usize,
    index_locality_cache: bool,
    aggressive_caching: bool,
    packet_size: usize,
    oram_access_batches_size: usize,
    min_matching_prefix_level: u32,
}

impl ExperimentConfig {
    pub fn new(
        rids_per_slot: usize,
        index_locality_cache: bool,
        aggressive_caching: bool,
        packet_size: usize,
        oram_access_batches_size: usize,
        min_matching_prefix_level: u32,
    ) -> Self {
        if aggressive_caching {
            assert!(index_locality_cache);
        }
        ExperimentConfig {
            rids_per_slot,
            index_locality_cache,
            aggressive_caching,
            packet_size,
            oram_access_batches_size,
            min_matching_prefix_level,
        }
    }
    pub fn rids_per_slot(&self) -> usize {
        self.rids_per_slot
    }
    pub fn index_locality_cache(&self) -> bool {
        self.index_locality_cache
    }
    pub fn aggressive_caching(&self) -> bool {
        self.aggressive_caching
    }
    pub fn packet_size(&self) -> usize {
        self.packet_size
    }
    pub fn oram_access_batches_size(&self) -> usize {
        self.oram_access_batches_size
    }
    pub fn min_matching_prefix_level(&self) -> u32 {
        self.min_matching_prefix_level
    }
}
*/

#[derive(Serialize, Deserialize, Clone)]
pub struct OramConfig {
    number_of_oram: usize,
    tree_height: usize,
    oram_degree: usize,
    bucket_size: usize,
}

impl OramConfig {
    pub fn new(
        number_of_oram: usize,
        tree_height: usize,
        oram_degree: usize,
        bucket_size: usize,
    ) -> Self {
        OramConfig {
            number_of_oram,
            tree_height,
            oram_degree,
            bucket_size,
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
    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }
    pub fn bucket_serialized_size(&self) -> usize {
        self.bucket_size + 24
    }
    pub fn bucket_ciphertext_len(&self) -> usize {
        self.bucket_serialized_size() + AES_TAG_LEN + NONCE_SIZE
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DynamicConfig {
    save_model: bool,
    log_block_accesses: bool,
    initial: bool,
    shared_enclave_key: [u8; crate::SHARED_KEY_LEN],
    use_encryption: bool,
    index_locality_cache: bool,
    aggressive_locality_caching: bool,
    direct_eviction: bool,
    locality_cache_direct_flush: bool,
    min_matching_prefix_level: u32,
    bounded_locality_cache: usize,
    dummy_fill_oram_access_batch: bool,
    oram_access_batches_size: usize,
    oram_random_batch_size: bool,
    keep_not_requested_in_buckets: f64,
}

impl DynamicConfig {
    pub fn save_model(&self) -> bool {
        self.save_model
    }
    pub fn new(save_model: bool, log_block_accesses: bool, min_matching_prefix_level: u32) -> Self {
        DynamicConfig {
            save_model,
            log_block_accesses,
            initial: false,
            shared_enclave_key: [0u8; crate::SHARED_KEY_LEN],
            use_encryption: false,
            index_locality_cache: false,
            aggressive_locality_caching: false,
            direct_eviction: false,
            locality_cache_direct_flush: false,
            min_matching_prefix_level,
            bounded_locality_cache: 0,
            dummy_fill_oram_access_batch: false,
            oram_access_batches_size: 1,
            oram_random_batch_size: false,
            keep_not_requested_in_buckets: 0.0,
        }
    }
    pub fn log_block_accesses(&self) -> bool {
        self.log_block_accesses
    }
    pub fn initial(&self) -> bool {
        self.initial
    }
    pub fn set_initial(&mut self, initial: bool) {
        log_runtime(&format!("DynamicConfig - set_inital: {}", initial), true);
        self.initial = initial;
    }
    pub fn shared_enclave_key(&self) -> &[u8; crate::SHARED_KEY_LEN] {
        &self.shared_enclave_key
    }
    pub fn set_shared_enclave_key(&mut self, shared_enclave_key: [u8; crate::SHARED_KEY_LEN]) {
        self.shared_enclave_key = shared_enclave_key;
        self.activate_encryption();
    }
    pub fn activate_encryption(&mut self) {
        log_runtime("Encryption is activated!", true);
        self.use_encryption = true;
    }
    pub fn deactivate_encryption(&mut self) {
        log_runtime("Encryption is deactivated!", true);
        self.use_encryption = false;
    }
    pub fn use_encryption(&self) -> bool {
        self.use_encryption
    }
    pub fn index_locality_cache(&self) -> bool {
        self.index_locality_cache
    }
    pub fn set_index_locality_cache(&mut self, index_locality_cache: bool) {
        self.index_locality_cache = index_locality_cache;
    }
    pub fn aggressive_locality_caching(&self) -> bool {
        self.aggressive_locality_caching
    }
    pub fn set_aggressive_locality_caching(&mut self, aggressive_locality_caching: bool) {
        self.aggressive_locality_caching = aggressive_locality_caching;
    }
    pub fn direct_eviction(&self) -> bool {
        self.direct_eviction
    }
    pub fn set_direct_eviction(&mut self, direct_eviction: bool) {
        self.direct_eviction = direct_eviction;
    }
    pub fn locality_cache_direct_flush(&self) -> bool {
        self.locality_cache_direct_flush
    }
    pub fn set_locality_cache_direct_flush(&mut self, locality_cache_direct_flush: bool) {
        self.locality_cache_direct_flush = locality_cache_direct_flush;
    }
    pub fn min_matching_prefix_level(&self) -> u32 {
        self.min_matching_prefix_level
    }
    pub fn set_min_matching_prefix_level(&mut self, min_matching_prefix_level: u32) {
        self.min_matching_prefix_level = min_matching_prefix_level;
    }
    pub fn bounded_locality_cache(&self) -> usize {
        self.bounded_locality_cache
    }
    pub fn set_bounded_locality_cache(&mut self, bounded_locality_cache: usize) {
        self.bounded_locality_cache = bounded_locality_cache;
    }
    pub fn set_dummy_fill_oram_access_batch(&mut self, dummy_fill_oram_access_batch: bool) {
        self.dummy_fill_oram_access_batch = dummy_fill_oram_access_batch;
    }
    pub fn dummy_fill_oram_access_batch(&self) -> bool {
        self.dummy_fill_oram_access_batch
    }
    pub fn oram_access_batches_size(&self) -> usize {
        self.oram_access_batches_size
    }
    pub fn oram_random_batch_size(&self) -> bool {
        self.oram_random_batch_size
    }
    pub fn set_oram_access_batches_size(&mut self, oram_access_batches_size: usize) {
        self.oram_access_batches_size = oram_access_batches_size;
    }
    pub fn set_oram_random_batch_size(&mut self, oram_random_batch_size: bool) {
        self.oram_random_batch_size = oram_random_batch_size;
    }
    pub fn keep_not_requested_in_buckets(&self) -> f64 {
        self.keep_not_requested_in_buckets
    }
    pub fn set_keep_not_requested_in_buckets(&mut self, keep_not_requested_in_buckets: f64) {
        self.keep_not_requested_in_buckets = keep_not_requested_in_buckets;
    }
}
