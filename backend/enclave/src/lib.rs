// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "sample"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tcrypto;

extern crate bincode;
extern crate chrono;
extern crate rand;
extern crate serde;
extern crate serde_bytes;
#[macro_use]
extern crate lazy_static;
extern crate alloc;
extern crate crc32fast;
extern crate ring;
extern crate sha2;

mod config;
mod crypto;
mod data_management;
mod enclave_caches;
mod enclave_state;
mod helpers;
mod index_locality_cache;
mod logger;
mod micro_benchmark;
mod oblivious_data_structures;
mod oblivious_ram;
mod obt_stash;
mod oram_interface;
mod packet_stash;
mod preparation;
mod query_response_cache;
mod query_state;
mod query_state_cache;
mod slot_cache;
mod sql_engine;
mod test_enclave;
mod test_oram;
mod utils;
mod workloads;

// SGX SDK Imports
use config::OramConfig;
use sgx_types::*;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::slice;
use std::string::String;
use std::sync::{Arc, SgxMutex, SgxMutexGuard};
use std::vec::Vec;

// Custom Imports
use enclave_state::{EnclaveState, EnclaveStateCache, EnclaveStateToSend};
use index_locality_cache::{clear_index_locality_cache_to_packet_stash, IndexLocalityCache};
use logger::log_runtime;
use micro_benchmark::oram_access_benchmark;
use oblivious_ram::api;
use oblivious_ram::api::reset_server_statistics;
use oblivious_ram::components::BucketContent;
use oblivious_ram::functions::transform_buckets_to_bucket_contents;
use oram_interface::{
    ByteObject, ExperimentWorkloadRequest, GenericRequestToEnclave, GenericRequestToServer,
};
use packet_stash::clear_to_oram;
use preparation::check_environment;
use sql_engine::sql_database::components::SqlDmlQuery;
use workloads::*;

const MAX_PACKET_SIZE: usize = 7566;
// in bytes for content of packet (without meta, -168)

const NONCE_SIZE: usize = 12;
const AES_TAG_LEN: usize = 16;

const EMPTY_NONCE: [u8; 12] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
// in bytes for content of block (without meta)

const NUMBER_OF_THREADS: usize = 8;
const SERVER_IP: &str = "http://127.0.0.1:5000";

const BLOCK_ID_BYTE_LEN: usize = 16;

const RIDS_PER_SLOT: usize = 50;

//const ENCRYPTION_CIPHER: u8 = 0u8; // 0: AES, 1: ChaCha
const SHARED_KEY_LEN: usize = 16;

const DUMMY_SEQUENCE: &str = "AAAABBBBCCCCDDDD";

const DEBUG_RUNTIME_CHECKS: bool = false;
const DEBUG_PRINTS: bool = false;
const PRINT_PACKET_EVICTIONS: bool = false;

extern "C" {
    pub fn ocall_get_oram_batch(
        ret_val: *mut sgx_status_t,
        instance: u32,
        leaves: *const u8,
        leaves_len: u32,
    ) -> sgx_status_t;
    pub fn ocall_write_oram_batch(
        ret_val: *mut sgx_status_t,
        instance: u32,
        leaves: *const u8,
        leaves_len: u32,
        buckets: *const u8,
        buckets_len: u32,
    ) -> sgx_status_t;
    pub fn ocall_generic_request(
        ret_val: *mut sgx_status_t,
        request: *const u8,
        request_len: u32,
    ) -> sgx_status_t;
    pub fn ocall_setup_oram(
        ret_val: *mut sgx_status_t,
        instance: u32,
        offset: u32,
        buckets: *const u8,
        buckets_len: u32,
    ) -> sgx_status_t;
}

pub struct PathCache {
    queue: Vec<Vec<Vec<u8>>>,
}

impl PathCache {
    pub fn pop(&mut self) -> Option<Vec<Vec<u8>>> {
        self.queue.pop()
    }
    pub fn new_empty() -> Self {
        PathCache { queue: Vec::new() }
    }
    pub fn push(&mut self, batch: Vec<Vec<u8>>) {
        self.queue.push(batch);
    }
}

lazy_static! {
    static ref enclave_state_cache: SgxMutex<EnclaveStateCache> =
        SgxMutex::new(EnclaveStateCache::new(None));
    static ref buckets_from_server_cache: SgxMutex<PathCache> =
        SgxMutex::new(PathCache::new_empty());
}

#[no_mangle]
pub extern "C" fn ecall_generic_request(request: *const u8, request_len: u32) -> sgx_status_t {
    let request_len = request_len as usize;
    let request_slice = unsafe { slice::from_raw_parts(request, request_len) };
    let request: GenericRequestToEnclave = bincode::deserialize(request_slice).unwrap();

    match request {
        GenericRequestToEnclave::ExperimentWorkloadRequest(exp_request) => {
            let enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
            let enclave_state = enclave_state_cache_locked.enclave_state_ref().unwrap();
            process_experiment_workload_request(enclave_state, exp_request);
        }
        GenericRequestToEnclave::ClearIndexLocalityCache => {
            let enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
            let enclave_state = enclave_state_cache_locked.enclave_state_ref().unwrap();
            if enclave_state.lock_dynamic_config().index_locality_cache() {
                clear_index_locality_cache_to_packet_stash(enclave_state);
            }
        }
        GenericRequestToEnclave::ClearPacketStash => {
            let enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
            let enclave_state = enclave_state_cache_locked.enclave_state_ref().unwrap();
            clear_to_oram(&enclave_state);
        }
        GenericRequestToEnclave::InitEnclave(init_enclave_conf) => {
            let oram_config = OramConfig::new(
                init_enclave_conf.number_of_oram(),
                init_enclave_conf.tree_height(),
                init_enclave_conf.oram_degree(),
                init_enclave_conf.bucket_size(),
            );

            let index_locality_cache = init_enclave_conf.index_locality_cache() != 0u8;
            let enclave_state = preparation::prepare_ycsb_obt(
                init_enclave_conf.fill_grade() as usize,
                index_locality_cache,
                oram_config,
            );

            {
                let oram_config = enclave_state.lock_oram_config();
                check_environment(&oram_config);
            }
            preparation::setup_oram(&enclave_state);

            enclave_state
                .lock_statistics()
                .reset(index_locality_cache, init_enclave_conf.fill_grade());

            let mut enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
            enclave_state_cache_locked.set_enclave_state(Some(enclave_state));
            drop(enclave_state_cache_locked);

            reset_server_statistics();
        }
        GenericRequestToEnclave::EnclaveStateBackupRequest(file_name) => {
            let enclave_state_to_send = {
                let mut enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
                let enclave_state_to_send = {
                    let enclave_state = enclave_state_cache_locked.enclave_state_ref().unwrap();
                    enclave_state.lock_obt_node_cache().shrink_to_fit();
                    enclave_state.lock_query_response_cache().flush();
                    //oblivious_data_structures::ob_tree::backup_api::evict_all_roots(enclave_state);
                    if enclave_state.lock_dynamic_config().index_locality_cache() {
                        clear_index_locality_cache_to_packet_stash(enclave_state);
                    }
                    clear_to_oram(enclave_state);
                    println!("enclave_state to send will be generated...");
                    enclave_state.to_send().serialize()
                };
                enclave_state_cache_locked.set_enclave_state(None);
                enclave_state_to_send
            };

            println!(
                "GenericRequestToServer::EnclaveStateBackup starts! Length: {}",
                enclave_state_to_send.len()
            );
            if enclave_state_to_send.len() > 50000 {
                let mut start: usize = 0;
                let chunks_len = enclave_state_to_send.chunks(50000).len();
                for chunk in enclave_state_to_send.chunks(50000).into_iter() {
                    let complete = if start == (chunks_len - 1) {
                        true
                    } else {
                        false
                    };
                    api::send_generic_request(GenericRequestToServer::EnclaveStateBackup(
                        ByteObject::new(file_name.clone(), chunk.to_vec(), complete),
                    ));
                    start += 1;
                }
                assert_eq!(start, chunks_len);
            } else {
                api::send_generic_request(GenericRequestToServer::EnclaveStateBackup(
                    ByteObject::new(file_name, enclave_state_to_send, true),
                ));
            }
        }
        GenericRequestToEnclave::EnclaveStateRestoreBackupRequest(byte_obj) => {
            let mut enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
            let enclave_state_backup: EnclaveStateToSend =
                bincode::deserialize(byte_obj.data()).unwrap();
            let enclave_state_backup = EnclaveState::from_backup(enclave_state_backup);
            enclave_state_cache_locked.set_enclave_state(Some(enclave_state_backup));
            drop(enclave_state_cache_locked);
        }
        GenericRequestToEnclave::ORAMBenchmark => {
            let enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
            let enclave_state = enclave_state_cache_locked.enclave_state_ref().unwrap();
            oram_access_benchmark(enclave_state);
        }
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_run_tests() -> sgx_status_t {
    let enclave_state_cache_locked = enclave_state_cache.lock().unwrap();
    let enclave_state = enclave_state_cache_locked.enclave_state_ref().unwrap();

    //test_oram::test_read_write_oram(enclave_state);
    test_enclave::test_ob_tree_query_value();

    println!("Tests were successfull");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_return_oram_path(
    buckets: *const u8,
    buckets_len: u32,
    single_bucket_len: u64,
) -> sgx_status_t {
    let mut cache = buckets_from_server_cache.lock().unwrap();
    let buckets_len = buckets_len as usize;
    let buckets_slice = unsafe { slice::from_raw_parts(buckets, buckets_len) };

    let batch: Vec<Vec<u8>> = buckets_slice
        .chunks_exact(single_bucket_len as usize)
        .map(|bucket| bucket.to_vec())
        .collect();

    cache.push(batch);
    drop(cache);
    sgx_status_t::SGX_SUCCESS
}
