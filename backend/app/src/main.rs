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

use std::collections::HashMap;
use std::fmt::Error;
use std::io::{Read, Write};
use std::ops::{DerefMut, Div};
use std::path::PathBuf;
use std::ptr::copy_nonoverlapping;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use std::{fs, slice, thread};

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sgx_types::{
    sgx_attributes_t, sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t, sgx_status_t,
    SgxResult,
};
use sgx_urts::SgxEnclave;

use crate::app_state::{AppState, AppStateToBackup};
use crate::config::OramConfig;
use crate::file_interface::write_bytes;
use crate::helpers::general::get_unix_timestamp;
use actix_files::NamedFile;
use actix_web::error::{ErrorBadGateway, ErrorNotFound};
use actix_web::web::Json;
use actix_web::{get, post, web, HttpRequest, HttpResponse};

use crate::helpers::oram_helper::{get_number_of_leaves, get_number_of_tree_nodes};
use crate::json_interface::{add_to_json_array, get_json_array, setup_jsons, JsonError};
use crate::logger::{
    log_runtime, EnclaveAdditionalStatistics, EnclaveAdditionalStatisticsVecs,
    OramConfigOfExperiment, Statistics,
};
use crate::oblivious_ram::components::{Path, PathORAM};
use crate::oram_interface::{
    ByteObject, EnclaveStatistics, ExperimentWorkloadRequest, GenericRequestToEnclave,
    GenericRequestToServer, InitEnclaveConfig,
};
use crate::plotter::PlotColor;

mod app_state;
mod config;
mod crypto;
mod enclave_helper;
mod file_interface;
mod helpers;
mod json_interface;
mod logger;
mod oblivious_ram;
mod oram_interface;
mod plotter;
mod preparation;

const NONCE_SIZE: usize = 12;
const AES_TAG_LEN: usize = 16;

const NUMBER_OF_THREADS: usize = 8;
const DELETE_LOGS_AT_START: bool = false;
const LOG_BLOCK_ACCESSES: bool = true;
const DETAIL_LOG_BLOCK_ACCESSES: bool = false;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

const BINARY_DIR: &str = "../bin/";
const ENCLAVE_STATS_JSON: &str = "json/enclave_stats.json";
const SERVER_STATS_JSON: &str = "json/server_stats.json";
const ENCLAVE_ADDITIONAL_STATS_JSON: &str = "json/enclave_additional_stats.json";
const ENCLAVE_ADDITIONAL_STATS_VECS_JSON: &str = "json/enclave_additional_stats_vecs.json";
const ORAM_CONFIGS_JSON: &str = "json/oram_configs.json";
const EXP_REQUEST_JSON: &str = "json/experiment_request.json";
const PLOT_DIR: &str = "plots/";
const ORAM_PREFIX: &str = "orams/";
const BACKUP_PREFIX: &str = "backup/";

extern "C" {
    fn ecall_generic_request(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        request: *const u8,
        request_len: u32,
    ) -> sgx_status_t;
    fn ecall_run_tests(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    fn ecall_return_oram_path(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        buckets: *const u8,
        buckets_len: u32,
        single_bucket_len: u64,
    ) -> sgx_status_t;
}

lazy_static::lazy_static! {
    static ref APP_STATE: Arc<Mutex<AppState>> = Arc::new(Mutex::new(AppState::new_default()));

    static ref ACCESSED_POSITIONS: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref BATCH_SIZE_CHRONO: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_STASH_PACKET_AMOUNT: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_STASH_BYTE_SIZE: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_STASH_AVERAGE_BYTE_SIZE: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_STASH_MAX_BYTE_SIZE: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_NODE_CACHE_AMOUNT: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_NODE_CACHE_BYTE_SIZE: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_SLOT_CACHE_AMOUNT: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_SLOT_CACHE_BYTE_SIZE: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_LOCALITY_CACHE_AMOUNT: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_LOCALITY_CACHE_BYTE_SIZE: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_FREE_SPACE_IN_BATCH_OVER_TIME: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ENCLAVE_EVICTED_PACKETS_OVER_TIME: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));

    static ref ENCLAVE_STATE_BACKUP_BUFFER: Arc<Mutex<HashMap<String,Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    // with encryption:   275528, without: 275276
}

pub struct EnclaveIdHolder {
    enclave_id: Option<sgx_enclave_id_t>,
}

impl EnclaveIdHolder {
    pub fn enclave_id(&self) -> Option<sgx_enclave_id_t> {
        self.enclave_id
    }
    pub fn new(enclave_id: Option<sgx_enclave_id_t>) -> Self {
        EnclaveIdHolder { enclave_id }
    }
    pub fn set_enclave_id(&mut self, enclave_id: Option<sgx_enclave_id_t>) {
        self.enclave_id = enclave_id;
    }
}

pub struct EnclaveLock {
    locked: bool,
}

impl EnclaveLock {
    pub fn new() -> Self {
        EnclaveLock { locked: false }
    }
    pub fn lock(&mut self) {
        self.locked = true;
    }
    pub fn unlock(&mut self) {
        self.locked = false;
    }
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    {
        let app_state = APP_STATE.lock().unwrap();
    }

    crate::logger::initialize_loggers(crate::crypto::generate_random_key(8).as_str());
    display_const_config();
    initial_checks();
    setup_jsons();

    let enclave = match crate::enclave_helper::init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            panic!("Enclave cannot be initialized.");
        }
    };
    let enclave_id = enclave.geteid();
    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_id_holder = app_state.enclave_id();
        enclave_id_holder.set_enclave_id(Some(enclave_id));
    }

    {
        let init_enclave_config = {
            let app_state = APP_STATE.lock().unwrap();
            let oram_config = app_state.oblivious_ram_config();
            GenericRequestToEnclave::InitEnclave(InitEnclaveConfig::new(
                oram_config.number_of_oram(),
                oram_config.tree_height(),
                oram_config.oram_degree(),
                oram_config.bucket_size(),
                0u8,
                16,
            ))
        };
        let init_enclave_config = init_enclave_config.serialize();
        let init_enclave_config_len = init_enclave_config.len() as u32;

        /// Start enclave for upcoming experiments
        let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let result = unsafe {
            ecall_generic_request(
                enclave_id,
                &mut retval,
                init_enclave_config.as_ptr(),
                init_enclave_config_len,
            )
        };
        match result {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                panic!("[-] ECALL Enclave Failed {}!", result.as_str());
            }
        }
    }

    println!("Server starts now...");
    println!(" ");

    actix_web::HttpServer::new(|| {
        actix_web::App::new()
            .wrap(actix_cors::Cors::permissive())
            .service(test_route)
            .service(experiment_runner)
            .service(reset_request)
            .service(run_tests)
            .service(json_file_request)
            .service(json_file_filter_request)
            .service(plot_file_filter_request)
            .service(backup_request)
            .service(restore_backup_request)
            .service(clear_request)
            .service(oram_benchmark)
    })
    .bind(("0.0.0.0", 5000))?
    .run()
    .await
}

/*
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(index);
    cfg.service(experiment_runner);
}
 */

#[get("/plots/{filename}/{experiment_id}")]
async fn plot_file_filter_request(path: web::Path<(String, u64)>) -> actix_web::Result<NamedFile> {
    let (filename, experiment_id) = path.into_inner();

    let mut plot_file = BINARY_DIR.to_string();
    match filename.as_str() {
        "accessed_positions" => plot_file.push_str(&format!(
            "{}accessed_positions_histogram_{}.png",
            PLOT_DIR, experiment_id
        )),
        "batch_size_chrono" => plot_file.push_str(&format!(
            "{}batch_size_chrono_{}.png",
            PLOT_DIR, experiment_id
        )),
        "stash_byte_size" => plot_file.push_str(&format!(
            "{}stash_byte_size_{}.png",
            PLOT_DIR, experiment_id
        )),
        "stash_packet_amount" => plot_file.push_str(&format!(
            "{}stash_packet_amount_{}.png",
            PLOT_DIR, experiment_id
        )),
        "stash_packet_max_size" => plot_file.push_str(&format!(
            "{}stash_packet_max_size_{}.png",
            PLOT_DIR, experiment_id
        )),
        "stash_packet_average_size" => plot_file.push_str(&format!(
            "{}stash_packet_average_size_{}.png",
            PLOT_DIR, experiment_id
        )),
        "node_cache_amount" => plot_file.push_str(&format!(
            "{}node_cache_amount_{}.png",
            PLOT_DIR, experiment_id
        )),
        "node_cache_byte_size" => plot_file.push_str(&format!(
            "{}node_cache_byte_size_{}.png",
            PLOT_DIR, experiment_id
        )),
        "slot_cache_amount" => plot_file.push_str(&format!(
            "{}slot_cache_amount_{}.png",
            PLOT_DIR, experiment_id
        )),
        "slot_cache_byte_size" => plot_file.push_str(&format!(
            "{}slot_cache_byte_size_{}.png",
            PLOT_DIR, experiment_id
        )),
        "locality_cache_amount" => plot_file.push_str(&format!(
            "{}locality_cache_amount_{}.png",
            PLOT_DIR, experiment_id
        )),
        "locality_cache_byte_size" => plot_file.push_str(&format!(
            "{}locality_cache_byte_size_{}.png",
            PLOT_DIR, experiment_id
        )),
        "free_oram_space_in_batch_over_time" => plot_file.push_str(&format!(
            "{}free_oram_space_in_batch_over_time_{}.png",
            PLOT_DIR, experiment_id
        )),
        "evicted_packets_over_time" => plot_file.push_str(&format!(
            "{}evicted_packets_over_time_{}.png",
            PLOT_DIR, experiment_id
        )),
        &_ => return Err(ErrorNotFound("Resource was not found.")),
    }

    let plot_file: PathBuf = PathBuf::from(plot_file);
    Ok(NamedFile::open(plot_file)?)
}

#[get("/json/{filename}")]
async fn json_file_request(path: web::Path<(String)>) -> actix_web::Result<NamedFile> {
    let mut json_file = BINARY_DIR.to_string();

    let path = path.into_inner();
    match path.as_str() {
        "exp_request" => json_file.push_str(EXP_REQUEST_JSON),
        "enclave_stats" => json_file.push_str(ENCLAVE_STATS_JSON),
        "enclave_additional_stats" => json_file.push_str(ENCLAVE_ADDITIONAL_STATS_JSON),
        "server_stats" => json_file.push_str(SERVER_STATS_JSON),
        "oram_configs" => json_file.push_str(ORAM_CONFIGS_JSON),
        &_ => json_file.push_str(EXP_REQUEST_JSON),
    }

    let json_file: PathBuf = PathBuf::from(json_file);
    Ok(NamedFile::open(json_file)?)
}

#[get("/json/filter/{filename}/{id}")]
async fn json_file_filter_request(path: web::Path<(String, u64)>) -> impl actix_web::Responder {
    let mut json_file = BINARY_DIR.to_string();

    let (path, id) = path.into_inner();
    match path.as_str() {
        "exp_request" => {
            json_file.push_str(EXP_REQUEST_JSON);
            let data: Result<Vec<ExperimentWorkloadRequest>, JsonError> =
                get_json_array(&json_file);
            match data {
                Ok(mut some_data) => {
                    some_data.retain(|obj| obj.experiment_id() == id);
                    actix_web::HttpResponse::Ok().json(some_data)
                }
                Err(err) => {
                    eprintln!("Error: {}", err.to_string());
                    actix_web::HttpResponse::Ok().body("JSON file cannot be parsed!")
                }
            }
        }
        "enclave_stats" => {
            json_file.push_str(ENCLAVE_STATS_JSON);
            let data: Result<Vec<EnclaveStatistics>, JsonError> = get_json_array(&json_file);
            match data {
                Ok(mut some_data) => {
                    some_data.retain(|obj| obj.experiment_id() == id);
                    actix_web::HttpResponse::Ok().json(some_data)
                }
                Err(err) => {
                    eprintln!("Error: {}", err.to_string());
                    actix_web::HttpResponse::Ok().body("JSON file cannot be parsed!")
                }
            }
        }
        "enclave_additional_stats" => {
            json_file.push_str(ENCLAVE_ADDITIONAL_STATS_JSON);
            let data: Result<Vec<EnclaveAdditionalStatistics>, JsonError> =
                get_json_array(&json_file);
            match data {
                Ok(mut some_data) => {
                    some_data.retain(|obj| obj.experiment_id() == id);
                    actix_web::HttpResponse::Ok().json(some_data)
                }
                Err(err) => {
                    eprintln!("Error: {}", err.to_string());
                    actix_web::HttpResponse::Ok().body("JSON file cannot be parsed!")
                }
            }
        }
        "server_stats" => {
            json_file.push_str(SERVER_STATS_JSON);
            let data: Result<Vec<Statistics>, JsonError> = get_json_array(&json_file);
            match data {
                Ok(mut some_data) => {
                    some_data.retain(|obj| obj.experiment_id() == id);
                    actix_web::HttpResponse::Ok().json(some_data)
                }
                Err(err) => {
                    eprintln!("Error: {}", err.to_string());
                    actix_web::HttpResponse::Ok().body("JSON file cannot be parsed!")
                }
            }
        }
        "oram_configs" => {
            json_file.push_str(ORAM_CONFIGS_JSON);
            let data: Result<Vec<OramConfigOfExperiment>, JsonError> = get_json_array(&json_file);
            match data {
                Ok(mut some_data) => {
                    some_data.retain(|obj| obj.experiment_id() == id);
                    actix_web::HttpResponse::Ok().json(some_data)
                }
                Err(err) => {
                    eprintln!("Error: {}", err.to_string());
                    actix_web::HttpResponse::Ok().body("JSON file cannot be parsed!")
                }
            }
        }
        &_ => actix_web::HttpResponse::Ok().body("JSON file cannot be parsed!"),
    }
}

#[get("/restore_backup_request/{backup_name}/")]
async fn restore_backup_request(path: web::Path<(String)>) -> impl actix_web::Responder {
    let backup_name = path.into_inner();
    if backup_name.len() == 0 {
        return HttpResponse::BadRequest().body("The backup name was not specified.");
    }

    println!(" ");
    println!("Restore Backup Request: {}", &backup_name);

    let mut file_name = BACKUP_PREFIX.to_string();
    file_name.push_str(backup_name.as_str());
    file_name.push_str("/");

    let restored_app_state = {
        let mut app_state_file_name = file_name.clone();
        app_state_file_name.push_str("app_state");

        match file_interface::read_bytes(app_state_file_name) {
            None => false,
            Some(file) => {
                let restored_app_state: AppStateToBackup = bincode::deserialize(&file).unwrap();
                let new_path_oram = PathORAM::from_backup(
                    restored_app_state.oblivious_ram_config(),
                    ORAM_PREFIX.to_string(),
                    file_name.clone(),
                );

                let mut app_state = APP_STATE.lock().unwrap();
                app_state.restore_from_backup(restored_app_state, new_path_oram);
                true
            }
        }
    };

    display_const_config();

    if restored_app_state {
        let (enclave_id, enclave_request, enclave_request_len) = {
            let app_state = APP_STATE.lock().unwrap();
            {
                let mut enclave_lock = app_state.enclave_lock();
                if enclave_lock.is_locked() {
                    return actix_web::HttpResponse::Ok().body(
                        "The enclave is currently locked, this reset request was discarded.",
                    );
                } else {
                    enclave_lock.lock();
                }
            }

            let enclave_id = {
                let enclave_id_holder = app_state.enclave_id();
                enclave_id_holder.enclave_id().unwrap()
            };

            let mut enclave_state_file_name = file_name.clone();
            enclave_state_file_name.push_str("enclave_state");
            let enclave_request = match file_interface::read_bytes(enclave_state_file_name) {
                None => panic!("enclave_state could not be read!"),
                Some(file) => ByteObject::new(String::from(""), file, true),
            };

            let enclave_request =
                GenericRequestToEnclave::EnclaveStateRestoreBackupRequest(enclave_request);
            let enclave_request = enclave_request.serialize();
            let enclave_request_len = enclave_request.len() as u32;
            (enclave_id, enclave_request, enclave_request_len)
        };

        /// Reset enclave for upcoming experiments
        let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let result = unsafe {
            ecall_generic_request(
                enclave_id,
                &mut retval,
                enclave_request.as_ptr(),
                enclave_request_len,
            )
        };
        match result {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                panic!("[-] ECALL Enclave Failed {}!", result.as_str());
            }
        }

        {
            let app_state = APP_STATE.lock().unwrap();
            let mut enclave_lock = app_state.enclave_lock();
            enclave_lock.unlock();
        }

        println!("Backup >{}< was restored successfully!", backup_name);
        println!(" ");

        actix_web::HttpResponse::Ok().body("Backup restore was successfully!")
    } else {
        return HttpResponse::BadRequest()
            .body("The app state could not be restored from the backup.");
    }
}

#[get("/backup_request/{backup_name}/")]
async fn backup_request(path: web::Path<(String)>) -> impl actix_web::Responder {
    let backup_name = path.into_inner();
    if backup_name.len() == 0 {
        return HttpResponse::BadRequest().body("The backup name was not specified.");
    }
    let (enclave_id, enclave_request, enclave_request_len) = {
        let app_state = APP_STATE.lock().unwrap();
        {
            let mut enclave_lock = app_state.enclave_lock();
            if enclave_lock.is_locked() {
                return actix_web::HttpResponse::Ok()
                    .body("The enclave is currently locked, this reset request was discarded.");
            } else {
                enclave_lock.lock();
            }
        }

        let enclave_id = {
            let enclave_id_holder = app_state.enclave_id();
            enclave_id_holder.enclave_id().unwrap()
        };

        let enclave_request = GenericRequestToEnclave::EnclaveStateBackupRequest(backup_name);
        let enclave_request = enclave_request.serialize();
        let enclave_request_len = enclave_request.len() as u32;
        (enclave_id, enclave_request, enclave_request_len)
    };

    /// Reset enclave for upcoming experiments
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ecall_generic_request(
            enclave_id,
            &mut retval,
            enclave_request.as_ptr(),
            enclave_request_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ECALL Enclave Failed {}!", result.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_lock = app_state.enclave_lock();
        enclave_lock.unlock();
    }

    println!("Backup was successfully!");
    println!(" ");

    actix_web::HttpResponse::Ok().body("Backup was successfull!")
}

#[get("/test_route")]
async fn test_route() -> impl actix_web::Responder {
    println!("Test route");
    actix_web::HttpResponse::Ok().body("Hello world!")
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResetRequest {
    number_of_oram: usize,
    tree_height: usize,
    oram_degree: usize,
    bucket_size: usize,
    index_locality_cache: bool,
    fill_grade: u32,
}

impl ResetRequest {
    pub fn index_locality_cache(&self) -> bool {
        self.index_locality_cache
    }
    pub fn fill_grade(&self) -> u32 {
        self.fill_grade
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
}

#[post("/reset_request")]
async fn reset_request(info: actix_web::web::Json<ResetRequest>) -> impl actix_web::Responder {
    let (enclave_id, init_enclave_config, init_enclave_config_len) = {
        let app_state = APP_STATE.lock().unwrap();
        {
            let mut enclave_lock = app_state.enclave_lock();
            if enclave_lock.is_locked() {
                return actix_web::HttpResponse::Ok()
                    .body("The enclave is currently locked, this reset request was discarded.");
            } else {
                enclave_lock.lock();
            }
        }
        let reset_request = info.0;
        let index_locality_cache = if reset_request.index_locality_cache {
            1u8
        } else {
            0u8
        };

        let enclave_id = {
            let enclave_id_holder = app_state.enclave_id();
            enclave_id_holder.enclave_id().unwrap()
        };

        {
            let mut oram_config = app_state.oblivious_ram_config();
            oram_config.set_number_of_oram(reset_request.number_of_oram());
            oram_config.set_oram_degree(reset_request.oram_degree());
            oram_config.set_tree_height(reset_request.tree_height());
            oram_config.set_bucket_size(reset_request.bucket_size());
            let mut path_oram = app_state.oblivious_ram_directory();
            path_oram.reset(ORAM_PREFIX, &oram_config);
        }

        let init_enclave_config = GenericRequestToEnclave::InitEnclave(InitEnclaveConfig::new(
            reset_request.number_of_oram(),
            reset_request.tree_height(),
            reset_request.oram_degree(),
            reset_request.bucket_size(),
            index_locality_cache,
            reset_request.fill_grade(),
        ));
        let init_enclave_config = init_enclave_config.serialize();
        let init_enclave_config_len = init_enclave_config.len() as u32;
        (enclave_id, init_enclave_config, init_enclave_config_len)
    };

    display_const_config();

    /// Reset enclave for upcoming experiments
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ecall_generic_request(
            enclave_id,
            &mut retval,
            init_enclave_config.as_ptr(),
            init_enclave_config_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ECALL Enclave Failed {}!", result.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_lock = app_state.enclave_lock();
        enclave_lock.unlock();
    }
    actix_web::HttpResponse::Ok().body("Complete Reset was successfull!")
}

#[get("/clear_request/{component}/")]
async fn clear_request(path: web::Path<(String)>) -> impl actix_web::Responder {
    let component = path.into_inner();

    let clear_request_types = ["index_locality_cache", "packet_stash"];
    let clear_request_type_index: Option<usize> = clear_request_types
        .iter()
        .position(|component_type| component_type.eq(&component.as_str()));

    if component.len() == 0 || clear_request_type_index.is_none() {
        return HttpResponse::BadRequest().body("The backup name was not specified.");
    }
    let (enclave_id, enclave_request, enclave_request_len) = {
        let clear_request_type_index = clear_request_type_index.unwrap();

        let app_state = APP_STATE.lock().unwrap();
        {
            let mut enclave_lock = app_state.enclave_lock();
            if enclave_lock.is_locked() {
                return actix_web::HttpResponse::Ok()
                    .body("The enclave is currently locked, this reset request was discarded.");
            } else {
                enclave_lock.lock();
            }
        }

        let enclave_id = {
            let enclave_id_holder = app_state.enclave_id();
            enclave_id_holder.enclave_id().unwrap()
        };

        let enclave_request = match clear_request_type_index {
            0 => GenericRequestToEnclave::ClearIndexLocalityCache,
            1 => GenericRequestToEnclave::ClearPacketStash,
            _ => {
                panic!("");
            }
        };

        let enclave_request = enclave_request.serialize();
        let enclave_request_len = enclave_request.len() as u32;
        (enclave_id, enclave_request, enclave_request_len)
    };

    /// Reset enclave for upcoming experiments
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ecall_generic_request(
            enclave_id,
            &mut retval,
            enclave_request.as_ptr(),
            enclave_request_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ECALL Enclave Failed {}!", result.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_lock = app_state.enclave_lock();
        enclave_lock.unlock();
    }

    println!("Clear Request was successfully!");
    println!(" ");

    actix_web::HttpResponse::Ok().body("Clear Request was successfull!")
}

#[get("/run_tests")]
async fn run_tests() -> impl actix_web::Responder {
    let enclave_id = {
        let app_state = APP_STATE.lock().unwrap();
        {
            let mut enclave_lock = app_state.enclave_lock();
            if enclave_lock.is_locked() {
                return actix_web::HttpResponse::Ok()
                    .body("The enclave is currently locked, this testing request was discarded.");
            } else {
                enclave_lock.lock();
            }
        }
        let enclave_id_holder = app_state.enclave_id();
        enclave_id_holder.enclave_id().unwrap()
    };

    /// Reset enclave for upcoming experiments
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe { ecall_run_tests(enclave_id, &mut retval) };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ECALL Enclave Failed {}!", result.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_lock = app_state.enclave_lock();
        enclave_lock.unlock();
    }
    actix_web::HttpResponse::Ok().body("run_tests was successfully called!")
}

#[get("/oram_benchmark/")]
async fn oram_benchmark() -> impl actix_web::Responder {
    let (enclave_id, enclave_request, enclave_request_len) = {
        let app_state = APP_STATE.lock().unwrap();
        {
            let mut enclave_lock = app_state.enclave_lock();
            if enclave_lock.is_locked() {
                return actix_web::HttpResponse::Ok()
                    .body("The enclave is currently locked, this testing request was discarded.");
            } else {
                enclave_lock.lock();
            }
        }
        let enclave_id_holder = app_state.enclave_id();
        let enclave_id = enclave_id_holder.enclave_id().unwrap();

        let enclave_request = GenericRequestToEnclave::ORAMBenchmark;

        let enclave_request = enclave_request.serialize();
        let enclave_request_len = enclave_request.len() as u32;
        (enclave_id, enclave_request, enclave_request_len)
    };

    /// Reset enclave for upcoming experiments
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ecall_generic_request(
            enclave_id,
            &mut retval,
            enclave_request.as_ptr(),
            enclave_request_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ECALL Enclave Failed {}!", result.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_lock = app_state.enclave_lock();
        enclave_lock.unlock();
    }
    actix_web::HttpResponse::Ok().body("oram_benchmark was successfully called!")
}

#[post("/experiment_runner")]
async fn experiment_runner(
    info: actix_web::web::Json<ExperimentWorkloadRequest>,
) -> impl actix_web::Responder {
    let (enclave_id, exp_request, exp_request_len) = {
        let app_state = APP_STATE.lock().unwrap();
        {
            let mut enclave_lock = app_state.enclave_lock();
            if enclave_lock.is_locked() {
                return actix_web::HttpResponse::Ok().body(
                    "The enclave is currently locked, this experiment request was discarded.",
                );
            } else {
                enclave_lock.lock();
            }
        }

        let mut exp_request = info.0;
        exp_request.set_experiment_id(get_unix_timestamp());
        add_to_json_array(exp_request.clone(), EXP_REQUEST_JSON);

        let exp_request = GenericRequestToEnclave::ExperimentWorkloadRequest(exp_request);
        let exp_request = exp_request.serialize();
        let exp_request_len = exp_request.len() as u32;

        let enclave_id = {
            let enclave_id_holder = app_state.enclave_id();
            enclave_id_holder.enclave_id().unwrap()
        };

        (enclave_id, exp_request, exp_request_len)
    };

    /// Send experiment request to enclave
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ecall_generic_request(
            enclave_id,
            &mut retval,
            exp_request.as_ptr(),
            exp_request_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ECALL Enclave Failed {}!", result.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        let mut enclave_lock = app_state.enclave_lock();
        enclave_lock.unlock();
    }
    actix_web::HttpResponse::Ok().body("Successfull experiment workload.")
}

#[no_mangle]
pub extern "C" fn ocall_get_oram_batch(
    instance: u32,
    leaves: *const u8,
    leaves_len: u32,
) -> sgx_status_t {
    let leaves_slice = unsafe { slice::from_raw_parts(leaves, leaves_len as usize) };
    let mut requested_leaves: Vec<u32> =
        bincode::deserialize(leaves_slice).expect("It must be a leaf vector.");
    requested_leaves.sort();

    {
        let mut accessed_positions = ACCESSED_POSITIONS.lock().unwrap();
        for leaf in requested_leaves.iter() {
            accessed_positions[*leaf as usize] += 1;
        }

        let mut batch_crono = BATCH_SIZE_CHRONO.lock().unwrap();
        batch_crono.push(requested_leaves.len() as f64);
    }

    let (enclave_id, buckets, bucket_ciphertext_len) = {
        let app_state = APP_STATE.lock().unwrap();
        let oram_config = app_state.oblivious_ram_config();
        let mut oram_locked = app_state.oblivious_ram_directory();
        let mut statistics_locked = app_state.statistics();

        let oram_instance_file = oram_locked
            .get_tree(instance as usize)
            .expect("ORAM instance unknown.");
        let time = Instant::now();
        let buckets = crate::oblivious_ram::components::read_batch(
            &oram_config,
            oram_instance_file,
            requested_leaves,
        );
        statistics_locked.inc_oram_read_time(time.elapsed().as_nanos());
        statistics_locked.inc_oram_reads();

        let enclave_id = {
            let enclave_id_holder = app_state.enclave_id();
            enclave_id_holder.enclave_id().unwrap()
        };

        (
            enclave_id,
            buckets,
            oram_config.bucket_ciphertext_len() as u64,
        )
    };

    let buckets_len = buckets.len() as u32;
    let buckets_ptr = buckets.as_ptr();

    let time = Instant::now();
    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
    unsafe {
        ecall_return_oram_path(
            enclave_id,
            &mut retval,
            buckets_ptr,
            buckets_len,
            bucket_ciphertext_len,
        );
    }
    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            panic!("[-] ecall_write_oram_path failed {}!", retval.as_str());
        }
    }

    {
        let app_state = APP_STATE.lock().unwrap();
        app_state
            .statistics()
            .inc_response_write_time(time.elapsed().as_nanos());
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_write_oram_batch(
    instance: u32,
    leaves: *const u8,
    leaves_len: u32,
    buckets: *const u8,
    buckets_len: u32,
) {
    let leaves_slice = unsafe { slice::from_raw_parts(leaves, leaves_len as usize) };
    let mut requested_leaves: Vec<u32> =
        bincode::deserialize(leaves_slice).expect("It must be a leaf vector.");
    requested_leaves.sort();
    let buckets_slice = unsafe { slice::from_raw_parts(buckets, buckets_len as usize) };

    {
        let app_state = APP_STATE.lock().unwrap();
        let oram_config = app_state.oblivious_ram_config();
        let mut oram_locked = app_state.oblivious_ram_directory();
        let oram_instance_file = oram_locked
            .get_tree(instance as usize)
            .expect("ORAM instance unknown.");

        let mut statistics_locked = app_state.statistics();
        let time = Instant::now();
        crate::oblivious_ram::components::write_batch(
            &oram_config,
            oram_instance_file,
            requested_leaves,
            buckets_slice,
        );
        statistics_locked.inc_oram_write_time(time.elapsed().as_nanos());
        statistics_locked.inc_oram_writes();
    }
}

#[no_mangle]
pub extern "C" fn ocall_generic_request(request: *const u8, request_len: u32) -> sgx_status_t {
    let request = {
        let app_state = APP_STATE.lock().unwrap();
        let mut statistics_locked = app_state.statistics();
        let time = Instant::now();
        let request_len = request_len as usize;
        let request_slice = unsafe { slice::from_raw_parts(request, request_len) };
        let request: oram_interface::GenericRequestToServer =
            bincode::deserialize(request_slice).expect("Deserializing has not worked.");
        statistics_locked.inc_deserialize_request_time(time.elapsed().as_nanos());
        request
    };

    match request {
        GenericRequestToServer::TestMsg(_) => {}
        GenericRequestToServer::Signal(signal_type) => match signal_type {
            1u8 => {
                let app_state = APP_STATE.lock().unwrap();
                app_state.statistics().reset();
            }
            _ => {}
        },
        GenericRequestToServer::Statistics(enclave_stats) => {
            let (number_of_oram, experiment_id) = {
                let experiment_id = enclave_stats.experiment_id();
                let app_state = APP_STATE.lock().unwrap();
                let mut statistics_locked = app_state.statistics();
                let oram_config = app_state.oblivious_ram_config();

                let oram_config_experiment =
                    OramConfigOfExperiment::new(experiment_id, &oram_config);
                add_to_json_array(oram_config_experiment, ORAM_CONFIGS_JSON);

                add_to_json_array(enclave_stats, ENCLAVE_STATS_JSON);
                statistics_locked.set_experiment_id(experiment_id);
                add_to_json_array(statistics_locked.clone_me(), SERVER_STATS_JSON);
                statistics_locked.reset();
                (oram_config.number_of_oram(), experiment_id)
            };

            let mut additional_enclave_statistics_vecs =
                EnclaveAdditionalStatisticsVecs::new_empty(experiment_id);

            let mut additional_enclave_statistics = EnclaveAdditionalStatistics::new(experiment_id);

            {
                let accessed_positions = ACCESSED_POSITIONS.lock().unwrap();
                additional_enclave_statistics_vecs
                    .set_accessed_positions(accessed_positions.clone());
            }

            crate::plotter::plot_accessed_positions(
                number_of_oram,
                PLOT_DIR.to_string(),
                experiment_id,
            );
            {
                let mut batch_size_crono = BATCH_SIZE_CHRONO.lock().unwrap();
                additional_enclave_statistics_vecs.set_batch_size(batch_size_crono.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut batch_size_crono,
                    "batch_size_chrono",
                    experiment_id,
                    "ORAM batch size over time",
                    "ORAM Batches in the Runtime",
                    "Batch Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_max_batch_size(max);
                additional_enclave_statistics.set_average_batch_size(avg);
            }
            {
                let mut data = ENCLAVE_STASH_BYTE_SIZE.lock().unwrap();
                additional_enclave_statistics_vecs.set_stash_byte_size(data.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "stash_byte_size",
                    experiment_id,
                    "Stash Byte Size",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_max_stash_byte_size(max);
                additional_enclave_statistics.set_average_stash_byte_size(avg);
            }
            {
                let mut data = ENCLAVE_STASH_PACKET_AMOUNT.lock().unwrap();
                additional_enclave_statistics_vecs.set_stash_packet_amount(data.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "stash_packet_amount",
                    experiment_id,
                    "Stash Amount of Packets",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_max_stash_packet_amount(max);
                additional_enclave_statistics.set_average_stash_packet_amount(avg);
            }
            {
                let mut data = ENCLAVE_STASH_AVERAGE_BYTE_SIZE.lock().unwrap();
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "stash_packet_average_size",
                    experiment_id,
                    "stash_packet_average_size",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
            }
            {
                let mut data = ENCLAVE_STASH_MAX_BYTE_SIZE.lock().unwrap();
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "stash_packet_max_size",
                    experiment_id,
                    "stash_packet_max_size",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
            }
            {
                let mut data = ENCLAVE_NODE_CACHE_AMOUNT.lock().unwrap();
                additional_enclave_statistics_vecs.set_nodecache_packet_amount(data.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "node_cache_amount",
                    experiment_id,
                    "Node Cache Amount",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_max_nodecache_packet_amount(max);
                additional_enclave_statistics.set_average_nodecache_packet_amount(avg);
            }
            {
                let mut data = ENCLAVE_NODE_CACHE_BYTE_SIZE.lock().unwrap();
                additional_enclave_statistics_vecs.set_nodecache_byte_size(data.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "node_cache_byte_size",
                    experiment_id,
                    "Node Cache Byte Size",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_max_nodecache_byte_size(max);
                additional_enclave_statistics.set_average_nodecache_byte_size(avg);
            }
            {
                let mut data = ENCLAVE_SLOT_CACHE_AMOUNT.lock().unwrap();
                crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "slot_cache_amount",
                    experiment_id,
                    "Slot Cache Amount",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
            }
            {
                let mut data = ENCLAVE_SLOT_CACHE_BYTE_SIZE.lock().unwrap();
                crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "slot_cache_byte_size",
                    experiment_id,
                    "Slot Cache Byte Size",
                    "Batch execution runtime",
                    "Byte Size",
                    PlotColor::RED,
                );
            }
            {
                let mut data = ENCLAVE_LOCALITY_CACHE_AMOUNT.lock().unwrap();
                additional_enclave_statistics_vecs.set_localitycache_packet_amount(data.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "locality_cache_amount",
                    experiment_id,
                    "Locality Cache Amount",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_average_localitycache_packet_amount(avg);
                additional_enclave_statistics.set_max_localitycache_packet_amount(max);
            }
            {
                let mut data = ENCLAVE_LOCALITY_CACHE_BYTE_SIZE.lock().unwrap();
                additional_enclave_statistics_vecs.set_localitycache_byte_size(data.clone());
                let (max, avg) = crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "locality_cache_byte_size",
                    experiment_id,
                    "Locality Cache Byte Size",
                    "Batch execution runtime",
                    "Size",
                    PlotColor::RED,
                );
                additional_enclave_statistics.set_average_localitycache_byte_size(avg);
                additional_enclave_statistics.set_max_localitycache_byte_size(max);
            }
            {
                let mut data = ENCLAVE_EVICTED_PACKETS_OVER_TIME.lock().unwrap();
                crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "evicted_packets_over_time",
                    experiment_id,
                    "Evicted Packets over time",
                    "Batch execution runtime",
                    "Number of evicted packets",
                    PlotColor::RED,
                );
            }
            {
                let mut data = ENCLAVE_FREE_SPACE_IN_BATCH_OVER_TIME.lock().unwrap();
                additional_enclave_statistics_vecs.set_free_space_in_buckets(data.clone());
                crate::plotter::plot_and_empty_f64_data_vec(
                    PLOT_DIR.to_string(),
                    &mut data,
                    "free_oram_space_in_batch_over_time",
                    experiment_id,
                    "Free Space in ORAM batch over time",
                    "Batch execution runtime",
                    "Free Space",
                    PlotColor::RED,
                );
            }
            add_to_json_array(additional_enclave_statistics, ENCLAVE_ADDITIONAL_STATS_JSON);
            add_to_json_array(
                additional_enclave_statistics_vecs,
                ENCLAVE_ADDITIONAL_STATS_VECS_JSON,
            );
        }
        GenericRequestToServer::Shutdown(_) => {}
        GenericRequestToServer::EnvironmentVariables(env_vars) => {
            let app_state = APP_STATE.lock().unwrap();
            let oram_config = app_state.oblivious_ram_config();
            assert_eq!(
                env_vars.number_of_oram(),
                oram_config.number_of_oram(),
                "NUMBER_OF_ORAM: Environment variables between enclave and server do not match."
            );
            assert_eq!(
                env_vars.tree_height(),
                oram_config.tree_height(),
                "TREE_HEIGHT: Environment variables between enclave and server do not match."
            );
            assert_eq!(
                env_vars.oram_degree(),
                oram_config.oram_degree(),
                "ORAM_DEGREE: Environment variables between enclave and server do not match."
            );
            assert_eq!(
                env_vars.max_bucket_size(),
                oram_config.bucket_size(),
                "MAX_BUCKET_SIZE: Environment variables between enclave and server do not match."
            );
            assert_eq!(env_vars.bucket_serialized_size(), oram_config.bucket_serialized_size(), "BUCKET_SERIALIZED_SIZE: Environment variables between enclave and server do not match.");
            assert_eq!(env_vars.bucket_ciphertext_len(), oram_config.bucket_ciphertext_len(), "BUCKET_CIPHERTEXT_LEN: Environment variables between enclave and server do not match.");
            log_runtime(
                "EnvironmentVariables among the enclave and server were initialized correctly.",
                true,
            );
        }
        GenericRequestToServer::ResourceUsageReport(resource_usg_rep) => {
            {
                let mut stats = ENCLAVE_STASH_PACKET_AMOUNT.lock().unwrap();
                stats.push(resource_usg_rep.stash_number_of_packets() as f64);
            }
            {
                let mut stats = ENCLAVE_STASH_BYTE_SIZE.lock().unwrap();
                stats.push(resource_usg_rep.stash_total_byte_size() as f64);
            }
            {
                let mut stats = ENCLAVE_STASH_AVERAGE_BYTE_SIZE.lock().unwrap();
                stats.push(resource_usg_rep.stash_average_byte_size() as f64);
            }
            {
                let mut stats = ENCLAVE_STASH_MAX_BYTE_SIZE.lock().unwrap();
                stats.push(resource_usg_rep.stash_max_byte_size() as f64);
            }
            {
                let mut stats = ENCLAVE_NODE_CACHE_AMOUNT.lock().unwrap();
                stats.push(resource_usg_rep.node_cache_amount() as f64);
            }
            {
                let mut stats = ENCLAVE_NODE_CACHE_BYTE_SIZE.lock().unwrap();
                stats.push(resource_usg_rep.node_cache_byte_size() as f64);
            }
            {
                let mut stats = ENCLAVE_SLOT_CACHE_AMOUNT.lock().unwrap();
                stats.push(resource_usg_rep.slot_cache_amount() as f64);
            }
            {
                let mut stats = ENCLAVE_SLOT_CACHE_BYTE_SIZE.lock().unwrap();
                stats.push(resource_usg_rep.slot_cache_byte_size() as f64);
            }
            {
                let mut stats = ENCLAVE_LOCALITY_CACHE_AMOUNT.lock().unwrap();
                stats.push(resource_usg_rep.locality_cache_amount() as f64);
            }
            {
                let mut stats = ENCLAVE_LOCALITY_CACHE_BYTE_SIZE.lock().unwrap();
                stats.push(resource_usg_rep.locality_cache_byte_size() as f64);
            }
            {
                let mut stats = ENCLAVE_EVICTED_PACKETS_OVER_TIME.lock().unwrap();
                stats.push(resource_usg_rep.evicted_packets_in_batch() as f64);
            }
            {
                let mut stats = ENCLAVE_FREE_SPACE_IN_BATCH_OVER_TIME.lock().unwrap();
                stats.push(resource_usg_rep.free_oram_space_after() as f64);
            }
        }
        GenericRequestToServer::EnclaveStateBackup(byte_object) => {
            println!("EnclaveStateBackup: {}", byte_object.header());

            let (file_name_id, mut data, complete) = byte_object.destroy();

            if !complete {
                let mut enclave_state_buffer = ENCLAVE_STATE_BACKUP_BUFFER.lock().unwrap();
                match enclave_state_buffer.get_mut(file_name_id.as_str()) {
                    None => {
                        enclave_state_buffer.insert(file_name_id, data);
                    }
                    Some(some_entry) => {
                        some_entry.append(&mut data);
                    }
                }
            } else {
                let mut enclave_state_buffer = ENCLAVE_STATE_BACKUP_BUFFER.lock().unwrap();
                let data = match enclave_state_buffer.remove(file_name_id.as_str()) {
                    None => data,
                    Some(mut some_entry) => {
                        some_entry.append(&mut data);
                        some_entry
                    }
                };

                let mut file_name = BACKUP_PREFIX.to_string();
                file_name.push_str(file_name_id.as_str());
                file_name.push_str("/");

                fs::create_dir(file_name.clone()).expect("Create Backup Dir");

                {
                    let mut file_name_enclave_state = file_name.clone();
                    file_name_enclave_state.push_str("enclave_state");
                    file_interface::write_bytes(file_name_enclave_state, &data);
                }

                {
                    let app_state = APP_STATE.lock().unwrap();
                    {
                        let mut file_name_app_state = file_name.clone();
                        file_name_app_state.push_str("app_state");
                        let app_state_serialized = app_state.to_backup().serialize();
                        file_interface::write_bytes(file_name_app_state, &app_state_serialized);
                    }
                    {
                        let oram_config = app_state.oblivious_ram_config();
                        PathORAM::to_backup(
                            &oram_config,
                            ORAM_PREFIX.to_string(),
                            file_name.clone(),
                        );
                    }
                }
            }
        }
        _ => {
            panic!("Unexpected case.");
        }
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_setup_oram(
    instance: u32,
    offset: u32,
    buckets: *const u8,
    buckets_len: u32,
) -> sgx_status_t {
    let app_state = APP_STATE.lock().unwrap();
    let oram_locked = app_state.oblivious_ram_directory();
    let oram_config = app_state.oblivious_ram_config();

    let oram_instance_file = oram_locked
        .get_tree(instance as usize)
        .expect("ORAM instance unknown.");

    let buckets_slice = unsafe { slice::from_raw_parts(buckets, buckets_len as usize) };

    oblivious_ram::components::setup_oram(
        oram_config.bucket_ciphertext_len(),
        oram_instance_file,
        offset,
        buckets_slice,
    );

    sgx_status_t::SGX_SUCCESS
}

fn display_const_config() {
    let app_state = APP_STATE.lock().unwrap();
    let oram_config = app_state.oblivious_ram_config();

    log_runtime(" ", true);
    log_runtime(" ### START OF UNTRUSTED SERVER OUTPUT: ###", true);
    log_runtime(
        &format!(
            "Your {} ORAMs have a storage of {} buckets each..",
            oram_config.number_of_oram(),
            (oram_config
                .oram_degree()
                .pow(oram_config.tree_height() as u32)
                - 1)
        ),
        true,
    );
    log_runtime(&format!("Your ORAM config: NUMBER_OF_ORAM {} | ORAM_TREE_HEIGHT {} | ORAM_DEGREE {} | MAX_BUCKET_SIZE {}", oram_config.number_of_oram(), oram_config.tree_height(), oram_config.oram_degree(), oram_config.bucket_size()), true);
    let oram_byte_size = (oram_config.bucket_size()
        * get_number_of_tree_nodes(oram_config.oram_degree(), oram_config.tree_height() as u32))
        * oram_config.number_of_oram();
    log_runtime(
        &format!(
            "Your oblivious storage has a size of {} bytes ({} MB)",
            oram_byte_size,
            oram_byte_size.div(usize::pow(10, 6))
        ),
        true,
    );
    log_runtime(" ### END OF UNTRUSTED SERVER OUTPUT. ###", true);
    log_runtime(" ", true);
}

fn initial_checks() {
    assert!(
        std::path::Path::new("logging/").exists(),
        "The environment was not set up correctly. Please create the folder >logging<."
    );
    assert!(
        std::path::Path::new("plots/").exists(),
        "The environment was not set up correctly. Please create the folder >plots<."
    );
    assert!(
        std::path::Path::new("json/").exists(),
        "The environment was not set up correctly. Please create the folder >json<."
    );
    assert!(
        std::path::Path::new("backup/").exists(),
        "The environment was not set up correctly. Please create the folder >backup<."
    );
    assert!(
        std::path::Path::new("orams/").exists(),
        "The environment was not set up correctly. Please create the folder >orams<."
    );
    assert!(
        std::path::Path::new("orams_backup/").exists(),
        "The environment was not set up correctly. Please create the folder >orams_backup<."
    );
}
