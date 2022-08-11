use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::Div;

use serde::{Deserialize, Serialize};

use crate::{OramConfig, DELETE_LOGS_AT_START};

#[derive(Serialize, Deserialize, Clone)]
pub struct EnclaveAdditionalStatistics {
    experiment_id: u64,
    max_stash_packet_amount: f64,
    max_stash_byte_size: f64,
    average_stash_packet_amount: f64,
    average_stash_byte_size: f64,
    max_nodecache_packet_amount: f64,
    max_nodecache_byte_size: f64,
    average_nodecache_packet_amount: f64,
    average_nodecache_byte_size: f64,
    max_localitycache_byte_size: f64,
    max_localitycache_packet_amount: f64,
    average_localitycache_byte_size: f64,
    average_localitycache_packet_amount: f64,
    average_batch_size: f64,
    max_batch_size: f64,
}

impl EnclaveAdditionalStatistics {
    pub fn new(experiment_id: u64) -> Self {
        EnclaveAdditionalStatistics {
            experiment_id,
            max_stash_packet_amount: 0.0,
            max_stash_byte_size: 0.0,
            average_stash_packet_amount: 0.0,
            average_stash_byte_size: 0.0,
            max_nodecache_packet_amount: 0.0,
            max_nodecache_byte_size: 0.0,
            average_nodecache_packet_amount: 0.0,
            average_nodecache_byte_size: 0.0,
            max_localitycache_byte_size: 0.0,
            max_localitycache_packet_amount: 0.0,
            average_localitycache_byte_size: 0.0,
            average_localitycache_packet_amount: 0.0,
            average_batch_size: 0.0,
            max_batch_size: 0.0,
        }
    }
    pub fn set_max_stash_packet_amount(&mut self, max_stash_packet_amount: f64) {
        self.max_stash_packet_amount = max_stash_packet_amount;
    }
    pub fn set_max_stash_byte_size(&mut self, max_stash_byte_size: f64) {
        self.max_stash_byte_size = max_stash_byte_size;
    }
    pub fn set_average_stash_packet_amount(&mut self, average_stash_packet_amount: f64) {
        self.average_stash_packet_amount = average_stash_packet_amount;
    }
    pub fn set_average_stash_byte_size(&mut self, average_stash_byte_size: f64) {
        self.average_stash_byte_size = average_stash_byte_size;
    }
    pub fn set_max_nodecache_packet_amount(&mut self, max_nodecache_packet_amount: f64) {
        self.max_nodecache_packet_amount = max_nodecache_packet_amount;
    }
    pub fn set_max_nodecache_byte_size(&mut self, max_nodecache_byte_size: f64) {
        self.max_nodecache_byte_size = max_nodecache_byte_size;
    }
    pub fn set_average_nodecache_packet_amount(&mut self, average_nodecache_packet_amount: f64) {
        self.average_nodecache_packet_amount = average_nodecache_packet_amount;
    }
    pub fn set_average_nodecache_byte_size(&mut self, average_nodecache_byte_size: f64) {
        self.average_nodecache_byte_size = average_nodecache_byte_size;
    }
    pub fn set_average_batch_size(&mut self, average_batch_size: f64) {
        self.average_batch_size = average_batch_size;
    }
    pub fn set_max_batch_size(&mut self, max_batch_size: f64) {
        self.max_batch_size = max_batch_size;
    }
    pub fn experiment_id(&self) -> u64 {
        self.experiment_id
    }
    pub fn set_max_localitycache_byte_size(&mut self, max_localitycache_byte_size: f64) {
        self.max_localitycache_byte_size = max_localitycache_byte_size;
    }
    pub fn set_max_localitycache_packet_amount(&mut self, max_localitycache_packet_amount: f64) {
        self.max_localitycache_packet_amount = max_localitycache_packet_amount;
    }
    pub fn set_average_localitycache_byte_size(&mut self, average_localitycache_byte_size: f64) {
        self.average_localitycache_byte_size = average_localitycache_byte_size;
    }
    pub fn set_average_localitycache_packet_amount(
        &mut self,
        average_localitycache_packet_amount: f64,
    ) {
        self.average_localitycache_packet_amount = average_localitycache_packet_amount;
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EnclaveAdditionalStatisticsVecs {
    experiment_id: u64,
    accessed_positions: Vec<u64>,
    stash_packet_amount: Vec<f64>,
    stash_byte_size: Vec<f64>,
    nodecache_packet_amount: Vec<f64>,
    nodecache_byte_size: Vec<f64>,
    localitycache_byte_size: Vec<f64>,
    localitycache_packet_amount: Vec<f64>,
    free_space_in_buckets: Vec<f64>,
    batch_size: Vec<f64>,
}

impl EnclaveAdditionalStatisticsVecs {
    pub fn new_empty(experiment_id: u64) -> Self {
        EnclaveAdditionalStatisticsVecs {
            experiment_id,
            accessed_positions: Vec::new(),
            stash_packet_amount: Vec::new(),
            stash_byte_size: Vec::new(),
            nodecache_packet_amount: Vec::new(),
            nodecache_byte_size: Vec::new(),
            localitycache_byte_size: Vec::new(),
            localitycache_packet_amount: Vec::new(),
            free_space_in_buckets: Vec::new(),
            batch_size: Vec::new(),
        }
    }
    pub fn set_stash_packet_amount(&mut self, stash_packet_amount: Vec<f64>) {
        self.stash_packet_amount = stash_packet_amount;
    }
    pub fn set_stash_byte_size(&mut self, stash_byte_size: Vec<f64>) {
        self.stash_byte_size = stash_byte_size;
    }
    pub fn set_nodecache_packet_amount(&mut self, nodecache_packet_amount: Vec<f64>) {
        self.nodecache_packet_amount = nodecache_packet_amount;
    }
    pub fn set_nodecache_byte_size(&mut self, nodecache_byte_size: Vec<f64>) {
        self.nodecache_byte_size = nodecache_byte_size;
    }
    pub fn set_localitycache_byte_size(&mut self, localitycache_byte_size: Vec<f64>) {
        self.localitycache_byte_size = localitycache_byte_size;
    }
    pub fn set_localitycache_packet_amount(&mut self, localitycache_packet_amount: Vec<f64>) {
        self.localitycache_packet_amount = localitycache_packet_amount;
    }
    pub fn set_batch_size(&mut self, batch_size: Vec<f64>) {
        self.batch_size = batch_size;
    }
    pub fn set_free_space_in_buckets(&mut self, free_space_in_buckets: Vec<f64>) {
        self.free_space_in_buckets = free_space_in_buckets;
    }
    pub fn set_accessed_positions(&mut self, accessed_positions: Vec<u64>) {
        self.accessed_positions = accessed_positions;
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OramConfigOfExperiment {
    experiment_id: u64,
    number_of_oram: usize,
    tree_height: usize,
    oram_degree: usize,
    bucket_size: usize,
    oram_byte_size: usize,
}

impl OramConfigOfExperiment {
    pub fn experiment_id(&self) -> u64 {
        self.experiment_id
    }
    pub fn new(experiment_id: u64, oram_config: &OramConfig) -> Self {
        let oram_byte_size = (oram_config.bucket_size()
            * crate::get_number_of_tree_nodes(
                oram_config.oram_degree(),
                oram_config.tree_height() as u32,
            ))
            * oram_config.number_of_oram();
        //let oram_mb_size = oram_byte_size.div(usize::pow(10, 6));
        OramConfigOfExperiment {
            experiment_id,
            number_of_oram: oram_config.number_of_oram(),
            tree_height: oram_config.tree_height(),
            oram_degree: oram_config.oram_degree(),
            bucket_size: oram_config.bucket_size(),
            oram_byte_size,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Statistics {
    experiment_id: u64,
    oram_reads: u64,
    oram_read_time: u128,
    oram_writes: u64,
    oram_write_time: u128,
    response_write_time: u128,
    deserialize_request_time: u128,
}

impl Statistics {
    pub fn reset(&mut self) {
        self.experiment_id = 0;
        self.oram_reads = 0;
        self.oram_read_time = 0;
        self.oram_writes = 0;
        self.oram_write_time = 0;
        self.response_write_time = 0;
        self.deserialize_request_time = 0;
        log_runtime("ORAM server statistics reset successful.", true);
    }
    pub fn new() -> Self {
        Statistics {
            experiment_id: 0,
            oram_reads: 0,
            oram_read_time: 0,
            oram_writes: 0,
            oram_write_time: 0,
            response_write_time: 0,
            deserialize_request_time: 0,
        }
    }
    pub fn oram_reads(&self) -> u64 {
        self.oram_reads
    }
    pub fn inc_oram_reads(&mut self) {
        self.oram_reads += 1;
    }
    pub fn oram_read_time(&self) -> f64 {
        (self.oram_read_time as f64) / 1000000.0
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
    pub fn oram_writes(&self) -> u64 {
        self.oram_writes
    }
    pub fn inc_oram_writes(&mut self) {
        self.oram_writes += 1;
    }
    pub fn response_write_time(&self) -> f64 {
        (self.response_write_time as f64) / 1000000.0
    }
    pub fn inc_response_write_time(&mut self, time: u128) {
        self.response_write_time += time;
    }
    pub fn deserialize_request_time(&self) -> f64 {
        (self.deserialize_request_time as f64) / 1000000.0
    }
    pub fn inc_deserialize_request_time(&mut self, time: u128) {
        self.deserialize_request_time += time;
    }
    pub fn clone_me(&self) -> Statistics {
        self.clone()
    }
    pub fn set_experiment_id(&mut self, experiment_id: u64) {
        self.experiment_id = experiment_id;
    }
    pub fn experiment_id(&self) -> u64 {
        self.experiment_id
    }
}

pub fn initialize_loggers(experiment_name: &str) {
    if DELETE_LOGS_AT_START {
        delete_file("logging/", "runtime");
        delete_file("logging/", "error");
        delete_file("logging/", "results");
        delete_file("logging/", "access");
    } else {
        log_runtime(" ", false);
        log_error(" ");
        log_results(" ");
        log_access(" ");
    }

    let now = chrono::offset::Local::now();
    let starter_time = String::from("Start at ") + &now.to_string();
    log_runtime(" ", true);
    log_runtime(
        " ################## NEW EXPERIMENT ################## ",
        true,
    );
    log_runtime(&format!("Name: {}", experiment_name), true);
    log_runtime(&starter_time, true);

    log_error(" ### NEW EXPERIMENT ### ");
    log_error(&format!("Name: {}", experiment_name));
    log_error(&starter_time);

    log_results(" ### NEW EXPERIMENT ### ");
    log_results(&format!("Name: {}", experiment_name));
    log_results(&starter_time);

    log_access(" ### NEW EXPERIMENT ### ");
    log_access(&format!("Name: {}", experiment_name));
    log_access(&starter_time);
}

pub fn log_runtime(message: &str, console: bool) {
    writeln_to_file("logging/", "runtime", message);
    if console {
        println!("{}", message);
    }
}

pub fn log_access(message: &str) {
    writeln_to_file("logging/", "access", message);
}

pub fn log_error(message: &str) {
    writeln_to_file("logging/", "error", message);
}

pub fn log_results(message: &str) {
    writeln_to_file("logging/", "results", message);
}

fn writeln_to_file(path: &str, file_name: &str, content: &str) {
    let path_file_name = String::from(path) + file_name + ".txt";
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path_file_name)
        .unwrap();
    if let Err(e) = writeln!(file, "{}", content) {
        eprintln!("Couldn't append to file {}", e);
    }
}

fn write_to_file(path: &str, file_name: &str, content: &str) {
    let path_file_name = String::from(path) + file_name + ".txt";
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path_file_name)
        .unwrap();
    if let Err(e) = write!(file, "{}", content) {
        eprintln!("Couldn't append to file {}", e);
    }
}

fn delete_file(path: &str, file_name: &str) {
    let path_file_name = String::from(path) + file_name + ".txt";
    match fs::remove_file(path_file_name) {
        Ok(_) => {}
        Err(_) => {
            log_error(&format!(
                "Deletion of file {}{} was not possible.",
                path, file_name
            ));
        }
    }
}
