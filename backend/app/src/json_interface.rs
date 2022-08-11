use crate::oram_interface::EnclaveStatistics;
use crate::{
    EnclaveAdditionalStatistics, EnclaveAdditionalStatisticsVecs, ExperimentWorkloadRequest,
    OramConfigOfExperiment, Statistics, ENCLAVE_ADDITIONAL_STATS_JSON,
    ENCLAVE_ADDITIONAL_STATS_VECS_JSON, ENCLAVE_STATS_JSON, EXP_REQUEST_JSON, ORAM_CONFIGS_JSON,
    SERVER_STATS_JSON,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::{fmt, fs};

#[derive(Debug, Clone)]
pub struct JsonError {
    message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "JSON interface error: {}", self.message.as_str())
    }
}

pub fn setup_jsons() {
    let enclave_stats: Vec<EnclaveStatistics> = Vec::new();
    let enclave_additional_stats: Vec<EnclaveAdditionalStatistics> = Vec::new();
    let server_stats: Vec<Statistics> = Vec::new();
    let exp_request: Vec<ExperimentWorkloadRequest> = Vec::new();
    let oram_exp_configs: Vec<OramConfigOfExperiment> = Vec::new();
    let enclave_additional_stats_vec: Vec<EnclaveAdditionalStatisticsVecs> = Vec::new();
    create_initial_json_file(enclave_stats, ENCLAVE_STATS_JSON);
    create_initial_json_file(enclave_additional_stats, ENCLAVE_ADDITIONAL_STATS_JSON);
    create_initial_json_file(server_stats, SERVER_STATS_JSON);
    create_initial_json_file(exp_request, EXP_REQUEST_JSON);
    create_initial_json_file(oram_exp_configs, ORAM_CONFIGS_JSON);
    create_initial_json_file(
        enclave_additional_stats_vec,
        ENCLAVE_ADDITIONAL_STATS_VECS_JSON,
    );
}

fn create_initial_json_file<'a, T: Serialize + Deserialize<'a>>(data: Vec<T>, path: &str) {
    assert!(data.is_empty());
    match std::path::Path::new(path).exists() {
        true => {
            println!("JSON file {} does already exists.", path);
        }
        false => {
            let buffer =
                serde_json::to_string(&data).expect("Serialization to JSON does not work.");
            match std::fs::write(path, buffer) {
                Ok(_) => {}
                Err(err) => {
                    panic!("Error in writing JSON: {}", err.to_string());
                }
            }
        }
    }
}

pub fn add_to_json_array<T: Serialize + DeserializeOwned>(data_to_add: T, path: &str) {
    match fs::read_to_string(path) {
        Ok(some_file) => {
            let mut data: Vec<T> = serde_json::from_str(some_file.as_str()).unwrap();

            data.push(data_to_add);

            match std::fs::write(path, serde_json::to_string(&data).unwrap()) {
                Ok(_) => {}
                Err(err) => {
                    eprintln!("Error in writing JSON: {}", err.to_string());
                }
            }
        }
        Err(err) => {
            eprintln!("Cannot read JSON file: {}", err.to_string());
        }
    }
}

pub fn get_json_array<T: Serialize + DeserializeOwned>(path: &str) -> Result<Vec<T>, JsonError> {
    match fs::read_to_string(path) {
        Ok(some_file) => {
            let mut data: Vec<T> = serde_json::from_str(some_file.as_str()).unwrap();
            Ok(data)
        }
        Err(err) => Err(JsonError {
            message: err.to_string(),
        }),
    }
}
