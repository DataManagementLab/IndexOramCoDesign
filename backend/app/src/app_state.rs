use crate::config::OramConfig;
use crate::{EnclaveIdHolder, EnclaveLock, PathORAM, Statistics, ORAM_PREFIX};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LockResult, Mutex, MutexGuard};

pub struct AppState {
    oblivious_ram_config: Mutex<OramConfig>,
    oblivious_ram_directory: Mutex<PathORAM>,
    statistics: Mutex<Statistics>,
    enclave_id: Mutex<EnclaveIdHolder>,
    enclave_lock: Mutex<EnclaveLock>,
}

impl AppState {
    pub fn oblivious_ram_config(&self) -> MutexGuard<OramConfig> {
        self.oblivious_ram_config.lock().unwrap()
    }
    pub fn oblivious_ram_directory(&self) -> MutexGuard<PathORAM> {
        self.oblivious_ram_directory.lock().unwrap()
    }
    pub fn statistics(&self) -> MutexGuard<Statistics> {
        self.statistics.lock().unwrap()
    }
    pub fn enclave_id(&self) -> MutexGuard<EnclaveIdHolder> {
        self.enclave_id.lock().unwrap()
    }
    pub fn enclave_lock(&self) -> MutexGuard<EnclaveLock> {
        self.enclave_lock.lock().unwrap()
    }
    pub fn new_default() -> Self {
        let oram_config = OramConfig::new_default();
        let path_oram = PathORAM::new(ORAM_PREFIX, &oram_config);
        AppState {
            oblivious_ram_config: Mutex::new(oram_config),
            oblivious_ram_directory: Mutex::new(path_oram),
            statistics: Mutex::new(Statistics::new()),
            enclave_id: Mutex::new(EnclaveIdHolder::new(None)),
            enclave_lock: Mutex::new(EnclaveLock::new()),
        }
    }
    pub fn to_backup(&self) -> AppStateToBackup {
        let oblivious_ram_config = self.oblivious_ram_config();
        let statistics = self.statistics();
        AppStateToBackup::new(&oblivious_ram_config, &statistics)
    }
    pub fn restore_from_backup(&mut self, backup: AppStateToBackup, path_oram: PathORAM) {
        let (oram_config, statistics) = backup.destroy();
        self.oblivious_ram_config = Mutex::new(oram_config);
        self.oblivious_ram_directory = Mutex::new(path_oram);
        self.statistics = Mutex::new(statistics);
        //self.enclave_id = Mutex::new(EnclaveIdHolder::new(None));
        //self.enclave_lock = Mutex::new(EnclaveLock::new());
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AppStateToBackup {
    oblivious_ram_config: OramConfig,
    statistics: Statistics,
}

impl AppStateToBackup {
    pub fn new(oblivious_ram_config: &OramConfig, statistics: &Statistics) -> Self {
        AppStateToBackup {
            oblivious_ram_config: oblivious_ram_config.clone(),
            statistics: statistics.clone(),
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("Serializing the object has not worked out.")
    }
    pub fn destroy(self) -> (OramConfig, Statistics) {
        (self.oblivious_ram_config, self.statistics)
    }
    pub fn oblivious_ram_config(&self) -> &OramConfig {
        &self.oblivious_ram_config
    }
}
