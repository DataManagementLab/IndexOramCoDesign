use crate::logger::Statistics;
use crate::oblivious_ram::components::PathORAM;
use std::sync::{Mutex, MutexGuard};

/*
pub fn create_environment() -> AppState {
    let oblivious_ram = PathORAM::generate_empty();
    let statistics = Statistics::new();
    AppState::new(Mutex::new(oblivious_ram), Mutex::new(statistics))
}

pub struct AppState {
    oblivious_ram: Mutex<PathORAM>,
    statistics: Mutex<Statistics>,
}

impl AppState {
    pub fn new(oblivious_ram: Mutex<PathORAM>, statistics: Mutex<Statistics>) -> Self {
        AppState {
            oblivious_ram,
            statistics,
        }
    }
    pub fn lock_oblivious_ram(&self) -> MutexGuard<PathORAM> {
        self.oblivious_ram.lock().unwrap()
    }
    pub fn lock_statistics(&self) -> MutexGuard<Statistics> {
        self.statistics.lock().unwrap()
    }
}
 */
