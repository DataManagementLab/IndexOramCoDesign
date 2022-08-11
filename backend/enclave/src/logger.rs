use serde::{Deserialize, Serialize};

pub fn log_runtime(message: &str, console: bool) {
    println!("{}", message);
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StatisticsToSend {
    free_oram_space_after: f64,
    evicted_packets_in_batch: usize,
}

impl StatisticsToSend {
    pub fn free_oram_space_after(&self) -> f64 {
        self.free_oram_space_after
    }
    pub fn evicted_packets_in_batch(&self) -> usize {
        self.evicted_packets_in_batch
    }
    pub fn set_free_oram_space_after(&mut self, free_oram_space_after: f64) {
        self.free_oram_space_after = free_oram_space_after;
    }
    pub fn inc_evicted_packets_in_batch(&mut self, evicted_packets_in_batch: usize) {
        self.evicted_packets_in_batch += evicted_packets_in_batch;
    }
    pub fn reset_and_return(&mut self) -> (f64, usize) {
        let free_oram_space_after = self.free_oram_space_after;
        let evicted_packets_in_batch = self.evicted_packets_in_batch;

        self.free_oram_space_after = 0.0;
        self.evicted_packets_in_batch = 0;

        (free_oram_space_after, evicted_packets_in_batch)
    }
    pub fn new() -> Self {
        StatisticsToSend {
            free_oram_space_after: 0.0,
            evicted_packets_in_batch: 0,
        }
    }
}
