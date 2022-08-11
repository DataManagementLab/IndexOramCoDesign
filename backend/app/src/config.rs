use crate::{AES_TAG_LEN, NONCE_SIZE};
use serde::{Deserialize, Serialize};

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
    pub fn new_default() -> Self {
        OramConfig {
            number_of_oram: 1,
            tree_height: 10,
            oram_degree: 2,
            bucket_size: 32000,
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
    pub fn set_number_of_oram(&mut self, number_of_oram: usize) {
        self.number_of_oram = number_of_oram;
    }
    pub fn set_tree_height(&mut self, tree_height: usize) {
        self.tree_height = tree_height;
    }
    pub fn set_oram_degree(&mut self, oram_degree: usize) {
        self.oram_degree = oram_degree;
    }
    pub fn set_bucket_size(&mut self, bucket_size: usize) {
        self.bucket_size = bucket_size;
    }
}
