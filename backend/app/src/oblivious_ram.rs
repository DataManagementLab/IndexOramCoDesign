use serde::{Deserialize, Serialize};

pub mod components {
    use std::fs;
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::ops::Mul;
    use std::path::PathBuf;

    use indicatif::ProgressBar;
    use memmap2::{Mmap, MmapMut};
    use rayon::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::config::OramConfig;
    use crate::helpers::oram_helper::{
        get_number_of_leaves, index_at_level, number_of_buckets_in_level,
    };
    use crate::{get_number_of_tree_nodes, log_runtime, ACCESSED_POSITIONS, NONCE_SIZE};

    pub fn read_batch(
        oram_config: &OramConfig,
        oram_buffer_path: &PathBuf,
        leaves: Vec<u32>,
    ) -> Vec<u8> {
        //log_runtime("read_batch", true);
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(oram_buffer_path)
            .expect("ORAM file cannot be opened.");
        let mut mmap = unsafe { Mmap::map(&file).expect("Mmap cannot be opened.") };
        let oram = mmap.as_ref();

        let oram_tree_height = oram_config.tree_height();
        let bucket_cipher_text_len = oram_config.bucket_ciphertext_len();
        let oram_degree = oram_config.oram_degree();

        let mut read_path: Vec<u8> = Vec::with_capacity(oram_tree_height * bucket_cipher_text_len);

        let number_of_leaves =
            get_number_of_leaves(oram_config.oram_degree(), oram_tree_height as u32);
        let mut oram_offset: usize = 0;
        for level in 0..oram_tree_height {
            let level_len = number_of_buckets_in_level(oram_degree, level as u32);
            let area_size = number_of_leaves / level_len;
            let mut last_leaf_level_index = level_len;

            for leaf in leaves.iter() {
                let leaf_level_index = index_at_level(leaf, area_size);
                if leaf_level_index != last_leaf_level_index {
                    let oram_bucket_range_indexes = (
                        (oram_offset + leaf_level_index) * bucket_cipher_text_len,
                        (oram_offset + leaf_level_index + 1) * bucket_cipher_text_len,
                    );

                    match oram.get(oram_bucket_range_indexes.0..oram_bucket_range_indexes.1) {
                        None => {
                            panic!("ORAM cannot be overridden.");
                        }
                        Some(oram_bucket) => {
                            read_path.extend_from_slice(oram_bucket);
                        }
                    }
                    last_leaf_level_index = leaf_level_index;
                }
            }
            oram_offset += level_len;
        }
        read_path
    }

    /// leaves must be sorted
    pub fn write_batch(
        oram_config: &OramConfig,
        oram_buffer_path: &PathBuf,
        leaves: Vec<u32>,
        buckets: &[u8],
    ) {
        //log_runtime("write_batch", true);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(oram_buffer_path)
            .expect("ORAM file cannot be opened.");
        let mut mmap = unsafe { MmapMut::map_mut(&file).expect("MmapMut cannot be opened.") };
        let oram = mmap.as_mut();

        let oram_tree_height = oram_config.tree_height();
        let bucket_cipher_text_len = oram_config.bucket_ciphertext_len();
        let oram_degree = oram_config.oram_degree();

        let number_of_leaves =
            get_number_of_leaves(oram_config.oram_degree(), oram_tree_height as u32);

        let mut buckets_i: usize = 0;
        let mut oram_offset: usize = 0;
        for level in 0..oram_tree_height {
            let level_len = number_of_buckets_in_level(oram_degree, level as u32);
            let area_size = number_of_leaves / level_len;
            let mut last_leaf_level_index = level_len;

            for leaf in leaves.iter() {
                let leaf_level_index = index_at_level(leaf, area_size);
                if leaf_level_index != last_leaf_level_index {
                    let buckets_range_indexes = (
                        buckets_i * bucket_cipher_text_len,
                        (buckets_i + 1) * bucket_cipher_text_len,
                    );
                    let oram_bucket_range_indexes = (
                        (oram_offset + leaf_level_index) * bucket_cipher_text_len,
                        (oram_offset + leaf_level_index + 1) * bucket_cipher_text_len,
                    );

                    let bucket_new =
                        match buckets.get(buckets_range_indexes.0..buckets_range_indexes.1) {
                            None => {
                                panic!("Can't access the needed bucket to write.");
                            }
                            Some(some_new_bucket) => some_new_bucket,
                        };
                    match oram.get_mut(oram_bucket_range_indexes.0..oram_bucket_range_indexes.1) {
                        None => {
                            panic!("ORAM cannot be overridden.");
                        }
                        Some(oram_bucket) => {
                            oram_bucket.copy_from_slice(bucket_new);
                            buckets_i += 1;
                        }
                    }
                    last_leaf_level_index = leaf_level_index;
                }
            }
            oram_offset += level_len;
        }

        assert_eq!(buckets_i * bucket_cipher_text_len, buckets.len());
    }

    pub fn setup_oram(
        bucket_ciphertext_len: usize,
        oram_buffer_path: &PathBuf,
        offset: u32,
        buckets: &[u8],
    ) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(oram_buffer_path)
            .expect("ORAM file cannot be opened.");
        let mut mmap = unsafe { MmapMut::map_mut(&file).expect("MmapMut cannot be opened.") };
        let oram = mmap.as_mut();

        let mut oram_offset: usize = offset as usize;
        for new_bucket_chunk in buckets.chunks_exact(bucket_ciphertext_len) {
            let oram_bucket_range_indexes = (
                oram_offset * bucket_ciphertext_len,
                (oram_offset + 1) * bucket_ciphertext_len,
            );

            match oram.get_mut(oram_bucket_range_indexes.0..oram_bucket_range_indexes.1) {
                None => {
                    panic!("ORAM cannot be overridden.");
                }
                Some(oram_bucket) => {
                    oram_bucket.copy_from_slice(new_bucket_chunk);
                    oram_offset += 1;
                }
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct PathORAM {
        trees: Vec<PathBuf>,
    }

    impl PathORAM {
        pub fn reset(&mut self, prefix: &str, oram_config: &OramConfig) {
            {
                let mut accessed_positions_statistics = ACCESSED_POSITIONS.lock().unwrap();
                accessed_positions_statistics.truncate(0);

                let accessed_positions_len = get_number_of_leaves(
                    oram_config.oram_degree(),
                    oram_config.tree_height() as u32,
                ) + 1;

                let mut new_pos_vec = vec![0u64; accessed_positions_len];
                accessed_positions_statistics.append(&mut new_pos_vec);
                assert_eq!(accessed_positions_statistics.len(), accessed_positions_len);
            }

            let trees = PathORAM::generate_empty(prefix, oram_config);
            self.trees = trees;
        }
        fn generate_empty(prefix: &str, oram_config: &OramConfig) -> Vec<PathBuf> {
            let oram_tree_height = oram_config.tree_height();
            let number_of_nodes_per_tree =
                get_number_of_tree_nodes(oram_config.oram_degree(), oram_tree_height as u32);
            let mut trees: Vec<PathBuf> = Vec::new();

            let number_of_oram = oram_config.number_of_oram();
            let bucket_ciphertext_len = oram_config.bucket_ciphertext_len();
            log_runtime("ORAM file system generation starts...", true);
            let bar = ProgressBar::new(number_of_oram as u64);
            for oram_id in 0..number_of_oram {
                let path = String::from(prefix) + "ORAM" + oram_id.to_string().as_str();
                match fs::remove_file(&path) {
                    Ok(_) => {}
                    Err(_) => {}
                }
                {
                    let mut file =
                        File::create(path.clone()).expect("Creating the ORAM file does not work.");
                    let tree: Vec<u8> =
                        vec![0u8; number_of_nodes_per_tree * (bucket_ciphertext_len)];
                    file.write_all(&tree)
                        .expect("write_all to file does not work.");
                }
                trees.push(PathBuf::from(path));
                bar.inc(1);
            }
            bar.finish();
            log_runtime("ORAM file generation has finished!", true);
            trees
        }
        pub fn get_tree(&self, index: usize) -> Option<&PathBuf> {
            self.trees.get(index)
        }
        pub fn new_empty() -> Self {
            PathORAM { trees: Vec::new() }
        }
        pub fn new(prefix: &str, oram_config: &OramConfig) -> Self {
            let mut path_oram = PathORAM::new_empty();
            path_oram.reset(prefix, oram_config);
            path_oram
        }
        pub fn from_backup(
            oram_config: &OramConfig,
            production_path: String,
            backup_path: String,
        ) -> PathORAM {
            let new_path_oram = PathORAM::new(&production_path, oram_config);
            for oram_id in 0..oram_config.number_of_oram() {
                let current_oram_file =
                    { production_path.clone() + "ORAM" + oram_id.to_string().as_str() };
                let backup_oram_file =
                    { backup_path.clone() + "ORAM" + oram_id.to_string().as_str() };
                match fs::copy(backup_oram_file, current_oram_file) {
                    Ok(_) => {}
                    Err(err) => {
                        panic!("ORAM Copy does not work: {}", err.to_string());
                    }
                }
            }
            new_path_oram
        }
        pub fn to_backup(oram_config: &OramConfig, production_path: String, backup_path: String) {
            PathORAM::new(&backup_path, &oram_config);
            for oram_id in 0..oram_config.number_of_oram() {
                let current_oram_file =
                    { production_path.clone() + "ORAM" + oram_id.to_string().as_str() };
                let backup_oram_file =
                    { backup_path.clone() + "ORAM" + oram_id.to_string().as_str() };
                match fs::copy(current_oram_file, backup_oram_file) {
                    Ok(_) => {}
                    Err(err) => {
                        panic!("ORAM Copy does not work: {}", err.to_string());
                    }
                }
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Path {
        #[serde(with = "serde_bytes")]
        buckets: Vec<u8>,
    }

    impl Path {
        pub fn new(buckets: Vec<u8>) -> Self {
            Path { buckets }
        }
        pub fn destroy(self) -> Vec<u8> {
            self.buckets
        }
        pub fn serialize(&self) -> Vec<u8> {
            let encoded: Vec<u8> = bincode::serialize(self).unwrap();
            encoded
        }
    }
}
