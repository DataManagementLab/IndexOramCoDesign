pub mod range {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Range<T> {
        lower: T,
        upper: T,
    }

    impl<T> Range<T> {
        pub fn new(lower: T, upper: T) -> Self {
            Range { lower, upper }
        }
        pub fn lower(&self) -> &T {
            &self.lower
        }
        pub fn upper(&self) -> &T {
            &self.upper
        }
        pub fn set_lower(&mut self, lower: T) {
            self.lower = lower;
        }
        pub fn set_upper(&mut self, upper: T) {
            self.upper = upper;
        }
        pub fn destroy_and_return_components(self) -> (T, T) {
            (self.lower, self.upper)
        }
    }
}

pub mod oram_helper {
    use rand::Rng;
    use std::ops::Sub;

    /// Number of buckets at this tree level
    pub fn number_of_buckets_in_level(oram_degree: usize, level: u32) -> usize {
        oram_degree.pow(level)
    }

    // level starting from zero (root level)
    pub fn index_at_level(leaf: &u32, area_size: usize) -> usize {
        let leaf = (*leaf as usize) - 1;
        leaf / area_size
        /*
        // Number of buckets at this tree level
        let leaf = *leaf as usize;
        let index = {
            // AREA SIZE: The number of leaves that are represented by one bucket in this level
            let rest = if (leaf % area_size) == 0 {
                // When there is no rest, the logical index suits
                0
            } else {
                // When there is a rest, we need to upgrade the logical index to the next higher
                // bucket
                1
            };
            (leaf / area_size) + rest - 1
            // -1 for getting the physical index (starting from zero)
        };
        index
         */
    }

    pub fn get_number_of_leaves(oram_degree: usize, oram_tree_height: u32) -> usize {
        let number_leaves = usize::pow(oram_degree, oram_tree_height.sub(1) as u32);
        number_leaves
    }

    pub fn get_number_of_tree_nodes(oram_degree: usize, height: u32) -> usize {
        usize::pow(oram_degree, height).sub(1)
    }
}

pub mod convert {
    pub fn u32_to_sparse_bytes(index: u32) -> Vec<u8> {
        let bytes = index.to_be_bytes().to_vec();
        if index < 256u32 {
            return vec![bytes[3]];
        }
        if index < 65536u32 {
            return vec![bytes[2], bytes[3]];
        }
        if index < 16777216u32 {
            return vec![bytes[1], bytes[2], bytes[3]];
        }
        assert!(bytes.len() <= 4);
        bytes
    }

    pub fn sparse_bytes_to_u32(bytes: &Vec<u8>) -> u32 {
        assert!(bytes.len() <= 4, "len is {}", bytes.len());
        let mut u32_array = [0u8; 4];
        for i in 0..bytes.len() {
            u32_array[i + (4 - bytes.len())] = bytes[i];
        }
        u32::from_be_bytes(u32_array)
    }
}

pub mod general {
    use std::time::SystemTime;

    pub fn get_unix_timestamp() -> u64 {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        }
    }
}
