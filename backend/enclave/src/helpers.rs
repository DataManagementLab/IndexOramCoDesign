pub mod range {
    use serde::{Deserialize, Serialize};
    use std::vec::Vec;

    use sql_engine::sql_data_types::components::SqlDataType;
    use sql_engine::sql_data_types::functions::{compress_sql_data_type, decompress_sql_data_type};
    use sql_engine::sql_database::components::SqlAttribute;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ByteRange {
        #[serde(with = "serde_bytes")]
        lower: Vec<u8>,
        #[serde(with = "serde_bytes")]
        upper: Vec<u8>,
    }

    #[allow(dead_code)]
    impl ByteRange {
        pub fn lower(&self) -> &Vec<u8> {
            &self.lower
        }
        pub fn upper(&self) -> &Vec<u8> {
            &self.upper
        }
        pub fn new(lower: Vec<u8>, upper: Vec<u8>) -> Self {
            ByteRange { lower, upper }
        }
        pub fn set_lower(&mut self, lower: Vec<u8>) {
            self.lower = lower;
        }
        pub fn set_upper(&mut self, upper: Vec<u8>) {
            self.upper = upper;
        }
    }

    pub fn sql_data_type_range_to_lossy_byte_range(range: &Range<SqlDataType>) -> ByteRange {
        let lower = compress_sql_data_type(range.lower(), true, false);
        let upper = compress_sql_data_type(range.upper(), true, true);
        ByteRange::new(lower, upper)
    }

    pub fn byte_range_to_sql_data_types(
        range: &ByteRange,
        attribute_config: &SqlAttribute,
    ) -> (SqlDataType, SqlDataType) {
        let lower = decompress_sql_data_type(range.lower(), attribute_config);
        let upper = decompress_sql_data_type(range.upper(), attribute_config);
        (lower, upper)
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Range<T>
    where
        T: Ord,
    {
        lower: T,
        upper: T,
    }

    #[allow(dead_code)]
    impl<T: std::cmp::Ord> Range<T> {
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
        pub fn extend(&mut self, other: Range<T>) {
            let other_range = other.destroy_and_return_components();
            if self.lower().cmp(&other_range.0).is_gt() {
                self.lower = other_range.0;
            }
            if self.upper().cmp(&other_range.1).is_lt() {
                self.upper = other_range.1;
            }
        }
        pub fn extend_lower(&mut self, other: T) {
            if self.lower().cmp(&other).is_gt() {
                self.lower = other;
            }
        }
        pub fn extend_upper(&mut self, other: T) {
            if self.upper().cmp(&other).is_lt() {
                self.upper = other;
            }
        }
        pub fn intersects(&self, other: &Range<T>) -> bool {
            if self.lower().cmp(&other.lower()).is_ge() && self.lower().cmp(&other.upper()).is_le()
            {
                return true;
            }
            if self.upper().cmp(&other.lower()).is_ge() && self.upper().cmp(&other.upper()).is_le()
            {
                return true;
            }
            if self.lower().cmp(&other.lower()).is_le() && self.upper().cmp(&other.upper()).is_ge()
            {
                return true;
            }
            return false;
        }
        pub fn contains(&self, other: &T) -> bool {
            if self.lower().cmp(other).is_le() && self.upper().cmp(other).is_ge() {
                return true;
            }
            false
        }
    }
}

pub mod oram_helper {
    use rand::Rng;
    use std::ops::Sub;

    pub fn get_possible_positions(
        oram_degree: usize,
        oram_tree_height: usize,
        height: u32,
        position: u32,
    ) -> (u32, u32) {
        if height >= (oram_tree_height as u32) {
            return (position, position);
        }
        let amount_of_nodes_in_height = (oram_degree as u32).pow(height);
        let area_size = (get_number_of_leaves(oram_degree, oram_tree_height) as u32)
            / amount_of_nodes_in_height;
        let area_index = (position - 1) / area_size;
        // area_index: Amount of areas that fit into the position number (come before the position)
        // -1 is for considering the edge case of the most right position in an area
        let area_start = (area_size * area_index) + 1;
        (area_start, (area_start + area_size - 1))
    }

    #[allow(dead_code)]
    pub fn get_number_of_intersecting_buckets(
        oram_degree: usize,
        oram_tree_height: usize,
        pos1: u32,
        pos2: u32,
    ) -> u32 {
        let mut intersecting_nodes: u32 = 1;

        let number_of_leaves = get_number_of_leaves(oram_degree, oram_tree_height);
        for level_i in 1..oram_tree_height {
            let index1 = index_at_oram_level(oram_degree, pos1, level_i, number_of_leaves);
            let index2 = index_at_oram_level(oram_degree, pos2, level_i, number_of_leaves);
            if index1 == index2 {
                intersecting_nodes += 1;
            } else {
                break;
            }
        }
        intersecting_nodes
    }

    // level starting from zero (root level)
    #[allow(dead_code)]
    pub fn index_at_oram_level(
        oram_degree: usize,
        leaf: u32,
        level: usize,
        number_of_leaves: usize,
    ) -> usize {
        let level_len = oram_degree.pow(level as u32);
        let area_size = number_of_leaves / level_len;
        // AREA SIZE: The number of leaves that are represented by one bucket in this level
        let leaf = (leaf as usize) - 1;
        leaf / area_size
    }

    // logical position: starts with one
    pub fn get_random_oram_position(oram_degree: usize, oram_tree_height: usize) -> u32 {
        let mut rng = rand::thread_rng();
        let number_leaves = get_number_of_leaves(oram_degree, oram_tree_height) + 1;
        let rand_pos: u32 = rng.gen_range(1, number_leaves as u32);
        rand_pos
    }

    pub fn get_random_oram_id(number_of_oram: u32) -> u32 {
        let mut rng = rand::thread_rng();
        let oram_id: u32 = rng.gen_range(0, number_of_oram);
        oram_id
    }

    pub fn get_number_of_leaves(oram_degree: usize, oram_tree_height: usize) -> usize {
        let number_leaves = usize::pow(oram_degree, oram_tree_height.sub(1) as u32);
        number_leaves
    }

    #[allow(dead_code)]
    pub fn get_number_of_inner_nodes(oram_degree: u32, oram_tree_height: usize) -> u32 {
        get_number_of_tree_nodes(oram_degree, (oram_tree_height - 1) as u32)
    }

    pub fn get_number_of_tree_nodes(oram_degree: u32, height: u32) -> u32 {
        u32::pow(oram_degree, height).sub(1)
    }
}

pub mod convert {
    use std::vec::Vec;

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn sparse_bytes_to_u32(bytes: &Vec<u8>) -> u32 {
        assert!(bytes.len() <= 4, "len is {}", bytes.len());
        let mut u32_array = [0u8; 4];
        for i in 0..bytes.len() {
            u32_array[i + (4 - bytes.len())] = bytes[i];
        }
        u32::from_be_bytes(u32_array)
    }
}

pub mod generators {
    use serde::{Deserialize, Serialize};
    use std::time::SystemTime;
    use std::untrusted::time::SystemTimeEx;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct PacketIdProvider {
        current: u128,
    }

    impl PacketIdProvider {
        pub fn new() -> Self {
            PacketIdProvider { current: 1u128 }
        }
        pub fn make_id(&mut self) -> u128 {
            let id = self.current;
            self.current += 1;
            id
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct QueryIdProvider {
        current: u128,
    }

    impl QueryIdProvider {
        pub fn new() -> Self {
            QueryIdProvider { current: 1 }
        }
        pub fn make_id(&mut self) -> u128 {
            let id = self.current;
            self.current += 1;
            id
        }
        pub fn last(&self) -> u128 {
            self.current - 1
        }
    }

    pub fn get_unix_timestamp() -> u64 {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        }
    }
}
