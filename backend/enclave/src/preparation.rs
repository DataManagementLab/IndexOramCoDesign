use alloc::string::ToString;
use rand::Rng;
use sgx_types::sgx_status_t;


use std::string::String;
use std::sync::SgxMutex;


use std::vec::Vec;

use config::{DynamicConfig, OramConfig};

use helpers::generators::{
    get_unix_timestamp, PacketIdProvider, QueryIdProvider,
};
use helpers::oram_helper::{get_number_of_leaves, get_number_of_tree_nodes};
use logger::{log_runtime, StatisticsToSend};
use oblivious_ram::api;
use oblivious_ram::components::BucketContent;
use ocall_setup_oram;
use oram_interface::{EnclaveStatistics, EnvironmentVariables};
use query_response_cache::QueryResponseCache;
use query_state_cache::QueryStateCache;
use slot_cache::SlotCache;
use crate::crypto::{generate_random_rid, NonceProvider};
use crate::enclave_state::EnclaveState;
use crate::index_locality_cache::IndexLocalityCache;
use crate::oblivious_data_structures::ob_tree::components::ObTreeDirectory;
use crate::obt_stash::ObTreeNodeCache;
use crate::packet_stash::PacketStash;
use crate::sql_engine::sql_data_types::components::{SqlAbstractDataType, SqlDataType};
use crate::sql_engine::sql_database::components::{
    SqlAttribute, SqlDatabaseScheme, SqlTableRow, SqlTableScheme,
};

pub fn setup_oram(enclave_state: &EnclaveState) {
    let dynamic_config = enclave_state.lock_dynamic_config();
    let mut nonce_provider = enclave_state.lock_nonce_provider();

    let (
        number_of_oram,
        oram_degree,
        oram_tree_height,
        bucket_size,
        bucket_serialized_size,
        bucket_ciphertext_len,
    ) = {
        let oram_config = enclave_state.lock_oram_config();
        (
            oram_config.number_of_oram(),
            oram_config.oram_degree(),
            oram_config.tree_height(),
            oram_config.bucket_size(),
            oram_config.bucket_serialized_size(),
            oram_config.bucket_ciphertext_len(),
        )
    };

    let number_of_leaves = get_number_of_leaves(oram_degree, oram_tree_height) as u32;
    let number_of_nodes = get_number_of_tree_nodes(oram_degree as u32, oram_tree_height as u32);

    for instance in 0..number_of_oram {
        let mut level: u32 = 0;
        let mut current_index_in_level: u32 = 0;
        let mut level_len: u32 = 1;
        let mut area_size = number_of_leaves;
        let mut number_of_already_sent_buckets: u32 = 0;

        let mut buckets: Vec<u8> = Vec::new();

        for node_iter in 0..number_of_nodes {
            let area_start = (area_size * current_index_in_level) + 1;
            let bucket = BucketContent::new_as_dummy(
                (area_start, (area_start + area_size - 1)),
                bucket_size,
            );
            buckets.append(&mut bucket.encrypt(
                dynamic_config.shared_enclave_key(),
                nonce_provider.make_nonce(),
                bucket_serialized_size,
                bucket_ciphertext_len,
            ));

            if (node_iter % 10 == 0) || (node_iter == (number_of_nodes - 1)) {
                let buckets_len = buckets.len() as u32;
                let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
                unsafe {
                    ocall_setup_oram(
                        &mut rt as *mut sgx_status_t,
                        instance as u32,
                        number_of_already_sent_buckets,
                        buckets.as_ptr(),
                        buckets_len,
                    );
                }
                number_of_already_sent_buckets = node_iter + 1;
                buckets.truncate(0);
            }

            current_index_in_level += 1;
            if current_index_in_level == level_len {
                current_index_in_level = 0;
                level += 1;

                level_len = oram_degree.pow(level) as u32;
                area_size = number_of_leaves / level_len;
            }
        }

        assert_eq!(number_of_already_sent_buckets, number_of_nodes);
    }
    log_runtime("Initial ORAM generation by the enclave has finished.", true);
}

pub fn check_environment(oram_config: &OramConfig) {
    let environment_vars = EnvironmentVariables::new(
        oram_config.number_of_oram(),
        oram_config.tree_height(),
        oram_config.oram_degree(),
        oram_config.bucket_size(),
        oram_config.bucket_serialized_size(),
        oram_config.bucket_ciphertext_len(),
    );
    api::send_environment_variables(environment_vars);
}

fn create_dynamic_config(
    index_locality_cache: bool,
    bucket_size: usize,
    min_matching_prefix_level: u32,
) -> DynamicConfig {
    let mut shared_key = [0u8; crate::SHARED_KEY_LEN];
    for i in 0..shared_key.len() {
        let mut rng = rand::thread_rng();
        let a_byte: u8 = rng.gen();
        shared_key[i] = a_byte;
    }

    let mut dummy_nonce_provider = NonceProvider::new();
    let dummy_bucket_content = BucketContent::new_as_dummy((0, 0), bucket_size);
    let bucket_content_byte_size =
        bincode::serialized_size(&dummy_bucket_content).expect("") as usize;

    /*
    let bucket1 = dummy_bucket_content.encrypt_to_bucket(&shared_key, dummy_nonce_provider.make_nonce());
    //Bucket::new(dummy_bucket_content.serialize_content(&shared_key));

    let oram_byte_size = (MAX_BUCKET_SIZE * get_number_of_tree_nodes(TREE_HEIGHT as u32)) * NUMBER_OF_ORAM;
    log_runtime(&format!("Your oblivious storage has a size of {} bytes ({} MB)", oram_byte_size, oram_byte_size.div(usize::pow(10, 6))), true);

    let mut dummy_bucket_content2 = BucketContent::new_as_dummy();
    //Bucket::new(dummy_bucket_content2.serialize_content(&shared_key, ));
    dummy_bucket_content2.insert_packet(Packet::new_dummy(MAX_PACKET_SIZE));
    let bucket_content_byte_size2 = bincode::serialized_size(&dummy_bucket_content2).expect("") as usize;
    let bucket2 = dummy_bucket_content2.encrypt_to_bucket(&shared_key, dummy_nonce_provider.make_nonce());
    assert_eq!(bucket_content_byte_size, bucket_content_byte_size2);
    assert_eq!(bucket1.content().len(), bucket2.content().len());
     */

    let mut dynamic_config: DynamicConfig =
        DynamicConfig::new(false, true, min_matching_prefix_level);
    dynamic_config.set_index_locality_cache(index_locality_cache);
    dynamic_config.set_shared_enclave_key(shared_key);
    //dynamic_config.deactivate_encryption();
    dynamic_config
}

fn prepare_ycsb_database() -> SqlDatabaseScheme {
    let mut database_scheme = SqlDatabaseScheme::new_empty(String::from("ycsb"));
    let mut attributes: Vec<SqlAttribute> = Vec::new();
    attributes.push(SqlAttribute::new(
        String::from("YCSB_KEY"),
        SqlAbstractDataType::AbstractSQLText,
        true,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD0"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD1"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD2"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD3"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD4"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD5"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD6"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD7"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD8"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));
    attributes.push(SqlAttribute::new(
        String::from("FIELD9"),
        SqlAbstractDataType::AbstractSQLText,
        false,
    ));

    database_scheme.add_table(SqlTableScheme::new(
        String::from("usertable"),
        0,
        attributes,
    ));

    //let (data, rids) = generate_rows(number_of_records, database_scheme.get_table_scheme_by_str("usertable").unwrap(), 0);

    database_scheme
}

pub fn prepare_ycsb_obt(
    fill_grade: usize,
    active_index_locality_flag: bool,
    oram_config: OramConfig,
) -> EnclaveState {
    let mut database_scheme = prepare_ycsb_database();
    let number_of_trees = database_scheme
        .get_table_scheme_by_str("usertable")
        .unwrap()
        .attributes()
        .len();

    let index_locality_cache: Option<IndexLocalityCache> = if active_index_locality_flag {
        println!("Index Locality Cache is active");
        Some(IndexLocalityCache::new_empty())
    } else {
        println!("Index Locality Cache is not active");
        None
    };

    let bucket_size = oram_config.bucket_size();
    let standard_min_matching_prefix_level = oram_config.tree_height() - 1;
    let enclave_state = EnclaveState::new(
        SgxMutex::new(create_dynamic_config(
            index_locality_cache.is_some(),
            bucket_size,
            standard_min_matching_prefix_level as u32,
        )),
        SgxMutex::new(PacketStash::new_empty()),
        SgxMutex::new(index_locality_cache),
        SgxMutex::new(ObTreeNodeCache::new_empty()),
        SgxMutex::new(ObTreeDirectory::new()),
        SgxMutex::new(database_scheme),
        SgxMutex::new(EnclaveStatistics::new(
            active_index_locality_flag,
            fill_grade as u32,
        )),
        SgxMutex::new(NonceProvider::new()),
        SgxMutex::new(QueryIdProvider::new()),
        SgxMutex::new(SlotCache::new_empty()),
        SgxMutex::new(QueryStateCache::new_empty()),
        SgxMutex::new(QueryResponseCache::new_empty()),
        SgxMutex::new(PacketIdProvider::new()),
        SgxMutex::new(oram_config),
        SgxMutex::new(StatisticsToSend::new()),
        fill_grade,
    );
    ObTreeDirectory::initialize(&enclave_state);

    enclave_state
}

pub fn generate_rows(
    amount: usize,
    table_scheme: &SqlTableScheme,
) -> (Vec<SqlTableRow>, Vec<SqlDataType>) {
    let mut rows: Vec<SqlTableRow> = Vec::with_capacity(amount);
    let mut rids: Vec<SqlDataType> = Vec::with_capacity(amount);
    for _ in 0..amount {
        let (row, rid, _) = generate_row(table_scheme);
        rows.push(row);
        rids.push(rid);
    }
    (rows, rids)
}

pub fn generate_row(table_scheme: &SqlTableScheme) -> (SqlTableRow, SqlDataType, usize) {
    let key_index = table_scheme.primary_key() as usize;
    //log_runtime(&format!("Generation of {} example rows starts...", amount), true);
    let mut rid = SqlDataType::SQLNull;
    let mut data_size = 0;
    let mut row: Vec<SqlDataType> = Vec::with_capacity(table_scheme.attributes().len());
    for (attribute_i, attribute) in table_scheme.attributes().iter().enumerate() {
        let mut rng = rand::thread_rng();
        match attribute.data_type() {
            SqlAbstractDataType::AbstractSQLInteger => {
                let val: i64 = rng.gen();
                let val = SqlDataType::SQLInteger(val);
                if attribute_i == key_index {
                    rid = val.clone();
                }
                row.push(val);
            }
            SqlAbstractDataType::AbstractSQLBool => {
                let rnd: usize = rng.gen_range(0, 2);
                let val = if rnd > 0 { true } else { false };
                row.push(SqlDataType::SQLBool(val));
            }
            SqlAbstractDataType::AbstractSQLText => {
                let val: String = if attribute_i == key_index {
                    let len: usize = rng.gen_range(32, 64);
                    let mut text = generate_random_rid(len);
                    let timestamp = get_unix_timestamp().to_string();
                    text.push_str(timestamp.as_str());
                    text
                } else {
                    let len: usize = rng.gen_range(1, 100);
                    let mut text = generate_random_rid(len);
                    text
                };
                let val = SqlDataType::SQLText(val);
                if attribute_i == key_index {
                    rid = val.clone();
                }
                row.push(val);
            }
            SqlAbstractDataType::AbstractSQLDate => {
                let day: u8 = rng.gen_range(1, 28);
                let month: u8 = rng.gen_range(1, 12);
                let year: u16 = rng.gen_range(0, 3000);
                row.push(SqlDataType::SQLDate { day, month, year });
            }
            SqlAbstractDataType::AbstractSQLDateTime => {
                let day: u8 = rng.gen_range(1, 28);
                let month: u8 = rng.gen_range(1, 12);
                let year: u16 = rng.gen_range(0, 3000);
                let hour: u8 = rng.gen_range(0, 23);
                let minute: u8 = rng.gen_range(0, 59);
                let second: u8 = rng.gen_range(0, 59);
                row.push(SqlDataType::SQLDateTime {
                    day,
                    month,
                    year,
                    hour,
                    minute,
                    second,
                });
            }
            SqlAbstractDataType::AbstractSQLTime => {
                let hour: u8 = rng.gen_range(0, 23);
                let minute: u8 = rng.gen_range(0, 59);
                let second: u8 = rng.gen_range(0, 59);
                row.push(SqlDataType::SQLTime {
                    hour,
                    minute,
                    second,
                });
            }
            SqlAbstractDataType::AbstractSQLNull => {
                row.push(SqlDataType::SQLNull);
            }
        }
    }
    let row = SqlTableRow::new(row);
    data_size += row.byte_size();
    //log_runtime(&format!("Generation of example rows has completed! Size: {} bytes ({} MB)", data_size, data_size.div(usize::pow(10, 6))), true);
    (row, rid, data_size)
}
