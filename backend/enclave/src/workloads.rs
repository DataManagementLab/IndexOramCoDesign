use alloc::collections::BTreeMap;
use core::cmp::min;
use rand::prelude::SliceRandom;
use rand::Rng;
use std::collections::HashMap;
use std::string::String;
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::vec::Vec;

use clear_index_locality_cache_to_packet_stash;
use helpers::oram_helper::get_possible_positions;
use helpers::range::Range;
use oblivious_data_structures::ob_tree::components::{
    ObTree, ObTreeQuery, ObTreeQueryValue, ObTreeQueryValueRange,
};
use oblivious_data_structures::position_tag::PositionTag;
use oblivious_ram::api;
use oblivious_ram::api::send_generic_request;
use oblivious_ram::functions::{read_process_and_evict_oram_request_batch, Object};
use oblivious_ram::packaging::Packet;
use oram_interface::{GenericRequestToServer, ResourceUsageReport};
use preparation::generate_row;
use query_state::ObjectType::NodeObjectType;
use query_state::{
    InsertOperationState, NextPos, ObTreeOperation, ObjectType, ParentNodeId, QueryState,
};
use query_state_cache::state_transition;
use sql_engine::sql_database::components::SqlAttribute;
use PRINT_PACKET_EVICTIONS;
use {enclave_caches, DEBUG_PRINTS};
use {ExperimentWorkloadRequest, IndexLocalityCache};

use crate::enclave_state::EnclaveState;
use crate::logger::*;
use crate::oblivious_data_structures::page::SlotContent;
use crate::packet_stash::clear_to_oram;
use crate::preparation::generate_rows;
use crate::sql_engine::sql_data_types::components::SqlDataType;

fn process_query_state_cache(enclave_state: &EnclaveState) {
    {
        let mut query_state_cache = enclave_state.lock_query_state_cache();
        if query_state_cache.served() == query_state_cache.last() {
            assert_eq!(
                query_state_cache.size(),
                0,
                "size(): {}\r\n, served(): {}\r\n, last(): {}",
                query_state_cache.size(),
                query_state_cache.served(),
                query_state_cache.last()
            );
            return;
        }
    }

    let oram_access_batches_size: usize = {
        let dynamic_config = enclave_state.lock_dynamic_config();
        let size: usize = dynamic_config.oram_access_batches_size();
        if dynamic_config.oram_random_batch_size() {
            let mut rng = rand::thread_rng();
            rng.gen_range(1, size + 1)
        } else {
            size
        }
    };

    let mut needed_objects: HashMap<u128, ObjectType> = HashMap::new();

    let min_matching_prefix_level = enclave_state
        .lock_dynamic_config()
        .min_matching_prefix_level();

    let (current_query_id, mut queries_to_process) = {
        let mut query_state_cache = enclave_state.lock_query_state_cache();
        let current_query_id = query_state_cache.served() + 1;
        let mut queries_to_process: Vec<u128> = vec![current_query_id];
        (current_query_id, queries_to_process)
    };

    let (is_valid, shared_oram_instance, leaf, packet_id, object_type) = match enclave_state
        .lock_query_state_cache()
        .get_mut(&current_query_id)
    {
        None => {
            panic!(
                "Main Query with ID {} not found in the query_state_cache.",
                current_query_id
            );
        }
        Some(some_current_query) => {
            some_current_query.set_operation_permission(true);
            let (current_next_pos, object_type) = some_current_query.next_as_tuple(enclave_state);
            let (shared_oram_instance, leaf, packet_id) = current_next_pos.destroy();
            let is_valid = some_current_query.next().is_valid();
            (is_valid, shared_oram_instance, leaf, packet_id, object_type)
        }
    };

    if is_valid {
        let mut leaves: Vec<u32> = Vec::new();

        {
            if !(enclave_caches::api::contains_slot_or_node(
                enclave_state,
                &packet_id,
                &object_type,
            ) || (enclave_state.lock_dynamic_config().index_locality_cache()
                && enclave_state
                    .lock_index_locality_cache()
                    .as_mut()
                    .unwrap()
                    .remove_and_get_object(enclave_state, &packet_id, &object_type)))
            {
                needed_objects.insert(packet_id, object_type);
                leaves.push(leaf);
            }
        }

        let mut interval: Option<(u32, u32)> = {
            if !needed_objects.is_empty() {
                let (oram_degree, oram_tree_height) = {
                    let oram_config = enclave_state.lock_oram_config();
                    (oram_config.oram_degree(), oram_config.tree_height())
                };
                Some(get_possible_positions(
                    oram_degree,
                    oram_tree_height,
                    min_matching_prefix_level,
                    leaf,
                ))
            } else {
                None
            }
        };

        {
            let mut query_state_cache = enclave_state.lock_query_state_cache();
            let query_state_machine = query_state_cache.size() > 1;

            if query_state_machine {
                let last_query_id = query_state_cache.last();
                let mut query_iter = current_query_id + 1;
                while (query_iter <= last_query_id) && (leaves.len() < oram_access_batches_size) {
                    match query_state_cache.get_mut(&query_iter) {
                        None => {}
                        Some(some_current_query) => {
                            if some_current_query.operation_status().is_active() {
                                match some_current_query.next() {
                                    NextPos::Request(some_next_pos, object_type) => {
                                        let mut query_iter_can_be_served_locally = false;
                                        {
                                            if enclave_caches::api::contains_slot_or_node(
                                                enclave_state,
                                                some_next_pos.packet_id(),
                                                object_type,
                                            ) || (enclave_state
                                                .lock_dynamic_config()
                                                .index_locality_cache()
                                                && enclave_state
                                                    .lock_index_locality_cache()
                                                    .as_mut()
                                                    .unwrap()
                                                    .remove_and_get_object(
                                                        enclave_state,
                                                        some_next_pos.packet_id(),
                                                        object_type,
                                                    ))
                                            {
                                                query_iter_can_be_served_locally = true;
                                                queries_to_process.push(query_iter);
                                            }
                                        }

                                        if !query_iter_can_be_served_locally
                                            && (some_next_pos.oram_id() == shared_oram_instance)
                                        {
                                            let leaf = some_next_pos.path();
                                            if interval.is_none()
                                                || ((leaf >= interval.as_ref().unwrap().0)
                                                    && (leaf <= interval.as_ref().unwrap().1))
                                            {
                                                if interval.is_none() {
                                                    interval = {
                                                        let (oram_degree, oram_tree_height) = {
                                                            let oram_config =
                                                                enclave_state.lock_oram_config();
                                                            (
                                                                oram_config.oram_degree(),
                                                                oram_config.tree_height(),
                                                            )
                                                        };
                                                        Some(get_possible_positions(
                                                            oram_degree,
                                                            oram_tree_height,
                                                            min_matching_prefix_level,
                                                            leaf,
                                                        ))
                                                    };
                                                }

                                                if !leaves.contains(&leaf) {
                                                    leaves.push(leaf);
                                                }
                                                needed_objects.insert(
                                                    some_next_pos.copy_packet_id(),
                                                    object_type.clone(),
                                                );
                                                queries_to_process.push(query_iter);
                                            }
                                        };
                                    }
                                    NextPos::Start => {
                                        let obt_query = some_current_query.ob_tree_query();
                                        match enclave_state
                                            .lock_obt_tree_directory()
                                            .get_tree(&obt_query.index_id())
                                        {
                                            None => {
                                                panic!("The index tree must exists.");
                                            }
                                            Some(some_index_tree) => {
                                                let root = some_index_tree.root();

                                                let mut query_iter_can_be_served_locally = false;
                                                {
                                                    let object_type = ObjectType::NodeObjectType;
                                                    if enclave_caches::api::contains_slot_or_node(
                                                        enclave_state,
                                                        root.packet_id(),
                                                        &object_type,
                                                    ) || (enclave_state
                                                        .lock_dynamic_config()
                                                        .index_locality_cache()
                                                        && enclave_state
                                                            .lock_index_locality_cache()
                                                            .as_mut()
                                                            .unwrap()
                                                            .remove_and_get_object(
                                                                enclave_state,
                                                                root.packet_id(),
                                                                &object_type,
                                                            ))
                                                    {
                                                        query_iter_can_be_served_locally = true;
                                                        queries_to_process.push(query_iter);
                                                    }
                                                }

                                                if !query_iter_can_be_served_locally
                                                    && (root.oram_id() == shared_oram_instance)
                                                {
                                                    let leaf = root.path();
                                                    if interval.is_none()
                                                        || ((leaf >= interval.as_ref().unwrap().0)
                                                            && (leaf
                                                                <= interval.as_ref().unwrap().1))
                                                    {
                                                        if interval.is_none() {
                                                            interval = {
                                                                let (oram_degree, oram_tree_height) = {
                                                                    let oram_config = enclave_state
                                                                        .lock_oram_config();
                                                                    (
                                                                        oram_config.oram_degree(),
                                                                        oram_config.tree_height(),
                                                                    )
                                                                };
                                                                Some(get_possible_positions(
                                                                    oram_degree,
                                                                    oram_tree_height,
                                                                    min_matching_prefix_level,
                                                                    leaf,
                                                                ))
                                                            };
                                                        }

                                                        if !leaves.contains(&leaf) {
                                                            leaves.push(leaf);
                                                        }
                                                        needed_objects.insert(
                                                            root.copy_packet_id(),
                                                            ObjectType::NodeObjectType,
                                                        );
                                                        queries_to_process.push(query_iter);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    NextPos::InvalidRequest => {
                                        queries_to_process.push(query_iter);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    };
                    query_iter += 1;
                }
            }
        }

        if !needed_objects.is_empty() {
            if enclave_state
                .lock_dynamic_config()
                .dummy_fill_oram_access_batch()
            {
                let interval_size =
                    (interval.as_ref().unwrap().1 - (interval.as_ref().unwrap().0 - 1)) as usize;
                if interval_size <= oram_access_batches_size {
                    leaves = (interval.as_ref().unwrap().0..(interval.as_ref().unwrap().1 + 1))
                        .collect();
                    let mut rng = rand::thread_rng();
                    leaves.shuffle(&mut rng);
                } else {
                    while leaves.len() < oram_access_batches_size {
                        if leaves.len() == interval_size {
                            break;
                        }
                        let mut rng = rand::thread_rng();
                        let mut rand_leaf = rng.gen_range(
                            interval.as_ref().unwrap().0,
                            interval.as_ref().unwrap().1 + 1,
                        );
                        while leaves.contains(&rand_leaf) {
                            rand_leaf = rng.gen_range(
                                interval.as_ref().unwrap().0,
                                interval.as_ref().unwrap().1 + 1,
                            );
                        }
                        leaves.push(rand_leaf);
                    }
                }
            }

            read_process_and_evict_oram_request_batch(
                enclave_state,
                shared_oram_instance,
                leaves,
                needed_objects,
            );
        }
    }

    if DEBUG_PRINTS || PRINT_PACKET_EVICTIONS {
        println!("State transitions start...");
    }
    for query_id in queries_to_process.iter() {
        let query = enclave_state
            .lock_query_state_cache()
            .remove(query_id)
            .unwrap();
        state_transition(enclave_state, query);
    }
}

pub fn process_experiment_workload_request(
    enclave_state: &EnclaveState,
    exp_request: ExperimentWorkloadRequest,
) {
    {
        let mut dynamic_config = enclave_state.lock_dynamic_config();

        dynamic_config.set_aggressive_locality_caching(exp_request.aggressive_caching());
        if exp_request.aggressive_caching() {
            assert!(dynamic_config.index_locality_cache());
        }
        dynamic_config.set_direct_eviction(exp_request.direct_eviction());
        dynamic_config.set_locality_cache_direct_flush(exp_request.locality_cache_direct_flush());
        dynamic_config.set_min_matching_prefix_level(exp_request.min_matching_prefix_level());
        dynamic_config.set_bounded_locality_cache(exp_request.bounded_locality_cache());
        dynamic_config.set_dummy_fill_oram_access_batch(exp_request.dummy_fill_oram_access_batch());
        dynamic_config.set_oram_access_batches_size(exp_request.oram_access_batch_size());
        dynamic_config.set_oram_random_batch_size(exp_request.oram_random_batch_size());
        dynamic_config
            .set_keep_not_requested_in_buckets(exp_request.keep_not_requested_in_buckets());
    }

    match exp_request.query_type() {
        "INSERTION" => {
            select_and_mixed_workload(enclave_state, 0, &exp_request);
        }
        "SELECTION" => {
            select_and_mixed_workload(enclave_state, exp_request.query_amount(), &exp_request);
        }
        "SELECT80INSERT20" => {
            let select_amount = ((exp_request.query_amount() as f64) * 0.8) as usize;
            select_and_mixed_workload(enclave_state, select_amount, &exp_request);
        }
        "SELECT20INSERT80" => {
            let select_amount = ((exp_request.query_amount() as f64) * 0.2) as usize;
            select_and_mixed_workload(enclave_state, select_amount, &exp_request);
        }
        "SELECT50INSERT50" => {
            let select_amount = ((exp_request.query_amount() as f64) * 0.5) as usize;
            select_and_mixed_workload(enclave_state, select_amount, &exp_request);
        }
        &_ => {}
    }

    fn select_and_mixed_workload(
        enclave_state: &EnclaveState,
        selections: usize,
        exp_request: &ExperimentWorkloadRequest,
    ) {
        let mut rids_to_search: Option<Vec<SqlDataType>> = {
            if exp_request.pre_data_volume() > 0 {
                let mut inserted_rids: Option<Vec<SqlDataType>> = ycsb_obt_query_workload(
                    exp_request.experiment_id(),
                    exp_request.experiment_name(),
                    false,
                    None,
                    exp_request.pre_data_volume(),
                    exp_request.query_batch_size(),
                    exp_request.clear_stash_afterwards(),
                    selections > 0,
                    false,
                    exp_request.index() as u16,
                    enclave_state,
                );
                match inserted_rids.as_mut() {
                    None => None,
                    Some(some_inserted_rids) => {
                        if exp_request.skew() {
                            log_runtime("RIDs to search are sorted.", true);
                            some_inserted_rids.sort();
                        } else {
                            let mut rng = rand::thread_rng();
                            some_inserted_rids.shuffle(&mut rng);
                        }
                        let mut rng = rand::thread_rng();
                        assert!(some_inserted_rids.len() >= selections);
                        let start_index: usize =
                            rng.gen_range(0, some_inserted_rids.len() - selections);
                        let end_index: usize = start_index + selections;
                        Some(some_inserted_rids[start_index..end_index].to_vec())
                    }
                }
            } else {
                None
            }
        };
        if selections > 0 {
            let mut rng = rand::thread_rng();
            rids_to_search.as_mut().unwrap().shuffle(&mut rng);
        }

        if enclave_state.lock_dynamic_config().index_locality_cache() {
            clear_index_locality_cache_to_packet_stash(enclave_state);
        }
        clear_to_oram(enclave_state);

        ycsb_obt_query_workload(
            exp_request.experiment_id(),
            exp_request.experiment_name(),
            false,
            rids_to_search,
            exp_request.query_amount(),
            exp_request.query_batch_size(),
            exp_request.clear_stash_afterwards(),
            false,
            true,
            exp_request.index() as u16,
            &enclave_state,
        );
    }

    log_runtime(
        &format!(
            "Workload with name >{}< has successfully finished.",
            exp_request.experiment_name()
        ),
        true,
    );
}

fn ycsb_obt_query_workload(
    exp_id: u64,
    name: &str,
    initial: bool,
    mut rids_to_search: Option<Vec<SqlDataType>>,
    query_amount: usize,
    query_batch_size: usize,
    clear_stash_afterwards: bool,
    give_me_rids: bool,
    display_stats: bool,
    index_id: u16,
    enclave_state: &EnclaveState,
) -> Option<Vec<SqlDataType>> {
    assert_eq!(query_amount % query_batch_size, 0);
    let mut inserted_rids: Option<Vec<SqlDataType>> = if give_me_rids {
        Some(Vec::with_capacity(query_amount))
    } else {
        None
    };

    let mut number_selects = match rids_to_search.as_ref() {
        None => 0,
        Some(some_rids_to_search) => some_rids_to_search.len(),
    };
    let mut number_inserts = query_amount - number_selects;
    assert_eq!(number_inserts + number_selects, query_amount);
    log_runtime(
        &format!(
            "Number of insertions: {}, number of selections: {}",
            number_inserts, number_selects
        ),
        true,
    );

    let mut query_distribution = Vec::with_capacity(query_amount);
    query_distribution.append(&mut vec![0u8; number_inserts]);
    query_distribution.append(&mut vec![1u8; number_selects]);
    let mut rng = rand::thread_rng();
    query_distribution.shuffle(&mut rng);

    {
        let index_locality_cache = enclave_state.lock_dynamic_config().index_locality_cache();
        let obt_fill_grade = enclave_state.fill_grade();
        enclave_state
            .lock_statistics()
            .reset(index_locality_cache, obt_fill_grade as u32);
        enclave_state.lock_statistics_to_send().reset_and_return();
    }
    api::reset_server_statistics();
    if initial {
        enclave_state.lock_dynamic_config().set_initial(true);
    }

    let database_scheme = enclave_state.lock_database_scheme();
    let table_scheme = database_scheme
        .get_table_scheme_by_str("usertable")
        .unwrap();
    let key_conf = table_scheme.get_attribute(0).unwrap().clone();

    log_runtime(&format!("####### WORKLOAD: {} #######", name), true);
    log_runtime(
        &format!(
            "The primary tree has a height of {} before the workload.",
            enclave_state
                .lock_obt_tree_directory()
                .get_tree(&index_id)
                .unwrap()
                .height()
        ),
        true,
    );
    log_runtime(
        &format!("Workload of {} queries starts...", query_amount),
        true,
    );

    let mut remaining_batch_size = query_batch_size;
    let mut all_queries_are_served = false;
    let mut generated_queries = 0;
    let mut generated_data_size = 0;

    while !all_queries_are_served {
        let mut query_state_cache = enclave_state.lock_query_state_cache();

        for _ in 0..remaining_batch_size {
            if query_distribution[generated_queries] == 0u8 {
                let (row, rid, row_size) = generate_row(table_scheme);
                generated_data_size += row_size;

                match inserted_rids.as_mut() {
                    None => {}
                    Some(some_inserted_rids) => {
                        some_inserted_rids.push(rid);
                    }
                }
                let key = row.values().get(0).unwrap().clone();
                query_state_cache.insert_new(
                    &mut enclave_state.lock_obt_tree_directory(),
                    QueryState::new(
                        enclave_state.lock_query_id_provider().make_id(),
                        ObTreeOperation::INSERT(InsertOperationState::new(SlotContent::Row(row))),
                        ObTreeQuery::new(ObTreeQueryValue::Single(key), key_conf.clone(), index_id),
                        None,
                        NextPos::Start,
                    ),
                );
            } else {
                let current_rid = rids_to_search.as_mut().unwrap().pop().unwrap();

                query_state_cache.insert_new(
                    &mut enclave_state.lock_obt_tree_directory(),
                    QueryState::new(
                        enclave_state.lock_query_id_provider().make_id(),
                        ObTreeOperation::SELECT,
                        ObTreeQuery::new(
                            ObTreeQueryValue::Single(current_rid),
                            key_conf.clone(),
                            index_id,
                        ),
                        None,
                        NextPos::Start,
                    ),
                );
            }
            generated_queries += 1;
            if (generated_queries % 2000) == 0 {
                log_runtime(
                    &format!("{} queries were generated.", generated_queries),
                    true,
                );
            }
        }

        drop(query_state_cache);

        let time = Instant::now();
        process_query_state_cache(enclave_state);
        enclave_state
            .lock_statistics()
            .inc_workload_time(time.elapsed().as_nanos());

        if display_stats {
            let stash = enclave_state.lock_packet_stash();
            let node_cache = enclave_state.lock_obt_node_cache();
            let slot_cache = enclave_state.lock_slot_cache();
            let (free_oram_space_after, evicted_packets) =
                enclave_state.lock_statistics_to_send().reset_and_return();
            let (locality_amount, locality_bytes) = {
                match enclave_state.lock_index_locality_cache().as_ref() {
                    None => (0u64, 0u64),
                    Some(some_cache) => (some_cache.size() as u64, some_cache.byte_size()),
                }
            };
            let (
                stash_number_of_packets,
                stash_total_byte_size,
                stash_max_byte_size,
                stash_average_byte_size,
            ) = stash.resource_usage();
            api::send_generic_request(GenericRequestToServer::ResourceUsageReport(
                ResourceUsageReport::new(
                    stash_number_of_packets,
                    stash_total_byte_size,
                    stash_max_byte_size,
                    stash_average_byte_size,
                    node_cache.size() as u64,
                    node_cache.byte_size() as u64,
                    slot_cache.size() as u64,
                    slot_cache.byte_size() as u64,
                    locality_amount,
                    locality_bytes,
                    free_oram_space_after,
                    evicted_packets as u64,
                ),
            ));
        }

        let cache_size = enclave_state.lock_query_state_cache().size();
        remaining_batch_size = min(
            query_batch_size - cache_size,
            query_amount - generated_queries,
        );
        if remaining_batch_size == 0 && cache_size == 0 {
            all_queries_are_served = true;
        }
    }

    {
        enclave_state
            .lock_statistics()
            .inc_generated_data_byte_size(generated_data_size);
    }

    log_runtime(
        &format!(
            "The primary tree has a height of {} after the workload of {} generated queries.",
            enclave_state
                .lock_obt_tree_directory()
                .get_tree(&index_id)
                .unwrap()
                .height(),
            generated_queries
        ),
        true,
    );

    if display_stats {
        let mut statistics = enclave_state.lock_statistics().clone_me();
        statistics.set_experiment_id(exp_id);
        crate::oblivious_ram::api::send_enclave_statistics(statistics);
    }

    if clear_stash_afterwards {
        log_runtime("Packet stash will be cleared to ORAM.", true);
        clear_to_oram(enclave_state);
    }
    if enclave_state.lock_obt_node_cache().size() != enclave_state.lock_obt_tree_directory().size()
    /* enclave_state.lock_obt_tree_directory().size() */
    {
        panic!("ERROR: enclave_state.lock_obt_node_cache().size(): {} != enclave_state.lock_obt_tree_directory().size(): {}", enclave_state.lock_obt_node_cache().size(), enclave_state.lock_obt_tree_directory().size());
    }

    if initial {
        enclave_state.lock_dynamic_config().set_initial(false);
    }
    inserted_rids
}

/*
pub fn test_ycsb_obt_workload_insert(experiment_name: &str, dynamic_config: &mut DynamicConfig) {
    let fill_grade: usize = 20;
    let number_of_initial_tuples = 15000;
    let number_of_selects = 0;
    let number_of_inserts = 1000;
    let ycsb_key = 0;
    let insert_secondary: bool = false;

    dynamic_config.set_initial(true);
    let (mut packet_stash,
        mut stats,
        mut ob_node_cache,
        mut oram,
        database_scheme,
        mut obt_directory,
        mut index_locality_cache,
        mut rids) =
        prepare_ycsb_obt(number_of_initial_tuples, fill_grade, dynamic_config, insert_secondary);
    let table_scheme = database_scheme.get_table_scheme_by_str("usertable").unwrap();
    //let key_config = table_scheme.get_attribute(1).unwrap();
    assert!(ob_node_cache.is_empty());
    assert!(packet_stash.is_empty());
    dynamic_config.set_initial(false);

    if number_of_selects > 0 {
        stats.reset();
        log_runtime(" ", true);
        log_runtime(&format!("A workload with {} selection starts...", number_of_selects), true);
        log_runtime(&format!("The primary tree has a height of {}", obt_directory.get_tree(&0).unwrap().height()), true);
        let key_config = table_scheme.get_attribute(ycsb_key).unwrap();
        for _i in 0..number_of_selects {
            let mut rng = rand::thread_rng();
            let random_rid = rng.gen_range(0..rids.len());
            let random_rid = rids.get(random_rid).unwrap();
            //log_runtime(&format!("{}: random_rid_index: {}", i, random_rid_index), true);
            let result: Option<SlotContent> = obt_search_key(&random_rid, key_config, ycsb_key, &mut obt_directory, dynamic_config, &mut oram, &mut packet_stash, &mut index_locality_cache, &mut ob_node_cache, &mut stats);
            assert!(result.unwrap().row().unwrap().values().get(ycsb_key).unwrap().eq(random_rid));
        }
        stats.display();
        clear_to_oram(dynamic_config, &mut oram, &mut packet_stash, &mut stats);
        assert!(ob_node_cache.is_empty());
        assert!(packet_stash.is_empty());
    }

    if number_of_inserts > 0 {
        stats.reset();
        log_runtime(&format!("The primary tree has a height of {}", obt_directory.get_tree(&0).unwrap().height()), true);
        let (data_rows, _rids) = generate_rows(number_of_inserts, table_scheme, 0);
        log_runtime("Insertion of example rows starts...", true);
        let bar = ProgressBar::new(data_rows.len() as u64);
        for row in data_rows {
            insert_row(row, 0, &mut obt_directory, table_scheme, fill_grade, dynamic_config, &mut oram, &mut packet_stash, &mut index_locality_cache, &mut ob_node_cache, &mut stats, insert_secondary);
            bar.inc(1);
        }
        bar.finish();
        log_runtime(&format!("The primary tree has a height of {}", obt_directory.get_tree(&0).unwrap().height()), true);
        stats.display();
        clear_to_oram(dynamic_config, &mut oram, &mut packet_stash, &mut stats);
        assert!(ob_node_cache.is_empty());
        assert!(packet_stash.is_empty());
    }
}
 */
