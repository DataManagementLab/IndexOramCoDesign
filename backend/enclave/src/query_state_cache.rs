use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use enclave_state::EnclaveState;
use oblivious_data_structures::ob_tree::api::traverse_ob_tree;
use oblivious_data_structures::ob_tree::components::{
    ObTreeDirectory,
};
use query_state::{NextPos, QueryState};
use {DEBUG_RUNTIME_CHECKS};

/// The cache of QueryStates
#[derive(Serialize, Deserialize, Clone)]
pub struct QueryStateCache {
    /// The latest query that is returned by the protocol (every query id equal or less than this is returned).
    /// The number 0 is reserved.
    served: u128,
    /// Contains all cached QueryStates.
    map: HashMap<u128, QueryState>,
    /// The greatest query id that is in cache. Number 0 is reserved.
    last: u128,
}

impl QueryStateCache {
    /// Generates a new empty QueryStateCache
    pub fn new_empty() -> Self {
        QueryStateCache {
            served: 0u128,
            map: HashMap::new(),
            last: 0u128,
        }
    }
    pub fn get_mut(&mut self, key: &u128) -> Option<&mut QueryState> {
        self.map.get_mut(key)
    }
    pub fn get(&self, key: &u128) -> Option<&QueryState> {
        self.map.get(key)
    }
    pub fn remove(&mut self, key: &u128) -> Option<QueryState> {
        self.map.remove(key)
    }
    pub fn insert_new(
        &mut self,
        ob_tree_directory: &mut ObTreeDirectory,
        mut query_state: QueryState,
    ) -> Option<QueryState> {
        let mut ob_tree = ob_tree_directory
            .mut_tree(&query_state.ob_tree_query().index_id())
            .unwrap();
        match ob_tree
            .mut_query_locks()
            .get_mut(query_state.ob_tree_query().value())
        {
            None => {
                assert!(ob_tree
                    .mut_query_locks()
                    .insert(
                        query_state.ob_tree_query().value().clone(),
                        vec![query_state.id()]
                    )
                    .is_none());
                query_state.set_operation_permission(true);
            }
            Some(some_lock) => {
                if some_lock.is_empty() {
                    query_state.set_operation_permission(true);
                } else {
                    query_state.set_operation_permission(false);
                }
                // TODO: IF range is greater, update key to higher range
                some_lock.push(query_state.id());
            }
        }
        drop(ob_tree);

        if query_state.id() > self.last {
            self.last = query_state.id();
        }
        self.map.insert(query_state.id(), query_state)
    }
    pub fn re_insert(&mut self, query_state: QueryState) -> Option<QueryState> {
        assert!(!(query_state.id() > self.last));
        self.map.insert(query_state.id(), query_state)
    }
    /// Returns the number of cached QueryStates.
    pub fn size(&self) -> usize {
        self.map.len()
    }
    pub fn served(&self) -> u128 {
        self.served
    }
    pub fn set_served(&mut self, served: u128) {
        self.served = served;
    }
    pub fn last(&self) -> u128 {
        self.last
    }
    pub fn set_last(&mut self, last: u128) {
        self.last = last;
    }
}

pub fn state_transition(enclave_state: &EnclaveState, mut query: QueryState) {
    traverse_ob_tree(enclave_state, &mut query);

    let mut query_state_cache = enclave_state.lock_query_state_cache();
    match query.next() {
        NextPos::Finite => {
            let (locality_cache_direct_flush, index_locality_cache) = {
                let dynamic_config = enclave_state.lock_dynamic_config();
                (
                    dynamic_config.locality_cache_direct_flush(),
                    dynamic_config.index_locality_cache(),
                )
            };

            if locality_cache_direct_flush && index_locality_cache {
                let mut index_locality_cache = enclave_state.lock_index_locality_cache();
                match index_locality_cache.as_mut() {
                    None => {}
                    Some(some_locality_cache) => {
                        let mut stash = enclave_state.lock_packet_stash();
                        let mut statistics = enclave_state.lock_statistics();
                        some_locality_cache.flush_packets_of_query_id_to_stash(
                            &mut stash,
                            &query.id(),
                            &mut statistics,
                        );
                    }
                }
            }
            match query.found() {
                None => {}
                Some(some_found) => {
                    if DEBUG_RUNTIME_CHECKS {
                        //if some_found.len() == 1 && (some_found.get(0).unwrap().row().is_some()) {
                        assert!(some_found[0].row().unwrap().values()[0].eq(query
                            .ob_tree_query()
                            .value()
                            .single()
                            .unwrap()));
                        //}
                    }
                    enclave_state
                        .lock_query_response_cache()
                        .insert(query.id(), some_found.clone());
                }
            }
            if query.id() == (query_state_cache.served() + 1) {
                let mut served_id = query.id();
                for query_iter_id in (served_id + 1)..(query_state_cache.last() + 1) {
                    match query_state_cache.get(&query_iter_id) {
                        None => {
                            served_id = query_iter_id;
                        }
                        Some(next_main_query) => match next_main_query.next() {
                            NextPos::Finite => {
                                served_id = query_iter_id;
                            }
                            _ => {
                                break;
                            }
                        },
                    }
                }
                query_state_cache.set_served(served_id);
                //log_runtime(&format!("New served_id: {}", served_id), true);
            }
            let mut obt_directory = enclave_state.lock_obt_tree_directory();
            let mut ob_tree = obt_directory
                .mut_tree(&query.ob_tree_query().index_id())
                .unwrap();
            ob_tree.remove_from_query_locks(
                query.ob_tree_query().value(),
                &query.id(),
                &mut query_state_cache,
            );
            //query_state_cache.remove(&query.id());
            return;
        }
        _ => {}
    }
    query_state_cache.re_insert(query);
}
