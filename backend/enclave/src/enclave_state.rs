use config::OramConfig;
use serde::{Deserialize, Serialize};
use std::string::String;
use std::sync::{SgxMutex, SgxMutexGuard};
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::vec::Vec;

use helpers::generators::{ObTreeNodeIdProvider, PacketIdProvider, QueryIdProvider};
use logger::StatisticsToSend;
use oram_interface::EnclaveStatistics;
use query_response_cache::QueryResponseCache;
use query_state::QueryState;
use query_state_cache::QueryStateCache;
use slot_cache::SlotCache;

use crate::config::DynamicConfig;
use crate::crypto::NonceProvider;
use crate::index_locality_cache::IndexLocalityCache;
use crate::oblivious_data_structures::ob_tree::components::ObTreeDirectory;
use crate::obt_stash::ObTreeNodeCache;
use crate::packet_stash::PacketStash;
use crate::sql_engine::sql_database::components::SqlDatabaseScheme;

pub struct EnclaveStateCache {
    enclave_state: Option<EnclaveState>,
}

impl EnclaveStateCache {
    pub fn new(enclave_state: Option<EnclaveState>) -> Self {
        EnclaveStateCache { enclave_state }
    }
    pub fn enclave_state_ref(&self) -> Option<&EnclaveState> {
        self.enclave_state.as_ref()
    }
    pub fn set_enclave_state(&mut self, enclave_state: Option<EnclaveState>) {
        self.enclave_state = enclave_state;
    }
}

/// EnclaveState maintains all dynamic information needed at runtime of the protocol.
pub struct EnclaveState {
    dynamic_config: SgxMutex<DynamicConfig>,
    packet_stash: SgxMutex<PacketStash>,
    index_locality_cache: SgxMutex<Option<IndexLocalityCache>>,
    obt_node_cache: SgxMutex<ObTreeNodeCache>,
    obt_tree_directory: SgxMutex<ObTreeDirectory>,
    database_scheme: SgxMutex<SqlDatabaseScheme>,
    statistics: SgxMutex<EnclaveStatistics>,
    nonce_provider: SgxMutex<NonceProvider>,
    query_id_provider: SgxMutex<QueryIdProvider>,
    slot_cache: SgxMutex<SlotCache>,
    query_state_cache: SgxMutex<QueryStateCache>,
    query_response_cache: SgxMutex<QueryResponseCache>,
    packet_id_provider: SgxMutex<PacketIdProvider>,
    oram_config: SgxMutex<OramConfig>,
    statistics_to_send: SgxMutex<StatisticsToSend>,
    fill_grade: usize,
}

impl EnclaveState {
    pub fn new(
        dynamic_config: SgxMutex<DynamicConfig>,
        packet_stash: SgxMutex<PacketStash>,
        index_locality_cache: SgxMutex<Option<IndexLocalityCache>>,
        obt_node_cache: SgxMutex<ObTreeNodeCache>,
        obt_tree_directory: SgxMutex<ObTreeDirectory>,
        database_scheme: SgxMutex<SqlDatabaseScheme>,
        statistics: SgxMutex<EnclaveStatistics>,
        nonce_provider: SgxMutex<NonceProvider>,
        query_id_provider: SgxMutex<QueryIdProvider>,
        slot_cache: SgxMutex<SlotCache>,
        query_state_cache: SgxMutex<QueryStateCache>,
        query_response_cache: SgxMutex<QueryResponseCache>,
        packet_id_provider: SgxMutex<PacketIdProvider>,
        oram_config: SgxMutex<OramConfig>,
        statistics_to_send: SgxMutex<StatisticsToSend>,
        fill_grade: usize,
    ) -> Self {
        EnclaveState {
            dynamic_config,
            packet_stash,
            index_locality_cache,
            obt_node_cache,
            obt_tree_directory,
            database_scheme,
            statistics,
            nonce_provider,
            query_id_provider,
            slot_cache,
            query_state_cache,
            query_response_cache,
            packet_id_provider,
            oram_config,
            statistics_to_send,
            fill_grade,
        }
    }
    pub fn lock_packet_stash(&self) -> SgxMutexGuard<PacketStash> {
        self.packet_stash.lock().unwrap()
    }
    pub fn lock_index_locality_cache(&self) -> SgxMutexGuard<Option<IndexLocalityCache>> {
        self.index_locality_cache.lock().unwrap()
    }
    pub fn lock_obt_node_cache(&self) -> SgxMutexGuard<ObTreeNodeCache> {
        self.obt_node_cache.lock().unwrap()
    }
    pub fn lock_statistics(&self) -> SgxMutexGuard<EnclaveStatistics> {
        self.statistics.lock().unwrap()
    }
    pub fn lock_nonce_provider(&self) -> SgxMutexGuard<NonceProvider> {
        self.nonce_provider.lock().unwrap()
    }
    pub fn lock_obt_tree_directory(&self) -> SgxMutexGuard<ObTreeDirectory> {
        self.obt_tree_directory.lock().unwrap()
    }
    pub fn lock_database_scheme(&self) -> SgxMutexGuard<SqlDatabaseScheme> {
        self.database_scheme.lock().unwrap()
    }
    pub fn lock_dynamic_config(&self) -> SgxMutexGuard<DynamicConfig> {
        self.dynamic_config.lock().unwrap()
    }
    pub fn fill_grade(&self) -> usize {
        self.fill_grade
    }
    pub fn lock_query_id_provider(&self) -> SgxMutexGuard<QueryIdProvider> {
        self.query_id_provider.lock().unwrap()
    }
    pub fn lock_slot_cache(&self) -> SgxMutexGuard<SlotCache> {
        self.slot_cache.lock().unwrap()
    }
    pub fn lock_query_state_cache(&self) -> SgxMutexGuard<QueryStateCache> {
        self.query_state_cache.lock().unwrap()
    }
    pub fn lock_query_response_cache(&self) -> SgxMutexGuard<QueryResponseCache> {
        self.query_response_cache.lock().unwrap()
    }
    pub fn lock_oram_config(&self) -> SgxMutexGuard<OramConfig> {
        self.oram_config.lock().unwrap()
    }
    pub fn lock_packet_id_provider(&self) -> SgxMutexGuard<PacketIdProvider> {
        self.packet_id_provider.lock().unwrap()
    }
    pub fn lock_statistics_to_send(&self) -> SgxMutexGuard<StatisticsToSend> {
        self.statistics_to_send.lock().unwrap()
    }
    pub fn to_send(&self) -> EnclaveStateToSend {
        let lock_dynamic_config = self.lock_dynamic_config();
        let lock_obt_node_cache = self.lock_obt_node_cache();
        let lock_obt_tree_directory = self.lock_obt_tree_directory();
        let lock_database_scheme = self.lock_database_scheme();
        let lock_nonce_provider = self.lock_nonce_provider();
        let lock_query_id_provider = self.lock_query_id_provider();
        let lock_slot_cache = self.lock_slot_cache();
        let lock_packet_id_provider = self.lock_packet_id_provider();
        let lock_oram_config = self.lock_oram_config();
        let fill_grade = self.fill_grade;
        EnclaveStateToSend::new(
            &lock_dynamic_config,
            &lock_obt_node_cache,
            &lock_obt_tree_directory,
            &lock_database_scheme,
            &lock_nonce_provider,
            &lock_query_id_provider,
            &lock_slot_cache,
            &lock_packet_id_provider,
            &lock_oram_config,
            fill_grade,
        )
    }
    pub fn from_backup(backup: EnclaveStateToSend) -> EnclaveState {
        let (
            dynamic_config,
            obt_node_cache,
            obt_tree_directory,
            database_scheme,
            nonce_provider,
            query_id_provider,
            slot_cache,
            packet_id_provider,
            oram_config,
            fill_grade,
        ) = backup.destroy();
        let query_state_cache = {
            let mut query_cache = QueryStateCache::new_empty();
            let served_query_id = query_id_provider.last();
            query_cache.set_served(served_query_id);
            query_cache.set_last(served_query_id);
            query_cache
        };
        let active_loc_cache = dynamic_config.index_locality_cache();
        EnclaveState::new(
            SgxMutex::new(dynamic_config),
            SgxMutex::new(PacketStash::new_empty()),
            SgxMutex::new(if active_loc_cache {
                Some(IndexLocalityCache::new_empty())
            } else {
                None
            }),
            SgxMutex::new(obt_node_cache),
            SgxMutex::new(obt_tree_directory),
            SgxMutex::new(database_scheme),
            SgxMutex::new(EnclaveStatistics::new(active_loc_cache, fill_grade as u32)),
            SgxMutex::new(nonce_provider),
            SgxMutex::new(query_id_provider),
            SgxMutex::new(slot_cache),
            SgxMutex::new(query_state_cache),
            SgxMutex::new(QueryResponseCache::new_empty()),
            SgxMutex::new(packet_id_provider),
            SgxMutex::new(oram_config),
            SgxMutex::new(StatisticsToSend::new()),
            fill_grade,
        )
    }
}

/// EnclaveState maintains all dynamic information needed at runtime of the protocol.
#[derive(Serialize, Deserialize, Clone)]
pub struct EnclaveStateToSend {
    dynamic_config: DynamicConfig,
    obt_node_cache: ObTreeNodeCache,
    obt_tree_directory: ObTreeDirectory,
    database_scheme: SqlDatabaseScheme,
    nonce_provider: NonceProvider,
    query_id_provider: QueryIdProvider,
    slot_cache: SlotCache,
    packet_id_provider: PacketIdProvider,
    oram_config: OramConfig,
    fill_grade: usize,
}

impl EnclaveStateToSend {
    pub fn new(
        dynamic_config: &DynamicConfig,
        obt_node_cache: &ObTreeNodeCache,
        obt_tree_directory: &ObTreeDirectory,
        database_scheme: &SqlDatabaseScheme,
        nonce_provider: &NonceProvider,
        query_id_provider: &QueryIdProvider,
        slot_cache: &SlotCache,
        packet_id_provider: &PacketIdProvider,
        oram_config: &OramConfig,
        fill_grade: usize,
    ) -> Self {
        EnclaveStateToSend {
            dynamic_config: dynamic_config.clone(),
            obt_node_cache: obt_node_cache.clone(),
            obt_tree_directory: obt_tree_directory.clone(),
            database_scheme: database_scheme.clone(),
            nonce_provider: nonce_provider.clone(),
            query_id_provider: query_id_provider.clone(),
            slot_cache: slot_cache.clone(),
            packet_id_provider: packet_id_provider.clone(),
            oram_config: oram_config.clone(),
            fill_grade,
        }
    }
    pub fn destroy(
        self,
    ) -> (
        DynamicConfig,
        ObTreeNodeCache,
        ObTreeDirectory,
        SqlDatabaseScheme,
        NonceProvider,
        QueryIdProvider,
        SlotCache,
        PacketIdProvider,
        OramConfig,
        usize,
    ) {
        (
            self.dynamic_config,
            self.obt_node_cache,
            self.obt_tree_directory,
            self.database_scheme,
            self.nonce_provider,
            self.query_id_provider,
            self.slot_cache,
            self.packet_id_provider,
            self.oram_config,
            self.fill_grade,
        )
    }
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serializing the request has not worked out.")
    }
}
