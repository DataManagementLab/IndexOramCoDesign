pub mod api {
    use sgx_types::sgx_status_t;

    use std::vec::Vec;

    use oram_interface::{EnclaveStatistics, EnvironmentVariables};

    use {ocall_generic_request, ocall_get_oram_batch, ocall_write_oram_batch};
    use BUCKETS_FROM_SERVER_CACHE;


    pub fn send_environment_variables(environment_variables: EnvironmentVariables) {
        let request = crate::oram_interface::GenericRequestToServer::EnvironmentVariables(
            environment_variables,
        )
            .serialize();
        let request_len = request.len() as u32;

        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsafe {
            ocall_generic_request(&mut rt as *mut sgx_status_t, request.as_ptr(), request_len);
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            panic!("Error in OCALL: {}", rt.as_str());
        }
    }

    pub fn send_enclave_statistics(enclave_stats: EnclaveStatistics) {
        let request =
            crate::oram_interface::GenericRequestToServer::Statistics(enclave_stats).serialize();
        let request_len = request.len() as u32;
        /*
        let mut response_buf: Vec<u8> = Vec::new();
        let mut response_len : u32 = 0;
        //response_buf.as_mut_ptr(), &mut response_len as *mut u32
         */

        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsafe {
            ocall_generic_request(&mut rt as *mut sgx_status_t, request.as_ptr(), request_len);
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            panic!("Error in OCALL: {}", rt.as_str());
        }
    }

    pub fn reset_server_statistics() {
        let request = crate::oram_interface::GenericRequestToServer::Signal(1u8).serialize();
        let request_len = request.len() as u32;
        /*
        let mut response_buf: Vec<u8> = Vec::new();
        let mut response_len : u32 = 0;
        //response_buf.as_mut_ptr(), &mut response_len as *mut u32
         */

        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsafe {
            ocall_generic_request(&mut rt as *mut sgx_status_t, request.as_ptr(), request_len);
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            panic!("Error in OCALL: {}", rt.as_str());
        }
    }

    /*
    pub fn get_statistics() {
        let request_url = format!("{server_ip}/display_statistics/",
                                  server_ip = crate::SERVER_IP);
        let response = sgx_https::get(&request_url).unwrap();
        assert!(response.status().is_success(), "{}", response.text().unwrap());
    }
     */

    pub fn send_generic_request(request: crate::oram_interface::GenericRequestToServer) {
        let request = request.serialize();
        let request_len = request.len() as u32;

        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsafe {
            ocall_generic_request(&mut rt as *mut sgx_status_t, request.as_ptr(), request_len);
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            panic!("Error in send_request OCALL: {}", rt.as_str());
        }
    }

    pub fn get_paths(instance: u32, leaves: &Vec<u32>) -> Option<Vec<Vec<u8>>> {
        let leaves = bincode::serialize(leaves).unwrap();
        let leaves_len = leaves.len() as u32;

        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsafe {
            ocall_get_oram_batch(
                &mut rt as *mut sgx_status_t,
                instance,
                leaves.as_ptr(),
                leaves_len,
            );
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            panic!("Error in OCALL ocall_get_oram_batch: {}", rt.as_str());
        }

        let mut cache = BUCKETS_FROM_SERVER_CACHE.lock().unwrap();
        cache.pop()
    }

    pub fn write_paths(instance: u32, leaves: &Vec<u32>, buckets: Vec<u8>) {
        let leaves = bincode::serialize(leaves).unwrap();
        let leaves_len = leaves.len() as u32;
        let buckets_len = buckets.len() as u32;

        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsafe {
            ocall_write_oram_batch(
                &mut rt as *mut sgx_status_t,
                instance,
                leaves.as_ptr(),
                leaves_len,
                buckets.as_ptr(),
                buckets_len,
            );
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            panic!("Error in OCALL: {}", rt.as_str());
        }
    }
}

pub mod functions {
    use rand::Rng;
    use std::collections::HashMap;


    use std::time::Instant;
    use std::untrusted::time::InstantEx;
    use std::vec::Vec;

    use config::DynamicConfig;
    use crypto::NonceProvider;
    use enclave_state::EnclaveState;

    use helpers::range::{byte_range_to_sql_data_types};
    use logger::StatisticsToSend;
    use oblivious_data_structures::ob_tree::components::{
        ObTreeNode, ObTreeNodeForORAM, ObTreeQueryValue, ObTreeQueryValueRange, Origin,
    };
    use oblivious_data_structures::page::Slot;

    use oblivious_ram::api;
    use oblivious_ram::components::{
        bucket_to_bucket_content, BucketContent, BucketContentForLocal,
    };
    use oblivious_ram::packaging::Packet;
    use oram_interface::EnclaveStatistics;
    use packet_stash::PacketStash;
    use query_state::ObjectType;


    use {OramConfig};


    use {PRINT_PACKET_EVICTIONS};

    pub fn transform_buckets_to_bucket_contents(
        dynamic_config: &DynamicConfig,
        statistics: &mut EnclaveStatistics,
        buckets: Vec<Vec<u8>>,
        bucket_ciphertext_len: usize,
    ) -> Vec<BucketContent> {
        let time: Instant = Instant::now();
        //assert_eq!((buckets.len() % BUCKET_CIPHERTEXT_LEN), 0);
        let buckets: Vec<BucketContent> = buckets
            .into_iter()
            .map(|bucket| {
                bucket_to_bucket_content(
                    bucket,
                    dynamic_config.shared_enclave_key(),
                    dynamic_config.use_encryption(),
                    bucket_ciphertext_len,
                )
            })
            .collect();
        statistics.inc_time_transform_buckets_to_bucket_contents(time.elapsed().as_nanos());
        buckets
    }

    pub fn evict_and_transform_bucket_contents_to_buckets(
        oram_config: &OramConfig,
        dynamic_config: &DynamicConfig,
        packet_stash: &mut PacketStash,
        statistics: &mut EnclaveStatistics,
        statistics_to_send: &mut StatisticsToSend,
        nonce_provider: &mut NonceProvider,
        oram_buckets: Vec<BucketContentForLocal>,
        oram_id: u32,
    ) -> Vec<u8> {
        let complete_ciphertext_len = oram_config.bucket_ciphertext_len() * oram_buckets.len();

        let mut new_buckets: Vec<u8> = vec![0u8; complete_ciphertext_len];
        let whole_space = oram_config.bucket_size() * oram_buckets.len();
        let mut free_space = 0;
        let min_packet_size = Packet::new_dummy(32, oram_config.bucket_size()).byte_size();

        let mut nonces: Vec<[u8; 12]> = Vec::with_capacity(oram_buckets.len());
        {
            for _i in 0..oram_buckets.len() {
                nonces.push(nonce_provider.make_nonce());
            }
        }

        let (mut bucket_start_i, mut bucket_end_i) = (
            complete_ciphertext_len - oram_config.bucket_ciphertext_len(),
            complete_ciphertext_len,
        );

        let stash_keys = packet_stash.get_keys(oram_id);

        for mut oram_bucket in oram_buckets.into_iter().rev() {
            let time_evict_into_oram_batch_from_packet_stash: Instant = Instant::now();
            let number_of_evicted_packets = packet_stash.evict_into_oram_bucket(
                min_packet_size,
                oram_id,
                &mut oram_bucket,
                &stash_keys,
            );
            statistics.inc_time_evict_into_oram_batch_from_packet_stash(
                time_evict_into_oram_batch_from_packet_stash
                    .elapsed()
                    .as_nanos(),
            );
            statistics_to_send.inc_evicted_packets_in_batch(number_of_evicted_packets);
            statistics.inc_evicted_packets(number_of_evicted_packets);

            free_space += oram_bucket.free_space();

            let time: Instant = Instant::now();
            match new_buckets.get_mut(bucket_start_i..bucket_end_i) {
                None => {
                    panic!("New bucket cannot be written.");
                }
                Some(new_bucket) => {
                    if dynamic_config.use_encryption() {
                        let nonce = nonces.pop().unwrap();
                        new_bucket.copy_from_slice(&mut oram_bucket.to_bucket_content().encrypt(
                            dynamic_config.shared_enclave_key(),
                            nonce,
                            oram_config.bucket_serialized_size(),
                            oram_config.bucket_ciphertext_len(),
                        ));
                    } else {
                        new_bucket.copy_from_slice(
                            &mut oram_bucket
                                .to_bucket_content()
                                .serialize(oram_config.bucket_ciphertext_len()),
                        );
                    };
                }
            }
            statistics.inc_time_transform_bucket_contents_to_buckets(time.elapsed().as_nanos());

            bucket_start_i -= oram_config.bucket_ciphertext_len();
            bucket_end_i -= oram_config.bucket_ciphertext_len();
        }

        let free_space = (free_space as f64) / (whole_space as f64);
        statistics_to_send.set_free_oram_space_after(free_space);
        new_buckets
    }

    pub enum Object {
        SlotObject(Slot),
        NodeObject(ObTreeNode),
    }

    pub fn transform_oram_fragments_to_logical_object(
        statistics: &mut EnclaveStatistics,
        fragments: &[u8],
        object_type: &ObjectType,
        origin: Origin,
    ) -> Object {
        match object_type {
            ObjectType::NodeObjectType => {
                let time = Instant::now();
                let node: ObTreeNodeForORAM = bincode::deserialize(&fragments)
                    .expect("transform_oram_fragments_to_logical_object has not worked!");
                statistics.inc_time_transform_fragments_to_obt_node(time.elapsed().as_nanos());
                Object::NodeObject(node.to_ob_tree_node(origin))
            }
            ObjectType::SlotObjectType => {
                let time = Instant::now();
                let mut slot: Slot = bincode::deserialize(&fragments)
                    .expect("transform_oram_fragments_to_logical_object has not worked!");
                statistics.inc_time_transform_fragments_to_obt_slot(time.elapsed().as_nanos());
                slot.set_origin(origin);
                Object::SlotObject(slot)
            }
        }
    }

    pub fn read_process_and_evict_oram_request_batch(
        enclave_state: &EnclaveState,
        oram_instance: u32,
        leaves: Vec<u32>,
        mut needed_objects: HashMap<u128, ObjectType>,
    ) {
        let dynamic_config = enclave_state.lock_dynamic_config();
        let aggressive_caching = dynamic_config.aggressive_locality_caching();
        let bounded_locality_cache = dynamic_config.bounded_locality_cache();
        let keep_not_requested_in_buckets = {
            let mut rng = rand::thread_rng();
            rng.gen_bool(dynamic_config.keep_not_requested_in_buckets())
        };

        let (bucket_size, bucket_ciphertext_len) = {
            let oram_config = enclave_state.lock_oram_config();
            (
                oram_config.bucket_size(),
                oram_config.bucket_ciphertext_len(),
            )
        };

        let oram_buckets = {
            let mut statistics = enclave_state.lock_statistics();
            statistics.inc_requested_oram_leaves(leaves.len() as u64);

            let oram_read_time: Instant = Instant::now();
            let oram_buckets = api::get_paths(oram_instance, &leaves)
                .expect("We should have got returned path data from ORAM.");
            statistics.inc_oram_read_time(oram_read_time.elapsed().as_nanos());
            statistics.inc_oram_reads();
            oram_buckets
        };

        let length_fetched_oram_batch = oram_buckets.len() * bucket_ciphertext_len;

        {
            let needed_objects_len = needed_objects.len();
            enclave_state
                .lock_packet_stash()
                .lookup_stash_for_requested_packets(
                    enclave_state,
                    &oram_instance,
                    &leaves,
                    &mut needed_objects,
                );
            enclave_state
                .lock_statistics()
                .inc_number_packets_found_in_stash(
                    (needed_objects_len - needed_objects.len()) as u64,
                );
        }

        let mut statistics = enclave_state.lock_statistics();
        // The number of "needed_objects" corresponds now to the number of packets
        // that are requested from ORAM in this batch
        statistics.inc_number_packets_requested_from_oram(needed_objects.len() as u64);

        let oram_buckets = transform_buckets_to_bucket_contents(
            &dynamic_config,
            &mut statistics,
            oram_buckets,
            bucket_ciphertext_len,
        );

        let iter_buckets_time: Instant = Instant::now();
        let mut free_space_in_locality_cache = {
            match enclave_state.lock_index_locality_cache().as_mut() {
                None => false,
                Some(some_cache) => some_cache.size() < bounded_locality_cache,
            }
        };

        let mut just_bucket_transformation = false;
        let local_buckets: Vec<BucketContentForLocal> = oram_buckets
            .into_iter()
            .map(|bucket_content| {
                let mut local_bucket = bucket_content.to_bucket_content_for_local(bucket_size);

                let can_cache = dynamic_config.index_locality_cache();

                for packet_index in (0..local_bucket.packets().len()).rev() {
                    if just_bucket_transformation {
                        break;
                    }

                    let (packet_id, index_id) = {
                        let packet = local_bucket.packets().get(packet_index).unwrap();
                        (packet.position().copy_packet_id(), *packet.index_id())
                    };

                    match needed_objects.remove(&packet_id) {
                        None => {
                            let mut cached_the_packet: bool = false;
                            if can_cache
                                && free_space_in_locality_cache
                                && local_bucket
                                .packets()
                                .get(packet_index)
                                .unwrap()
                                .value_range()
                                .is_some()
                            {
                                let time_iterate_buckets_for_locality_cache = Instant::now();
                                let time_byte_range_to_sql_data_types = Instant::now();
                                let packet_value_range = {
                                    let (lower, upper) = byte_range_to_sql_data_types(
                                        local_bucket
                                            .packets()
                                            .get(packet_index)
                                            .unwrap()
                                            .value_range()
                                            .as_ref()
                                            .unwrap(),
                                        enclave_state
                                            .lock_obt_tree_directory()
                                            .get_tree(&index_id)
                                            .unwrap()
                                            .attribute_config(),
                                    );
                                    ObTreeQueryValue::Range(ObTreeQueryValueRange::new(
                                        lower, upper,
                                    ))
                                };
                                statistics.inc_time_byte_range_to_sql_data_types(
                                    time_byte_range_to_sql_data_types.elapsed().as_nanos(),
                                );

                                match enclave_state
                                    .lock_obt_tree_directory()
                                    .get_tree(&index_id)
                                    .unwrap()
                                    .get_query_locks_at_value(&packet_value_range)
                                {
                                    None => {}
                                    Some(some_index_meta) => {
                                        if !some_index_meta.is_empty() {
                                            cached_the_packet = true;
                                            let mut index_locality_cache =
                                                enclave_state.lock_index_locality_cache();
                                            let (packet, _) =
                                                local_bucket.remove_packet(packet_index);
                                            index_locality_cache
                                                .as_mut()
                                                .unwrap()
                                                .insert(packet, *some_index_meta.last().unwrap());
                                            free_space_in_locality_cache =
                                                index_locality_cache.as_ref().unwrap().size()
                                                    < bounded_locality_cache;
                                        }
                                    }
                                }
                                statistics.inc_time_iterate_buckets_for_locality_cache(
                                    time_iterate_buckets_for_locality_cache.elapsed().as_nanos(),
                                );
                            }
                            if !cached_the_packet {
                                if !keep_not_requested_in_buckets {
                                    let time = Instant::now();
                                    let mut stash = enclave_state.lock_packet_stash();
                                    let (packet, packet_size) =
                                        local_bucket.remove_packet(packet_index);
                                    stash.add_packet(packet, packet_size);
                                    statistics.inc_insert_packet_of_bucket_to_stash_time(
                                        time.elapsed().as_nanos(),
                                    );
                                }
                            }
                        }
                        Some(some_needed_object) => {
                            let (packet, _) = local_bucket.remove_packet(packet_index);
                            if PRINT_PACKET_EVICTIONS {
                                println!("Removed packet from bucket: ID {}", packet_id);
                            }
                            //current_position_tag = searched_packet.next().clone(); TODO

                            let object = transform_oram_fragments_to_logical_object(
                                &mut statistics,
                                packet.content(),
                                &some_needed_object,
                                Origin::ObliviousRAM,
                            );
                            match object {
                                Object::SlotObject(slot) => {
                                    enclave_state.lock_slot_cache().insert_slot(packet_id, slot);
                                }
                                Object::NodeObject(node) => {
                                    enclave_state
                                        .lock_obt_node_cache()
                                        .insert_node(packet_id, node);
                                }
                            }

                            // When we have found all needed objects,
                            // we can stop going through the buckets
                        }
                    }

                    just_bucket_transformation = needed_objects.is_empty()
                        && (!aggressive_caching && keep_not_requested_in_buckets);
                }

                local_bucket
            })
            .collect();

        let iter_buckets_time = iter_buckets_time.elapsed();
        statistics.inc_iter_buckets_from_oram_time(iter_buckets_time.as_nanos());

        let oram_buckets: Vec<u8> = {
            let mut nonce_provider = enclave_state.lock_nonce_provider();
            let oram_config = enclave_state.lock_oram_config();
            let mut packet_stash = enclave_state.lock_packet_stash();
            let mut statistics_to_send = enclave_state.lock_statistics_to_send();
            evict_and_transform_bucket_contents_to_buckets(
                &oram_config,
                &dynamic_config,
                &mut packet_stash,
                &mut statistics,
                &mut statistics_to_send,
                &mut nonce_provider,
                local_buckets,
                oram_instance,
            )
        };

        assert_eq!(
            length_fetched_oram_batch,
            oram_buckets.len(),
            "length_fetched_oram_batch: {} != oram_buckets.len(): {}",
            length_fetched_oram_batch,
            oram_buckets.len()
        );
        let oram_write_time: Instant = Instant::now();
        api::write_paths(oram_instance, &leaves, oram_buckets);
        let oram_write_time = oram_write_time.elapsed();
        statistics.inc_oram_write_time(oram_write_time.as_nanos());
        statistics.inc_oram_writes();

        drop(statistics);
        drop(dynamic_config);

        //assert!(needed_objects.is_empty());
        if !needed_objects.is_empty() {
            for needed_object in needed_objects {
                println!(
                    "Object {} of type {} was not found in ORAM.",
                    needed_object.0,
                    needed_object.1.as_str()
                );
                assert!(enclave_state
                    .lock_slot_cache()
                    .get_slot(&needed_object.0)
                    .is_none());
                assert!(enclave_state
                    .lock_obt_node_cache()
                    .get_node(&needed_object.0)
                    .is_none());
                //search_complete_oram_content(enclave_state, oram_instance, needed_object.0);
            }
            println!("Visited leaves: {:?}", leaves);
            println!("At ORAM instance {}", oram_instance);
            panic!("Needed objects were not all found in ORAM.");
        }
    }

    /*
    fn search_complete_oram_content(
        enclave_state: &EnclaveState,
        oram_instance: u32,
        packet_id: u128,
    ) {
        let dynamic_config = enclave_state.lock_dynamic_config();
        let mut statistics = enclave_state.lock_statistics();
        let mut nonce_provider = enclave_state.lock_nonce_provider();

        let number_of_leaves = get_number_of_leaves() as u32;
        for leaf in 1..(number_of_leaves + 1) {
            let leaves = vec![leaf];
            let oram_buckets = api::get_paths(oram_instance, &leaves)
                .expect("We should have got returned path data from ORAM.");

            let mut oram_buckets = transform_buckets_to_bucket_contents(
                &dynamic_config,
                &mut statistics,
                oram_buckets,
            );
            assert_eq!(oram_buckets.len(), TREE_HEIGHT);

            for bucket_content in oram_buckets.iter_mut() {
                for packet in bucket_content.packets() {
                    if packet.position().packet_id().eq(&packet_id) {
                        println!(
                            "Bucket: {}..{}",
                            bucket_content.poss_positions().0,
                            bucket_content.poss_positions().1
                        );
                        println!(
                            "search_complete_oram_content found the packet! {}",
                            packet_id
                        );
                        return;
                    }
                }
            }

            let oram_buckets: Vec<u8> = transform_bucket_contents_to_buckets(
                &dynamic_config,
                &mut statistics,
                &mut nonce_provider,
                oram_buckets,
            );

            api::write_paths(oram_instance, &leaves, oram_buckets);
        }
    }
     */
}

pub mod components {
    use core::convert::TryInto;


    use serde::{Deserialize, Serialize};
    use std::string::{ToString};
    use std::vec::Vec;


    use oblivious_ram::packaging::Packet;
    use AES_TAG_LEN;
    use DEBUG_RUNTIME_CHECKS;

    use SHARED_KEY_LEN;
    use {NONCE_SIZE};

    #[derive(Clone)]
    pub struct BucketContentForLocal {
        poss_positions: (u32, u32),
        packets: Vec<Packet>,
        free_space: usize,
    }

    impl BucketContentForLocal {
        pub fn new(poss_positions: (u32, u32), packets: Vec<Packet>, free_space: usize) -> Self {
            BucketContentForLocal {
                poss_positions,
                packets,
                free_space,
            }
        }
        #[allow(dead_code)]
        fn packets_byte_size(&self) -> usize {
            let mut size = 0;
            for packet in self.packets.iter() {
                size += packet.byte_size();
            }
            size
        }
        pub fn remove_packet(&mut self, index: usize) -> (Packet, usize) {
            let packet = self.packets.remove(index);
            let size = packet.byte_size();
            self.free_space += size;
            (packet, size)
        }
        pub fn insert_packet_with_size(&mut self, packet: Packet, size: usize) {
            self.packets.push(packet);
            self.free_space -= size;
        }
        pub fn poss_positions(&self) -> (u32, u32) {
            self.poss_positions
        }
        pub fn packets(&self) -> &Vec<Packet> {
            &self.packets
        }
        pub fn free_space(&self) -> usize {
            self.free_space
        }
        pub fn to_bucket_content(self) -> BucketContent {
            let (poss_positions, packets, free_space) =
                (self.poss_positions, self.packets, self.free_space);
            BucketContent::new_from_packets_with_free_space(poss_positions, packets, free_space)
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct BucketContent {
        poss_positions: (u32, u32),
        packets: Vec<Packet>,
        #[serde(with = "serde_bytes")]
        padding: Vec<u8>,
    }

    impl BucketContent {
        #[allow(dead_code)]
        pub fn new(poss_positions: (u32, u32), packets: Vec<Packet>, bucket_size: usize) -> Self {
            let mut size = 0;
            for packet in packets.iter() {
                size += packet.byte_size();
            }
            if size > bucket_size {
                panic!("packets size > MAX_BUCKET_SIZE ");
            }
            BucketContent {
                poss_positions,
                packets,
                padding: vec![0u8; bucket_size - size],
            }
        }
        pub fn new_from_packets_with_free_space(
            poss_positions: (u32, u32),
            packets: Vec<Packet>,
            free_space: usize,
        ) -> Self {
            BucketContent {
                poss_positions,
                packets,
                padding: vec![0u8; free_space],
            }
        }
        pub fn new_as_dummy(poss_positions: (u32, u32), bucket_size: usize) -> Self {
            BucketContent {
                poss_positions,
                packets: vec![],
                padding: vec![0u8; bucket_size],
            }
        }
        pub fn to_bucket_content_for_local(self, bucket_size: usize) -> BucketContentForLocal {
            let packets_size = self.packets_byte_size();
            BucketContentForLocal::new(
                self.poss_positions,
                self.packets,
                bucket_size - packets_size,
            )
        }
        fn packets_byte_size(&self) -> usize {
            let mut size = 0;
            for packet in self.packets.iter() {
                size += packet.byte_size();
            }
            size
        }
        pub fn encrypt(
            &self,
            shared_key: &[u8; SHARED_KEY_LEN],
            nonce: [u8; 12],
            bucket_serialized_size: usize,
            bucket_ciphertext_len: usize,
        ) -> Vec<u8> {
            //println!("self.padding.len(): {}", self.padding.len());
            //println!("self.used_space(): {}", self.used_space());
            let mut encoded: Vec<u8> = bincode::serialize(self).unwrap();
            assert_eq!(
                encoded.len(),
                bucket_serialized_size,
                "Assertion fails: encoded.len(): {} != bucket_serialized_size: {}",
                encoded.len(),
                bucket_serialized_size
            );
            let mut sealing_key = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, shared_key).unwrap(),
            );
            match ring::aead::LessSafeKey::seal_in_place_append_tag(
                &mut sealing_key,
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut encoded,
            ) {
                Ok(_) => {}
                Err(err) => {
                    panic!("Error in encryption of bucket: {}", err.to_string());
                }
            }
            encoded.append(&mut nonce.to_vec());
            assert_eq!(
                encoded.len(),
                bucket_ciphertext_len,
                "Assertion fails: encoded.len(): {} != bucket_ciphertext_len: {}",
                encoded.len(),
                bucket_ciphertext_len
            );
            encoded
        }
        pub fn serialize(&self, bucket_ciphertext_len: usize) -> Vec<u8> {
            let mut encoded: Vec<u8> = bincode::serialize(self).unwrap();
            let mut tag = vec![0u8; AES_TAG_LEN];
            let mut nonce = vec![0u8; NONCE_SIZE];
            encoded.append(&mut tag);
            encoded.append(&mut nonce);
            assert_eq!(
                encoded.len(),
                bucket_ciphertext_len,
                "Assertion fails: encoded.len(): {} != bucket_ciphertext_len: {}",
                encoded.len(),
                bucket_ciphertext_len
            );
            encoded
        }
    }

    pub fn bucket_to_bucket_content(
        mut bucket: Vec<u8>,
        shared_key: &[u8; SHARED_KEY_LEN],
        use_encryption: bool,
        bucket_ciphertext_len: usize,
    ) -> BucketContent {
        if DEBUG_RUNTIME_CHECKS {
            assert_eq!(bucket.len(), bucket_ciphertext_len);
        }
        if use_encryption {
            let mut opening_key = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, shared_key).unwrap(),
            );
            let nonce: [u8; 12] = (&bucket[bucket_ciphertext_len - NONCE_SIZE..])
                .to_vec()
                .try_into()
                .unwrap();
            bucket.truncate(bucket_ciphertext_len - NONCE_SIZE);
            match ring::aead::LessSafeKey::open_in_place(
                &mut opening_key,
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut bucket,
            ) {
                Ok(_) => {}
                Err(err) => {
                    panic!("Error in decryption of bucket: {}", err.to_string());
                }
            }
        } else {
            bucket.truncate(bucket_ciphertext_len - (NONCE_SIZE + AES_TAG_LEN));
        }
        let bucket: BucketContent = bincode::deserialize(bucket.as_slice()).unwrap();
        bucket
    }
}

pub mod packaging {
    use serde::{Deserialize, Serialize};
    use std::cmp::min;
    use std::time::Instant;
    use std::untrusted::time::InstantEx;
    use std::vec::Vec;
    use EnclaveState;
    use helpers::range::ByteRange;
    use oram_interface::EnclaveStatistics;
    use crate::oblivious_data_structures::position_tag::PositionTag;
    use crate::{MAX_PACKET_SIZE};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Packet {
        position: PositionTag,
        // mapped path and packet id of next packet:
        next: PositionTag,
        #[serde(with = "serde_bytes")]
        content: Vec<u8>,
        index_id: u16,
        value_range: Option<ByteRange>,
    }

    impl Packet {
        pub fn new(
            position: PositionTag,
            next: PositionTag,
            content: Vec<u8>,
            index_id: u16,
            value_range: Option<ByteRange>,
            bucket_size: usize,
        ) -> Self {
            assert!(content.len() <= MAX_PACKET_SIZE);
            let packet = Packet {
                position,
                next,
                content,
                index_id,
                value_range,
            };
            assert!(packet.byte_size() <= bucket_size);
            packet
        }
        pub fn new_dummy(size: usize, bucket_size: usize) -> Self {
            assert!(size <= MAX_PACKET_SIZE);
            let packet = Packet {
                position: PositionTag::new_dummy(),
                next: PositionTag::new_dummy(),
                content: vec![0u8; size],
                index_id: 0u16,
                value_range: None,
            };
            let packet_size = packet.byte_size();
            assert!(
                packet_size <= bucket_size,
                "{} <= {} fails",
                packet_size,
                bucket_size
            );
            packet
        }
        pub fn position(&self) -> &PositionTag {
            &self.position
        }
        pub fn next(&self) -> &PositionTag {
            &self.next
        }
        pub fn content(&self) -> &Vec<u8> {
            &self.content
        }
        #[allow(dead_code)]
        pub fn destroy_packet_and_return_content(self) -> Vec<u8> {
            self.content
        }
        pub fn byte_size(&self) -> usize {
            bincode::serialized_size(&self).expect("") as usize
        }
        #[allow(dead_code)]
        pub fn meta_byte_size() -> usize {
            2 * PositionTag::byte_size()
        }
        /*
        pub fn set_content(&mut self, content: Vec<u8>) {
            assert!(content.len() <= MAX_PACKET_SIZE);
            self.content = content;
            assert!(self.byte_size() <= MAX_BUCKET_SIZE);
        }
         */
        pub fn value_range(&self) -> &Option<ByteRange> {
            &self.value_range
        }
        pub fn index_id(&self) -> &u16 {
            &self.index_id
        }
    }

    /// Gets an encoded ORT item and its position tag.
    /// It builds a vector of ORAM blocks.
    /// The first block of the vector has the position given by the parameter.
    pub fn transform_bytes_to_oram_packets(
        enclave_state: &EnclaveState,
        position: &PositionTag,
        encoded: Vec<u8>,
        value_range: Option<ByteRange>,
        statistics: &mut EnclaveStatistics,
        index_id: u16,
    ) -> Vec<Packet> {
        let start_time: Instant = Instant::now();

        let mut packets: Vec<Packet> = Vec::new();
        let encoded_len: usize = encoded.len();
        let mut necessary_packets: usize = encoded_len / usize::from(MAX_PACKET_SIZE);
        if (encoded_len % usize::from(MAX_PACKET_SIZE)) > 0 {
            necessary_packets += 1;
        }

        let mut next_packets: Vec<PositionTag> = Vec::with_capacity(necessary_packets);
        if necessary_packets > 1 {
            for _next_packet in 1..necessary_packets {
                next_packets.push(PositionTag::new_random(enclave_state));
            }
        }
        next_packets.push(position.clone()); //first packet
        assert_eq!(next_packets.len(), necessary_packets);

        let mut offset: usize = 0;
        for _b in 0..necessary_packets {
            assert!(offset < encoded_len);
            let payload_encoded = min(
                usize::from(encoded_len),
                offset as usize + MAX_PACKET_SIZE as usize,
            );

            let content_for_packet: Vec<u8> = encoded[offset..payload_encoded].to_vec();
            let this_packet: PositionTag = next_packets.pop().unwrap();
            let next_packet: PositionTag;
            match next_packets.last() {
                None => next_packet = PositionTag::new_dummy(),
                Some(pos) => next_packet = pos.clone(),
            }
            offset = offset + content_for_packet.len();
            let packet: Packet = Packet::new(
                this_packet,
                next_packet,
                content_for_packet,
                index_id,
                value_range.clone(),
                enclave_state.lock_oram_config().bucket_size(),
            );
            packets.push(packet);
        }

        assert_eq!(offset, encoded_len);
        match packets.first() {
            None => {}
            Some(first) => {
                assert!(first.position().packet_id().eq(position.packet_id()));
                assert_eq!(first.position().path(), position.path());
                assert_eq!(first.position().oram_id(), position.oram_id());
            }
        }
        match packets.last() {
            None => {}
            Some(last) => {
                assert!(last.next().packet_id().eq(&0u128));
            }
        }
        if packets.len() > 1 {
            statistics.inc_times_more_than_one_packet();
        }
        let start_time = start_time.elapsed();
        statistics.inc_time_transform_bytes_to_oram_packets(start_time.as_nanos());
        packets
    }
}
