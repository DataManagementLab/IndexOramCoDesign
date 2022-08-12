use crypto::generate_random_key;

use oblivious_data_structures::position_tag::PositionTag;

use oblivious_ram::packaging::Packet;
use rand::Rng;


use {EnclaveState};
use {MAX_PACKET_SIZE};

#[allow(dead_code)]
fn generate_random_packet(enclave_state: &EnclaveState) -> Packet {
    let mut rng = rand::thread_rng();
    let rand_int: usize = rng.gen_range(1, MAX_PACKET_SIZE);
    let mut random_content = generate_random_key(rand_int).into_bytes();
    random_content.truncate(MAX_PACKET_SIZE);
    Packet::new(
        PositionTag::new_random(enclave_state),
        PositionTag::new_dummy(),
        random_content,
        0,
        None,
        enclave_state.lock_oram_config().bucket_size(),
    )
}

/*
pub fn test_read_write_oram(enclave_state: &EnclaveState) {
    for _ in 0..10000 {
        let mut rng = rand::thread_rng();
        let mut inserted_packet_ids: HashSet<u128> = HashSet::new();
        let dynamic_config = enclave_state.lock_dynamic_config();
        let mut statistics = enclave_state.lock_statistics();
        let mut nonce_provider = enclave_state.lock_nonce_provider();

        let (number_of_oram, oram_degree, oram_tree_height, bucket_ciphertext_len) = {
            let oram_config = enclave_state.lock_oram_config();
            (
                oram_config.number_of_oram(),
                oram_config.oram_degree(),
                oram_config.tree_height(),
                oram_config.bucket_ciphertext_len(),
            )
        };

        let oram_instance = 0;
        let rand_start: u32 = rng.gen_range(
            1u32,
            (get_number_of_leaves(oram_degree, oram_tree_height) - 1) as u32,
        );
        let rand_end: u32 = rng.gen_range(
            rand_start,
            core::cmp::min(
                get_number_of_leaves(oram_degree, oram_tree_height) as u32,
                rand_start + 10,
            ),
        );
        let mut leaves: Vec<u32> = Vec::with_capacity((rand_end - rand_start) as usize);
        for leaf in rand_start..rand_end {
            leaves.push(leaf);
        }

        let oram_buckets = oblivious_ram::api::get_paths(oram_instance, &leaves)
            .expect("We should have got returned path data from ORAM.");
        let mut oram_buckets = transform_buckets_to_bucket_contents(
            &dynamic_config,
            &mut statistics,
            oram_buckets,
            bucket_ciphertext_len,
        );
        for bucket_content in oram_buckets.iter_mut() {
            let mut random_packets: Vec<Packet> = Vec::new();
            let mut free_space = bucket_content.free_space();
            let mut random_packets_size = 0;

            let mut random_packet = generate_random_packet(enclave_state);
            let mut random_packet_size = random_packet.byte_size();
            while free_space >= random_packet_size {
                inserted_packet_ids.insert(random_packet.position().copy_packet_id());
                random_packets.push(random_packet);
                free_space -= random_packet_size;
                random_packets_size += random_packet_size;

                random_packet = generate_random_packet(enclave_state);
                random_packet_size = random_packet.byte_size();
            }
            bucket_content.insert_packets_with_size(&mut random_packets, random_packets_size);
        }
        let oram_buckets: Vec<u8> = {
            let oram_config = enclave_state.lock_oram_config();
            let mut statistics_to_send = enclave_state.lock_statistics_to_send();
            transform_bucket_contents_to_buckets(
                &oram_config,
                &dynamic_config,
                &mut statistics,
                &mut statistics_to_send,
                &mut nonce_provider,
                oram_buckets,
            )
        };
        oblivious_ram::api::write_paths(oram_instance, &leaves, oram_buckets);

        /// Now we check the correct write
        let oram_buckets = oblivious_ram::api::get_paths(oram_instance, &leaves)
            .expect("We should have got returned path data from ORAM.");
        let mut oram_buckets = transform_buckets_to_bucket_contents(
            &dynamic_config,
            &mut statistics,
            oram_buckets,
            bucket_ciphertext_len,
        );
        for bucket_content in oram_buckets.iter_mut() {
            for packet in bucket_content.packets() {
                let packet_id = packet.position().packet_id();
                if inserted_packet_ids.contains(packet_id) {
                    inserted_packet_ids.remove(packet_id);
                }
            }
        }

        assert!(inserted_packet_ids.is_empty());
    }
}

 */
