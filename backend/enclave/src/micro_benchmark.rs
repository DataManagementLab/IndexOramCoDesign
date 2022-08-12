use helpers::oram_helper::get_number_of_leaves;
use oblivious_ram::components::BucketContentForLocal;
use oblivious_ram::functions::evict_and_transform_bucket_contents_to_buckets;
use rand::Rng;
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::vec::Vec;
use transform_buckets_to_bucket_contents;
use {oblivious_ram, EnclaveState};

pub fn oram_access_benchmark(enclave_state: &EnclaveState) {
    let (number_of_oram, oram_degree, oram_tree_height, bucket_size, bucket_ciphertext_len) = {
        let oram_config = enclave_state.lock_oram_config();
        (
            oram_config.number_of_oram(),
            oram_config.oram_degree(),
            oram_config.tree_height(),
            oram_config.bucket_size(),
            oram_config.bucket_ciphertext_len(),
        )
    };

    let mut number_accesses = 0;
    let mut total_read_time: f64 = 0.0;
    let mut total_write_time: f64 = 0.0;
    let mut total_free_space: f64 = 0.0;

    println!("oram_access_benchmark starts evaluation...");

    let mut rng = rand::thread_rng();

    for oram_instance in 0..number_of_oram {
        for _ in 0..10000 {
            let pos: usize =
                rng.gen_range(1, get_number_of_leaves(oram_degree, oram_tree_height) + 1);
            let oram_instance = oram_instance as u32;
            let leaves = vec![pos as u32];
            number_accesses += 1;

            let oram_buckets = {
                let oram_read_time: Instant = Instant::now();
                let oram_buckets = oblivious_ram::api::get_paths(oram_instance, &leaves)
                    .expect("We should have got returned path data from ORAM.");
                total_read_time += oram_read_time.elapsed().as_nanos() as f64;

                oram_buckets
            };

            let oram_buckets = {
                let dynamic_config = enclave_state.lock_dynamic_config();
                let mut statistics = enclave_state.lock_statistics();
                transform_buckets_to_bucket_contents(
                    &dynamic_config,
                    &mut statistics,
                    oram_buckets,
                    bucket_ciphertext_len,
                )
            };

            let local_buckets: Vec<BucketContentForLocal> = oram_buckets
                .into_iter()
                .map(|bucket_content| bucket_content.to_bucket_content_for_local(bucket_size))
                .collect();

            let oram_buckets: Vec<u8> = {
                let dynamic_config = enclave_state.lock_dynamic_config();
                let mut statistics = enclave_state.lock_statistics();
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

            let oram_write_time: Instant = Instant::now();
            oblivious_ram::api::write_paths(oram_instance, &leaves, oram_buckets);
            total_write_time += oram_write_time.elapsed().as_nanos() as f64;

            {
                let statistics_to_send = enclave_state.lock_statistics_to_send();
                total_free_space += statistics_to_send.free_oram_space_after();
            }
        }
    }

    let total_read_time = total_read_time / (number_accesses as f64);
    let total_write_time = total_write_time / (number_accesses as f64);
    let total_free_space = total_free_space / (number_accesses as f64);
    println!("Average Read Time: {}", total_read_time);
    println!("Average Write Time: {}", total_write_time);
    println!("Average Free Space: {}", total_free_space);
    println!("Number accesses: {}", number_accesses);
}
