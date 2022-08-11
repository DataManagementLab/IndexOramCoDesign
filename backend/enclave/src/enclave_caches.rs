pub mod api {
    use query_state::ObjectType;
    use EnclaveState;

    pub fn contains_slot_or_node(
        enclave_state: &EnclaveState,
        object_id: &u128,
        object_type: &ObjectType,
    ) -> bool {
        match object_type {
            ObjectType::NodeObjectType => {
                if enclave_state
                    .lock_obt_node_cache()
                    .get_node(object_id)
                    .is_some()
                {
                    enclave_state
                        .lock_statistics()
                        .inc_number_nodes_found_in_node_cache();
                    return true;
                }
            }
            ObjectType::SlotObjectType => {
                if enclave_state
                    .lock_slot_cache()
                    .get_slot(object_id)
                    .is_some()
                {
                    enclave_state
                        .lock_statistics()
                        .inc_number_slots_found_in_slot_cache();
                    return true;
                }
            }
        }
        false
    }
}
