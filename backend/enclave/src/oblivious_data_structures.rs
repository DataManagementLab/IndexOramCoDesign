pub mod position_tag {
    use serde::{Deserialize, Serialize};
    use std::string::String;

    use EnclaveState;

    use crate::helpers::oram_helper::{get_random_oram_id, get_random_oram_position};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct PositionTagWithoutId {
        oram_id: u32,
        path: u32,
    }

    impl PositionTagWithoutId {
        pub fn oram_id(&self) -> u32 {
            self.oram_id
        }
        pub fn path(&self) -> u32 {
            self.path
        }
        pub fn new(oram_id: u32, path: u32) -> Self {
            PositionTagWithoutId { oram_id, path }
        }
        pub fn with_id(&self, packet_id: u128) -> PositionTag {
            PositionTag {
                oram_id: self.oram_id(),
                path: self.path(),
                packet_id,
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct PositionTag {
        oram_id: u32,
        path: u32,
        packet_id: u128,
    }

    impl PositionTag {
        pub fn new_random_from_packet_id(
            number_of_oram: u32,
            oram_degree: usize,
            oram_tree_height: usize,
            packet_id: u128,
        ) -> PositionTag {
            PositionTag {
                oram_id: get_random_oram_id(number_of_oram),
                path: get_random_oram_position(oram_degree, oram_tree_height),
                packet_id,
            }
        }
        pub fn without_id(&self) -> PositionTagWithoutId {
            PositionTagWithoutId::new(self.oram_id, self.path)
        }
        pub fn byte_size() -> usize {
            4usize + 4usize + 16usize
        }
        pub fn new_random(enclave_state: &EnclaveState) -> Self {
            let oram_config = enclave_state.lock_oram_config();
            PositionTag {
                oram_id: get_random_oram_id(oram_config.number_of_oram() as u32),
                path: get_random_oram_position(
                    oram_config.oram_degree(),
                    oram_config.tree_height(),
                ),
                packet_id: enclave_state.lock_packet_id_provider().make_id(),
            }
        }
        pub fn clone_with_random_block_id(&self, enclave_state: &EnclaveState) -> PositionTag {
            PositionTag {
                oram_id: self.oram_id(),
                path: self.path(),
                packet_id: enclave_state.lock_packet_id_provider().make_id(),
            }
        }
        pub fn new_dummy() -> Self {
            PositionTag {
                oram_id: 0,
                path: 0,
                packet_id: 0,
            }
        }
        pub fn path(&self) -> u32 {
            self.path
        }
        pub fn mut_path(&mut self) -> &mut u32 {
            &mut self.path
        }
        pub fn set_path(&mut self, path: u32) {
            self.path = path;
        }
        pub fn set_from(&mut self, mut position_tag: PositionTag) {
            let (oram_id, path, packet_id) = position_tag.destroy();
            self.oram_id = oram_id;
            self.path = path;
            self.packet_id = packet_id;
        }
        pub fn oram_id(&self) -> u32 {
            self.oram_id
        }
        pub fn mut_oram_id(&mut self) -> &mut u32 {
            &mut self.oram_id
        }
        pub fn set_oram_id(&mut self, oram_id: u32) {
            self.oram_id = oram_id;
        }
        pub fn equals(&self, position: &PositionTag) -> bool {
            return if self.packet_id().eq(&position.packet_id())
                && self.oram_id().eq(&position.oram_id())
                && self.path().eq(&position.path())
            {
                true
            } else {
                false
            };
        }
        pub fn equals_same_path(&self, position: &PositionTag) -> bool {
            return if self.oram_id().eq(&position.oram_id()) && self.path().eq(&position.path()) {
                true
            } else {
                false
            };
        }
        pub fn destroy(self) -> (u32, u32, u128) {
            (self.oram_id, self.path, self.packet_id)
        }
        pub fn packet_id(&self) -> &u128 {
            &self.packet_id
        }
        pub fn copy_packet_id(&self) -> u128 {
            self.packet_id
        }
        pub fn set_packet_id(&mut self, packet_id: u128) {
            self.packet_id = packet_id;
        }
        pub fn to_string(&self) -> String {
            String::from(&format!(
                "{}_{}_{}",
                self.oram_id, self.path, self.packet_id
            ))
        }
    }
}

pub mod page {
    use helpers::range::ByteRange;
    use serde::{Deserialize, Serialize};
    use std::time::Instant;
    use std::untrusted::time::InstantEx;
    use std::vec::Vec;

    use oblivious_data_structures::ob_tree::components::{Origin};
    use query_state::{ObTreeSlotContentFilter, ParentId};
    use sql_engine::sql_data_types::components::SqlDataType;


    use crate::enclave_state::EnclaveState;
    use crate::oblivious_data_structures::position_tag::PositionTag;
    use crate::oblivious_ram::packaging::transform_bytes_to_oram_packets;
    use crate::sql_engine::sql_database::components::SqlTableRow;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct RIDChainItem {
        rids: Vec<SqlDataType>,
        next: Option<SlotPointer>,
        visited: Option<Vec<u128>>,
    }

    impl RIDChainItem {
        pub fn rids(&self) -> &Vec<SqlDataType> {
            &self.rids
        }
        pub fn add_rid(&mut self, rid: SqlDataType) {
            self.rids.push(rid);
        }
        pub fn pop_rid(&mut self) -> Option<SqlDataType> {
            self.rids.pop()
        }
        pub fn mut_rids(&mut self) -> &mut Vec<SqlDataType> {
            &mut self.rids
        }
        pub fn new(rids: Vec<SqlDataType>, next: Option<SlotPointer>) -> Self {
            RIDChainItem {
                rids,
                next,
                visited: None,
            }
        }
        pub fn next(&self) -> &Option<SlotPointer> {
            &self.next
        }
        pub fn set_next(&mut self, next: Option<SlotPointer>) {
            self.next = next;
        }
        pub fn add_query_to_visited(&mut self, query_id: u128) {
            match self.visited.as_mut() {
                None => {
                    self.visited = Some(Vec::new());
                    self.add_query_to_visited(query_id);
                }
                Some(some_visited) => {
                    some_visited.push(query_id);
                }
            }
        }
        pub fn remove_query_from_visited(&mut self, query_id: &u128) {
            match self.visited.as_mut() {
                None => {
                    panic!("Visited is not set");
                }
                Some(some_visited) => {
                    some_visited.retain(|q| q != query_id);
                }
            }
        }
        pub fn visited(&self) -> &Option<Vec<u128>> {
            &self.visited
        }
        pub fn visited_empty(&self) -> bool {
            return match self.visited.as_ref() {
                None => true,
                Some(some_visited) => some_visited.is_empty(),
            };
        }
        pub fn delete_ob_tree_filter(&mut self, filter: &ObTreeSlotContentFilter) -> usize {
            match filter {
                ObTreeSlotContentFilter::ATTRIBUTES(_) => {
                    panic!("A RID filter does not work with a SqlTableRow.");
                }
                ObTreeSlotContentFilter::RIDS(rids_to_delete) => {
                    self.mut_rids()
                        .retain(|slot_rid| !rids_to_delete.contains(slot_rid));
                    self.rids().len()
                }
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub enum SlotContent {
        Row(SqlTableRow),
        RIDs(RIDChainItem),
    }

    impl SlotContent {
        pub fn row(&self) -> Option<&SqlTableRow> {
            match self {
                SlotContent::Row(val) => Some(val),
                _ => None,
            }
        }
        pub fn rids(&self) -> Option<&RIDChainItem> {
            match self {
                SlotContent::RIDs(val) => Some(val),
                _ => None,
            }
        }
        pub fn mut_rids(&mut self) -> Option<&mut RIDChainItem> {
            match self {
                SlotContent::RIDs(val) => Some(val),
                _ => None,
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Slot {
        content: SlotContent,
        parent: Option<ParentId>,
        origin: Origin,
    }

    impl Slot {
        pub fn content(&self) -> &SlotContent {
            &self.content
        }
        pub fn mut_content(&mut self) -> &mut SlotContent {
            &mut self.content
        }
        pub fn content_copy(&self) -> SlotContent {
            self.content.clone()
        }
        pub fn new(content: SlotContent, origin: Origin) -> Self {
            Slot {
                content,
                parent: None,
                origin,
            }
        }
        pub fn evict(
            &self,
            enclave_state: &EnclaveState,
            locality_meta: Option<ByteRange>,
            index_id: u16,
        ) -> SlotPointer {
            let new_position = PositionTag::new_random(enclave_state);
            let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
            let mut statistics = enclave_state.lock_statistics();
            let packets = transform_bytes_to_oram_packets(
                enclave_state,
                &new_position,
                encoded,
                locality_meta,
                &mut statistics,
                index_id,
            );
            let insert_packet_to_stash_time: Instant = Instant::now();
            {
                let mut packet_stash = enclave_state.lock_packet_stash();
                for packet in packets {
                    let packet_size = packet.byte_size();
                    packet_stash.add_packet(packet, packet_size);
                }
            }
            statistics
                .inc_insert_packet_to_stash_time(insert_packet_to_stash_time.elapsed().as_nanos());
            SlotPointer::new(new_position)
        }
        pub fn set_parent(&mut self, parent: Option<ParentId>) {
            self.parent = parent;
        }
        pub fn mut_parent(&mut self) -> Option<&mut ParentId> {
            self.parent.as_mut()
        }
        pub fn parent(&self) -> &Option<ParentId> {
            &self.parent
        }
        pub fn origin(&self) -> &Origin {
            &self.origin
        }
        pub fn set_origin(&mut self, origin: Origin) {
            self.origin = origin;
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct SlotPointer {
        position: PositionTag,
        fill_amount: usize,
    }

    impl SlotPointer {
        pub fn new(position: PositionTag) -> Self {
            SlotPointer {
                position,
                fill_amount: 0,
            }
        }
        pub fn position(&self) -> &PositionTag {
            &self.position
        }
        pub fn set_position(&mut self, position: PositionTag) {
            self.position = position;
        }
        pub fn fill_amount(&self) -> usize {
            self.fill_amount
        }
        pub fn set_fill_amount(&mut self, fill_amount: usize) {
            self.fill_amount = fill_amount;
        }
    }

    pub fn create_slot_and_evict(
        enclave_state: &EnclaveState,
        content: SlotContent,
        locality_meta: Option<ByteRange>,
        index_id: u16,
        origin: Origin,
    ) -> SlotPointer {
        let slot = Slot::new(content, origin);
        return slot.evict(enclave_state, locality_meta, index_id);
    }
}

pub mod ob_tree {
    pub mod components {
        use alloc::collections::BTreeMap;
        use core::cmp::Ordering;


        use serde::{Deserialize, Serialize};
        use std::collections::HashMap;


        use std::time::Instant;
        use std::untrusted::time::InstantEx;
        use std::vec::Vec;

        use helpers::range::{sql_data_type_range_to_lossy_byte_range, Range};

        use oblivious_data_structures::position_tag::PositionTagWithoutId;
        use obt_stash::ObTreeNodeCache;
        use query_state::ObjectType::SlotObjectType;
        use query_state::{NextPos, ObjectType, ParentId, ParentNodeId, QueryState};
        use query_state_cache::QueryStateCache;
        use slot_cache::SlotCache;
        use sql_engine::sql_data_types::components::SqlDataType;
        use sql_engine::sql_database::components::SqlAttribute;
        use utils::Pair;
        use {log_runtime};
        use {DEBUG_PRINTS};

        use crate::enclave_state::EnclaveState;
        use crate::oblivious_data_structures::page::SlotPointer;
        use crate::oblivious_data_structures::position_tag::PositionTag;
        use crate::oblivious_ram::packaging::transform_bytes_to_oram_packets;

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTree {
            root: PositionTag,
            attribute_config: SqlAttribute,
            height: usize,
            query_locks: BTreeMap<ObTreeQueryValue, Vec<u128>>,
        }

        impl ObTree {
            fn new(root: PositionTag, attribute_config: SqlAttribute) -> Self {
                ObTree {
                    root,
                    attribute_config,
                    height: 1,
                    query_locks: BTreeMap::new(),
                }
            }
            pub fn create(enclave_state: &EnclaveState, attribute_config: SqlAttribute) -> Self {
                let mut root = ObTreeNode::new(Vec::new(), Vec::new(), None, Origin::Local);
                root.set_parent_node(ParentNode::NoParent);
                let root_pos = PositionTag::new_random(enclave_state);
                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                obt_node_cache.insert_node(root_pos.copy_packet_id(), root);
                ObTree::new(root_pos, attribute_config)
            }
            pub fn set_root(&mut self, root: PositionTag) {
                if DEBUG_PRINTS {
                    log_runtime(
                        &format!("A new root with ID {} is set.", root.packet_id()),
                        true,
                    );
                }
                self.root = root;
            }
            pub fn root(&self) -> &PositionTag {
                &self.root
            }
            pub fn height(&self) -> usize {
                self.height
            }
            pub fn inc_height(&mut self) {
                self.height += 1;
            }
            pub fn mut_query_locks(&mut self) -> &mut BTreeMap<ObTreeQueryValue, Vec<u128>> {
                &mut self.query_locks
            }
            pub fn remove_from_query_locks(
                &mut self,
                key: &ObTreeQueryValue,
                query_id: &u128,
                query_state_cache: &mut QueryStateCache,
            ) {
                let mut is_empty = false;
                match self.mut_query_locks().get_mut(key) {
                    None => {
                        panic!("Query lock was not active!");
                    }
                    Some(some_lock) => {
                        let removed = some_lock.remove(0);
                        assert_eq!(&removed, query_id);
                        match some_lock.get(0) {
                            None => {
                                is_empty = true;
                            }
                            Some(some_successor_query) => {
                                query_state_cache
                                    .get_mut(some_successor_query)
                                    .expect("Query must be in cache!")
                                    .set_operation_permission(true);
                            }
                        }
                    }
                }
                if is_empty {
                    self.mut_query_locks().remove(key);
                }
            }
            pub fn query_locks(&self) -> &BTreeMap<ObTreeQueryValue, Vec<u128>> {
                &self.query_locks
            }
            pub fn get_query_locks_at_value(&self, value: &ObTreeQueryValue) -> Option<&Vec<u128>> {
                return match self.query_locks().get(value) {
                    None => None,
                    Some(some_locks) => Some(some_locks),
                };
            }
            pub fn attribute_config(&self) -> &SqlAttribute {
                &self.attribute_config
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTreeDirectory {
            trees: HashMap<u16, ObTree>,
        }

        impl ObTreeDirectory {
            pub fn new() -> Self {
                ObTreeDirectory {
                    trees: HashMap::new(),
                }
            }
            pub fn initialize(enclave_state: &EnclaveState) {
                let mut database_scheme = enclave_state.lock_database_scheme();
                let mut index_id_iter: u16 = 0;
                let mut trees: HashMap<u16, ObTree> = HashMap::new();

                for table in database_scheme.tables() {
                    for attribute in table.attributes() {
                        trees.insert(
                            index_id_iter,
                            ObTree::create(enclave_state, attribute.clone()),
                        );
                        index_id_iter += 1;
                    }
                }
                enclave_state.lock_obt_tree_directory().set_trees(trees);
            }
            pub fn get_tree(&self, index: &u16) -> Option<&ObTree> {
                self.trees.get(index)
            }
            pub fn mut_tree(&mut self, index: &u16) -> Option<&mut ObTree> {
                self.trees.get_mut(index)
            }
            pub fn insert_tree(&mut self, index: u16, tree: ObTree) {
                assert!(!self.trees.contains_key(&index));
                self.trees.insert(index, tree);
            }
            pub fn contains_tree(&self, index: &u16) -> bool {
                self.trees.contains_key(index)
            }
            fn set_trees(&mut self, trees: HashMap<u16, ObTree>) {
                self.trees = trees;
            }
            pub fn size(&self) -> usize {
                self.trees.len()
            }
            pub fn mut_trees(&mut self) -> &mut HashMap<u16, ObTree> {
                &mut self.trees
            }
            pub fn trees(&self) -> &HashMap<u16, ObTree> {
                &self.trees
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTreeNodeForORAM {
            child_pointers: Vec<ObTreeChildPointer>,
            tuple_pointers: Vec<ObTreeTuplePointer>,
            sub_tree_value_range: Option<Range<SqlDataType>>,
        }

        impl ObTreeNodeForORAM {
            fn destroy(
                self,
            ) -> (
                Vec<ObTreeChildPointer>,
                Vec<ObTreeTuplePointer>,
                Option<Range<SqlDataType>>,
            ) {
                (
                    self.child_pointers,
                    self.tuple_pointers,
                    self.sub_tree_value_range,
                )
            }
            pub fn to_ob_tree_node(self, origin: Origin) -> ObTreeNode {
                let (child_pointers, tuple_pointers, sub_tree_value_range) = self.destroy();
                ObTreeNode::new(child_pointers, tuple_pointers, sub_tree_value_range, origin)
            }
            pub fn new(
                child_pointers: Vec<ObTreeChildPointer>,
                tuple_pointers: Vec<ObTreeTuplePointer>,
                sub_tree_value_range: Option<Range<SqlDataType>>,
            ) -> Self {
                ObTreeNodeForORAM {
                    child_pointers,
                    tuple_pointers,
                    sub_tree_value_range,
                }
            }
            fn serialize(&self) -> Vec<u8> {
                let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
                encoded
            }
            pub fn evict(
                &self,
                enclave_state: &EnclaveState,
                new_position: &PositionTag,
                index_id: u16,
            ) {
                let mut statistics = enclave_state.lock_statistics();

                let value_range = if enclave_state.lock_dynamic_config().index_locality_cache()
                    && self.sub_tree_value_range.is_some()
                {
                    Some(sql_data_type_range_to_lossy_byte_range(
                        self.sub_tree_value_range.as_ref().unwrap(),
                    ))
                } else {
                    None
                };

                let serialize_time = Instant::now();
                let encoded = self.serialize();
                statistics.inc_time_serialize_obtree_node(serialize_time.elapsed().as_nanos());

                let packets = transform_bytes_to_oram_packets(
                    enclave_state,
                    new_position,
                    encoded,
                    value_range,
                    &mut statistics,
                    index_id,
                );

                let insert_packet_to_stash_time = Instant::now();
                {
                    let mut packet_stash = enclave_state.lock_packet_stash();
                    for packet in packets {
                        let packet_size = packet.byte_size();
                        packet_stash.add_packet(packet, packet_size);
                    }
                }
                statistics.inc_insert_packet_to_stash_time(
                    insert_packet_to_stash_time.elapsed().as_nanos(),
                );
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub enum ParentNode {
            NoParent,
            ParentNodeId(ParentNodeId),
            EvictedParent(PositionTagWithoutId),
            NotSet,
        }

        impl ParentNode {
            pub fn parent_node_id(&self) -> Option<&ParentNodeId> {
                match self {
                    ParentNode::ParentNodeId(parent_node_id) => Some(parent_node_id),
                    _ => None,
                }
            }
            pub fn mut_parent_node_id(&mut self) -> Option<&mut ParentNodeId> {
                match self {
                    ParentNode::ParentNodeId(parent_node_id) => Some(parent_node_id),
                    _ => None,
                }
            }
            pub fn evicted_parent(&self) -> Option<&PositionTagWithoutId> {
                match self {
                    ParentNode::EvictedParent(my_new_pos) => Some(my_new_pos),
                    _ => None,
                }
            }
            pub fn is_no_parent(&self) -> bool {
                match self {
                    ParentNode::NoParent => true,
                    _ => false,
                }
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub enum Origin {
            IndexLocalityCache,
            ObliviousRAM,
            Local,
            Stash,
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTreeNode {
            child_pointers: Vec<ObTreeChildPointer>,
            tuple_pointers: Vec<ObTreeTuplePointer>,
            sub_tree_value_range: Option<Range<SqlDataType>>,
            /// Indices per child node if a query plans to traverse it next.
            query_next_traversing_meta: Option<Vec<Vec<u128>>>,
            /// Indices per tuple if a query plans to traverse it next.
            query_next_tuple_meta: Option<Vec<Vec<u128>>>,
            parent_node: ParentNode,
            /// List of queries which want to prevent the eviction of the node.
            do_not_evict: Option<Vec<u128>>,
            origin: Origin,
            traversal_visits: u64,
        }

        impl ObTreeNode {
            pub fn new(
                child_pointers: Vec<ObTreeChildPointer>,
                tuple_pointers: Vec<ObTreeTuplePointer>,
                sub_tree_value_range: Option<Range<SqlDataType>>,
                origin: Origin,
            ) -> Self {
                ObTreeNode {
                    child_pointers,
                    tuple_pointers,
                    sub_tree_value_range,
                    query_next_traversing_meta: None,
                    query_next_tuple_meta: None,
                    //planned_delete_meta: None,
                    parent_node: ParentNode::NotSet,
                    do_not_evict: None,
                    origin,
                    traversal_visits: 0u64,
                }
            }
            pub fn child_pointers(&self) -> &Vec<ObTreeChildPointer> {
                &self.child_pointers
            }
            pub fn child_pointer(&self, index: usize) -> Option<&ObTreeChildPointer> {
                self.child_pointers.get(index)
            }
            pub fn mut_child_pointer(&mut self, index: usize) -> Option<&mut ObTreeChildPointer> {
                self.child_pointers.get_mut(index)
            }
            pub fn swap_child_pointer(
                &mut self,
                index: usize,
                child_pointer: ObTreeChildPointer,
            ) -> ObTreeChildPointer {
                let old = self.child_pointers.remove(index);
                if DEBUG_PRINTS {
                    log_runtime(
                        &format!(
                            "swap_child_pointer - old: {}, new: {}",
                            old.position.packet_id(),
                            child_pointer.position().packet_id()
                        ),
                        true,
                    );
                }
                self.child_pointers.insert(index, child_pointer);
                old
            }
            pub fn set_child_pointers(&mut self, child_pointers: Vec<ObTreeChildPointer>) {
                self.child_pointers = child_pointers;
            }
            pub fn insert_child_pointer(
                &mut self,
                enclave_state: &EnclaveState,
                index: usize,
                child_pointer: ObTreeChildPointer,
            ) {
                self.child_pointers.insert(index, child_pointer);

                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                for new_index in (index + 1)..self.child_pointers.len() {
                    let child_pointer = self.child_pointers.get(new_index).unwrap();
                    match obt_node_cache.mut_node(child_pointer.position().packet_id()) {
                        None => {}
                        Some(some_child_node) => match some_child_node.mut_parent_node() {
                            ParentNode::ParentNodeId(some_parent_node_id) => {
                                some_parent_node_id.set_chosen_path(new_index as u32);
                            }
                            _ => {}
                        },
                    }
                }
                drop(obt_node_cache);
                match self.query_next_traversing_meta.as_mut() {
                    None => {}
                    Some(some_meta) => {
                        some_meta.insert(index, vec![]);
                        assert_eq!(some_meta.len(), self.child_pointers.len());
                        let mut query_state_cache = enclave_state.lock_query_state_cache();
                        for new_index in (index + 1)..some_meta.len() {
                            for query_iter_id in some_meta.get(new_index).unwrap().iter() {
                                let mut query_iter =
                                    query_state_cache.get_mut(query_iter_id).unwrap();
                                match query_iter.mut_parent() {
                                    None => {
                                        panic!("Parent must be set!");
                                    }
                                    Some(some_parent) => {
                                        some_parent.mut_node().expect("Must be a node parent, since it points to the current one.").set_chosen_path(new_index as u32);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            pub fn tuple_pointers(&self) -> &Vec<ObTreeTuplePointer> {
                &self.tuple_pointers
            }
            pub fn tuple_pointer(&self, index: usize) -> Option<&ObTreeTuplePointer> {
                self.tuple_pointers.get(index)
            }
            pub fn mut_tuple_pointer(&mut self, index: usize) -> Option<&mut ObTreeTuplePointer> {
                self.tuple_pointers.get_mut(index)
            }
            pub fn set_tuple_pointer_status(
                &mut self,
                enclave_state: &EnclaveState,
                index: usize,
                status: ObTreeTuplePointerStatus,
            ) {
                let mut tuple_pointer_position = self
                    .mut_tuple_pointer(index)
                    .unwrap()
                    .slot_pointer()
                    .position()
                    .clone();
                match self.query_next_tuple_meta.as_ref() {
                    None => {}
                    Some(some_query_next_tuple_meta) => {
                        match some_query_next_tuple_meta.get(index) {
                            None => {}
                            Some(query_entry) => {
                                let mut query_state_cache = enclave_state.lock_query_state_cache();
                                for query_id in query_entry.iter() {
                                    match query_state_cache.get_mut(query_id) {
                                        None => {}
                                        Some(query) => match &status {
                                            ObTreeTuplePointerStatus::ACTIVE => {
                                                if !query.next().is_valid() {
                                                    query.set_next(NextPos::Request(
                                                        tuple_pointer_position.clone(),
                                                        SlotObjectType,
                                                    ));
                                                }
                                            }
                                            ObTreeTuplePointerStatus::REMOVED => {
                                                if query.next().is_valid() {
                                                    query.set_next(NextPos::InvalidRequest);
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
                let mut tuple_pointer = self.mut_tuple_pointer(index).unwrap();
                tuple_pointer.set_status(status);
            }
            pub fn insert_tuple_pointer(
                &mut self,
                enclave_state: &EnclaveState,
                index: usize,
                tuple_pointer: ObTreeTuplePointer,
                tuple_pointer_meta: Option<Vec<u128>>,
            ) {
                self.tuple_pointers.insert(index, tuple_pointer);
                let mut slot_cache = enclave_state.lock_slot_cache();
                for new_index in (index + 1)..self.tuple_pointers.len() {
                    let tuple_pointer = self.tuple_pointers.get(new_index).unwrap();
                    match slot_cache.mut_slot(tuple_pointer.slot_pointer().position().packet_id()) {
                        None => {}
                        Some(some_slot) => match some_slot.mut_parent() {
                            None => {}
                            Some(some_parent) => {
                                some_parent
                                    .mut_node()
                                    .unwrap()
                                    .set_chosen_path(new_index as u32);
                            }
                        },
                    }
                }

                match self.query_next_tuple_meta.as_mut() {
                    None => match tuple_pointer_meta {
                        None => {}
                        Some(some_tuple_pointer_meta) => {
                            let mut query_next_tuple_meta =
                                vec![vec![]; self.tuple_pointers.len() - 1];
                            query_next_tuple_meta.insert(index, some_tuple_pointer_meta);
                            self.query_next_tuple_meta = Some(query_next_tuple_meta);
                        }
                    },
                    Some(some_meta) => {
                        match tuple_pointer_meta {
                            None => {
                                some_meta.insert(index, vec![]);
                            }
                            Some(some_tuple_pointer_meta) => {
                                some_meta.insert(index, some_tuple_pointer_meta);
                            }
                        }
                        assert_eq!(some_meta.len(), self.tuple_pointers.len());
                        let mut query_state_cache = enclave_state.lock_query_state_cache();
                        for new_index in (index + 1)..some_meta.len() {
                            for query_iter_id in some_meta.get(new_index).unwrap().iter() {
                                let mut query_iter =
                                    query_state_cache.get_mut(query_iter_id).unwrap();
                                match query_iter.mut_parent() {
                                    None => {
                                        panic!("Parent must be set!");
                                    }
                                    Some(some_parent) => match some_parent.mut_node() {
                                        None => {}
                                        Some(some_node) => {
                                            some_node.set_chosen_path(new_index as u32);
                                        }
                                    },
                                }
                            }
                        }
                    }
                }
            }
            pub fn set_tuple_pointers(&mut self, tuple_pointers: Vec<ObTreeTuplePointer>) {
                self.tuple_pointers = tuple_pointers;
            }

            pub fn get_local_range(
                &self,
            ) -> Pair<Option<&ObTreeTuplePointer>, Option<&ObTreeTuplePointer>> {
                Pair::new(self.tuple_pointers.first(), self.tuple_pointers.last())
            }
            pub fn sub_tree_value_range(&self) -> &Option<Range<SqlDataType>> {
                &self.sub_tree_value_range
            }
            pub fn destroy_and_get_sub_tree_value_range(self) -> Option<Range<SqlDataType>> {
                self.sub_tree_value_range
            }
            pub fn mut_sub_tree_value_range(&mut self) -> &mut Option<Range<SqlDataType>> {
                &mut self.sub_tree_value_range
            }
            pub fn destroy_and_return_sub_tree_value_range(self) -> Option<Range<SqlDataType>> {
                self.sub_tree_value_range
            }
            pub fn set_sub_tree_value_range(
                &mut self,
                sub_tree_value_range: Option<Range<SqlDataType>>,
            ) {
                self.sub_tree_value_range = sub_tree_value_range;
            }

            pub fn evict(
                self,
                enclave_state: &EnclaveState,
                new_position: &PositionTag,
                index_id: u16,
            ) {
                assert!(
                    self.query_next_traversing_meta.is_none()
                        && self.query_next_tuple_meta.is_none()
                        && self.do_not_evict.is_none(),
                    //&& self.needed_by.is_none(),
                    "1: {}, 2: {}, 3: {}",
                    self.query_next_traversing_meta.is_none(),
                    self.query_next_tuple_meta.is_none(),
                    self.do_not_evict.is_none()
                );

                {
                    let mut statistics = enclave_state.lock_statistics();
                    statistics.inc_total_node_evictions();
                    statistics.inc_total_node_traversal_visits(self.traversal_visits);
                }

                let node_to_evict = ObTreeNodeForORAM::new(
                    self.child_pointers,
                    self.tuple_pointers,
                    self.sub_tree_value_range,
                );
                node_to_evict.evict(enclave_state, new_position, index_id);
            }

            pub fn query_next_traversing_meta(&self) -> &Option<Vec<Vec<u128>>> {
                &self.query_next_traversing_meta
            }
            pub fn set_query_next_traversing_meta(
                &mut self,
                query_next_traversing_meta: Option<Vec<Vec<u128>>>,
            ) {
                self.query_next_traversing_meta = query_next_traversing_meta;
            }
            pub fn remove_complete_query_next_traversing_meta(&mut self) -> Option<Vec<Vec<u128>>> {
                let old_meta = self.query_next_traversing_meta.clone();
                self.query_next_traversing_meta = None;
                old_meta
            }
            pub fn query_next_traversing_meta_empty_at(&self, index: usize) -> bool {
                match self.query_next_traversing_meta() {
                    None => true,
                    Some(some_meta) => some_meta.get(index).unwrap().is_empty(),
                }
            }
            pub fn insert_into_query_next_traversing_meta(&mut self, index: usize, query_id: u128) {
                match self.query_next_traversing_meta.as_mut() {
                    None => {
                        self.query_next_traversing_meta =
                            Some(vec![vec![]; self.child_pointers.len()]);
                        self.insert_into_query_next_traversing_meta(index, query_id);
                    }
                    Some(some_meta) => {
                        assert_eq!(
                            some_meta.len(),
                            self.child_pointers.len(),
                            "{} != {}",
                            some_meta.len(),
                            self.child_pointers.len()
                        );
                        if DEBUG_PRINTS {
                            log_runtime(
                                &format!(
                                    "insert_into_query_next_traversing_meta: Query {}, index {}, child_pos_id: {}",
                                    query_id, index, self.child_pointers.get(index).unwrap().position().packet_id()
                                ),
                                true,
                            );
                        }
                        match some_meta.get_mut(index) {
                            None => {
                                panic!("Error in insert_into_query_next_traversing_meta.");
                            }
                            Some(some_meta_vec) => {
                                some_meta_vec.push(query_id);
                            }
                        }
                    }
                }
            }
            pub fn pop_entry_from_query_next_traversing_meta(
                &mut self,
                index: usize,
            ) -> Option<Vec<u128>> {
                match self.query_next_traversing_meta.as_mut() {
                    None => {}
                    Some(some_meta) => {
                        assert!(some_meta.len() == self.child_pointers.len());
                        match some_meta.get_mut(index) {
                            None => {}
                            Some(some_meta_vec) => {
                                let entry = some_meta_vec.clone();
                                some_meta_vec.truncate(0);
                                return Some(entry);
                            }
                        }
                    }
                }
                return None;
            }
            fn remove_query_from_query_next_traversing_meta(
                &mut self,
                index: usize,
                query_id: &u128,
            ) {
                match self.query_next_traversing_meta.as_mut() {
                    None => {}
                    Some(some_meta) => {
                        assert!(some_meta.len() == self.child_pointers.len());
                        let mut does_not_contain = false;
                        match some_meta.get_mut(index) {
                            None => {
                                panic!("Error in insert_into_query_next_traversing_meta.");
                            }
                            Some(some_meta_vec) => {
                                if !some_meta_vec.contains(query_id) {
                                    does_not_contain = true;
                                } else {
                                    some_meta_vec.retain(|q| q != query_id);
                                }
                            }
                        }
                        if does_not_contain {
                            log_runtime(
                                &format!(
                                    "does_not_contain query {} in index {} of meta",
                                    query_id, index
                                ),
                                true,
                            );
                            for i in 0..some_meta.len() {
                                match some_meta.get_mut(i) {
                                    None => {
                                        panic!("Error in insert_into_query_next_traversing_meta.");
                                    }
                                    Some(some_meta_vec) => {
                                        if some_meta_vec.contains(query_id) {
                                            log_runtime(&format!("but i {} contains", i), true);
                                            break;
                                        }
                                    }
                                }
                            }
                            panic!("Error in insert_into_query_next_traversing_meta.");
                        }
                    }
                }
            }

            pub fn query_next_tuple_meta(&self) -> &Option<Vec<Vec<u128>>> {
                &self.query_next_tuple_meta
            }
            pub fn remove_complete_query_next_tuple_meta(&mut self) -> Option<Vec<Vec<u128>>> {
                let old_meta = self.query_next_tuple_meta.clone();
                self.query_next_tuple_meta = None;
                old_meta
            }
            pub fn query_next_tuple_meta_empty_at(&self, index: usize) -> bool {
                match self.query_next_tuple_meta.as_ref() {
                    None => {}
                    Some(some_meta) => match some_meta.get(index) {
                        None => {}
                        Some(some_entry) => {
                            if !some_entry.is_empty() {
                                return false;
                            }
                        }
                    },
                }
                true
            }
            pub fn insert_into_query_next_tuple_meta(&mut self, index: usize, query_id: u128) {
                match self.query_next_tuple_meta.as_mut() {
                    None => {
                        self.query_next_tuple_meta = Some(vec![vec![]; self.tuple_pointers.len()]);
                        self.insert_into_query_next_tuple_meta(index, query_id);
                    }
                    Some(some_meta) => {
                        assert!(some_meta.len() == self.tuple_pointers.len());
                        match some_meta.get_mut(index) {
                            None => {
                                panic!("Error in insert_into_query_next_traversing_meta.");
                            }
                            Some(some_meta_vec) => {
                                some_meta_vec.push(query_id);
                            }
                        }
                    }
                }
            }
            pub fn remove_query_from_query_next_tuple_meta(
                &mut self,
                index: usize,
                query_id: &u128,
            ) {
                match self.query_next_tuple_meta.as_mut() {
                    None => {}
                    Some(some_meta) => {
                        assert!(some_meta.len() == self.tuple_pointers.len());
                        match some_meta.get_mut(index) {
                            None => {
                                panic!("Error in insert_into_query_next_traversing_meta.");
                            }
                            Some(some_meta_vec) => {
                                some_meta_vec.retain(|q| q != query_id);
                            }
                        }
                    }
                }
            }

            pub fn do_not_evict(&self) -> &Option<Vec<u128>> {
                &self.do_not_evict
            }
            pub fn add_to_do_not_evict(&mut self, query: u128) {
                match self.do_not_evict.as_mut() {
                    None => {
                        self.do_not_evict = Some(Vec::new());
                        self.add_to_do_not_evict(query);
                    }
                    Some(some_do_not_evict) => {
                        some_do_not_evict.push(query);
                    }
                }
            }
            pub fn remove_from_do_not_evict(&mut self, query_id: &u128) {
                let mut is_empty = false;
                match self.do_not_evict.as_mut() {
                    None => {}
                    Some(some_do_not_evict) => {
                        some_do_not_evict.retain(|q| q.ne(query_id));
                        if some_do_not_evict.is_empty() {
                            is_empty = true;
                        }
                    }
                }
                if is_empty {
                    self.do_not_evict = None;
                }
            }
            pub fn remove_complete_do_not_evict(&mut self) -> Option<Vec<u128>> {
                let removal = self.do_not_evict.clone();
                self.do_not_evict = None;
                removal
            }

            pub fn next_meta_empty(&mut self) -> bool {
                match self.query_next_tuple_meta() {
                    None => {}
                    Some(some_meta) => {
                        for entry in some_meta.iter() {
                            if !entry.is_empty() {
                                return false;
                            }
                        }
                    }
                }
                match self.query_next_traversing_meta() {
                    None => {}
                    Some(some_meta) => {
                        for entry in some_meta.iter() {
                            if !entry.is_empty() {
                                return false;
                            }
                        }
                    }
                }
                self.query_next_tuple_meta = None;
                self.query_next_traversing_meta = None;
                true
            }
            pub fn parent_node(&self) -> &ParentNode {
                &self.parent_node
            }
            pub fn mut_parent_node(&mut self) -> &mut ParentNode {
                &mut self.parent_node
            }
            pub fn set_parent_node(&mut self, parent_node: ParentNode) {
                self.parent_node = parent_node;
            }
            pub fn set_query_next_tuple_meta(
                &mut self,
                query_next_tuple_meta: Option<Vec<Vec<u128>>>,
            ) {
                self.query_next_tuple_meta = query_next_tuple_meta;
            }

            pub fn broadcast_eviction_to_children(&mut self, enclave_state: &EnclaveState) {
                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                for child in self.child_pointers.iter_mut() {
                    let child_id = child.position().copy_packet_id();
                    match obt_node_cache.mut_node(&child_id) {
                        None => {}
                        Some(mut some_child_node) => match some_child_node.parent_node() {
                            ParentNode::ParentNodeId(_) => {
                                let new_child_pos = {
                                    let oram_config = enclave_state.lock_oram_config();
                                    PositionTag::new_random_from_packet_id(
                                        oram_config.number_of_oram() as u32,
                                        oram_config.oram_degree(),
                                        oram_config.tree_height(),
                                        child_id,
                                    )
                                };
                                some_child_node.set_parent_node(ParentNode::EvictedParent(
                                    new_child_pos.without_id(),
                                ));
                                child.set_position(new_child_pos);
                            }
                            _ => (),
                        },
                    }
                }
            }

            pub fn no_child_node_is_in_cache(&self, obt_node_cache: &ObTreeNodeCache) -> bool {
                for child in self.child_pointers().iter() {
                    if obt_node_cache
                        .get_node(child.position().packet_id())
                        .is_some()
                    {
                        return false;
                    }
                }
                true
            }
            pub fn no_slot_node_is_in_cache(&self, slot_cache: &SlotCache) -> bool {
                for tuple in self.tuple_pointers().iter() {
                    if slot_cache
                        .get_slot(tuple.slot_pointer().position().packet_id())
                        .is_some()
                    {
                        return false;
                    }
                }
                true
            }
            pub fn searched_child_node_is_fetched_now(
                &mut self,
                query_id: &u128,
                chosen_path: usize,
                child_node_id: &u128,
            ) {
                self.remove_query_from_query_next_traversing_meta(chosen_path, query_id);
                if self
                    .child_pointers()
                    .get(chosen_path)
                    .unwrap()
                    .position()
                    .packet_id()
                    != child_node_id
                {
                    log_runtime(&format!("index in parent: {}", chosen_path), true);
                    panic!("parent points to != real current node id");
                }
            }
            pub fn traverse_child_pointer_with_query(
                &mut self,
                this_node_position_id: u128,
                child_pointer_index: usize,
                query_state: &mut QueryState,
            ) -> u128 {
                let next_position = self
                    .child_pointers()
                    .get(child_pointer_index)
                    .unwrap()
                    .position()
                    .clone();
                let child_id = next_position.copy_packet_id();
                self.insert_into_query_next_traversing_meta(child_pointer_index, query_state.id());
                query_state.set_next(NextPos::Request(next_position, ObjectType::NodeObjectType));
                query_state.set_parent(Some(ParentId::Node(ParentNodeId::new(
                    this_node_position_id,
                    child_pointer_index as u32,
                ))));
                child_id
            }
            pub fn origin(&self) -> &Origin {
                &self.origin
            }
            pub fn inc_traversal_visits(&mut self) {
                self.traversal_visits += 1;
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTreeChildPointer {
            position: PositionTag,
            leaf_slots: Option<u16>,
        }

        impl ObTreeChildPointer {
            pub fn position(&self) -> &PositionTag {
                &self.position
            }
            pub fn set_position(&mut self, position: PositionTag) {
                self.position = position;
            }
            pub fn new(position: PositionTag, leaf_slots: Option<u16>) -> Self {
                ObTreeChildPointer {
                    position,
                    leaf_slots,
                }
            }
            pub fn leaf_slots(&self) -> Option<u16> {
                self.leaf_slots
            }
            pub fn set_leaf_slots(&mut self, leaf_slots: Option<u16>) {
                self.leaf_slots = leaf_slots;
            }
            pub fn replace_me_from(&mut self, position: PositionTag, leaf_slots: Option<u16>) {
                self.position = position;
                self.leaf_slots = leaf_slots;
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTreeTuplePointer {
            #[serde(with = "serde_bytes")]
            key: Vec<u8>,
            slot_pointer: SlotPointer,
            status: ObTreeTuplePointerStatus,
        }

        impl ObTreeTuplePointer {
            pub fn new(key: Vec<u8>, slot_pointer: SlotPointer) -> Self {
                ObTreeTuplePointer {
                    key,
                    slot_pointer,
                    status: ObTreeTuplePointerStatus::ACTIVE,
                }
            }
            pub fn key(&self) -> &Vec<u8> {
                &self.key
            }
            pub fn set_key(&mut self, key: Vec<u8>) {
                self.key = key;
            }
            pub fn slot_pointer(&self) -> &SlotPointer {
                &self.slot_pointer
            }
            pub fn set_slot_pointer(&mut self, slot_pointer: SlotPointer) {
                self.slot_pointer = slot_pointer;
            }
            pub fn mut_slot_pointer(&mut self) -> &mut SlotPointer {
                &mut self.slot_pointer
            }
            pub fn status(&self) -> &ObTreeTuplePointerStatus {
                &self.status
            }
            pub fn is_active(&self) -> bool {
                match &self.status {
                    ObTreeTuplePointerStatus::ACTIVE => true,
                    _ => false,
                }
            }
            pub fn set_status(&mut self, status: ObTreeTuplePointerStatus) {
                self.status = status;
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub enum ObTreeTuplePointerStatus {
            ACTIVE,
            REMOVED,
        }

        impl ObTreeTuplePointerStatus {
            pub fn is_removed(&self) -> bool {
                match self {
                    ObTreeTuplePointerStatus::ACTIVE => false,
                    ObTreeTuplePointerStatus::REMOVED => true,
                }
            }
        }

        #[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
        pub struct ObTreeQueryValueRange {
            lower: SqlDataType,
            upper: SqlDataType,
        }

        impl ObTreeQueryValueRange {
            pub fn new(lower: SqlDataType, upper: SqlDataType) -> Self {
                ObTreeQueryValueRange { lower, upper }
            }
            pub fn lower(&self) -> &SqlDataType {
                &self.lower
            }
            pub fn upper(&self) -> &SqlDataType {
                &self.upper
            }
            pub fn set_lower(&mut self, lower: SqlDataType) {
                self.lower = lower;
            }
            pub fn set_upper(&mut self, upper: SqlDataType) {
                self.upper = upper;
            }
            pub fn destroy_and_return_components(self) -> (SqlDataType, SqlDataType) {
                (self.lower, self.upper)
            }
            pub fn extend(&mut self, other: ObTreeQueryValueRange) {
                let other_range = other.destroy_and_return_components();
                if self.lower().cmp(&other_range.0).is_gt() {
                    self.lower = other_range.0;
                }
                if self.upper().cmp(&other_range.1).is_lt() {
                    self.upper = other_range.1;
                }
            }
            pub fn extend_lower(&mut self, other: SqlDataType) {
                if self.lower().cmp(&other).is_gt() {
                    self.lower = other;
                }
            }
            pub fn extend_upper(&mut self, other: SqlDataType) {
                if self.upper().cmp(&other).is_lt() {
                    self.upper = other;
                }
            }
            pub fn intersects(&self, other: &ObTreeQueryValueRange) -> bool {
                self.cmp(other).is_eq()
            }
            pub fn contains(&self, other: &SqlDataType) -> bool {
                self.lower().cmp(other).is_le() && self.upper().cmp(other).is_ge()
            }
        }

        impl PartialOrd for ObTreeQueryValueRange {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for ObTreeQueryValueRange {
            fn cmp(&self, other: &Self) -> Ordering {
                if self.lower().cmp(&other.lower()).is_ge() {
                    return if self.lower().cmp(&other.upper()).is_le() {
                        Ordering::Equal
                    } else {
                        Ordering::Greater
                    };
                } else if self.upper().cmp(other.lower()).is_ge() {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            }
        }

        #[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
        pub enum ObTreeQueryValue {
            Single(SqlDataType),
            Range(ObTreeQueryValueRange),
        }

        impl ObTreeQueryValue {
            pub fn single(&self) -> Option<&SqlDataType> {
                match self {
                    ObTreeQueryValue::Single(row) => Some(row),
                    ObTreeQueryValue::Range(_) => None,
                }
            }
            pub fn range(&self) -> Option<&ObTreeQueryValueRange> {
                match self {
                    ObTreeQueryValue::Single(_) => None,
                    ObTreeQueryValue::Range(range) => Some(range),
                }
            }
            pub fn mut_range(&mut self) -> Option<&mut ObTreeQueryValueRange> {
                match self {
                    ObTreeQueryValue::Single(_) => None,
                    ObTreeQueryValue::Range(range) => Some(range),
                }
            }
            pub fn clone_as_range(&self) -> Range<SqlDataType> {
                match self {
                    ObTreeQueryValue::Single(single) => Range::new(single.clone(), single.clone()),
                    ObTreeQueryValue::Range(range) => {
                        Range::new(range.lower().clone(), range.upper().clone())
                    }
                }
            }
            pub fn intersects(&self, other: &ObTreeQueryValue) -> bool {
                return match self {
                    ObTreeQueryValue::Single(single) => match other {
                        ObTreeQueryValue::Single(other_single) => single.eq(other_single),
                        ObTreeQueryValue::Range(other_range) => other_range.contains(single),
                    },
                    ObTreeQueryValue::Range(range) => match other {
                        ObTreeQueryValue::Single(other_single) => range.contains(other_single),
                        ObTreeQueryValue::Range(other_range) => range.intersects(other_range),
                    },
                };
            }
        }

        impl PartialOrd for ObTreeQueryValue {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for ObTreeQueryValue {
            fn cmp(&self, other: &Self) -> Ordering {
                return match self {
                    ObTreeQueryValue::Single(single) => match other {
                        ObTreeQueryValue::Single(other_single) => single.cmp(other_single),
                        ObTreeQueryValue::Range(other_range) => {
                            if single.cmp(other_range.lower()).is_lt() {
                                Ordering::Less
                            } else if single.cmp(other_range.upper()).is_le() {
                                Ordering::Equal
                            } else {
                                Ordering::Greater
                            }
                        }
                    },
                    ObTreeQueryValue::Range(range) => match other {
                        ObTreeQueryValue::Single(other_single) => {
                            if range.lower().cmp(other_single).is_gt() {
                                Ordering::Greater
                            } else if range.upper().cmp(other_single).is_ge() {
                                Ordering::Equal
                            } else {
                                Ordering::Less
                            }
                        }
                        ObTreeQueryValue::Range(other_range) => range.cmp(other_range),
                    },
                };
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct ObTreeQuery {
            value: ObTreeQueryValue,
            key_config: SqlAttribute,
            index_id: u16,
        }

        impl ObTreeQuery {
            pub fn value(&self) -> &ObTreeQueryValue {
                &self.value
            }
            pub fn key_config(&self) -> &SqlAttribute {
                &self.key_config
            }
            pub fn index_id(&self) -> u16 {
                self.index_id
            }
            pub fn new(value: ObTreeQueryValue, key_config: SqlAttribute, index_id: u16) -> Self {
                ObTreeQuery {
                    value,
                    key_config,
                    index_id,
                }
            }
        }
    }

    mod helpers {
        use core::cmp::Ordering;

        use std::time::Instant;
        use std::untrusted::time::InstantEx;
        use std::vec::Vec;

        use helpers::range::{ByteRange, Range};
        use oblivious_data_structures::ob_tree;

        use oblivious_data_structures::ob_tree::components::{
            ObTreeTuplePointer, Origin,
        };
        use oblivious_data_structures::page::{
            create_slot_and_evict,
        };

        use oram_interface::EnclaveStatistics;
        use query_state::{NextPos, QueryState};
        use sql_engine::sql_data_types::components::SqlDataType;
        use sql_engine::sql_data_types::functions::{
            compress_sql_data_type, decompress_sql_data_type,
        };
        use sql_engine::sql_database::components::SqlAttribute;
        use {EnclaveState};

        #[derive(Clone, PartialEq)]
        pub enum ObTreeKeyCmpOperator {
            Equal,
            Less,
            Greater,
        }

        // Searches for a key range in a vector of tuple pointers
        pub fn search_range_value_in_node_tuple_pointers(
            statistics: &mut EnclaveStatistics,
            tuple_pointers: &Vec<ObTreeTuplePointer>,
            searched_range: &Range<SqlDataType>,
            key_config: &SqlAttribute,
        ) -> ((usize, ObTreeKeyCmpOperator), (usize, ObTreeKeyCmpOperator)) {
            let mut found_lower = false;

            let mut left: (usize, ObTreeKeyCmpOperator) =
                (tuple_pointers.len(), ObTreeKeyCmpOperator::Greater);
            let mut right: (usize, ObTreeKeyCmpOperator) =
                (tuple_pointers.len(), ObTreeKeyCmpOperator::Greater);

            for (iter_key, iter_tuple_pointer) in tuple_pointers.iter().enumerate() {
                let time_decompress_sql_data_type: Instant = Instant::now();
                let iter_key_decompr =
                    decompress_sql_data_type(iter_tuple_pointer.key(), key_config);
                statistics.inc_time_decompress_sql_data_type(
                    time_decompress_sql_data_type.elapsed().as_nanos(),
                );

                if !found_lower {
                    match searched_range.lower().cmp(&iter_key_decompr) {
                        Ordering::Less => {
                            found_lower = true;
                            left.0 = iter_key;
                            left.1 = ObTreeKeyCmpOperator::Less;
                        }
                        Ordering::Equal => {
                            found_lower = true;
                            left.0 = iter_key;
                            left.1 = ObTreeKeyCmpOperator::Equal;
                        }
                        _ => {}
                    }
                } else {
                    match searched_range.upper().cmp(&iter_key_decompr) {
                        Ordering::Less => {
                            right.0 = iter_key;
                            right.1 = ObTreeKeyCmpOperator::Less;
                            break;
                        }
                        Ordering::Equal => {
                            right.0 = iter_key;
                            right.1 = ObTreeKeyCmpOperator::Equal;
                            break;
                        }
                        _ => {}
                    }
                }
            }

            (left, right)
        }

        // Searches for a key in a vector of tuple pointers
        pub fn search_single_value_in_node_tuple_pointers(
            statistics: &mut EnclaveStatistics,
            tuple_pointers: &Vec<ObTreeTuplePointer>,
            searched_value: &SqlDataType,
            key_config: &SqlAttribute,
        ) -> (usize, ObTreeKeyCmpOperator) {
            let mut found_index: (usize, ObTreeKeyCmpOperator) =
                (tuple_pointers.len(), ObTreeKeyCmpOperator::Greater);

            for (iter_key, iter_tuple_pointer) in tuple_pointers.iter().enumerate() {
                let time_decompress_sql_data_type: Instant = Instant::now();
                let iter_key_decompr =
                    decompress_sql_data_type(iter_tuple_pointer.key(), key_config);
                statistics.inc_time_decompress_sql_data_type(
                    time_decompress_sql_data_type.elapsed().as_nanos(),
                );
                match searched_value.cmp(&iter_key_decompr) {
                    Ordering::Less => {
                        found_index.0 = iter_key;
                        found_index.1 = ObTreeKeyCmpOperator::Less;
                        break;
                    }
                    Ordering::Equal => {
                        found_index.0 = iter_key;
                        found_index.1 = ObTreeKeyCmpOperator::Equal;
                        break;
                    }
                    _ => {}
                }
            }

            found_index
        }

        pub fn helper_insert_new_tuple_to_obt_leaf(
            enclave_state: &EnclaveState,
            query_state: &mut QueryState,
            current_node_id: u128,
            index_to_insert: usize,
        ) {
            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
            let mut node = obt_node_cache.mut_node(&current_node_id).unwrap();

            let mut slot_content = query_state
                .operation_type()
                .get_insert_query_state()
                .unwrap()
                .slot_content()
                .clone();
            let key_compr = compress_sql_data_type(
                query_state.ob_tree_query().value().single().unwrap(),
                false,
                false,
            );
            let locality_meta = if enclave_state.lock_dynamic_config().index_locality_cache() {
                Some(ByteRange::new(key_compr.clone(), key_compr.clone()))
            } else {
                None
            };
            let tuple_pointer_insert = ObTreeTuplePointer::new(
                key_compr,
                create_slot_and_evict(
                    enclave_state,
                    slot_content,
                    locality_meta,
                    query_state.ob_tree_query().index_id(),
                    Origin::Local,
                ),
            );
            node.insert_tuple_pointer(enclave_state, index_to_insert, tuple_pointer_insert, None);

            return match node.tuple_pointers().len() <= 2 * enclave_state.fill_grade() {
                true => {
                    // normal insert was possible. no balancing needed.
                    if enclave_state.lock_dynamic_config().index_locality_cache() {
                        let range = node.get_local_range();
                        let range = Some(Range::new(
                            decompress_sql_data_type(
                                range.first().unwrap().key(),
                                query_state.ob_tree_query().key_config(),
                            ),
                            decompress_sql_data_type(
                                range.second().unwrap().key(),
                                query_state.ob_tree_query().key_config(),
                            ),
                        ));
                        node.set_sub_tree_value_range(range.clone());
                    };

                    /*
                    enclave_state
                        .lock_statistics()
                        .inc_time_insert_point(start_time.elapsed().as_nanos());
                     */

                    drop(obt_node_cache);
                    query_state.set_next(NextPos::Finite);
                    query_state.set_parent(None);
                    ob_tree::eviction::evict_node_bottom_up(
                        enclave_state,
                        current_node_id,
                        query_state.id(),
                        true,
                        query_state.ob_tree_query().index_id(),
                        Instant::now(),
                    )
                }
                false => {
                    // split leaf and move middle to parent
                    // adapt the node meta
                    assert!(node.query_next_traversing_meta().is_none());
                    drop(obt_node_cache);
                    query_state.set_next(NextPos::Finite);
                    query_state.set_parent(None);
                    ob_tree::internal_manipulation::split_node(
                        enclave_state,
                        current_node_id,
                        None,
                        None,
                        index_to_insert as u32,
                        query_state.ob_tree_query().index_id(),
                        query_state.ob_tree_query().key_config().clone(),
                        query_state.id(),
                    )
                }
            };
        }
    }

    mod eviction {
        use std::time::Instant;
        use std::untrusted::time::InstantEx;


        use helpers::range::ByteRange;
        use oblivious_data_structures::ob_tree::components::{
            ParentNode,
        };
        use oblivious_data_structures::page::{Slot, SlotContent};
        use oblivious_data_structures::position_tag::PositionTag;
        use query_state::{ParentNodeId};

        use {EnclaveState, DEBUG_RUNTIME_CHECKS};

        pub fn evict_slot_back_to_front(
            enclave_state: &EnclaveState,
            current_slot_id: u128,
            query_id: u128,
            index_id: u16,
        ) -> Option<ParentNodeId> {
            let mut current_slot = enclave_state
                .lock_slot_cache()
                .remove_slot(&current_slot_id)
                .unwrap();

            return match current_slot.content() {
                SlotContent::Row(_) => {
                    // The slot is a row tuple.
                    match helper_evict_tuple_from_node(
                        enclave_state,
                        &mut current_slot,
                        query_id,
                        index_id,
                    ) {
                        None => {
                            enclave_state
                                .lock_slot_cache()
                                .insert_slot(current_slot_id, current_slot);
                            None
                        }
                        Some(some_parent_node_id) => Some(some_parent_node_id),
                    }
                }
                SlotContent::RIDs(_) => {
                    // The slot is a RID chain item.
                    // Check if no other queries want to visit its successor item, and that its successor is not in the cache
                    if current_slot.content().rids().unwrap().visited_empty()
                        && !(current_slot.content().rids().unwrap().next().is_some()
                        && enclave_state
                        .lock_slot_cache()
                        .get_slot(
                            current_slot
                                .content()
                                .rids()
                                .unwrap()
                                .next()
                                .as_ref()
                                .unwrap()
                                .position()
                                .packet_id(),
                        )
                        .is_some())
                    {
                        // Check if the parent of the slot is a node
                        if current_slot.parent().as_ref().unwrap().node().is_some() {
                            match helper_evict_tuple_from_node(
                                enclave_state,
                                &mut current_slot,
                                query_id,
                                index_id,
                            ) {
                                None => {
                                    enclave_state
                                        .lock_slot_cache()
                                        .insert_slot(current_slot_id, current_slot);
                                    None
                                }
                                Some(some_parent_node_id) => Some(some_parent_node_id),
                            }
                        } else {
                            let mut slot_cache = enclave_state.lock_slot_cache();
                            let predecessor_slot_id = current_slot
                                .parent()
                                .as_ref()
                                .unwrap()
                                .slot()
                                .unwrap()
                                .copy_cache_id();
                            // The predecessor is also a RID chain item, i.e. a slot.
                            let mut predecessor_slot =
                                slot_cache.mut_slot(&predecessor_slot_id).unwrap();
                            // Check if any query has visited the predecessor and visits the current slot as next step.
                            if predecessor_slot
                                .mut_content()
                                .mut_rids()
                                .unwrap()
                                .visited_empty()
                            {
                                // We can safely evict the current slot now.
                                let new_slot_pointer =
                                    current_slot.evict(enclave_state, None, index_id);
                                predecessor_slot
                                    .mut_content()
                                    .mut_rids()
                                    .unwrap()
                                    .set_next(Some(new_slot_pointer));
                                return evict_slot_back_to_front(
                                    enclave_state,
                                    predecessor_slot_id,
                                    query_id,
                                    index_id,
                                );
                            } else {
                                drop(slot_cache);
                                enclave_state
                                    .lock_slot_cache()
                                    .insert_slot(current_slot_id, current_slot);
                                None
                            }
                        }
                    } else {
                        enclave_state
                            .lock_slot_cache()
                            .insert_slot(current_slot_id, current_slot);
                        None
                    }
                }
            };

            fn helper_evict_tuple_from_node(
                enclave_state: &EnclaveState,
                current_slot: &mut Slot,
                query_id: u128,
                index_id: u16,
            ) -> Option<ParentNodeId> {
                let mut obt_node_cache = enclave_state.lock_obt_node_cache();

                let parent_node_id = current_slot
                    .parent()
                    .as_ref()
                    .unwrap()
                    .node()
                    .expect("Parent of row must be a node");
                let parent_node_tuple_index = parent_node_id.chosen_path() as usize;

                // The parent node that points to the slot
                let mut parent_node =
                    obt_node_cache
                        .mut_node(parent_node_id.cache_id())
                        .expect(&format!(
                            "Parent {} must be in cache.",
                            parent_node_id.cache_id()
                        ));
                parent_node
                    .remove_query_from_query_next_tuple_meta(parent_node_tuple_index, &query_id);

                if parent_node.query_next_tuple_meta_empty_at(parent_node_tuple_index) {
                    // No other query is busy with the tuple of our slot
                    // We can evict slot
                    let parent_node_id = parent_node_id.clone();
                    let fill_amount: Option<usize> = match current_slot.content().rids() {
                        None => None,
                        Some(some_rids) => Some(some_rids.rids().len()),
                    };
                    let tuple_pointer = parent_node
                        .mut_tuple_pointer(parent_node_tuple_index)
                        .unwrap();
                    let locality_meta =
                        if enclave_state.lock_dynamic_config().index_locality_cache() {
                            Some(ByteRange::new(
                                tuple_pointer.key().clone(),
                                tuple_pointer.key().clone(),
                            ))
                        } else {
                            None
                        };
                    current_slot.set_parent(None);
                    let mut slot_pointer =
                        current_slot.evict(enclave_state, locality_meta, index_id);
                    match fill_amount {
                        None => {}
                        Some(some_fill_amount) => {
                            slot_pointer.set_fill_amount(some_fill_amount);
                        }
                    }
                    tuple_pointer.set_slot_pointer(slot_pointer);
                    drop(obt_node_cache);
                    return Some(parent_node_id);
                }
                return None;
            }
        }

        pub fn cast_remove_do_not_evict_upwards(
            enclave_state: &EnclaveState,
            current_node_tag: u128,
            query_id: u128,
        ) {
            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
            let current_node = obt_node_cache.mut_node(&current_node_tag).unwrap();
            current_node.remove_from_do_not_evict(&query_id);
            match current_node.parent_node() {
                ParentNode::ParentNodeId(some_parent_id) => {
                    let some_parent_id = some_parent_id.copy_cache_id();
                    drop(obt_node_cache);
                    cast_remove_do_not_evict_upwards(enclave_state, some_parent_id, query_id);
                }
                ParentNode::NoParent => {}
                _ => {
                    panic!("cast_remove_do_not_evict_upwards has not completed.")
                }
            }
        }

        pub fn evict_node_bottom_up(
            enclave_state: &EnclaveState,
            current_node_tag: u128,
            query_id: u128,
            remove_from_do_not_evict: bool,
            index_id: u16,
            start_time: Instant,
        ) {
            let mut current_node = {
                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                obt_node_cache.remove_node(&current_node_tag).unwrap()
            };
            if remove_from_do_not_evict {
                current_node.remove_from_do_not_evict(&query_id);
            }

            // If metas are not empty, we cannot evict the current node
            if !(current_node.next_meta_empty() && current_node.do_not_evict().is_none()) {
                if remove_from_do_not_evict && current_node.parent_node().parent_node_id().is_some()
                {
                    cast_remove_do_not_evict_upwards(
                        enclave_state,
                        current_node
                            .parent_node()
                            .parent_node_id()
                            .unwrap()
                            .copy_cache_id(),
                        query_id,
                    );
                }

                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                // current node is traversed or needed by other queries, we must stop the eviction here
                obt_node_cache.insert_node(current_node_tag, current_node);
                enclave_state
                    .lock_statistics()
                    .inc_time_evict_bottom_up(start_time.elapsed().as_nanos());
                drop(obt_node_cache);
                return;
            }

            // Look at parent of current_node
            match current_node.parent_node() {
                ParentNode::NoParent => {
                    // current_node has no parent, so it is the tree root.
                    // we do not want to evict the root since it is needed often.
                    if DEBUG_RUNTIME_CHECKS {
                        let obt_directory = enclave_state.lock_obt_tree_directory();
                        assert_eq!(
                            obt_directory
                                .get_tree(&index_id)
                                .unwrap()
                                .root()
                                .copy_packet_id(),
                            current_node_tag
                        );
                    }
                    let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                    obt_node_cache.insert_node(current_node_tag, current_node);
                    enclave_state
                        .lock_statistics()
                        .inc_time_evict_bottom_up(start_time.elapsed().as_nanos());
                    return;
                }
                ParentNode::EvictedParent(my_new_pos) => {
                    let my_new_pos = my_new_pos.with_id(current_node_tag);
                    current_node.broadcast_eviction_to_children(enclave_state);

                    if DEBUG_RUNTIME_CHECKS {
                        assert!(
                            current_node.no_slot_node_is_in_cache(&enclave_state.lock_slot_cache())
                        );
                    }

                    // That is why we can apply the eviction of "current_node"
                    // New position of "current_node" is "my_new_pos"
                    current_node.evict(enclave_state, &my_new_pos, index_id);
                }
                ParentNode::ParentNodeId(some_parent_id) => {
                    let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                    let mut parent_node = obt_node_cache
                        .mut_node(some_parent_id.cache_id())
                        .expect(&format!(
                            "Parent node {} does not exists.",
                            some_parent_id.cache_id()
                        ));

                    if DEBUG_RUNTIME_CHECKS {
                        assert_eq!(
                            parent_node
                                .child_pointers()
                                .get(some_parent_id.chosen_path() as usize)
                                .unwrap()
                                .position()
                                .packet_id(),
                            &current_node_tag
                        );
                    }

                    // Look if queries have visited parent node to target current_node
                    // If so, this node cannot be evicted
                    match parent_node
                        .query_next_traversing_meta_empty_at(some_parent_id.chosen_path() as usize)
                    {
                        true => {
                            drop(obt_node_cache);
                            let some_parent_id = some_parent_id.clone();

                            current_node.broadcast_eviction_to_children(enclave_state);

                            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                            let mut parent_node = obt_node_cache
                                .mut_node(some_parent_id.cache_id())
                                .expect("Parent node does not exists.");

                            // No query wants to visit "current_node" at the moment
                            if DEBUG_RUNTIME_CHECKS {
                                assert!(current_node
                                    .no_slot_node_is_in_cache(&enclave_state.lock_slot_cache()));
                            }

                            //current_node.set_parent_node(ParentNode::NoParent);
                            let leaf_slots = current_node.tuple_pointers().len() as u16;

                            // That is why we can apply the eviction of "current_node"
                            // New position of "current_node" is "new_node_position"
                            let new_node_position = {
                                let oram_config = enclave_state.lock_oram_config();
                                PositionTag::new_random_from_packet_id(
                                    oram_config.number_of_oram() as u32,
                                    oram_config.oram_degree(),
                                    oram_config.tree_height(),
                                    current_node_tag,
                                )
                            };
                            current_node.evict(enclave_state, &new_node_position, index_id);

                            // The parent node swaps the old position in its child pointer
                            // for the "current_node" with "new_node_position", where
                            // "current_node" was evicted to

                            parent_node
                                .mut_child_pointer(some_parent_id.chosen_path() as usize)
                                .unwrap()
                                .replace_me_from(new_node_position, Some(leaf_slots));

                            let parent_cache_tag = some_parent_id.copy_cache_id();

                            drop(obt_node_cache);
                            // We continue the eviction with the parent of "current_node"
                            return evict_node_bottom_up(
                                enclave_state,
                                parent_cache_tag,
                                query_id,
                                remove_from_do_not_evict,
                                index_id,
                                start_time,
                            );
                        }
                        false => {
                            // Queries have visited parent node to target "current_node".
                            // We re-insert the "current_node" to our node cache.
                            // Eviction must be stopped here.
                            drop(obt_node_cache);
                            if remove_from_do_not_evict {
                                cast_remove_do_not_evict_upwards(
                                    enclave_state,
                                    some_parent_id.copy_cache_id(),
                                    query_id,
                                );
                            }

                            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                            obt_node_cache.insert_node(current_node_tag, current_node);
                            enclave_state
                                .lock_statistics()
                                .inc_time_evict_bottom_up(start_time.elapsed().as_nanos());
                            return;
                        }
                    }
                }
                _ => {
                    panic!("Hard error: Parent is not set at eviction time.")
                }
            };
        }
    }

    /// Module for manipulation of an OB-Tree (splitting in insertions)
    mod internal_manipulation {
        use std::time::Instant;
        use std::untrusted::time::InstantEx;
        use std::vec::Vec;

        use helpers::range::Range;
        use oblivious_data_structures::ob_tree::components::ParentNode::NoParent;
        use oblivious_data_structures::ob_tree::components::{
            ObTreeChildPointer, ObTreeNode, ObTreeTuplePointer, Origin, ParentNode,
        };
        use oblivious_data_structures::ob_tree::eviction::evict_node_bottom_up;
        use oblivious_data_structures::position_tag::PositionTag;
        use query_state::{NextPos, ObjectType, ParentId, ParentNodeId};
        use sql_engine::sql_data_types::components::SqlDataType;
        use sql_engine::sql_data_types::functions::decompress_sql_data_type;
        use sql_engine::sql_database::components::SqlAttribute;
        use EnclaveState;
        use DEBUG_RUNTIME_CHECKS;
        use {log_runtime, DEBUG_PRINTS};

        pub fn split_node(
            enclave_state: &EnclaveState,
            right_node_tag: u128,
            left_range: Option<Range<SqlDataType>>,
            right_range: Option<Range<SqlDataType>>,
            index_of_new_middle: u32,
            index_id: u16,
            index_key_config: SqlAttribute,
            query_id: u128,
        ) {
            let start_time = Instant::now();

            let mut right_node = enclave_state
                .lock_obt_node_cache()
                .remove_node(&right_node_tag)
                .expect("");
            right_node.remove_from_do_not_evict(&query_id);

            //split node and move middle to parent
            let fill_grade = enclave_state.fill_grade();
            assert_eq!(right_node.tuple_pointers().len(), 2 * fill_grade + 1);
            let tuple_pointer_border = fill_grade;
            let child_pointer_border = fill_grade + 1;

            let pos_left = PositionTag::new_random(enclave_state);
            let pos_left_id = pos_left.copy_packet_id();
            let new_pos_right = {
                let oram_config = enclave_state.lock_oram_config();
                PositionTag::new_random_from_packet_id(
                    oram_config.number_of_oram() as u32,
                    oram_config.oram_degree(),
                    oram_config.tree_height(),
                    right_node_tag,
                )
            };
            let new_pos_right_id = right_node_tag;
            if DEBUG_PRINTS {
                log_runtime(&format!("New left node: {}", pos_left_id), true);
                log_runtime(&format!("right node: {}", right_node_tag), true);
            }

            let mut tuple_pointers_to_split = right_node.tuple_pointers().clone();
            let mut child_pointers_to_split = right_node.child_pointers().clone();
            let mut traverse_meta_to_split =
                right_node.remove_complete_query_next_traversing_meta();
            let mut tuple_meta_to_split = right_node.remove_complete_query_next_tuple_meta();
            let middle = tuple_pointers_to_split.remove(enclave_state.fill_grade());
            let middle_tuple_meta: Option<Vec<u128>> = match tuple_meta_to_split.as_mut() {
                None => None,
                Some(some_tuple_meta) => Some(some_tuple_meta.remove(enclave_state.fill_grade())),
            };

            // Creation of a new left node
            let mut new_left_node = if child_pointers_to_split.is_empty() {
                ObTreeNode::new(
                    vec![],
                    tuple_pointers_to_split[0..tuple_pointer_border].to_vec(),
                    None,
                    Origin::Local,
                )
            } else {
                ObTreeNode::new(
                    child_pointers_to_split[0..child_pointer_border].to_vec(),
                    tuple_pointers_to_split[0..tuple_pointer_border].to_vec(),
                    None,
                    Origin::Local,
                )
            };

            //Adaption of right_node pointers (shifting of right half to right_node)
            right_node.set_tuple_pointers(tuple_pointers_to_split[tuple_pointer_border..].to_vec());
            if !child_pointers_to_split.is_empty() {
                right_node
                    .set_child_pointers(child_pointers_to_split[(child_pointer_border)..].to_vec());
            }

            {
                let mut slot_cache = enclave_state.lock_slot_cache();
                for (tuple_iter, tuple_iter_pointer) in
                new_left_node.tuple_pointers().iter().enumerate()
                {
                    match slot_cache
                        .mut_slot(tuple_iter_pointer.slot_pointer().position().packet_id())
                    {
                        None => {}
                        Some(some_slot) => match some_slot.mut_parent() {
                            None => {}
                            Some(some_slot_parent) => {
                                let some_slot_parent_node = some_slot_parent.mut_node().unwrap();
                                some_slot_parent_node.set_chosen_path(tuple_iter as u32);
                                some_slot_parent_node.set_cache_id(pos_left_id);
                            }
                        },
                    }
                }
                for (tuple_iter, tuple_iter_pointer) in
                right_node.tuple_pointers().iter().enumerate()
                {
                    match slot_cache
                        .mut_slot(tuple_iter_pointer.slot_pointer().position().packet_id())
                    {
                        None => {}
                        Some(some_slot) => match some_slot.mut_parent() {
                            None => {}
                            Some(some_slot_parent) => {
                                let some_slot_parent_node = some_slot_parent.mut_node().unwrap();
                                some_slot_parent_node.set_chosen_path(tuple_iter as u32);
                                some_slot_parent_node.set_cache_id(new_pos_right_id);
                            }
                        },
                    }
                }
            }
            {
                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                for (child_index, child) in new_left_node.child_pointers().iter().enumerate() {
                    match obt_node_cache.mut_node(child.position().packet_id()) {
                        None => {}
                        Some(child_node) => match child_node.mut_parent_node() {
                            ParentNode::ParentNodeId(parent_node_id) => {
                                parent_node_id.set_cache_id(pos_left_id);
                                parent_node_id.set_chosen_path(child_index as u32);
                            }
                            _ => {}
                        },
                    }
                }
                for (child_index, child) in right_node.child_pointers().iter().enumerate() {
                    match obt_node_cache.mut_node(child.position().packet_id()) {
                        None => {}
                        Some(child_node) => match child_node.mut_parent_node() {
                            ParentNode::ParentNodeId(parent_node_id) => {
                                parent_node_id.set_cache_id(new_pos_right_id);
                                parent_node_id.set_chosen_path(child_index as u32);
                            }
                            _ => {}
                        },
                    }
                }
            }

            match traverse_meta_to_split {
                None => {}
                Some(some_meta) => {
                    new_left_node.set_query_next_traversing_meta(Some(
                        some_meta[0..child_pointer_border].to_vec(),
                    ));
                    right_node.set_query_next_traversing_meta(Some(
                        some_meta[child_pointer_border..].to_vec(),
                    ));
                    let mut query_state_cache = enclave_state.lock_query_state_cache();
                    match new_left_node.query_next_traversing_meta() {
                        None => {}
                        Some(traverse_meta) => {
                            assert_eq!(traverse_meta.len(), (fill_grade + 1));
                            for (index, entry) in traverse_meta.iter().enumerate() {
                                for query_iter in entry.iter() {
                                    let mut query_iter_state = query_state_cache
                                        .get_mut(query_iter)
                                        .expect("Query state must exists in cache.");
                                    match query_iter_state.mut_parent() {
                                        None => {
                                            panic!(
                                                "The parent must be set when in traversing meta."
                                            );
                                        }
                                        Some(some_query_parent) => {
                                            some_query_parent.mut_node().expect("Since we split a node and the query traversed this node in the last step, its parent id must also be a node reference.").set_cache_id(pos_left_id);
                                        }
                                    }
                                    let query_next = query_iter_state
                                        .next()
                                        .request()
                                        .expect("Must be a request")
                                        .0
                                        .packet_id();
                                    let child_pos = new_left_node
                                        .child_pointers()
                                        .get(index)
                                        .unwrap()
                                        .position()
                                        .packet_id();

                                    assert!(query_next.eq(child_pos));
                                }
                            }
                        }
                    }
                    match right_node.query_next_traversing_meta() {
                        None => {}
                        Some(traverse_meta) => {
                            assert_eq!(traverse_meta.len(), (fill_grade + 1));
                            for (index, entry) in traverse_meta.iter().enumerate() {
                                for query_iter in entry.iter() {
                                    let mut query_iter_state = query_state_cache
                                        .get_mut(query_iter)
                                        .expect("Query state must exists in cache.");
                                    match query_iter_state.mut_parent() {
                                        None => {
                                            panic!(
                                                "The parent must be set when in traversing meta."
                                            );
                                        }
                                        Some(some_query_parent) => {
                                            let parent_node_id = some_query_parent
                                                .mut_node()
                                                .expect("Since we split a node and the query traversed this node in the last step, its parent id must also be a node reference.");
                                            parent_node_id.set_chosen_path(index as u32);
                                            assert_eq!(parent_node_id.cache_id(), &right_node_tag);
                                            parent_node_id.set_cache_id(new_pos_right_id);
                                        }
                                    }
                                    let query_next = query_iter_state
                                        .next()
                                        .request()
                                        .expect("Must be a request")
                                        .0
                                        .packet_id();
                                    let child_pos = right_node
                                        .child_pointers()
                                        .get(index)
                                        .unwrap()
                                        .position()
                                        .packet_id();
                                    assert!(query_next.eq(child_pos));
                                }
                            }
                        }
                    }
                }
            }

            match tuple_meta_to_split {
                None => {}
                Some(some_meta) => {
                    new_left_node.set_query_next_tuple_meta(Some(
                        some_meta[0..tuple_pointer_border].to_vec(),
                    ));
                    right_node.set_query_next_tuple_meta(Some(
                        some_meta[tuple_pointer_border..].to_vec(),
                    ));
                    let mut query_state_cache = enclave_state.lock_query_state_cache();
                    match new_left_node.query_next_tuple_meta() {
                        None => {}
                        Some(tuple_meta) => {
                            assert_eq!(tuple_meta.len(), fill_grade);
                            for (index, entry) in tuple_meta.iter().enumerate() {
                                for query_iter in entry.iter() {
                                    let mut query_iter_state = query_state_cache
                                        .get_mut(query_iter)
                                        .expect("Query state must exists in cache.");
                                    match query_iter_state.mut_parent() {
                                        None => {
                                            panic!("The parent must be set when in tuple meta.");
                                        }
                                        Some(some_query_parent) => match some_query_parent {
                                            ParentId::Node(some_query_parent_node) => {
                                                some_query_parent_node.set_cache_id(pos_left_id);

                                                if DEBUG_RUNTIME_CHECKS
                                                    && query_iter_state.next().is_valid()
                                                {
                                                    assert!(query_iter_state
                                                        .next()
                                                        .request()
                                                        .expect("Must be a request")
                                                        .0
                                                        .equals(
                                                            new_left_node
                                                                .tuple_pointers()
                                                                .get(index)
                                                                .unwrap()
                                                                .slot_pointer()
                                                                .position()
                                                        ));
                                                }
                                            }
                                            _ => {}
                                        },
                                    }
                                }
                            }
                        }
                    }
                    match right_node.query_next_tuple_meta() {
                        None => {}
                        Some(tuple_meta) => {
                            assert_eq!(tuple_meta.len(), fill_grade);
                            for (index, entry) in tuple_meta.iter().enumerate() {
                                for query_iter in entry.iter() {
                                    let mut query_iter_state = query_state_cache
                                        .get_mut(query_iter)
                                        .expect("Query state must exists in cache.");
                                    match query_iter_state.mut_parent() {
                                        None => {
                                            panic!("The parent must be set when in tuple meta.");
                                        }
                                        Some(some_query_parent) => match some_query_parent {
                                            ParentId::Node(some_query_parent_node) => {
                                                some_query_parent_node
                                                    .set_cache_id(new_pos_right_id);
                                                assert_eq!(
                                                    some_query_parent_node.cache_id(),
                                                    &right_node_tag
                                                );
                                                some_query_parent_node
                                                    .set_chosen_path(index as u32);

                                                if DEBUG_RUNTIME_CHECKS
                                                    && query_iter_state.next().is_valid()
                                                {
                                                    assert!(query_iter_state
                                                        .next()
                                                        .request()
                                                        .expect("Must be a request")
                                                        .0
                                                        .equals(
                                                            right_node
                                                                .tuple_pointers()
                                                                .get(index)
                                                                .unwrap()
                                                                .slot_pointer()
                                                                .position()
                                                        ));
                                                }
                                            }
                                            _ => {}
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let middle_sql = decompress_sql_data_type(middle.key(), &index_key_config);
            match right_node.remove_complete_do_not_evict() {
                None => {}
                Some(some_do_not_evict) => {
                    for query_id_iter in some_do_not_evict {
                        let mut query_state_cache = enclave_state.lock_query_state_cache();
                        let mut query_iter = query_state_cache.get_mut(&query_id_iter).unwrap();

                        if query_iter
                            .ob_tree_query()
                            .value()
                            .single()
                            .unwrap()
                            .cmp(&middle_sql)
                            .is_lt()
                        {
                            new_left_node.add_to_do_not_evict(query_id_iter);
                        } else {
                            right_node.add_to_do_not_evict(query_id_iter);
                        }
                    }
                }
            }

            match right_node.mut_parent_node() {
                ParentNode::NoParent => {
                    new_left_node.set_parent_node(NoParent);
                }
                ParentNode::ParentNodeId(right_parent_node_id) => {
                    let parent_node_tag = right_parent_node_id.copy_cache_id();
                    let left_parent_node_path = right_parent_node_id.chosen_path();

                    right_parent_node_id.set_chosen_path(left_parent_node_path + 1u32);
                    new_left_node.set_parent_node(ParentNode::ParentNodeId(ParentNodeId::new(
                        parent_node_tag,
                        left_parent_node_path,
                    )));
                }
                _ => {
                    panic!("Not allowed case while runtime.");
                }
            }
            // Adaption of parent pointers
            if right_node.parent_node().parent_node_id().is_some() {} else {
                assert!(right_node.parent_node().is_no_parent());
            }

            assert_eq!(new_left_node.tuple_pointers().len(), fill_grade);
            assert_eq!(right_node.tuple_pointers().len(), fill_grade);
            if !child_pointers_to_split.is_empty() {
                assert_eq!(new_left_node.child_pointers().len(), fill_grade + 1);
                assert_eq!(right_node.child_pointers().len(), fill_grade + 1);
            }

            // TODO: To this before checking fetched nodes to make these ranges more precise by use
            // of subtree ranges from the fetched children since we build the ranges here from new
            // Adaption of Subtree ranges for locality caching
            if enclave_state.lock_dynamic_config().index_locality_cache() {
                let old_range = right_node.sub_tree_value_range().clone();

                let left_local_range = new_left_node.get_local_range();
                let left_local_range = Some(Range::new(
                    decompress_sql_data_type(
                        left_local_range.first().unwrap().key(),
                        &index_key_config,
                    ),
                    decompress_sql_data_type(
                        left_local_range.second().unwrap().key(),
                        &index_key_config,
                    ),
                ));
                new_left_node.set_sub_tree_value_range(left_local_range);

                let right_local_range = right_node.get_local_range();
                let right_local_range = Some(Range::new(
                    decompress_sql_data_type(
                        right_local_range.first().unwrap().key(),
                        &index_key_config,
                    ),
                    decompress_sql_data_type(
                        right_local_range.second().unwrap().key(),
                        &index_key_config,
                    ),
                ));
                right_node.set_sub_tree_value_range(right_local_range);

                match old_range {
                    None => {}
                    Some(some_old_range) => {
                        let (old_low, old_up) = some_old_range.destroy_and_return_components();
                        match new_left_node.mut_sub_tree_value_range() {
                            None => {}
                            Some(some_left_range) => some_left_range.extend_lower(old_low),
                        }
                        match right_node.mut_sub_tree_value_range() {
                            None => {}
                            Some(some_right_range) => some_right_range.extend_lower(old_up),
                        }
                    }
                }

                // Is the new tuple (index_of_new_middle) added to the left or right node
                if !child_pointers_to_split.is_empty() {
                    let child_index = index_of_new_middle as usize;
                    if child_index < (fill_grade + 1) {
                        new_left_node
                            .mut_sub_tree_value_range()
                            .as_mut()
                            .unwrap()
                            .extend(left_range.unwrap());
                    } else {
                        right_node
                            .mut_sub_tree_value_range()
                            .as_mut()
                            .unwrap()
                            .extend(left_range.unwrap());
                    }

                    if (child_index + 1) < (fill_grade + 1) {
                        new_left_node
                            .mut_sub_tree_value_range()
                            .as_mut()
                            .unwrap()
                            .extend(right_range.unwrap());
                    } else {
                        right_node
                            .mut_sub_tree_value_range()
                            .as_mut()
                            .unwrap()
                            .extend(right_range.unwrap());
                    }
                }
            };

            // Cloned ranges for later casting
            let right_range = right_node.sub_tree_value_range().clone();
            let left_range = new_left_node.sub_tree_value_range().clone();

            let parent_node = new_left_node.parent_node().clone();
            if DEBUG_PRINTS && parent_node.parent_node_id().is_some() {
                log_runtime(
                    &format!(
                        "split_node - parent: {}",
                        parent_node.parent_node_id().unwrap().cache_id()
                    ),
                    true,
                );
            }

            let evictable_left =
                new_left_node.do_not_evict().is_none() && new_left_node.next_meta_empty();
            let pos_left = if evictable_left {
                if DEBUG_RUNTIME_CHECKS {
                    assert!(
                        new_left_node.no_slot_node_is_in_cache(&enclave_state.lock_slot_cache())
                    );
                }
                if DEBUG_PRINTS {
                    log_runtime(
                        &format!(
                            "ObTreeNode eviction (left): {}, leaf: {}",
                            pos_left_id,
                            pos_left.path()
                        ),
                        true,
                    );
                }
                new_left_node.broadcast_eviction_to_children(enclave_state);
                //new_left_node.set_parent_node(ParentNode::NoParent);
                let leaf_slots = new_left_node.tuple_pointers().len() as u16;

                new_left_node.evict(enclave_state, &pos_left, index_id);

                let pointer = ObTreeChildPointer::new(pos_left, Some(leaf_slots));
                if DEBUG_RUNTIME_CHECKS {
                    assert!(enclave_state
                        .lock_packet_stash()
                        .contains_packet(pointer.position()));
                }
                pointer
            } else {
                let pointer = ObTreeChildPointer::new(
                    pos_left,
                    Some(new_left_node.tuple_pointers().len() as u16),
                );
                enclave_state
                    .lock_obt_node_cache()
                    .insert_node(pos_left_id, new_left_node);
                pointer
            };

            let evictable_right =
                right_node.do_not_evict().is_none() && right_node.next_meta_empty();
            let pos_right = if evictable_right {
                if DEBUG_RUNTIME_CHECKS {
                    assert!(right_node.no_slot_node_is_in_cache(&enclave_state.lock_slot_cache()));
                }
                if DEBUG_PRINTS {
                    log_runtime(
                        &format!(
                            "ObTreeNode eviction (right): {}, new packet id: {}, leaf: {}",
                            right_node_tag,
                            new_pos_right_id,
                            new_pos_right.path()
                        ),
                        true,
                    );
                }
                right_node.broadcast_eviction_to_children(enclave_state);
                //right_node.set_parent_node(ParentNode::NoParent);
                let leaf_slots = right_node.tuple_pointers().len() as u16;

                right_node.evict(enclave_state, &new_pos_right, index_id);

                let pointer = ObTreeChildPointer::new(new_pos_right, Some(leaf_slots));
                if DEBUG_RUNTIME_CHECKS {
                    assert!(enclave_state
                        .lock_packet_stash()
                        .contains_packet(pointer.position()));
                }
                pointer
            } else {
                let pointer = ObTreeChildPointer::new(
                    new_pos_right,
                    Some(right_node.tuple_pointers().len() as u16),
                );
                enclave_state
                    .lock_obt_node_cache()
                    .insert_node(new_pos_right_id, right_node);
                pointer
            };

            enclave_state
                .lock_statistics()
                .inc_time_split_node(start_time.elapsed().as_nanos());
            return cast_split_to_parent(
                enclave_state,
                index_id,
                index_key_config,
                query_id,
                parent_node,
                middle,
                middle_tuple_meta,
                pos_left,
                left_range,
                evictable_left,
                pos_right,
                right_range,
                evictable_right,
            );
        }

        fn cast_split_to_parent(
            enclave_state: &EnclaveState,
            index_id: u16,
            index_key_config: SqlAttribute,
            query_id: u128,
            parent_node: ParentNode,
            middle: ObTreeTuplePointer,
            middle_tuple_meta: Option<Vec<u128>>,
            left_child: ObTreeChildPointer,
            left_range: Option<Range<SqlDataType>>,
            left_eviction: bool,
            right_child: ObTreeChildPointer,
            right_range: Option<Range<SqlDataType>>,
            right_eviction: bool,
        ) {
            let start_time = Instant::now();

            if DEBUG_RUNTIME_CHECKS {
                let obt_node_cache = enclave_state.lock_obt_node_cache();
                match obt_node_cache.get_node(left_child.position().packet_id()) {
                    None => {
                        assert!(left_eviction);
                    }
                    Some(_) => {
                        assert!(!left_eviction);
                    }
                }
                match obt_node_cache.get_node(right_child.position().packet_id()) {
                    None => {
                        assert!(right_eviction);
                    }
                    Some(_) => {
                        assert!(!right_eviction);
                    }
                }
            }
            match parent_node {
                ParentNode::NoParent => {
                    // new root necessary
                    let sub_tree_value_range =
                        if enclave_state.lock_dynamic_config().index_locality_cache() {
                            let mut root_range = left_range.unwrap();
                            root_range.extend(right_range.unwrap());
                            Some(root_range)
                        } else {
                            None
                        };
                    let new_root_pos = PositionTag::new_random(enclave_state);
                    {
                        // If the children are in the cache, set their parent pointers to the new root
                        let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                        match obt_node_cache.mut_node(left_child.position().packet_id()) {
                            None => {}
                            Some(left_node) => {
                                left_node.set_parent_node(ParentNode::ParentNodeId(
                                    ParentNodeId::new(new_root_pos.copy_packet_id(), 0),
                                ));
                            }
                        }
                        match obt_node_cache.mut_node(right_child.position().packet_id()) {
                            None => {}
                            Some(right_node) => {
                                right_node.set_parent_node(ParentNode::ParentNodeId(
                                    ParentNodeId::new(new_root_pos.copy_packet_id(), 1),
                                ));
                            }
                        }
                    }
                    let mut new_root = ObTreeNode::new(
                        vec![left_child, right_child],
                        vec![middle],
                        sub_tree_value_range,
                        Origin::Local,
                    );
                    new_root.set_parent_node(NoParent);

                    match middle_tuple_meta {
                        None => {}
                        Some(some_middle_tuple_meta) => {
                            let mut query_state_cache = enclave_state.lock_query_state_cache();
                            for query_iter in some_middle_tuple_meta.iter() {
                                let mut query_iter_state = query_state_cache
                                    .get_mut(query_iter)
                                    .expect("Query state must exists in cache.");
                                match query_iter_state.mut_parent() {
                                    None => {
                                        panic!("The parent must be set when in tuple meta.");
                                    }
                                    Some(some_query_parent) => match some_query_parent {
                                        ParentId::Node(some_query_parent_node) => {
                                            some_query_parent_node
                                                .set_cache_id(new_root_pos.copy_packet_id());
                                            some_query_parent_node.set_chosen_path(0);

                                            if DEBUG_RUNTIME_CHECKS
                                                && query_iter_state.next().is_valid()
                                            {
                                                assert!(query_iter_state
                                                    .next()
                                                    .request()
                                                    .expect("Must be a request")
                                                    .0
                                                    .equals(
                                                        new_root
                                                            .tuple_pointers()
                                                            .get(0)
                                                            .unwrap()
                                                            .slot_pointer()
                                                            .position()
                                                    ));
                                            }
                                        }
                                        _ => {}
                                    },
                                }
                            }
                            new_root.set_query_next_tuple_meta(Some(vec![some_middle_tuple_meta]));
                        }
                    }
                    {
                        let mut slot_cache = enclave_state.lock_slot_cache();
                        match slot_cache.mut_slot(
                            new_root
                                .tuple_pointers()
                                .get(0)
                                .unwrap()
                                .slot_pointer()
                                .position()
                                .packet_id(),
                        ) {
                            None => {}
                            Some(some_slot) => match some_slot.mut_parent() {
                                None => {}
                                Some(some_slot_parent) => {
                                    let some_slot_parent_node =
                                        some_slot_parent.mut_node().unwrap();
                                    some_slot_parent_node.set_chosen_path(0u32);
                                    some_slot_parent_node
                                        .set_cache_id(new_root_pos.copy_packet_id());
                                }
                            },
                        }
                    }

                    enclave_state
                        .lock_obt_node_cache()
                        .insert_node(new_root_pos.copy_packet_id(), new_root);
                    {
                        let mut obt_directory = enclave_state.lock_obt_tree_directory();
                        let mut tree = obt_directory
                            .mut_tree(&index_id)
                            .expect("Index tree must exist.");
                        tree.set_root(new_root_pos);
                        tree.inc_height();
                    }

                    /*
                    let new_root =
                        new_root.evict(enclave_state, PositionTag::new_random(enclave_state), index_id);
                     */

                    enclave_state
                        .lock_statistics()
                        .inc_time_cast_split_to_parent(start_time.elapsed().as_nanos());
                    return;
                }
                ParentNode::ParentNodeId(some_parent_node_id) => {
                    if DEBUG_PRINTS {
                        log_runtime(
                            &format!(
                                "cast_split_to_parent: Parent ID: {}",
                                some_parent_node_id.cache_id()
                            ),
                            true,
                        );
                    }

                    // ID of parent:
                    let (parent_node_tag, parent_node_path) = some_parent_node_id.destroy();
                    let mut queries_shifted_to_parent_node = false;

                    let mut parent_node = enclave_state
                        .lock_obt_node_cache()
                        .remove_node(&parent_node_tag)
                        .unwrap();

                    // If queries target the node that was split before calling this method
                    // then change the queries to point to the current parent
                    {
                        if DEBUG_PRINTS {
                            log_runtime(
                                &format!(
                                    "cast_split_to_parent: Child cache ID: {}",
                                    parent_node
                                        .child_pointers()
                                        .get(parent_node_path as usize)
                                        .unwrap()
                                        .position()
                                        .packet_id()
                                ),
                                true,
                            );
                        }
                        let grandparent_node_id = parent_node.parent_node().clone();
                        match parent_node
                            .pop_entry_from_query_next_traversing_meta(parent_node_path as usize)
                        {
                            None => {}
                            Some(some_traversing_meta_entry) => {
                                let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                                //let parent_node_position = PositionTag::from_string(&parent_node_tag);
                                let mut query_state_cache = enclave_state.lock_query_state_cache();
                                for query_id_iter in some_traversing_meta_entry.iter() {
                                    let mut query =
                                        query_state_cache.get_mut(query_id_iter).expect(&format!(
                                            "Could not found query {} in query_state_cache.",
                                            query_id_iter
                                        ));
                                    match &grandparent_node_id {
                                        ParentNode::NoParent => {
                                            query.set_parent(None);
                                            query.set_next(NextPos::Start);
                                        }
                                        ParentNode::ParentNodeId(some_grandparent_node_id) => {
                                            let mut grandparent_node = obt_node_cache
                                                .mut_node(some_grandparent_node_id.cache_id())
                                                .unwrap();
                                            grandparent_node
                                                .insert_into_query_next_traversing_meta(
                                                    //some_grandparent_node_id.cache_id(),
                                                    some_grandparent_node_id.chosen_path() as usize,
                                                    query.id(),
                                                );
                                            query.set_parent(Some(ParentId::Node(
                                                some_grandparent_node_id.clone(),
                                            )));

                                            match query.mut_next() {
                                                NextPos::Request(some_next_pos, object_type) => {
                                                    match object_type {
                                                        ObjectType::NodeObjectType => {
                                                            // TODO: The following does not update instance and leaf since we do not have this information here at the moment
                                                            some_next_pos
                                                                .set_packet_id(parent_node_tag);
                                                            if DEBUG_PRINTS {
                                                                log_runtime(&format!("Query {} is reassigned to parent node {}", query_id_iter, parent_node_tag), true);
                                                            }
                                                            queries_shifted_to_parent_node = true;
                                                        }
                                                        _ => {
                                                            panic!("Cannot be this case.");
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    panic!("Cannot be this case.");
                                                }
                                            }
                                        }
                                        _ => {
                                            panic!("Cannot be this case.")
                                        }
                                    }
                                }
                            }
                        }
                    }

                    parent_node.swap_child_pointer(parent_node_path as usize, right_child);
                    parent_node.insert_child_pointer(
                        enclave_state,
                        parent_node_path as usize,
                        left_child,
                    );

                    {
                        // Slot meta of middle must be adapted to this new parent node
                        let mut slot_cache = enclave_state.lock_slot_cache();
                        match slot_cache.mut_slot(middle.slot_pointer().position().packet_id()) {
                            None => {}
                            Some(some_slot) => match some_slot.mut_parent() {
                                None => {}
                                Some(some_slot_parent) => {
                                    let some_slot_parent_node =
                                        some_slot_parent.mut_node().unwrap();
                                    some_slot_parent_node.set_chosen_path(parent_node_path);
                                    some_slot_parent_node.set_cache_id(parent_node_tag);
                                }
                            },
                        }
                    }
                    {
                        match middle_tuple_meta.as_ref() {
                            None => {}
                            Some(some_middle_tuple_meta) => {
                                let mut query_state_cache = enclave_state.lock_query_state_cache();
                                for query_iter in some_middle_tuple_meta.iter() {
                                    let mut query_iter_state = query_state_cache
                                        .get_mut(query_iter)
                                        .expect("Query state must exists in cache.");
                                    match query_iter_state.mut_parent() {
                                        None => {
                                            panic!("The parent must be set when in tuple meta.");
                                        }
                                        Some(some_query_parent) => match some_query_parent {
                                            ParentId::Node(some_query_parent_node) => {
                                                some_query_parent_node
                                                    .set_cache_id(parent_node_tag);
                                                some_query_parent_node
                                                    .set_chosen_path(parent_node_path);
                                            }
                                            _ => {}
                                        },
                                    }
                                }
                            }
                        }
                    }
                    parent_node.insert_tuple_pointer(
                        enclave_state,
                        parent_node_path as usize,
                        middle,
                        middle_tuple_meta,
                    );

                    if parent_node.tuple_pointers().len() <= 2 * enclave_state.fill_grade() {
                        if enclave_state.lock_dynamic_config().index_locality_cache() {
                            parent_node
                                .mut_sub_tree_value_range()
                                .as_mut()
                                .unwrap()
                                .extend(left_range.unwrap());
                            parent_node
                                .mut_sub_tree_value_range()
                                .as_mut()
                                .unwrap()
                                .extend(right_range.unwrap());
                        }

                        enclave_state
                            .lock_obt_node_cache()
                            .insert_node(parent_node_tag, parent_node);
                        enclave_state
                            .lock_statistics()
                            .inc_time_cast_split_to_parent(start_time.elapsed().as_nanos());
                        return evict_node_bottom_up(
                            enclave_state,
                            parent_node_tag,
                            query_id,
                            true,
                            index_id,
                            Instant::now(),
                        );
                    } else {
                        // node is overfilled. splitting this node is necessary again.
                        enclave_state
                            .lock_statistics()
                            .inc_time_cast_split_to_parent(start_time.elapsed().as_nanos());
                        enclave_state
                            .lock_obt_node_cache()
                            .insert_node(parent_node_tag, parent_node);
                        return split_node(
                            enclave_state,
                            parent_node_tag,
                            left_range,
                            right_range,
                            parent_node_path,
                            index_id,
                            index_key_config,
                            query_id,
                        );
                    }
                }
                _ => {
                    panic!("Runtime invariants should not let this case happen.");
                }
            }
        }

        /*
        pub fn move_or_merge(enclave_state: &EnclaveState, query_state: &QueryState, unfilled_node_id: u128) {
            let mut obt_node_cache = enclave_state.lock_obt_node_cache();

            let mut unfilled_node = obt_node_cache.mut_node(&unfilled_node_id).unwrap();
            match unfilled_node.parent_node() {
                None => {
                    // We are in the root
                    // It is okay that the root is unfilled
                    return;
                }
                Some(some_parent_id) => {
                    let parent_node = obt_node_cache.mut_node(some_parent_id.cache_id()).unwrap();
                    let mut move_possible = false;
                    if parent_node.child_pointer(some_parent_id.chosen_path() as usize).unwrap().leaf_slots().unwrap() > enclave_state.fill_grade() {
                        move_possible = true;
                    } else if parent_node.child_pointer(some_parent_id.chosen_path() as usize).unwrap().leaf_slots().unwrap() > enclave_state.fill_grade() {
                        move_possible = true;
                    }
                    if !move_possible {
                        // We have to merge
                    }
                }
            }
        }
         */
    }

    /// API module to use/traverse Ob-Tree from outside
    pub mod api {
        use std::time::Instant;
        use std::untrusted::time::InstantEx;
        use oblivious_data_structures::ob_tree;
        use oblivious_data_structures::ob_tree::components::{
            ObTreeQueryValue, ObTreeTuplePointerStatus, Origin, ParentNode,
        };
        use oblivious_data_structures::ob_tree::eviction::{
            evict_node_bottom_up,
        };
        use oblivious_data_structures::ob_tree::helpers::{
            helper_insert_new_tuple_to_obt_leaf, search_single_value_in_node_tuple_pointers,
            ObTreeKeyCmpOperator,
        };
        use oblivious_data_structures::page::{Slot};
        use query_state::{
            NextPos, ObTreeOperation, ObjectType, ParentId, ParentNodeId,
            ParentSlotId, QueryOperationStatus, QueryState,
        };
        use crate::enclave_state::EnclaveState;
        use crate::oblivious_data_structures::page::{SlotContent, SlotPointer};
        use crate::oblivious_data_structures::position_tag::PositionTag;
        use crate::RIDS_PER_SLOT;

        pub fn traverse_ob_tree(enclave_state: &EnclaveState, query_state: &mut QueryState) {
            // If the tuple to visit is not valid anymore because of deletion
            if !query_state.next().is_valid() {
                match query_state.ob_tree_query().value() {
                    ObTreeQueryValue::Single(_) => {
                        let parent_node_id =
                            query_state.parent_ref().unwrap().node().unwrap().clone();
                        {
                            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                            let mut parent_node =
                                obt_node_cache.mut_node(parent_node_id.cache_id()).unwrap();
                            parent_node.remove_query_from_query_next_tuple_meta(
                                parent_node_id.chosen_path() as usize,
                                &query_state.id(),
                            );
                            assert!(!parent_node
                                .tuple_pointer(parent_node_id.chosen_path() as usize)
                                .unwrap()
                                .is_active());
                            drop(obt_node_cache);
                            query_state.set_next(NextPos::Finite);
                            query_state.set_parent(None);
                        }
                        return ob_tree::eviction::evict_node_bottom_up(
                            enclave_state,
                            parent_node_id.copy_cache_id(),
                            query_state.id(),
                            false,
                            query_state.ob_tree_query().index_id(),
                            Instant::now(),
                        );
                    }
                    ObTreeQueryValue::Range(_) => {
                        // TODO: Continue range operation now with next tuple
                        panic!("Range operations are not implemented yet.");
                    }
                }
            }

            // We must differentiate if the current object is a node or a slot
            let (current_position, current_object_type) = query_state.next_as_tuple(enclave_state);
            match current_object_type {
                ObjectType::NodeObjectType => {
                    // A node is a leaf when it has no child pointers
                    let is_leaf = {
                        let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                        let mut node = obt_node_cache
                            .mut_node(current_position.packet_id())
                            .expect(&format!(
                                "Node {} is not in cache for query {}.",
                                current_position.packet_id(),
                                query_state.id()
                            ));
                        node.inc_traversal_visits();
                        match node.origin() {
                            Origin::IndexLocalityCache => enclave_state
                                .lock_statistics()
                                .inc_times_node_originally_from_locality_cache(),
                            _ => {}
                        }

                        let is_leaf = node.child_pointers().is_empty();

                        if query_state
                            .operation_type()
                            .get_insert_query_state()
                            .is_some()
                        {
                            if !is_leaf {
                                node.add_to_do_not_evict(query_state.id());
                            } else if !query_state.operation_permission() {
                                query_state.set_operation_status(QueryOperationStatus::LOCKED);
                            }
                        }

                        is_leaf
                    };

                    // Parent of current node must be set by query parent.
                    match query_state.parent() {
                        None => {}
                        Some(query_state_parent) => {
                            let node_parent_id = query_state_parent
                                .node()
                                .expect("A parent of a node must be a node.");
                            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                            obt_node_cache
                                .mut_node(current_position.packet_id())
                                .unwrap()
                                .set_parent_node(ParentNode::ParentNodeId(node_parent_id.clone()));
                        }
                    }

                    if query_state
                        .operation_type()
                        .get_insert_query_state()
                        .is_some()
                        && !query_state.operation_status().is_active()
                    {
                        // An Insert operation at the leaf level must be stopped here,
                        // when there is a lock
                        return;
                    }

                    // Direct eviction and Meta adaption of parent node
                    // -> Query can be removed from parent node meta.
                    {
                        let parent_node = enclave_state
                            .lock_obt_node_cache()
                            .get_node(current_position.packet_id())
                            .unwrap()
                            .parent_node()
                            .clone();
                        match parent_node {
                            ParentNode::ParentNodeId(parent_node_id) => {
                                {
                                    let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                                    let mut parent_node = obt_node_cache
                                        .mut_node(parent_node_id.cache_id())
                                        .expect("Parent node must be in cache.");
                                    parent_node.searched_child_node_is_fetched_now(
                                        &query_state.id(),
                                        parent_node_id.chosen_path() as usize,
                                        current_position.packet_id(),
                                    );
                                }
                                if query_state
                                    .operation_type()
                                    .get_insert_query_state()
                                    .is_none()
                                    && enclave_state.lock_dynamic_config().direct_eviction()
                                {
                                    evict_node_bottom_up(
                                        enclave_state,
                                        parent_node_id.copy_cache_id(),
                                        query_state.id(),
                                        false,
                                        query_state.ob_tree_query().index_id(),
                                        Instant::now(),
                                    );
                                }
                            }
                            _ => {}
                        }
                    }

                    let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                    let mut node = obt_node_cache
                        .mut_node(current_position.packet_id())
                        .unwrap();

                    match query_state.ob_tree_query().value() {
                        ObTreeQueryValue::Single(single) => {
                            let (index_to_insert, compares_to_tuple_at_index) =
                                search_single_value_in_node_tuple_pointers(
                                    &mut enclave_state.lock_statistics(),
                                    node.tuple_pointers(),
                                    single,
                                    query_state.ob_tree_query().key_config(),
                                );

                            match compares_to_tuple_at_index {
                                ObTreeKeyCmpOperator::Equal => {
                                    let (slot_position, active_tuple) = {
                                        let tuple_pointer =
                                            node.tuple_pointer(index_to_insert).unwrap();
                                        (
                                            tuple_pointer.slot_pointer().position().clone(),
                                            tuple_pointer.is_active(),
                                        )
                                    };

                                    let this_node_as_parent_id = ParentId::Node(ParentNodeId::new(
                                        current_position.copy_packet_id(),
                                        index_to_insert as u32,
                                    ));

                                    match query_state.operation_permission() {
                                        true => {
                                            if active_tuple {
                                                node.insert_into_query_next_tuple_meta(
                                                    index_to_insert,
                                                    query_state.id(),
                                                );
                                                query_state
                                                    .set_parent(Some(this_node_as_parent_id));
                                                query_state.set_next(NextPos::Request(
                                                    slot_position,
                                                    ObjectType::SlotObjectType,
                                                ));

                                                drop(obt_node_cache);
                                                let parent_node_id =
                                                    traverse_rid_chain(enclave_state, query_state);
                                                match parent_node_id {
                                                    None => {}
                                                    Some(some_parent_node_id) => {
                                                        evict_node_bottom_up(
                                                            enclave_state,
                                                            some_parent_node_id.copy_cache_id(),
                                                            query_state.id(),
                                                            query_state
                                                                .operation_type()
                                                                .get_insert_query_state()
                                                                .is_some(),
                                                            query_state.ob_tree_query().index_id(),
                                                            Instant::now(),
                                                        );
                                                    }
                                                }
                                                return;
                                            } else {
                                                // TODO: Insert must make inactive tuple active again
                                                drop(obt_node_cache);
                                                query_state.set_next(NextPos::Finite);
                                                query_state.set_parent(None);
                                                return ob_tree::eviction::evict_node_bottom_up(
                                                    enclave_state,
                                                    current_position.copy_packet_id(),
                                                    query_state.id(),
                                                    query_state
                                                        .operation_type()
                                                        .get_insert_query_state()
                                                        .is_some(),
                                                    query_state.ob_tree_query().index_id(),
                                                    Instant::now(),
                                                );
                                            }
                                        }
                                        false => {
                                            query_state
                                                .set_operation_status(QueryOperationStatus::LOCKED);
                                            node.insert_into_query_next_tuple_meta(
                                                index_to_insert,
                                                query_state.id(),
                                            );
                                            query_state.set_parent(Some(this_node_as_parent_id));
                                            if active_tuple {
                                                query_state.set_next(NextPos::Request(
                                                    slot_position,
                                                    ObjectType::SlotObjectType,
                                                ));
                                                return;
                                            } else {
                                                if query_state
                                                    .operation_type()
                                                    .get_insert_query_state()
                                                    .is_some()
                                                {
                                                    let parent_node_id = node
                                                        .parent_node()
                                                        .parent_node_id()
                                                        .unwrap()
                                                        .clone();
                                                    drop(obt_node_cache);
                                                    let mut obt_node_cache =
                                                        enclave_state.lock_obt_node_cache();

                                                    let mut parent_node = obt_node_cache
                                                        .mut_node(parent_node_id.cache_id())
                                                        .unwrap();

                                                    parent_node.traverse_child_pointer_with_query(
                                                        parent_node_id.copy_cache_id(),
                                                        parent_node_id.chosen_path() as usize,
                                                        query_state,
                                                    );
                                                } else {
                                                    query_state.set_next(NextPos::InvalidRequest);
                                                }
                                                return;
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    if !is_leaf {
                                        let child_node_id = node.traverse_child_pointer_with_query(
                                            current_position.copy_packet_id(),
                                            index_to_insert,
                                            query_state,
                                        );
                                        drop(node);
                                        let go_to_next_state =
                                            match obt_node_cache.mut_node(&child_node_id) {
                                                None => false,
                                                Some(some_child_node) => {
                                                    match some_child_node.parent_node() {
                                                        ParentNode::EvictedParent(_) => {
                                                            some_child_node.set_parent_node(
                                                                ParentNode::ParentNodeId(
                                                                    ParentNodeId::new(
                                                                        current_position
                                                                            .copy_packet_id(),
                                                                        index_to_insert as u32,
                                                                    ),
                                                                ),
                                                            );
                                                        }
                                                        _ => {}
                                                    }
                                                    true
                                                }
                                            };
                                        if go_to_next_state {
                                            drop(obt_node_cache);
                                            return traverse_ob_tree(enclave_state, query_state);
                                        }
                                        return;
                                    } else {
                                        return match query_state.operation_type() {
                                            ObTreeOperation::INSERT(_) => {
                                                assert!(query_state.operation_permission());
                                                drop(obt_node_cache);
                                                helper_insert_new_tuple_to_obt_leaf(
                                                    enclave_state,
                                                    query_state,
                                                    current_position.copy_packet_id(),
                                                    index_to_insert,
                                                )
                                            }
                                            _ => {
                                                drop(obt_node_cache);
                                                query_state.set_next(NextPos::Finite);
                                                query_state.set_parent(None);
                                                ob_tree::eviction::evict_node_bottom_up(
                                                    enclave_state,
                                                    current_position.copy_packet_id(),
                                                    query_state.id(),
                                                    false,
                                                    query_state.ob_tree_query().index_id(),
                                                    Instant::now(),
                                                )
                                            }
                                        };
                                    }
                                }
                            }
                        }
                        ObTreeQueryValue::Range(_) => {
                            panic!("Ranges are not implemented yet.");
                        }
                    }
                }
                ObjectType::SlotObjectType => {
                    let parent_node_id = traverse_rid_chain(enclave_state, query_state);
                    match parent_node_id {
                        None => {
                            return;
                        }
                        Some(some_parent_node_id) => {
                            return evict_node_bottom_up(
                                enclave_state,
                                some_parent_node_id.copy_cache_id(),
                                query_state.id(),
                                query_state
                                    .operation_type()
                                    .get_insert_query_state()
                                    .is_some(),
                                query_state.ob_tree_query().index_id(),
                                Instant::now(),
                            );
                        }
                    }
                }
            }
        }

        fn traverse_rid_chain(
            enclave_state: &EnclaveState,
            query_state: &mut QueryState,
        ) -> Option<ParentNodeId> {
            let mut slot_cache = enclave_state.lock_slot_cache();
            let current_slot_position = query_state.next().request().unwrap().0.clone();

            return match slot_cache.remove_slot(current_slot_position.packet_id()) {
                None => {
                    // The next slot is not in the cache, we have to set a request
                    None
                }
                Some(mut slot) => {
                    match slot.origin() {
                        Origin::IndexLocalityCache => enclave_state
                            .lock_statistics()
                            .inc_times_slot_originally_from_locality_cache(),
                        _ => {}
                    }

                    slot.set_parent(Some(query_state.parent_ref().unwrap().clone()));

                    let mut re_insert_slot = true;
                    let mut evict_slot_back_to_front: Option<u128> = None;
                    let mut deleted_everything: Option<ParentNodeId> = None;

                    let mut cont = false;
                    let mut next_pos: Option<PositionTag> = None;
                    let mut next_parent: Option<ParentId> = None;

                    match slot.mut_content() {
                        SlotContent::Row(row_item) => match query_state.operation_type() {
                            ObTreeOperation::INSERT(_) => {
                                panic!("Insertion to existing tuple-row is not possible.")
                            }
                            ObTreeOperation::SELECT => {
                                query_state.add_to_found(SlotContent::Row(row_item.clone()));
                                evict_slot_back_to_front =
                                    Some(current_slot_position.copy_packet_id());
                            }
                            ObTreeOperation::DELETE(delete_query) => {
                                let delete_row = match delete_query.slot_content_filter() {
                                    None => true,
                                    Some(some_slot_filter) => {
                                        row_item.matches_ob_tree_filter(some_slot_filter)
                                    }
                                };

                                if delete_row {
                                    let parent_node_id =
                                        slot.parent().as_ref().unwrap().node().unwrap();
                                    let mut obt_node_cache = enclave_state.lock_obt_node_cache();
                                    let mut node =
                                        obt_node_cache.mut_node(parent_node_id.cache_id()).unwrap();
                                    node.set_tuple_pointer_status(
                                        enclave_state,
                                        parent_node_id.chosen_path() as usize,
                                        ObTreeTuplePointerStatus::REMOVED,
                                    );
                                    re_insert_slot = false;
                                    deleted_everything = Some(parent_node_id.clone());
                                } else {
                                    evict_slot_back_to_front =
                                        Some(current_slot_position.copy_packet_id());
                                }
                            }
                        },
                        SlotContent::RIDs(rid_chain_item) => {
                            match query_state.parent_ref().unwrap() {
                                ParentId::Node(parent_node_id) => {
                                    match query_state.operation_type() {
                                        ObTreeOperation::INSERT(_) => {
                                            // For insertions, the tuple that is pointing to our slot
                                            // must be active
                                            let mut obt_node_cache =
                                                enclave_state.lock_obt_node_cache();
                                            let mut parent_node = obt_node_cache
                                                .mut_node(parent_node_id.cache_id())
                                                .unwrap();
                                            parent_node.set_tuple_pointer_status(
                                                enclave_state,
                                                parent_node_id.chosen_path() as usize,
                                                ObTreeTuplePointerStatus::ACTIVE,
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                ParentId::Slot(parent_slot_id) => {
                                    // If predecessor was a slot,
                                    // we must remove current query id from its meta
                                    let mut parent_slot =
                                        slot_cache.mut_slot(parent_slot_id.cache_id()).unwrap();
                                    parent_slot
                                        .mut_content()
                                        .mut_rids()
                                        .unwrap()
                                        .remove_query_from_visited(&query_state.id());
                                }
                            }

                            // Depending on the operation type,
                            // different actions are to make for our slot
                            match query_state.operation_type() {
                                ObTreeOperation::INSERT(insert_content) => {
                                    let mut insert_content = insert_content.slot_content().clone();
                                    if rid_chain_item.rids().len() >= RIDS_PER_SLOT {
                                        // If current slot is too full to add new content, we add a
                                        // new slot to the chain (between parent and current slot).
                                        // The rid_chain_item reference must be dropped because of
                                        // Rust's ownership model.
                                        drop(rid_chain_item);

                                        let new_position = PositionTag::new_random(enclave_state);
                                        let mut slot_pointer_predecessor =
                                            SlotPointer::new(new_position.clone());
                                        slot_pointer_predecessor.set_fill_amount(1);

                                        let parent_id = slot.parent().clone().unwrap();

                                        insert_content.mut_rids().unwrap().set_next(Some(
                                            SlotPointer::new(current_slot_position.clone()),
                                        ));
                                        slot.set_parent(Some(ParentId::Slot(ParentSlotId::new(
                                            new_position.copy_packet_id(),
                                        ))));
                                        match &parent_id {
                                            ParentId::Node(parent_node_id) => {
                                                let mut obt_node_cache =
                                                    enclave_state.lock_obt_node_cache();
                                                let parent_node = obt_node_cache
                                                    .mut_node(parent_node_id.cache_id())
                                                    .unwrap();
                                                match parent_node.query_next_tuple_meta() {
                                                    None => {}
                                                    Some(some_meta) => {
                                                        match some_meta
                                                            .get(parent_node_id.chosen_path()
                                                                as usize)
                                                        {
                                                            None => {}
                                                            Some(some_meta_entry) => {
                                                                let mut query_state_cache =
                                                                    enclave_state
                                                                        .lock_query_state_cache();
                                                                for other_query_id in
                                                                some_meta_entry.iter()
                                                                {
                                                                    let mut other_query =
                                                                        query_state_cache
                                                                            .get_mut(other_query_id)
                                                                            .unwrap();
                                                                    if other_query
                                                                        .next()
                                                                        .request()
                                                                        .unwrap()
                                                                        .0
                                                                        .equals(
                                                                            &current_slot_position,
                                                                        )
                                                                    {
                                                                        other_query.set_next(NextPos::Request(
                                                                            new_position.clone(),
                                                                            ObjectType::SlotObjectType,
                                                                        ));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                let mut tuple_pointer = parent_node
                                                    .mut_tuple_pointer(
                                                        parent_node_id.chosen_path() as usize
                                                    )
                                                    .unwrap();
                                                tuple_pointer
                                                    .set_slot_pointer(slot_pointer_predecessor);
                                            }
                                            ParentId::Slot(parent_slot_id) => {
                                                let mut parent_slot = slot_cache
                                                    .mut_slot(parent_slot_id.cache_id())
                                                    .unwrap();
                                                match parent_slot
                                                    .content()
                                                    .rids()
                                                    .unwrap()
                                                    .visited()
                                                {
                                                    None => {}
                                                    Some(some_visited) => {
                                                        let mut query_state_cache =
                                                            enclave_state.lock_query_state_cache();
                                                        for other_query_id in some_visited.iter() {
                                                            let mut other_query = query_state_cache
                                                                .get_mut(other_query_id)
                                                                .unwrap();
                                                            other_query.set_next(NextPos::Request(
                                                                new_position.clone(),
                                                                ObjectType::SlotObjectType,
                                                            ));
                                                        }
                                                    }
                                                }
                                                parent_slot
                                                    .mut_content()
                                                    .mut_rids()
                                                    .unwrap()
                                                    .set_next(Some(slot_pointer_predecessor));
                                            }
                                        }
                                        let mut new_slot = Slot::new(insert_content, Origin::Local);
                                        new_slot.set_parent(Some(parent_id));

                                        slot_cache
                                            .insert_slot(new_position.copy_packet_id(), new_slot);
                                        evict_slot_back_to_front =
                                            Some(current_slot_position.copy_packet_id());
                                    } else {
                                        rid_chain_item.mut_rids().append(
                                            insert_content.clone().mut_rids().unwrap().mut_rids(),
                                        );
                                        evict_slot_back_to_front =
                                            Some(current_slot_position.copy_packet_id());
                                    }
                                }
                                ObTreeOperation::SELECT => {
                                    query_state
                                        .add_to_found(SlotContent::RIDs(rid_chain_item.clone()));
                                    match rid_chain_item.next() {
                                        None => {
                                            evict_slot_back_to_front =
                                                Some(current_slot_position.copy_packet_id());
                                        }
                                        Some(some_next) => {
                                            cont = true;
                                            next_parent = Some(ParentId::Slot(ParentSlotId::new(
                                                current_slot_position.copy_packet_id(),
                                            )));
                                            next_pos = Some(some_next.position().clone());
                                        }
                                    }
                                }
                                ObTreeOperation::DELETE(delete_query) => {
                                    match delete_query.slot_content_filter() {
                                        None => {
                                            re_insert_slot = false;
                                            match rid_chain_item.next() {
                                                None => {
                                                    let parent_node_id = slot
                                                        .parent()
                                                        .as_ref()
                                                        .unwrap()
                                                        .node()
                                                        .unwrap();
                                                    let mut obt_node_cache =
                                                        enclave_state.lock_obt_node_cache();
                                                    let mut node = obt_node_cache
                                                        .mut_node(parent_node_id.cache_id())
                                                        .unwrap();
                                                    node.set_tuple_pointer_status(
                                                        enclave_state,
                                                        parent_node_id.chosen_path() as usize,
                                                        ObTreeTuplePointerStatus::REMOVED,
                                                    );
                                                    deleted_everything =
                                                        Some(parent_node_id.clone());
                                                }
                                                Some(some_next_item) => {
                                                    cont = true;
                                                    next_pos =
                                                        Some(some_next_item.position().clone());
                                                    next_parent = slot.parent().clone();
                                                }
                                            }
                                        }
                                        Some(some_slot_filter) => {
                                            let delete_item = rid_chain_item
                                                .delete_ob_tree_filter(some_slot_filter)
                                                == 0;
                                            match delete_item {
                                                true => {
                                                    // TODO: Change pointer of predecessor?
                                                    // This slot has to be completely removed
                                                    re_insert_slot = false;
                                                    match rid_chain_item.next() {
                                                        None => match slot
                                                            .parent()
                                                            .as_ref()
                                                            .unwrap()
                                                        {
                                                            ParentId::Node(_) => {
                                                                let parent_node_id = slot
                                                                    .parent()
                                                                    .as_ref()
                                                                    .unwrap()
                                                                    .node()
                                                                    .unwrap();
                                                                let mut obt_node_cache =
                                                                    enclave_state
                                                                        .lock_obt_node_cache();
                                                                let mut node = obt_node_cache
                                                                    .mut_node(
                                                                        parent_node_id.cache_id(),
                                                                    )
                                                                    .unwrap();
                                                                node.set_tuple_pointer_status(enclave_state, parent_node_id.chosen_path() as usize, ObTreeTuplePointerStatus::REMOVED);
                                                                deleted_everything =
                                                                    Some(parent_node_id.clone());
                                                            }
                                                            ParentId::Slot(some_parent_slot) => {
                                                                evict_slot_back_to_front = Some(
                                                                    some_parent_slot
                                                                        .copy_cache_id(),
                                                                );
                                                            }
                                                        },
                                                        Some(some_next_item) => {
                                                            cont = true;
                                                            next_pos = Some(
                                                                some_next_item.position().clone(),
                                                            );
                                                            next_parent = slot.parent().clone();
                                                        }
                                                    }
                                                }
                                                false => {
                                                    // This slot must be maintained
                                                    match rid_chain_item.next() {
                                                        None => {
                                                            evict_slot_back_to_front = Some(
                                                                current_slot_position
                                                                    .copy_packet_id(),
                                                            );
                                                        }
                                                        Some(some_next_item) => {
                                                            cont = true;
                                                            next_pos = Some(
                                                                some_next_item.position().clone(),
                                                            );
                                                            next_parent = Some(ParentId::Slot(
                                                                ParentSlotId::new(
                                                                    current_slot_position
                                                                        .copy_packet_id(),
                                                                ),
                                                            ));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if re_insert_slot {
                        if cont {
                            slot.mut_content()
                                .mut_rids()
                                .unwrap()
                                .add_query_to_visited(query_state.id());
                        }
                        slot_cache.insert_slot(current_slot_position.copy_packet_id(), slot);
                    } else if cont {
                        let parent_id = slot.parent().as_ref().unwrap();
                        match parent_id {
                            ParentId::Node(_) => {}
                            ParentId::Slot(parent_slot_id) => {
                                let mut parent_slot =
                                    slot_cache.mut_slot(parent_slot_id.cache_id()).unwrap();
                                parent_slot
                                    .mut_content()
                                    .mut_rids()
                                    .unwrap()
                                    .add_query_to_visited(query_state.id());
                            }
                        }
                    }

                    if cont {
                        drop(slot_cache);
                        assert!(evict_slot_back_to_front.is_none());
                        query_state.set_parent(Some(next_parent.unwrap()));
                        query_state.set_next(NextPos::Request(
                            next_pos.unwrap(),
                            ObjectType::SlotObjectType,
                        ));
                        traverse_rid_chain(enclave_state, query_state)
                    } else {
                        query_state.set_next(NextPos::Finite);
                        query_state.set_parent(None);

                        match evict_slot_back_to_front {
                            Some(some_slot_id) => {
                                drop(slot_cache);
                                ob_tree::eviction::evict_slot_back_to_front(
                                    enclave_state,
                                    some_slot_id,
                                    query_state.id(),
                                    query_state.ob_tree_query().index_id(),
                                )
                            }
                            _ => deleted_everything,
                        }
                    }
                }
            };
        }
    }

    pub mod backup_api {
        use oblivious_data_structures::position_tag::PositionTag;
        use {log_runtime, EnclaveState};

        pub fn evict_all_roots(enclave_state: &EnclaveState) {
            let mut obt_node_cache = enclave_state.lock_obt_node_cache();
            let slot_cache = enclave_state.lock_slot_cache();
            let mut obt_directory = enclave_state.lock_obt_tree_directory();

            for (_, tree) in obt_directory.trees().iter() {
                match obt_node_cache.get_node(tree.root().packet_id()) {
                    None => {}
                    Some(node) => {
                        if !(node.no_slot_node_is_in_cache(&slot_cache)
                            && node.no_child_node_is_in_cache(&obt_node_cache)
                            && node.parent_node().is_no_parent())
                        {
                            log_runtime(
                                "evict_all_roots cannot be applied, cache is not empty!",
                                true,
                            );
                            return;
                        }
                    }
                }
            }

            for (index_id, tree) in obt_directory.mut_trees().iter_mut() {
                match obt_node_cache.remove_node(tree.root().packet_id()) {
                    None => {}
                    Some(node) => {
                        let new_pos = PositionTag::new_random(enclave_state);
                        node.evict(enclave_state, &new_pos, *index_id);
                        tree.set_root(new_pos);
                    }
                }
            }

            println!(
                "evict_all_roots: OB-Tree Node Cache has a size of {} now.",
                obt_node_cache.size()
            );
        }
    }
}
