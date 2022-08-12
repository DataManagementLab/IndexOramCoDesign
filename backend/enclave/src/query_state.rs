use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};


use std::vec::Vec;


use oblivious_data_structures::ob_tree::components::{
    ObTreeQuery,
};
use oblivious_data_structures::page::{SlotContent};
use oblivious_data_structures::position_tag::PositionTag;
use sql_engine::sql_data_types::components::SqlDataType;
use {sql_engine, EnclaveState};
use {utils};

/// A QueryState defines the context of a query in the oblivious index
#[derive(Serialize, Deserialize, Clone)]
pub struct QueryState {
    /// Unique id given by the QueryProvider.
    id: u128,
    /// Defines if the query is about to insert, delete or select data.
    operation_type: ObTreeOperation,
    /// Defines which keys of which OB-Tree instance the query is about.
    ob_tree_query: ObTreeQuery,
    /// The last visited element of the index to be set as a parent in the next element.
    /// This information is needed for eviction purposes.
    parent: Option<ParentId>,
    /// Declares the ORAM position of the next index item to be visited by the query.
    next: NextPos,
    /// If the query is about to select data from an OB-Tree, this is collected here.
    found: Option<Vec<SlotContent>>,
    /// Defines if the query is locked or unlocked regarding the concurrency policy.
    operation_permission: bool,
    /// If the query is locked, it is still able to traverse the index tree.
    /// However, when the query has reached a key it wants to operate on, the status is also paused.
    operation_status: QueryOperationStatus,
}

impl QueryState {
    pub fn ob_tree_query(&self) -> &ObTreeQuery {
        &self.ob_tree_query
    }
    pub fn next(&self) -> &NextPos {
        &self.next
    }
    pub fn next_as_tuple(&self, enclave_state: &EnclaveState) -> (PositionTag, ObjectType) {
        match self.next() {
            NextPos::Start => (
                enclave_state
                    .lock_obt_tree_directory()
                    .get_tree(&self.ob_tree_query().index_id())
                    .unwrap()
                    .root()
                    .clone(),
                ObjectType::NodeObjectType,
            ),
            NextPos::Request(some_next_position, some_next_object) => {
                (some_next_position.clone(), some_next_object.clone())
            }
            _ => {
                panic!("next_as_tuple does not accept finished query states.")
            }
        }
    }
    pub fn mut_next(&mut self) -> &mut NextPos {
        &mut self.next
    }
    pub fn operation_type(&self) -> &ObTreeOperation {
        &self.operation_type
    }
    pub fn mut_operation_type(&mut self) -> &mut ObTreeOperation {
        &mut self.operation_type
    }
    pub fn id(&self) -> u128 {
        self.id
    }
    /// Sets the NextPos in the query which was computed by an Ob-Tree operation before
    pub fn set_next(&mut self, next: NextPos) {
        self.next = next;
    }
    pub fn parent(&self) -> &Option<ParentId> {
        &self.parent
    }
    pub fn parent_ref(&self) -> Option<&ParentId> {
        self.parent.as_ref()
    }
    /// Sets the parent node id in the query which is used in the next traversed node/slot
    pub fn set_parent(&mut self, parent: Option<ParentId>) {
        self.parent = parent;
    }
    pub fn mut_parent(&mut self) -> &mut Option<ParentId> {
        &mut self.parent
    }
    pub fn new(
        id: u128,
        operation_type: ObTreeOperation,
        ob_tree_query: ObTreeQuery,
        parent: Option<ParentId>,
        next: NextPos,
    ) -> Self {
        QueryState {
            id,
            operation_type,
            ob_tree_query,
            parent,
            next,
            found: None,
            operation_permission: false,
            operation_status: QueryOperationStatus::ACTIVE,
        }
    }
    pub fn add_to_found(&mut self, new: SlotContent) {
        match self.found.as_mut() {
            None => {
                self.found = Some(Vec::with_capacity(1));
                self.add_to_found(new);
            }
            Some(some_found) => {
                some_found.push(new);
            }
        }
    }
    pub fn found(&self) -> &Option<Vec<SlotContent>> {
        &self.found
    }
    pub fn operation_permission(&self) -> bool {
        self.operation_permission
    }
    pub fn set_operation_permission(&mut self, operation_permission: bool) {
        self.operation_permission = operation_permission;
        if operation_permission {
            self.set_operation_status(QueryOperationStatus::ACTIVE)
        }
    }
    pub fn set_operation_status(&mut self, operation_status: QueryOperationStatus) {
        self.operation_status = operation_status;
    }
    pub fn operation_status(&self) -> &QueryOperationStatus {
        &self.operation_status
    }
}


/// Contains Delete-Query specific information
#[derive(Serialize, Deserialize, Clone)]
pub struct DeleteOperationState {
    slot_content_filter: Option<ObTreeSlotContentFilter>,
}

impl DeleteOperationState {
    pub fn new(slot_content_filter: Option<ObTreeSlotContentFilter>) -> Self {
        DeleteOperationState {
            slot_content_filter,
        }
    }
    pub fn slot_content_filter(&self) -> &Option<ObTreeSlotContentFilter> {
        &self.slot_content_filter
    }
}

/// Contains Insert-Query specific information
#[derive(Serialize, Deserialize, Clone)]
pub struct InsertOperationState {
    slot_content: SlotContent,
}

impl InsertOperationState {
    pub fn slot_content(&self) -> &SlotContent {
        &self.slot_content
    }
    pub fn new(slot_content: SlotContent) -> Self {
        InsertOperationState { slot_content }
    }
}

/// Defines the operation type of a query
#[derive(Serialize, Deserialize, Clone)]
pub enum ObTreeOperation {
    INSERT(InsertOperationState),
    SELECT,
    DELETE(DeleteOperationState),
}

impl ObTreeOperation {
    pub fn get_insert_query_state(&self) -> Option<&InsertOperationState> {
        match self {
            ObTreeOperation::INSERT(state) => Some(state),
            _ => None,
        }
    }
    pub fn mut_insert_query_state(&mut self) -> Option<&mut InsertOperationState> {
        match self {
            ObTreeOperation::INSERT(state) => Some(state),
            _ => None,
        }
    }
    pub fn get_delete_query_state(&self) -> Option<&DeleteOperationState> {
        match self {
            ObTreeOperation::DELETE(delete_query_state) => Some(delete_query_state),
            _ => None,
        }
    }
    pub fn mut_delete_query_state(&mut self) -> Option<&mut DeleteOperationState> {
        match self {
            ObTreeOperation::DELETE(delete_query_state) => Some(delete_query_state),
            _ => None,
        }
    }
}

/// Defines whether the query is about the primary or a secondary index
#[derive(Serialize, Deserialize, Clone)]
pub enum ObTreeSlotContentFilter {
    ATTRIBUTES(HashMap<u32, utils::Pair<SqlDataType, sql_engine::sql_query::CmpOperator>>),
    RIDS(Vec<SqlDataType>),
}

impl ObTreeSlotContentFilter {
    pub fn attributes(
        &self,
    ) -> Option<&HashMap<u32, utils::Pair<SqlDataType, sql_engine::sql_query::CmpOperator>>> {
        match self {
            ObTreeSlotContentFilter::ATTRIBUTES(attributes) => Some(attributes),
            ObTreeSlotContentFilter::RIDS(_) => None,
        }
    }
    pub fn rids(&self) -> Option<&Vec<SqlDataType>> {
        match self {
            ObTreeSlotContentFilter::ATTRIBUTES(_) => None,
            ObTreeSlotContentFilter::RIDS(rids) => Some(rids),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ObjectType {
    NodeObjectType,
    SlotObjectType,
}

impl ObjectType {
    pub fn as_str(&self) -> &str {
        match self {
            ObjectType::NodeObjectType => "NodeObjectType",
            ObjectType::SlotObjectType => "SlotObjectType",
        }
    }
    pub fn is_slot_type(&self) -> bool {
        match self {
            ObjectType::SlotObjectType => true,
            _ => false,
        }
    }
}

/// The next position thats needs to retrieved from ORAM to process a query
#[derive(Serialize, Deserialize, Clone)]
pub enum NextPos {
    /// Has not visited an index yet
    Start,
    /// Contains a tuple of the next object to be fetched at which position
    Request(PositionTag, ObjectType),
    /// Defines the query state as invalid
    InvalidRequest,
    /// Query has finished
    Finite,
}

impl NextPos {
    pub fn request(&self) -> Option<(&PositionTag, &ObjectType)> {
        match self {
            NextPos::Request(pos, obj) => {
                return Some((pos, obj));
            }
            _ => {}
        }
        None
    }
    pub fn is_valid(&self) -> bool {
        match self {
            NextPos::InvalidRequest => {
                return false;
            }
            _ => {}
        }
        true
    }
}

/// Last visited Node/Slot of a query
#[derive(Serialize, Deserialize, Clone)]
pub enum ParentId {
    Node(ParentNodeId),
    Slot(ParentSlotId),
}

impl ParentId {
    pub fn node(&self) -> Option<&ParentNodeId> {
        match self {
            ParentId::Node(node) => Some(node),
            ParentId::Slot(_) => None,
        }
    }
    pub fn destroy_to_node(self) -> Option<ParentNodeId> {
        match self {
            ParentId::Node(node) => Some(node),
            ParentId::Slot(_) => None,
        }
    }
    pub fn slot(&self) -> Option<&ParentSlotId> {
        match self {
            ParentId::Node(_) => None,
            ParentId::Slot(slot) => Some(slot),
        }
    }
    pub fn mut_node(&mut self) -> Option<&mut ParentNodeId> {
        match self {
            ParentId::Node(node) => Some(node),
            ParentId::Slot(_) => None,
        }
    }
    pub fn mut_slot(&mut self) -> Option<&mut ParentSlotId> {
        match self {
            ParentId::Node(_) => None,
            ParentId::Slot(slot) => Some(slot),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ParentSlotId {
    cache_id: u128,
}

impl ParentSlotId {
    pub fn new(cache_id: u128) -> Self {
        ParentSlotId { cache_id }
    }
    pub fn cache_id(&self) -> &u128 {
        &self.cache_id
    }
    pub fn copy_cache_id(&self) -> u128 {
        self.cache_id
    }
    pub fn set_cache_id(&mut self, cache_id: u128) {
        self.cache_id = cache_id;
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ParentNodeId {
    cache_id: u128,
    chosen_path: u32,
}

impl ParentNodeId {
    pub fn cache_id(&self) -> &u128 {
        &self.cache_id
    }
    pub fn copy_cache_id(&self) -> u128 {
        self.cache_id
    }
    pub fn chosen_path(&self) -> u32 {
        self.chosen_path
    }
    pub fn destroy(self) -> (u128, u32) {
        (self.cache_id, self.chosen_path)
    }
    pub fn set_cache_id(&mut self, cache_id: u128) {
        self.cache_id = cache_id;
    }
    pub fn set_chosen_path(&mut self, chosen_path: u32) {
        self.chosen_path = chosen_path;
    }
    pub fn new(cache_id: u128, chosen_path: u32) -> Self {
        ParentNodeId {
            cache_id,
            chosen_path,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum QueryOperationStatus {
    ACTIVE,
    LOCKED,
}

impl QueryOperationStatus {
    pub fn is_active(&self) -> bool {
        return match self {
            QueryOperationStatus::ACTIVE => true,
            QueryOperationStatus::LOCKED => false,
        };
    }
}