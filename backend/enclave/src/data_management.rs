/* pub mod obt_access {
    use std::string::{String, ToString};
    use std::time::Instant;
    use std::untrusted::time::InstantEx;
    use std::vec::Vec;

    use helpers::range::Range;
    use logger::log_runtime;
    use oblivious_data_structures::ob_tree::components::ObTreeQuery;

    use crate::app_state::EnclaveState;
    use crate::oblivious_data_structures::ob_tree::functions::{
        insert_point, rid_search, single_tuple_search,
    };
    use crate::oblivious_data_structures::page::{RIDChainItem, SlotContent};
    use crate::sql_engine::sql_data_types::components::SqlDataType;
    use crate::sql_engine::sql_data_types::functions::{
        compress_sql_data_type, decompress_sql_data_type,
    };
    use crate::sql_engine::sql_database::components::{SqlAttribute, SqlTableRow, SqlTableScheme};

    pub fn insert_row(
        app_state: &EnclaveState,
        table_scheme: &SqlTableScheme,
        fill_grade: usize,
        insert_secondary: bool,
    ) {
        let timer: Instant = Instant::now();
        let rid_decr = row.values().get(key_index).unwrap().clone();

        /*
        if insert_secondary {
            let rid_compr = compress_sql_data_type(&rid_decr, false);
            for (index, column) in row.values().iter().enumerate() {
                if index != key_index {
                    if !column.is_sql_null() {
                        let key_insert_decr = column.clone();
                        let key_config = table_scheme.get_attribute(index).unwrap();
                        let request = ObTreeQuery::new(
                            true,
                            Range::new(&key_insert_decr, &key_insert_decr),
                            key_config,
                            index as u16,
                        );

                        let slot_content =
                            SlotContent::RIDs(RIDChainItem::new(vec![rid_compr.clone()], None));
                        let (root_position, tree_height) = insert_point(
                            app_state,
                            &request,
                            slot_content,
                            vec![index],
                            Vec::new(),
                            fill_grade,
                            app_state
                                .lock_obt_tree_directory()
                                .get_tree(&index)
                                .unwrap()
                                .root()
                                .clone(),
                            Instant::now(),
                        );
                        let mut obt_directory = app_state.lock_obt_tree_directory();
                        obt_directory
                            .mut_tree(&index)
                            .unwrap()
                            .set_root(root_position);
                        if tree_height.is_some() {
                            obt_directory
                                .mut_tree(&index)
                                .unwrap()
                                .set_height(tree_height.unwrap());
                        }
                    }
                }
            }
        }
         */

        let timer = timer.elapsed();
        app_state
            .lock_statistics()
            .inc_time_to_insert_rids(timer.as_nanos());
        let slot_content = SlotContent::Row(row);
        let request = ObTreeQuery::new(
            true,
            Range::new(&rid_decr, &rid_decr),
            table_scheme.get_attribute(key_index).unwrap(),
            key_index as u16,
        );
        let timer: Instant = Instant::now();
        let (root_position, tree_height) = insert_point(
            app_state,
            &request,
            slot_content,
            vec![key_index],
            Vec::new(),
            fill_grade,
            app_state
                .lock_obt_tree_directory()
                .get_tree(&key_index)
                .unwrap()
                .root()
                .clone(),
            Instant::now(),
        );
        let timer = timer.elapsed();
        app_state
            .lock_statistics()
            .inc_time_to_insert_rows(timer.as_nanos());
        let mut obt_directory = app_state.lock_obt_tree_directory();
        obt_directory
            .mut_tree(&key_index)
            .unwrap()
            .set_root(root_position);
        if tree_height.is_some() {
            obt_directory
                .mut_tree(&key_index)
                .unwrap()
                .set_height(tree_height.unwrap());
        }
    }

    pub fn get_all_rids(
        app_state: &EnclaveState,
        queries: Vec<(SqlDataType, &SqlAttribute, usize)>,
        rid_attribute_config: &SqlAttribute,
    ) -> Vec<SqlDataType> {
        let mut obt_directory = app_state.lock_obt_tree_directory();
        let start_of_requests: Instant = Instant::now();
        let mut rids = Vec::new();
        let mut multiple_queries = queries.len();
        let mut index = 0;
        for query in queries {
            let ob_tree = obt_directory.mut_tree(&query.2).unwrap();
            let chosen_path: Vec<usize> = vec![query.2];
            let request = ObTreeQuery::new(
                true,
                Range::new(&query.0, &query.0),
                query.1,
                query.2 as u16,
            );
            let rid_search_results =
                rid_search(app_state, &request, chosen_path, ob_tree.root().clone());
            ob_tree.set_root(rid_search_results.0);
            let mut number = 0;
            for rid_search_result in rid_search_results.1 {
                let value = decompress_sql_data_type(&rid_search_result, rid_attribute_config);
                rids.push(value);
                number += 1;
            }
            index += 1;
            if number == 2 {
                multiple_queries = index;
                break;
            }
        }
        //rids.sort();
        rids.sort_by(|a, b| b.cmp(a));

        if multiple_queries > 1 {
            let mut i = 0;
            while i < rids.len() {
                if rids.get(i).is_none() {
                    break;
                } else {
                    let mut remove = false;
                    let mut end = i + multiple_queries;
                    for k in i..i + multiple_queries {
                        if rids.get(k).is_none() {
                            remove = true;
                            break;
                        }
                        if rids.get(i).unwrap().cmp(rids.get(k).unwrap()).is_ne() {
                            remove = true;
                            end = k;
                            break;
                        }
                    }
                    if !remove {
                        i = i + 1;
                    }
                    for k in i..end {
                        if rids.get(k).is_none() {
                            break;
                        }
                        rids.remove(k);
                    }
                }
            }
        }
        let elapsed = start_of_requests.elapsed();
        log_runtime(
            &format!(
                "get_all_rids has finished! {} ms ({} ns) were required for the execution.",
                elapsed.as_millis(),
                elapsed.as_nanos()
            ),
            true,
        );
        rids
    }

    pub fn obt_search_key(
        app_state: &EnclaveState,
        key: &SqlDataType,
        key_config: &SqlAttribute,
        ob_tree_index: usize,
    ) -> Option<SlotContent> {
        let timer: Instant = Instant::now();
        let chosen_path = vec![ob_tree_index];
        let mut obt_directory = app_state.lock_obt_tree_directory();
        let ob_tree = obt_directory.mut_tree(&ob_tree_index).unwrap();
        let request =
            ObTreeQuery::new(true, Range::new(key, key), key_config, ob_tree_index as u16);
        let (root_pos, slot_content) =
            single_tuple_search(app_state, &request, chosen_path, ob_tree.root().clone());
        ob_tree.set_root(root_pos);
        /*
        log_runtime(
            &format!(
                "obt_search_key has finished! {} ms ({} ns) were required for the execution.",
                elapsed.as_millis(), elapsed.as_nanos()
            ),
            true,
        );
         */
        app_state
            .lock_statistics()
            .inc_time_obt_search_key(timer.elapsed().as_nanos());
        return slot_content;
    }
}

 */
