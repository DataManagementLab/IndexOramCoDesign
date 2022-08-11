use oblivious_data_structures::ob_tree::components::{ObTreeQueryValue, ObTreeQueryValueRange};
use sql_engine::sql_data_types::components::SqlDataType;
use sql_engine::sql_data_types::components::SqlDataType::SQLInteger;

pub fn test_ob_tree_query_value() {
    let val1 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(0));
    let val2 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(1));
    assert!(val1.cmp(&val2).is_lt());

    let val2 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(1));
    assert!(val2.cmp(&val2).is_eq());

    let val1 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(3));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(1), SQLInteger(4)));

    assert!(val1.cmp(&val2).is_eq());

    let val1 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(0));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(1), SQLInteger(4)));

    assert!(val1.cmp(&val2).is_lt());

    let val1 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(5));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(1), SQLInteger(4)));

    assert!(val1.cmp(&val2).is_gt());

    let val1 = ObTreeQueryValue::Single(SqlDataType::SQLInteger(4));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(1), SQLInteger(4)));

    assert!(val1.cmp(&val2).is_eq());

    let val1 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(4), SQLInteger(8)));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(1), SQLInteger(4)));

    assert!(val1.cmp(&val2).is_eq());

    let val1 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(0), SQLInteger(2)));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(1), SQLInteger(4)));

    assert!(val1.cmp(&val2).is_eq());

    let val1 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(0), SQLInteger(4)));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(5), SQLInteger(7)));

    assert!(val1.cmp(&val2).is_lt());

    let val1 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(8), SQLInteger(9)));
    let val2 = ObTreeQueryValue::Range(ObTreeQueryValueRange::new(SQLInteger(2), SQLInteger(7)));

    assert!(val1.cmp(&val2).is_gt());
}
