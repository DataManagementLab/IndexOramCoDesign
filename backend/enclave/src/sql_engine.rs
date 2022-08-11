pub mod sql_data_types {
    pub mod components {
        use chrono::{Date, DateTime, NaiveTime, TimeZone, Utc};
        use serde::{Deserialize, Serialize};
        use sql_engine::sql_query::CmpOperator;
        use std::cmp::Ordering;
        use std::string::{String, ToString};
        use std::vec::Vec;

        use crate::sql_engine::sql_data_types::functions::display_sql_data_type;

        #[derive(Serialize, Deserialize, Clone)]
        pub enum SqlAbstractDataType {
            //AbstractSQLTinyInt,
            AbstractSQLInteger,
            //AbstractSQLBigInteger,
            //AbstractSQLFloat,
            AbstractSQLBool,
            AbstractSQLText,
            //AbstractSQLChar,
            //AbstractSQLVarchar,
            AbstractSQLDate,
            AbstractSQLDateTime,
            AbstractSQLTime,
            //AbstractSQLTinyBlob,
            //AbstractSQLBlob,
            AbstractSQLNull,
        }

        impl SqlAbstractDataType {
            pub fn distribution_mappable(&self) -> bool {
                match self {
                    SqlAbstractDataType::AbstractSQLInteger => true,
                    SqlAbstractDataType::AbstractSQLBool => false,
                    SqlAbstractDataType::AbstractSQLText => true,
                    SqlAbstractDataType::AbstractSQLDate => true,
                    SqlAbstractDataType::AbstractSQLDateTime => true,
                    SqlAbstractDataType::AbstractSQLTime => true,
                    SqlAbstractDataType::AbstractSQLNull => false,
                }
            }
        }

        #[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
        pub enum SqlDataType {
            //SQLTinyInt(i8),
            SQLInteger(i64),
            //SQLBigInteger(i128),
            //SQLFloat { integer_part: i64, fractional_part: u64 },
            SQLBool(bool),
            SQLText(String),
            //SQLChar([char;255]),
            //SQLVarchar(Vec<char>),
            SQLDate {
                day: u8,
                month: u8,
                year: u16,
            },
            SQLDateTime {
                day: u8,
                month: u8,
                year: u16,
                hour: u8,
                minute: u8,
                second: u8,
            },
            SQLTime {
                hour: u8,
                minute: u8,
                second: u8,
            },
            //SQLTinyBlob([u8;255]),
            //SQLBlob([u8;65535]),
            SQLNull,
        }

        impl SqlDataType {
            pub fn compare_with_operator(
                &self,
                other: &SqlDataType,
                operator: &CmpOperator,
            ) -> bool {
                match operator {
                    CmpOperator::Equal => {
                        if !self.cmp(other).is_eq() {
                            return false;
                        }
                    }
                    CmpOperator::Less => {
                        if !self.cmp(other).is_lt() {
                            return false;
                        }
                    }
                    CmpOperator::Greater => {
                        if !self.cmp(other).is_gt() {
                            return false;
                        }
                    }
                    CmpOperator::LessEqual => {
                        if !self.cmp(other).is_le() {
                            return false;
                        }
                    }
                    CmpOperator::GreaterEqual => {
                        if !self.cmp(other).is_ge() {
                            return false;
                        }
                    }
                }
                return true;
            }
            pub fn byte_size(&self) -> usize {
                bincode::serialized_size(self).expect("") as usize
            }
            pub fn sql_integer(&self) -> Option<&i64> {
                match self {
                    SqlDataType::SQLInteger(val) => Some(val),
                    _ => None,
                }
            }
            /*
            fn sql_float(&self) -> Option<(&i64, &u64)> {
                match self {
                    SqlDataType::SQLFloat { integer_part, fractional_part } => Some((integer_part, fractional_part)),
                    _ => None,
                }
            }
            fn create_sql_float_from_f32(f32_float: f32) -> SqlDataType {
                let int_part = f32_float.floor() as i64;
                let frac_part = (f32_float - (int_part as f32)) as u64;
                SqlDataType::SQLFloat { integer_part: int_part, fractional_part: frac_part }
            }
            fn sql_float_to_f32(&self) -> Option<f32> {
                return match self.sql_float() {
                    None => {
                        None
                    }
                    Some(sql_float) => {
                        match format!("{}.{}", sql_float.0, sql_float.1).parse::<f32>() {
                            Ok(f32_float) => {
                                Some(f32_float)
                            }
                            Err(_) => {
                                None
                            }
                        }
                    }
                };
            }
             */
            pub fn sql_bool(&self) -> Option<&bool> {
                match self {
                    SqlDataType::SQLBool(val) => Some(val),
                    _ => None,
                }
            }
            pub fn sql_text(&self) -> Option<&String> {
                match self {
                    SqlDataType::SQLText(val) => Some(val),
                    _ => None,
                }
            }
            pub fn sql_date(&self) -> Option<(&u16, &u8, &u8)> {
                match self {
                    SqlDataType::SQLDate { year, month, day } => Some((year, month, day)),
                    _ => None,
                }
            }
            pub fn sql_date_to_date_obj(&self) -> Option<Date<Utc>> {
                return match self.sql_date() {
                    None => None,
                    Some(date) => {
                        Some(Utc.ymd(i32::from(*date.0), u32::from(*date.1), u32::from(*date.2)))
                    }
                };
            }
            pub fn sql_datetime(&self) -> Option<(&u16, &u8, &u8, &u8, &u8, &u8)> {
                match self {
                    SqlDataType::SQLDateTime {
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                    } => Some((year, month, day, hour, minute, second)),
                    _ => None,
                }
            }
            pub fn sql_datetime_to_datetime_obj(&self) -> Option<DateTime<Utc>> {
                return match self.sql_datetime() {
                    None => None,
                    Some(datetime) => Some(
                        Utc.ymd(
                            i32::from(*datetime.0),
                            u32::from(*datetime.1),
                            u32::from(*datetime.2),
                        )
                        .and_hms(
                            u32::from(*datetime.3),
                            u32::from(*datetime.4),
                            u32::from(*datetime.5),
                        ),
                    ),
                };
            }
            pub fn sql_time(&self) -> Option<(&u8, &u8, &u8)> {
                match self {
                    SqlDataType::SQLTime {
                        hour,
                        minute,
                        second,
                    } => Some((hour, minute, second)),
                    _ => None,
                }
            }
            pub fn sql_time_to_time_obj(&self) -> Option<NaiveTime> {
                return match self.sql_time() {
                    None => None,
                    Some(time) => Some(NaiveTime::from_hms(
                        u32::from(*time.0),
                        u32::from(*time.1),
                        u32::from(*time.2),
                    )),
                };
            }
            pub fn is_sql_null(&self) -> bool {
                match self {
                    SqlDataType::SQLNull => true,
                    _ => false,
                }
            }
        }

        impl PartialOrd for SqlDataType {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                if let SqlDataType::SQLInteger(val1) = &self {
                    if let SqlDataType::SQLInteger(val2) = other {
                        return Some(val1.cmp(val2));
                    }
                }
                /*
                if let SqlDataType::SQLFloat { integer_part: int1, fractional_part: frac1 } = &self {
                    if let SqlDataType::SQLFloat { integer_part: int2, fractional_part: frac2 } = other {
                        return if int1.cmp(int2).is_eq() {
                            Some(frac1.cmp(frac2))
                        } else {
                            Some(int1.cmp(int2))
                        };
                    }
                }
                 */
                if let SqlDataType::SQLBool(val1) = &self {
                    if let SqlDataType::SQLBool(val2) = other {
                        return Some(val1.cmp(val2));
                    }
                }
                if let SqlDataType::SQLText(val1) = &self {
                    if let SqlDataType::SQLText(val2) = other {
                        return Some(val1.cmp(val2));
                    }
                }
                if let SqlDataType::SQLDate {
                    day: day1,
                    month: month1,
                    year: year1,
                } = &self
                {
                    if let SqlDataType::SQLDate {
                        day: day2,
                        month: month2,
                        year: year2,
                    } = other
                    {
                        if year1.cmp(year2).is_eq() {
                            if month1.cmp(month2).is_eq() {
                                return Some(day1.cmp(day2));
                            }
                            return Some(month1.cmp(month2));
                        }
                        return Some(year1.cmp(year2));
                    }
                }
                if let SqlDataType::SQLDateTime {
                    day: day1,
                    month: month1,
                    year: year1,
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } = &self
                {
                    if let SqlDataType::SQLDateTime {
                        day: day2,
                        month: month2,
                        year: year2,
                        hour: hour2,
                        minute: minute2,
                        second: second2,
                    } = other
                    {
                        if year1.cmp(year2).is_eq() {
                            if month1.cmp(month2).is_eq() {
                                if day1.cmp(day2).is_eq() {
                                    if hour1.cmp(hour2).is_eq() {
                                        if minute1.cmp(minute2).is_eq() {
                                            return Some(second1.cmp(second2));
                                        }
                                        return Some(minute1.cmp(minute2));
                                    }
                                    return Some(hour1.cmp(hour2));
                                }
                                return Some(day1.cmp(day2));
                            }
                            return Some(month1.cmp(month2));
                        }
                        return Some(year1.cmp(year2));
                    }
                }
                if let SqlDataType::SQLTime {
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } = &self
                {
                    if let SqlDataType::SQLTime {
                        hour: hour2,
                        minute: minute2,
                        second: second2,
                    } = other
                    {
                        if hour1.cmp(hour2).is_eq() {
                            if minute1.cmp(minute2).is_eq() {
                                return Some(second1.cmp(second2));
                            }
                            return Some(minute1.cmp(minute2));
                        }
                        return Some(hour1.cmp(hour2));
                    }
                }
                if let SqlDataType::SQLNull = &self {
                    if let SqlDataType::SQLNull = other {
                        return Some(Ordering::Equal);
                    }
                }
                None
            }
        }

        impl Ord for SqlDataType {
            fn cmp(&self, other: &Self) -> Ordering {
                if let SqlDataType::SQLInteger(val1) = &self {
                    if let SqlDataType::SQLInteger(val2) = other {
                        return val1.cmp(val2);
                    }
                }
                /*
                if let SqlDataType::SQLFloat { integer_part: int1, fractional_part: frac1 } = &self {
                    if let SqlDataType::SQLFloat { integer_part: int2, fractional_part: frac2 } = other {
                        return if int1.cmp(int2).is_eq() {
                            frac1.cmp(frac2)
                        } else {
                            int1.cmp(int2)
                        };
                    }
                }
                 */
                if let SqlDataType::SQLBool(val1) = &self {
                    if let SqlDataType::SQLBool(val2) = other {
                        return val1.cmp(val2);
                    }
                }
                if let SqlDataType::SQLText(val1) = &self {
                    if let SqlDataType::SQLText(val2) = other {
                        return val1.cmp(val2);
                    }
                }
                if let SqlDataType::SQLDate {
                    day: day1,
                    month: month1,
                    year: year1,
                } = &self
                {
                    if let SqlDataType::SQLDate {
                        day: day2,
                        month: month2,
                        year: year2,
                    } = other
                    {
                        if year1.cmp(year2).is_eq() {
                            if month1.cmp(month2).is_eq() {
                                return day1.cmp(day2);
                            }
                            return month1.cmp(month2);
                        }
                        return year1.cmp(year2);
                    }
                }
                if let SqlDataType::SQLDateTime {
                    day: day1,
                    month: month1,
                    year: year1,
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } = &self
                {
                    if let SqlDataType::SQLDateTime {
                        day: day2,
                        month: month2,
                        year: year2,
                        hour: hour2,
                        minute: minute2,
                        second: second2,
                    } = other
                    {
                        if year1.cmp(year2).is_eq() {
                            if month1.cmp(month2).is_eq() {
                                if day1.cmp(day2).is_eq() {
                                    if hour1.cmp(hour2).is_eq() {
                                        if minute1.cmp(minute2).is_eq() {
                                            return second1.cmp(second2);
                                        }
                                        return minute1.cmp(minute2);
                                    }
                                    return hour1.cmp(hour2);
                                }
                                return day1.cmp(day2);
                            }
                            return month1.cmp(month2);
                        }
                        return year1.cmp(year2);
                    }
                }
                if let SqlDataType::SQLTime {
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } = &self
                {
                    if let SqlDataType::SQLTime {
                        hour: hour2,
                        minute: minute2,
                        second: second2,
                    } = other
                    {
                        if hour1.cmp(hour2).is_eq() {
                            if minute1.cmp(minute2).is_eq() {
                                return second1.cmp(second2);
                            }
                            return minute1.cmp(minute2);
                        }
                        return hour1.cmp(hour2);
                    }
                }
                if let SqlDataType::SQLNull = &self {
                    if let SqlDataType::SQLNull = other {
                        return Ordering::Equal;
                    }
                }
                panic!("{}", &format!("Fatal Error! You want to compare SqlData of different types which is not allowed. self: {}, other: {}", display_sql_data_type(self), display_sql_data_type(other)));
            }
        }
    }

    pub mod functions {
        use chrono::{Date, DateTime, Datelike, NaiveTime, Timelike, Utc};
        use std::cmp::min;
        use std::string::{String, ToString};
        use std::vec::Vec;

        use crate::sql_engine::sql_data_types::components::*;
        use crate::sql_engine::sql_database::components::SqlAttribute;

        pub fn date_obj_to_sql_date(date: Date<Utc>) -> SqlDataType {
            return SqlDataType::SQLDate {
                day: date.day() as u8,
                month: date.month() as u8,
                year: date.year() as u16,
            };
        }

        pub fn datetime_obj_to_sql_datetime(datetime: DateTime<Utc>) -> SqlDataType {
            return SqlDataType::SQLDateTime {
                day: datetime.day() as u8,
                month: datetime.month() as u8,
                year: datetime.year() as u16,
                hour: datetime.hour() as u8,
                minute: datetime.minute() as u8,
                second: datetime.second() as u8,
            };
        }

        pub fn time_obj_to_sql_time(time: NaiveTime) -> SqlDataType {
            return SqlDataType::SQLTime {
                hour: time.hour() as u8,
                minute: time.minute() as u8,
                second: time.second() as u8,
            };
        }

        pub fn create_sql_type_by_str(
            data: &str,
            sql_type: &SqlAbstractDataType,
        ) -> Result<SqlDataType, String> {
            return match sql_type {
                SqlAbstractDataType::AbstractSQLInteger => {
                    if data.len() == 0 {
                        return Ok(SqlDataType::SQLNull);
                    }
                    match data.parse::<i64>() {
                        Ok(parsed) => Ok(SqlDataType::SQLInteger(parsed)),
                        Err(error) => Result::Err(error.to_string()),
                    }
                }
                /*
                SqlAbstractDataType::AbstractSQLFloat => {
                    if data.len() == 0 {
                        return Ok(SqlDataType::SQLNull);
                    }
                    let mut parts = data.split(".");
                    let mut int1: i64;
                    let mut frac1: u64;
                    let current_part = parts.next().expect("There should be an integer part.");
                    match current_part.parse::<i64>() {
                        Ok(parsed) => {
                            int1 = parsed;
                        }
                        Err(error) => {
                            return Result::Err(error.to_string());
                        }
                    }
                    let current_part = parts.next().expect("There should be a fractional part.");
                    match current_part.parse::<u64>() {
                        Ok(parsed) => {
                            frac1 = parsed;
                        }
                        Err(error) => {
                            return Result::Err(error.to_string());
                        }
                    }
                    return Ok(SqlDataType::SQLFloat { integer_part: int1, fractional_part: frac1 });
                }
                 */
                SqlAbstractDataType::AbstractSQLBool => {
                    if data.len() == 0 {
                        return Ok(SqlDataType::SQLNull);
                    }
                    match data.parse::<u32>() {
                        Ok(parsed) => {
                            if parsed == 0 {
                                Ok(SqlDataType::SQLBool(false))
                            } else {
                                Ok(SqlDataType::SQLBool(true))
                            }
                        }
                        Err(error) => {
                            if data.to_uppercase().eq("TRUE") {
                                return Ok(SqlDataType::SQLBool(true));
                            } else if data.to_uppercase().eq("FALSE") {
                                return Ok(SqlDataType::SQLBool(false));
                            }
                            Result::Err(error.to_string())
                        }
                    }
                }
                SqlAbstractDataType::AbstractSQLText => Ok(SqlDataType::SQLText(data.to_string())),
                SqlAbstractDataType::AbstractSQLDate => {
                    if data.len() == 0 {
                        return Ok(SqlDataType::SQLNull);
                    }
                    let parts: Vec<&str> = data.split("/").collect();
                    if parts.len() != 3 {
                        return Result::Err("The number of date fields is not 3.".to_string());
                    }
                    let mut date: Vec<u16> = Vec::with_capacity(3);
                    for part in parts {
                        match part.parse::<u16>() {
                            Ok(parsed) => {
                                date.push(parsed);
                            }
                            Err(error) => {
                                return Result::Err(error.to_string());
                            }
                        }
                    }
                    Ok(SqlDataType::SQLDate {
                        day: date[1] as u8,
                        month: date[0] as u8,
                        year: date[2],
                    })
                }
                SqlAbstractDataType::AbstractSQLDateTime => {
                    if data.len() == 0 {
                        return Ok(SqlDataType::SQLNull);
                    }
                    let date_and_time: Vec<&str> = data.split(" ").collect();
                    if date_and_time.len() != 2 {
                        return Result::Err("There is no date or time.".to_string());
                    }
                    let mut date: Vec<u16> = Vec::with_capacity(3);
                    for part in date_and_time[0].split("/") {
                        match part.parse::<u16>() {
                            Ok(parsed) => {
                                date.push(parsed);
                            }
                            Err(error) => {
                                return Result::Err(error.to_string());
                            }
                        }
                    }
                    let mut time: Vec<u8> = Vec::with_capacity(3);
                    for part in date_and_time[1].split(":") {
                        match part.parse::<u8>() {
                            Ok(parsed) => {
                                time.push(parsed);
                            }
                            Err(error) => {
                                return Result::Err(error.to_string());
                            }
                        }
                    }
                    Ok(SqlDataType::SQLDateTime {
                        day: date[0] as u8,
                        month: date[1] as u8,
                        year: date[2],
                        hour: time[0],
                        minute: time[1],
                        second: time[2],
                    })
                }
                SqlAbstractDataType::AbstractSQLTime => {
                    if data.len() == 0 {
                        return Ok(SqlDataType::SQLNull);
                    }
                    let parts: Vec<&str> = data.split(":").collect();
                    if parts.len() != 3 {
                        return Result::Err("The number of time fields is not 3.".to_string());
                    }
                    let mut time: Vec<u8> = Vec::with_capacity(3);
                    for part in parts {
                        match part.parse::<u8>() {
                            Ok(parsed) => {
                                time.push(parsed);
                            }
                            Err(error) => {
                                return Result::Err(error.to_string());
                            }
                        }
                    }
                    Ok(SqlDataType::SQLTime {
                        hour: time[0],
                        minute: time[1],
                        second: time[2],
                    })
                }
                SqlAbstractDataType::AbstractSQLNull => Ok(SqlDataType::SQLNull),
            };
        }

        pub fn display_sql_data_type(data_type: &SqlDataType) -> String {
            let mut result: String = String::from("");
            match data_type {
                SqlDataType::SQLInteger(sql_integer) => {
                    result.push_str(&format!("{}", sql_integer));
                }
                SqlDataType::SQLNull => {
                    result.push_str("*Null*");
                }
                SqlDataType::SQLBool(val) => {
                    result.push_str(&format!("{}", val));
                }
                SqlDataType::SQLText(val) => result.push_str(&format!("{}", val)),
                /*
                SqlDataType::SQLFloat { integer_part: int1, fractional_part: frac1 } => {
                    result.push_str(&format!("{}{}", int1, frac1));
                }
                 */
                SqlDataType::SQLDate {
                    day: day1,
                    month: month1,
                    year: year1,
                } => {
                    result.push_str(&format!("{}-{}-{}", year1, month1, day1));
                }
                SqlDataType::SQLDateTime {
                    day: day1,
                    month: month1,
                    year: year1,
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } => {
                    result.push_str(&format!(
                        "{}-{}-{}/{}:{}:{}",
                        year1, month1, day1, hour1, minute1, second1
                    ));
                }
                SqlDataType::SQLTime {
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } => {
                    result.push_str(&format!("{}-{}-{}", hour1, minute1, second1));
                }
            }
            result
        }

        pub fn decompress_sql_data_type(
            data_type_compressed: &Vec<u8>,
            config: &SqlAttribute,
        ) -> SqlDataType {
            if data_type_compressed.len() == 0 {
                return SqlDataType::SQLNull;
            }
            match config.data_type() {
                SqlAbstractDataType::AbstractSQLInteger => {
                    assert_eq!(data_type_compressed.len(), 8);
                    let mut int_array = [0u8; 8];
                    for i in (0..8).rev() {
                        int_array[i] = data_type_compressed[i];
                    }
                    let int = i64::from_be_bytes(int_array);
                    SqlDataType::SQLInteger(int)
                }
                /*
                SqlAbstractDataType::AbstractSQLFloat => {
                    panic!("");
                }
                 */
                SqlAbstractDataType::AbstractSQLBool => {
                    assert_eq!(data_type_compressed.len(), 1);
                    return if *data_type_compressed.get(0).unwrap() == 0u8 {
                        SqlDataType::SQLBool(false)
                    } else {
                        SqlDataType::SQLBool(true)
                    };
                }
                SqlAbstractDataType::AbstractSQLText => {
                    let text = String::from_utf8(data_type_compressed.clone()).unwrap();
                    return SqlDataType::SQLText(text);
                }
                SqlAbstractDataType::AbstractSQLDate => {
                    assert_eq!(data_type_compressed.len(), 4);
                    let day1 = data_type_compressed[0];
                    let month1 = data_type_compressed[1];
                    let year1 =
                        u16::from_be_bytes([data_type_compressed[2], data_type_compressed[3]]);
                    SqlDataType::SQLDate {
                        day: day1,
                        month: month1,
                        year: year1,
                    }
                }
                SqlAbstractDataType::AbstractSQLDateTime => {
                    assert_eq!(data_type_compressed.len(), 7);
                    let day1 = data_type_compressed[0];
                    let month1 = data_type_compressed[1];
                    let year1 =
                        u16::from_be_bytes([data_type_compressed[2], data_type_compressed[3]]);
                    let hour1 = data_type_compressed[4];
                    let minute1 = data_type_compressed[5];
                    let second1 = data_type_compressed[6];
                    SqlDataType::SQLDateTime {
                        day: day1,
                        month: month1,
                        year: year1,
                        hour: hour1,
                        minute: minute1,
                        second: second1,
                    }
                }
                SqlAbstractDataType::AbstractSQLTime => {
                    let hour1 = data_type_compressed[0];
                    let minute1 = data_type_compressed[1];
                    let second1 = data_type_compressed[2];
                    SqlDataType::SQLTime {
                        hour: hour1,
                        minute: minute1,
                        second: second1,
                    }
                }
                SqlAbstractDataType::AbstractSQLNull => {
                    return SqlDataType::SQLNull;
                }
            }
        }

        pub fn compress_sql_data_type(
            data_type: &SqlDataType,
            lossy: bool,
            upper_range: bool,
        ) -> Vec<u8> {
            match data_type {
                SqlDataType::SQLInteger(sql_integer) => {
                    return sql_integer.to_be_bytes().to_vec();
                }
                SqlDataType::SQLNull => {
                    let null_vec: Vec<u8> = vec![];
                    return null_vec;
                }
                SqlDataType::SQLBool(val) => return if *val { vec![1u8; 1] } else { vec![0u8; 1] },
                SqlDataType::SQLText(val) => {
                    if val.len() == 0 {
                        return " ".as_bytes().to_vec();
                    }
                    if lossy {
                        let max = min(val.len(), 6);
                        let mut val = val[0..max].as_bytes().to_vec();
                        if upper_range {
                            let new = val.last().unwrap() + 1;
                            val[max - 1] = new;
                        }
                        return val;
                    } else {
                        val.as_bytes().to_vec()
                    }
                }
                /*
                SqlDataType::SQLFloat { integer_part: int1, fractional_part: frac1 } => {
                    panic!("");
                    // TODO
                }
                 */
                SqlDataType::SQLDate {
                    day: day1,
                    month: month1,
                    year: year1,
                } => {
                    let mut vec: Vec<u8> = Vec::new();
                    vec.push(*day1);
                    vec.push(*month1);
                    let mut year_bytes = year1.to_be_bytes().to_vec();
                    vec.append(&mut year_bytes);
                    assert_eq!(vec.len(), 4);
                    vec
                }
                SqlDataType::SQLDateTime {
                    day: day1,
                    month: month1,
                    year: year1,
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } => {
                    let mut vec: Vec<u8> = Vec::new();
                    vec.push(*day1);
                    vec.push(*month1);
                    let mut year_bytes = year1.to_be_bytes().to_vec();
                    vec.append(&mut year_bytes);
                    vec.push(*hour1);
                    vec.push(*minute1);
                    vec.push(*second1);
                    assert_eq!(vec.len(), 7);
                    vec
                }
                SqlDataType::SQLTime {
                    hour: hour1,
                    minute: minute1,
                    second: second1,
                } => {
                    let mut vec: Vec<u8> = Vec::new();
                    vec.push(*hour1);
                    vec.push(*minute1);
                    vec.push(*second1);
                    assert_eq!(vec.len(), 3);
                    vec
                }
            }
        }
    }
}

pub mod sql_query {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use sql_engine::sql_database::components::SqlTableRow;

    use crate::sql_engine::sql_data_types::components::SqlDataType;
    use crate::utils::Pair;

    pub struct QueryNewRow {
        table: u32,
        row: SqlTableRow,
    }

    impl QueryNewRow {
        pub fn new(table: u32, row: SqlTableRow) -> Self {
            QueryNewRow { table, row }
        }
        pub fn table(&self) -> u32 {
            self.table
        }
        pub fn destroy(self) -> (u32, SqlTableRow) {
            (self.table, self.row)
        }
        pub fn row(&self) -> &SqlTableRow {
            &self.row
        }
    }

    pub struct QueryNewValues {
        table: u32,
        attributes: HashMap<u32, SqlDataType>,
    }

    impl QueryNewValues {
        pub fn new(table: u32, attributes: HashMap<u32, SqlDataType>) -> Self {
            QueryNewValues { table, attributes }
        }
        pub fn table(&self) -> u32 {
            self.table
        }
        pub fn attributes(&self) -> &HashMap<u32, SqlDataType> {
            &self.attributes
        }
        pub fn set_table(&mut self, table: u32) {
            self.table = table;
        }
        pub fn set_attributes(&mut self, attributes: HashMap<u32, SqlDataType>) {
            self.attributes = attributes;
        }
    }

    pub struct QueryFilter {
        table: String,
        attributes: HashMap<u32, Pair<SqlDataType, CmpOperator>>,
    }

    impl QueryFilter {
        pub fn new(
            table: String,
            attributes: HashMap<u32, Pair<SqlDataType, CmpOperator>>,
        ) -> Self {
            QueryFilter { table, attributes }
        }
        pub fn table(&self) -> &String {
            &self.table
        }
        pub fn attributes(&self) -> &HashMap<u32, Pair<SqlDataType, CmpOperator>> {
            &self.attributes
        }
        pub fn set_table(&mut self, table: String) {
            self.table = table;
        }
        pub fn set_attributes(&mut self, attributes: HashMap<u32, Pair<SqlDataType, CmpOperator>>) {
            self.attributes = attributes;
        }
    }

    #[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
    pub enum CmpOperator {
        Equal,
        Less,
        Greater,
        LessEqual,
        GreaterEqual,
    }
}

pub mod sql_database {
    pub mod components {
        use serde::{Deserialize, Serialize};
        use std::string::{String, ToString};
        use std::vec::Vec;

        use logger::log_runtime;
        use query_state::ObTreeSlotContentFilter;
        use sql_engine::sql_query::{CmpOperator, QueryNewRow};
        use utils::Pair;

        use crate::sql_engine::sql_data_types::components::{SqlAbstractDataType, SqlDataType};
        use crate::sql_engine::sql_data_types::functions::display_sql_data_type;
        use crate::sql_engine::sql_query::{QueryFilter, QueryNewValues};

        #[derive(Serialize, Deserialize, Clone)]
        pub struct SqlDatabaseScheme {
            name: String,
            tables: Vec<SqlTableScheme>,
        }

        impl SqlDatabaseScheme {
            pub fn name(&self) -> &str {
                &self.name
            }
            pub fn tables(&self) -> &Vec<SqlTableScheme> {
                &self.tables
            }
            pub fn mut_tables(&mut self) -> &mut Vec<SqlTableScheme> {
                &mut self.tables
            }
            pub fn get_table_scheme(&self, name: &String) -> Option<&SqlTableScheme> {
                for table in self.tables() {
                    if table.name().eq(name) {
                        return Some(table);
                    }
                }
                return None;
            }
            pub fn get_table_scheme_by_str(&self, name: &str) -> Option<&SqlTableScheme> {
                for table in self.tables() {
                    if table.name().eq(name) {
                        return Some(table);
                    }
                }
                return None;
            }
            pub fn add_table(&mut self, table: SqlTableScheme) {
                log_runtime(
                    &format!(
                        "The table {} with {} attributes has been added to the database {}.",
                        table.name(),
                        table.attributes().len(),
                        self.name()
                    ),
                    false,
                );
                self.tables.push(table);
            }
            pub fn new(name: String, tables: Vec<SqlTableScheme>) -> Self {
                SqlDatabaseScheme { name, tables }
            }
            pub fn new_empty(name: String) -> Self {
                log_runtime(
                    &format!("An empty database with the name {} has been created.", name),
                    false,
                );
                SqlDatabaseScheme {
                    name,
                    tables: Vec::new(),
                }
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct SqlTableScheme {
            name: String,
            primary_key: u32,
            attributes: Vec<SqlAttribute>,
        }

        impl SqlTableScheme {
            pub fn name(&self) -> &String {
                &self.name
            }
            pub fn attributes(&self) -> &Vec<SqlAttribute> {
                &self.attributes
            }
            pub fn get_attribute(&self, index: usize) -> Option<&SqlAttribute> {
                return self.attributes().get(index);
            }
            pub fn new(name: String, primary_key: u32, attributes: Vec<SqlAttribute>) -> Self {
                SqlTableScheme {
                    name,
                    primary_key,
                    attributes,
                }
            }
            pub fn primary_key(&self) -> u32 {
                self.primary_key
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct SqlAttribute {
            name: String,
            data_type: SqlAbstractDataType,
            unique: bool,
        }

        impl SqlAttribute {
            pub fn name(&self) -> &str {
                &self.name
            }
            pub fn data_type(&self) -> &SqlAbstractDataType {
                &self.data_type
            }
            pub fn new(name: String, data_type: SqlAbstractDataType, unique: bool) -> Self {
                SqlAttribute {
                    name,
                    data_type,
                    unique,
                }
            }
            pub fn unique(&self) -> bool {
                self.unique
            }
        }

        #[derive()]
        pub enum SqlDmlOperation {
            SELECT,
            UPDATE,
            DELETE,
            INSERT,
        }

        #[derive()]
        pub enum SqlQueryValues {
            QueryNewValues(QueryNewValues),
            QueryNewRow(QueryNewRow),
        }

        #[derive()]
        pub struct SqlDmlQuery {
            operator: SqlDmlOperation,
            values: Option<SqlQueryValues>,
            where_condition: Option<Vec<QueryFilter>>,
        }

        impl SqlDmlQuery {
            pub fn new(
                operator: SqlDmlOperation,
                values: Option<SqlQueryValues>,
                where_condition: Option<Vec<QueryFilter>>,
            ) -> Self {
                SqlDmlQuery {
                    operator,
                    values,
                    where_condition,
                }
            }
            pub fn new_empty(operator: SqlDmlOperation) -> Self {
                SqlDmlQuery {
                    operator,
                    values: None,
                    where_condition: Some(Vec::new()),
                }
            }
            pub fn new_full_empty(operator: SqlDmlOperation) -> Self {
                SqlDmlQuery {
                    operator,
                    values: None,
                    where_condition: None,
                }
            }
            pub fn operator(&self) -> &SqlDmlOperation {
                &self.operator
            }
            pub fn where_condition(&self) -> &Option<Vec<QueryFilter>> {
                &self.where_condition
            }
            pub fn mut_where_condition(&mut self) -> &mut Option<Vec<QueryFilter>> {
                &mut self.where_condition
            }
            pub fn set_operator(&mut self, operator: SqlDmlOperation) {
                self.operator = operator;
            }
            pub fn set_where_condition(&mut self, where_condition: Option<Vec<QueryFilter>>) {
                self.where_condition = where_condition;
            }
            pub fn values(&self) -> &Option<SqlQueryValues> {
                &self.values
            }
            pub fn mut_values(&mut self) -> &mut Option<SqlQueryValues> {
                &mut self.values
            }
            pub fn set_values(&mut self, values: Option<SqlQueryValues>) {
                self.values = values;
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct SqlTableRow {
            values: Vec<SqlDataType>,
        }

        impl SqlTableRow {
            pub fn new(values: Vec<SqlDataType>) -> Self {
                SqlTableRow { values }
            }
            pub fn values(&self) -> &Vec<SqlDataType> {
                &self.values
            }
            pub fn get_value(&self, index: usize) -> Option<&SqlDataType> {
                self.values.get(index)
            }
            pub fn mut_values(&mut self) -> &mut Vec<SqlDataType> {
                &mut self.values
            }
            pub fn display(&self) -> String {
                let mut result: String = String::from("");
                for val in self.values.iter() {
                    result.push_str(&display_sql_data_type(val));
                    result.push_str(" ");
                }
                result
            }
            pub fn byte_size(&self) -> usize {
                bincode::serialized_size(self).expect("") as usize
            }
            pub fn matches_ob_tree_filter(&self, filter: &ObTreeSlotContentFilter) -> bool {
                match filter {
                    ObTreeSlotContentFilter::ATTRIBUTES(attributes) => {
                        for (attribute_index, attribute_filter) in attributes {
                            let own_value = self.get_value(*attribute_index as usize).unwrap();
                            if !attribute_filter
                                .first()
                                .compare_with_operator(own_value, attribute_filter.second())
                            {
                                return false;
                            }
                        }
                        return true;
                    }
                    ObTreeSlotContentFilter::RIDS(_) => {
                        panic!("A RID filter does not work with a SqlTableRow.");
                    }
                }
            }
        }
    }
}
