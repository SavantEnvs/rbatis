#![no_main]
use libfuzzer_sys::fuzz_target;
use rbdc_pg::type_info::{PgType, PgTypeInfo};
use rbdc_pg::types::decode::Decode;
use rbdc_pg::value::{PgValue, PgValueFormat};
use rbs::Value;

// Same code path as the original fork's `decode` harness (rbdc-pg PgValue ->
// rbs::Value decode), updated to rbdc-pg 4.9's API: PgType::try_from_oid is now
// pub(crate), so the type selector indexes the public PgType unit variants
// directly (covering every built-in decoder in Value::decode).
const PG_TYPES: &[PgType] = &[
    PgType::Bool,
    PgType::Bytea,
    PgType::Char,
    PgType::Name,
    PgType::Int8,
    PgType::Int2,
    PgType::Int4,
    PgType::Text,
    PgType::Oid,
    PgType::Json,
    PgType::JsonArray,
    PgType::Point,
    PgType::Lseg,
    PgType::Path,
    PgType::Box,
    PgType::Polygon,
    PgType::Line,
    PgType::LineArray,
    PgType::Cidr,
    PgType::CidrArray,
    PgType::Float4,
    PgType::Float8,
    PgType::Unknown,
    PgType::Circle,
    PgType::CircleArray,
    PgType::Macaddr8,
    PgType::Macaddr8Array,
    PgType::Macaddr,
    PgType::Inet,
    PgType::BoolArray,
    PgType::ByteaArray,
    PgType::CharArray,
    PgType::NameArray,
    PgType::Int2Array,
    PgType::Int4Array,
    PgType::TextArray,
    PgType::BpcharArray,
    PgType::VarcharArray,
    PgType::Int8Array,
    PgType::PointArray,
    PgType::LsegArray,
    PgType::PathArray,
    PgType::BoxArray,
    PgType::Float4Array,
    PgType::Float8Array,
    PgType::PolygonArray,
    PgType::OidArray,
    PgType::MacaddrArray,
    PgType::InetArray,
    PgType::Bpchar,
    PgType::Varchar,
    PgType::Date,
    PgType::Time,
    PgType::Timestamp,
    PgType::TimestampArray,
    PgType::DateArray,
    PgType::TimeArray,
    PgType::Timestamptz,
    PgType::TimestamptzArray,
    PgType::Interval,
    PgType::IntervalArray,
    PgType::NumericArray,
    PgType::Timetz,
    PgType::TimetzArray,
    PgType::Bit,
    PgType::BitArray,
    PgType::Varbit,
    PgType::VarbitArray,
    PgType::Numeric,
    PgType::Record,
    PgType::RecordArray,
    PgType::Uuid,
    PgType::UuidArray,
    PgType::Jsonb,
    PgType::JsonbArray,
    PgType::Int4Range,
    PgType::Int4RangeArray,
    PgType::NumRange,
    PgType::NumRangeArray,
    PgType::TsRange,
    PgType::TsRangeArray,
    PgType::TstzRange,
    PgType::TstzRangeArray,
    PgType::DateRange,
    PgType::DateRangeArray,
    PgType::Int8Range,
    PgType::Int8RangeArray,
    PgType::Jsonpath,
    PgType::JsonpathArray,
    PgType::Money,
    PgType::MoneyArray,
    PgType::Hstore,
    PgType::HstoreArray,
    PgType::Tsvector,
    PgType::Tsquery,
    PgType::Void,
];

fuzz_target!(|data: (u8, u32, &[u8])| {
    let (value_format, type_sel, data) = data;

    // unpack a value format
    let value_format = match value_format {
        0 => PgValueFormat::Binary,
        1 => PgValueFormat::Text,
        _ => return,
    };

    // unpack a type info
    let pg_type = PG_TYPES[(type_sel as usize) % PG_TYPES.len()].clone();
    let type_info = PgTypeInfo(pg_type);

    let mut element_len = data.len() as i32;
    if element_len == 0 {
        element_len = -1;
    }
    let mut sized_data = element_len.to_be_bytes().to_vec();
    sized_data.extend_from_slice(data);

    let value = PgValue::get(&mut sized_data.as_slice(), value_format, type_info, None);
    let _ = Value::decode(value.as_ref());
});
