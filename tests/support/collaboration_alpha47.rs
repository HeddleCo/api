// Test-only ordered MessagePack values preserve UUID binary versus byte arrays.
use serde::{
    Deserialize, Serialize,
    de::{MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Text(String),
    Binary(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}
impl Value {
    pub fn get(&self, key: &str) -> &Self {
        if let Self::Map(m) = self {
            &m.iter().find(|(k, _)| k == key).expect("fixture key").1
        } else {
            panic!("expected map")
        }
    }
    pub fn set(&mut self, key: &str, value: Self) {
        if let Self::Map(m) = self {
            if let Some((_, v)) = m.iter_mut().find(|(k, _)| k == key) {
                *v = value;
            } else {
                m.push((key.into(), value));
            }
        } else {
            panic!("expected map")
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        if let Self::Array(a) = self {
            a.iter()
                .map(|v| match v {
                    Self::Uint(n) => *n as u8,
                    Self::Int(n) => *n as u8,
                    _ => panic!("expected byte"),
                })
                .collect()
        } else {
            panic!("expected array")
        }
    }
    pub fn byte_array(bytes: &[u8]) -> Self {
        Self::Array(bytes.iter().map(|b| Self::Uint(u64::from(*b))).collect())
    }
}
impl Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => s.serialize_unit(),
            Self::Bool(v) => s.serialize_bool(*v),
            Self::Int(v) => s.serialize_i64(*v),
            Self::Uint(v) => s.serialize_u64(*v),
            Self::Text(v) => s.serialize_str(v),
            Self::Binary(v) => s.serialize_bytes(v),
            Self::Array(v) => {
                let mut seq = s.serialize_seq(Some(v.len()))?;
                for i in v {
                    seq.serialize_element(i)?;
                }
                seq.end()
            }
            Self::Map(v) => {
                let mut map = s.serialize_map(Some(v.len()))?;
                for (k, v) in v {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("fixture MessagePack")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Int(v))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Uint(v))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
                Ok(Value::Text(v.into()))
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Value, E> {
                Ok(Value::Binary(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut v = vec![];
                while let Some(i) = a.next_element()? {
                    v.push(i);
                }
                Ok(Value::Array(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut v = vec![];
                while let Some(i) = a.next_entry()? {
                    v.push(i);
                }
                Ok(Value::Map(v))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn decode(bytes: &[u8]) -> Value {
    rmp_serde::from_slice(bytes).expect("fixture msgpack")
}
pub fn encode(value: &Value) -> Vec<u8> {
    rmp_serde::to_vec_named(value).expect("fixture msgpack")
}
pub fn hash(domain: &str, bytes: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&[0]);
    h.update(bytes);
    h.finalize().as_bytes().to_vec()
}
