use serde::{Deserialize, Deserializer};

use super::query::StateToken;

/// Deserializes a present value as `Some`, rejecting an explicit JSON `null`.
/// Combined with `#[serde(default)]`, an absent member becomes `None`.
pub(crate) fn non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Like `non_null`, for a counter: rejects values above `i64::MAX`, the
/// published maximum.
pub(crate) fn non_null_counter<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value > i64::MAX as u64 {
        return Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Unsigned(value),
            &"an integer from 0 to 9223372036854775807",
        ));
    }
    Ok(Some(value))
}

/// Deserializes a single comma-separated query value into state tokens.
pub(crate) fn comma_list<'de, D>(deserializer: D) -> Result<Option<Vec<StateToken>>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    value
        .split(',')
        .map(|token| {
            StateToken::deserialize(serde::de::value::StrDeserializer::<D::Error>::new(token))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// A deserializer that accepts only a JSON object, for request types whose
/// derived deserializer would also accept other shapes such as an array.
pub(crate) struct ObjectOnly<D>(pub(crate) D);

impl<'de, D: Deserializer<'de>> Deserializer<'de> for ObjectOnly<D> {
    type Error = D::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.0.deserialize_map(visitor)
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_map(visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map
        enum identifier ignored_any
    }
}

/// Implements `Serialize` and `Deserialize` for request types declared with
/// `#[serde(remote = "Self")]`, deserializing only from a JSON object.
macro_rules! object_only {
    ($($ty:ty),* $(,)?) => {$(
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <$ty>::deserialize($crate::v1::types::serde_util::ObjectOnly(deserializer))
            }
        }

        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                <$ty>::serialize(self, serializer)
            }
        }
    )*};
}

pub(crate) use object_only;
