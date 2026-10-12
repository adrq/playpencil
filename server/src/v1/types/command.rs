use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::serde_util::non_null;

/// `{NAME: value}`.
#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(transparent)]
pub(crate) struct EnvWrite(pub(crate) BTreeMap<String, String>);

/// Names only.
#[derive(Debug, Default, Serialize, ToSchema)]
#[serde(transparent)]
pub(crate) struct EnvNames(pub(crate) Vec<String>);

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
pub(crate) struct CommandSpecWrite {
    /// Program and arguments.
    #[schema(min_items = 1)]
    pub(crate) command: Vec<String>,
    pub(crate) env: EnvWrite,
    pub(crate) cwd: String,
    #[schema(value_type = Option<i64>, nullable = false, minimum = 0, maximum = 4294967295_i64)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) uid: Option<u32>,
    #[schema(value_type = Option<i64>, nullable = false, minimum = 0, maximum = 4294967295_i64)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) gid: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommandSpecRead {
    #[schema(min_items = 1)]
    pub(crate) command: Vec<String>,
    pub(crate) env: EnvNames,
    pub(crate) cwd: String,
    #[schema(value_type = Option<i64>, nullable = false, minimum = 0, maximum = 4294967295_i64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) uid: Option<u32>,
    #[schema(value_type = Option<i64>, nullable = false, minimum = 0, maximum = 4294967295_i64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gid: Option<u32>,
}

super::serde_util::object_only!(CommandSpecWrite);
