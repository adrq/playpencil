use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::serde_util::comma_list;

/// `null`: no committed state yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateToken {
    Null,
    Stopped,
    Running,
    Destroyed,
}

#[derive(Debug, Deserialize, Serialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ListSandboxesQuery {
    /// Comma-separated.
    #[param(style = Form, explode = false, value_type = Option<Vec<StateToken>>, inline, min_items = 1)]
    #[serde(default, deserialize_with = "comma_list")]
    pub(crate) state: Option<Vec<StateToken>>,
    /// Exact match.
    pub(crate) name: Option<String>,
    /// Exact match.
    pub(crate) namespace: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct EventsQuery {
    pub(crate) since: Option<String>,
}
