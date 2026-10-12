use serde::Serialize;
use utoipa::ToSchema;

use super::sandbox::Reason;

/// Untyped; for unparseable requests.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Problem {
    #[schema(inline, nullable = false)]
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub(crate) problem_type: Option<AboutBlankType>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
}

#[expect(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) enum AboutBlankType {
    #[serde(rename = "about:blank")]
    AboutBlank,
}

#[cfg_attr(not(test), expect(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) enum NotFoundType {
    #[serde(rename = "https://playpencil.dev/problems/not_found")]
    NotFound,
}

#[cfg_attr(not(test), expect(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) enum InvalidInputType {
    #[serde(rename = "https://playpencil.dev/problems/invalid_input")]
    InvalidInput,
}

#[cfg_attr(not(test), expect(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) enum ConflictType {
    #[serde(rename = "https://playpencil.dev/problems/conflict")]
    Conflict,
}

#[cfg_attr(not(test), expect(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) enum InternalType {
    #[serde(rename = "https://playpencil.dev/problems/internal")]
    Internal,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct NotFoundProblem {
    #[schema(inline)]
    #[serde(rename = "type")]
    pub(crate) problem_type: NotFoundType,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct InvalidInputProblem {
    #[schema(inline)]
    #[serde(rename = "type")]
    pub(crate) problem_type: InvalidInputType,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    /// Offending field path.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) field: Option<String>,
    /// When `config.backend` is missing or unknown.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) available_backends: Option<Vec<String>>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) entries: Option<Vec<String>>,
    /// Why `entries` were rejected.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CreateConflictProblem {
    #[schema(inline)]
    #[serde(rename = "type")]
    pub(crate) problem_type: ConflictType,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    pub(crate) existing_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PatchConflictProblem {
    #[schema(inline)]
    #[serde(rename = "type")]
    pub(crate) problem_type: ConflictType,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    /// On a version mismatch.
    #[schema(nullable = false, minimum = 0, maximum = 9223372036854775807_i64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) current_version: Option<u64>,
    /// `null` before the first commit.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub(crate) current_state: Option<Option<String>>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) required_state: Option<String>,
    /// When `clear_reason` was missing.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<Reason>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ProcessConflictProblem {
    #[schema(inline)]
    #[serde(rename = "type")]
    pub(crate) problem_type: ConflictType,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    /// Says when the sandbox isn't ready.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    /// `null` before the first commit.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub(crate) current_state: Option<Option<String>>,
}

/// Policy not applied; the previous one is still enforced.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct InternalProblem {
    #[schema(inline)]
    #[serde(rename = "type")]
    pub(crate) problem_type: InternalType,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
}
