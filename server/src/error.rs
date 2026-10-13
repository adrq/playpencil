use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Query};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use playpencil_core::backend::BackendError;

/// JSON body extractor that routes deserialization failures (malformed JSON,
/// missing required fields) through `ApiError` so clients always receive the
/// standard `ErrorResponse` shape instead of Axum's default rejection body.
pub(crate) struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|rejection| ApiError::Validation(rejection.body_text()))?;
        Ok(ValidatedJson(value))
    }
}

/// Query-string extractor that routes deserialization failures (missing or
/// malformed query params) through `ApiError`, mirroring [`ValidatedJson`] so
/// query errors carry the same status and JSON shape as the rest of the API.
pub(crate) struct ValidatedQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ValidatedQuery<T>
where
    Query<T>: FromRequestParts<S, Rejection = QueryRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(|rejection| ApiError::Validation(rejection.body_text()))?;
        Ok(ValidatedQuery(value))
    }
}

#[derive(Serialize)]
pub(crate) struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

pub(crate) enum ApiError {
    Backend(BackendError),
    Validation(String),
    /// A valid but unsupported request option (`background:true` on the command
    /// route). Returned only after the sandbox lookup succeeds.
    NotImplemented(String),
    StatusQueryFailed {
        sandbox_id: String,
        source: BackendError,
    },
}

impl From<BackendError> for ApiError {
    fn from(e: BackendError) -> Self {
        Self::Backend(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, detail, sandbox_id) = match self {
            Self::Backend(BackendError::NotFound) => {
                (StatusCode::NOT_FOUND, "not_found", None, None)
            }
            Self::Backend(BackendError::InvalidState) => {
                (StatusCode::CONFLICT, "invalid_state", None, None)
            }
            Self::Backend(BackendError::InvalidInput(msg)) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                Some(msg),
                None,
            ),
            Self::Backend(BackendError::Internal(msg)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                Some(msg),
                None,
            ),
            Self::Validation(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                Some(msg),
                None,
            ),
            Self::NotImplemented(msg) => (
                StatusCode::NOT_IMPLEMENTED,
                "not_implemented",
                Some(msg),
                None,
            ),
            Self::StatusQueryFailed { sandbox_id, source } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "status_query_failed",
                Some(source.to_string()),
                Some(sandbox_id),
            ),
        };
        (
            status,
            Json(ErrorResponse {
                error: error.into(),
                detail,
                sandbox_id,
            }),
        )
            .into_response()
    }
}
