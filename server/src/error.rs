use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
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
    StartFailed {
        sandbox_id: String,
        source: BackendError,
    },
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
            Self::StartFailed { sandbox_id, source } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "start_failed",
                Some(source.to_string()),
                Some(sandbox_id),
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
