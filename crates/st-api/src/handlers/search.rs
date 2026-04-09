//! Full-text search endpoint.
//!
//! `GET /v1/search?q=...&limit=...&offset=...`

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use st_common::error::StError;
use st_common::types::Permission;
use st_index::SearchQuery;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

/// Maximum allowed offset for search pagination.
/// Deep offsets are expensive; use cursor-based pagination instead.
const MAX_SEARCH_OFFSET: u32 = 10_000;

/// Query parameters for the search endpoint.
#[derive(Debug, Deserialize)]
pub struct SearchQueryParams {
    /// The search query string. Required and must not be empty.
    pub q: String,
    /// Maximum results per page (default 20, max 100).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Offset for pagination (default 0).
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    20
}

/// Full-text search over forensic events.
///
/// `GET /v1/search?q=auth.login&limit=20&offset=0`
///
/// Returns paginated results with total count.
pub async fn search(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<SearchQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    if params.q.trim().is_empty() {
        return Err(ApiError::from(StError::Validation(
            "search query must not be empty".to_string(),
        )));
    }

    if params.offset > MAX_SEARCH_OFFSET {
        return Err(ApiError::from(StError::Validation(
            "offset too large, use cursor-based pagination for deep results".to_string(),
        )));
    }

    let query = SearchQuery {
        query: params.q,
        limit: params.limit,
        offset: params.offset,
    };

    let result = state
        .index
        .search(&query)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(result))
}
