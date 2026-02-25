//! Axum REST API handlers.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db;
use crate::events::EventRecord;

#[derive(Clone)]
pub struct ApiState {
    pub pool: SqlitePool,
}

// ─────────────────────────────────────────────────────────
// Response shapes
// ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct EventsResponse {
    pub project_id: String,
    pub count: usize,
    pub events: Vec<EventRecord>,
}

#[derive(Serialize)]
pub struct AllEventsResponse {
    pub count: usize,
    pub events: Vec<EventRecord>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Deserialize)]
pub struct VoteRequest {
    pub oracle: String,
    pub proof_hash: String,
}

#[derive(Deserialize)]
pub struct ThresholdRequest {
    pub threshold: u32,
}

#[derive(Serialize)]
pub struct VoteResponse {
    pub accepted: bool,
    pub message: String,
}

// ─────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────

/// `GET /health`
pub async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// `GET /projects/:id/events`
///
/// Returns all indexed events for the given project identifier.
pub async fn get_project_events(
    State(state): State<Arc<ApiState>>,
    Path(project_id): Path<String>,
) -> impl IntoResponse {
    match db::get_events_for_project(&state.pool, &project_id).await {
        Ok(events) => {
            let count = events.len();
            (
                StatusCode::OK,
                Json(serde_json::json!(EventsResponse {
                    project_id,
                    count,
                    events,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: e.to_string()
            })),
        )
            .into_response(),
    }
}

/// `GET /events`
///
/// Returns all indexed events across all projects.
pub async fn get_all_events(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    match db::get_all_events(&state.pool).await {
        Ok(events) => {
            let count = events.len();
            (
                StatusCode::OK,
                Json(serde_json::json!(AllEventsResponse { count, events })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: e.to_string()
            })),
        )
            .into_response(),
    }
}

/// `POST /admin/quorum`
///
/// Updates the global quorum threshold.
pub async fn set_quorum_threshold(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<ThresholdRequest>,
) -> impl IntoResponse {
    match db::set_quorum_threshold(&state.pool, payload.threshold).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "updated" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: e.to_string()
            })),
        )
            .into_response(),
    }
}

/// `POST /projects/:id/vote`
///
/// Submits an oracle vote for a project.
pub async fn submit_vote(
    State(state): State<Arc<ApiState>>,
    Path(project_id): Path<String>,
    Json(payload): Json<VoteRequest>,
) -> impl IntoResponse {
    match db::record_vote(
        &state.pool,
        &project_id,
        &payload.oracle,
        &payload.proof_hash,
    )
    .await
    {
        Ok(accepted) => {
            let (status, message) = if accepted {
                (StatusCode::CREATED, "Vote recorded")
            } else {
                (StatusCode::OK, "Duplicate vote ignored")
            };
            (
                status,
                Json(VoteResponse {
                    accepted,
                    message: message.to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: e.to_string()
            })),
        )
            .into_response(),
    }
}

/// `GET /projects/:id/quorum`
///
/// Returns current quorum status for a project.
pub async fn get_project_quorum(
    State(state): State<Arc<ApiState>>,
    Path(project_id): Path<String>,
) -> impl IntoResponse {
    match db::get_quorum_status(&state.pool, &project_id).await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: e.to_string()
            })),
        )
            .into_response(),
    }
}
