use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use super::session::MockSession;

/// The scenario control plane — `GET`/`POST`/`DELETE /_frogs/scenario`.
/// Registered by `commands::test` only, merged at the absolute root
/// (outside `apiRoot` and every optional middleware layer, CORS included:
/// no CORS headers plus `axum::Json`'s content-type requirement is what
/// keeps a browser page on another origin from flipping the scenario).
/// `frogs run` never constructs this router at all.
pub fn router(session: Arc<MockSession>) -> Router {
    Router::new().route("/_frogs/scenario", get(read).post(set).delete(clear)).with_state(session)
}

#[derive(Deserialize)]
struct ScenarioBody {
    #[serde(default)]
    name: Option<String>,
}

fn current(session: &MockSession) -> Response {
    // No request headers passed on purpose — the control plane reports the
    // process-wide setting, never a per-request header override.
    let choice = session
        .current_scenario(&HeaderMap::new())
        .unwrap_or_else(|_| unreachable!("no header means no unknown-name error"));
    Json(serde_json::json!({
        "scenario": choice.name,
        "source": choice.source.label(),
        "known": session.known_scenarios(),
    }))
    .into_response()
}

async fn read(State(session): State<Arc<MockSession>>) -> Response {
    current(&session)
}

async fn set(State(session): State<Arc<MockSession>>, Json(body): Json<ScenarioBody>) -> Response {
    match session.set_override(body.name) {
        Ok(()) => current(&session),
        Err(message) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message }))).into_response(),
    }
}

async fn clear(State(session): State<Arc<MockSession>>) -> Response {
    let _ = session.set_override(None);
    current(&session)
}
