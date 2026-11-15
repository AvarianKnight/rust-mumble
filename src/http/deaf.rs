use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use super::AppStateRef;

#[derive(Serialize, Deserialize)]
pub struct Deaf {
    deaf: bool,
    user: String,
}

pub async fn post_deaf(State(state): State<AppStateRef>, Json(deaf): Json<Deaf>) -> StatusCode {
    let client = state.server.get_client_by_name(deaf.user.as_str());

    match client {
        Some(client) => {
            client.set_deaf(deaf.deaf);

            StatusCode::OK
        }
        None => StatusCode::NOT_FOUND,
    }
}

pub async fn get_deaf(Path(username): Path<String>, State(state): State<AppStateRef>) -> Result<Json<Deaf>, StatusCode> {
    if let Some(client) = state.server.get_client_by_name(username.as_str()) {
        let deaf = Deaf {
            deaf: client.is_deaf(),
            user: username,
        };

        return Ok(Json(deaf));
    }

    Err(StatusCode::NOT_FOUND)
}
