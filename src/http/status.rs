use axum::Json;
use axum::extract::State;
use scc::Guard;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::AppStateRef;

#[derive(Serialize, Deserialize)]
pub struct MumbleClient {
    pub name: String,
    pub session_id: u32,
    pub channel: Option<String>,
    pub mute: bool,
    pub good: u32,
    pub late: u32,
    pub lost: u32,
    pub resync: u32,
    pub last_good_duration: u128,
    pub targets: Vec<MumbleTarget>,
}

#[derive(Serialize, Deserialize)]
pub struct MumbleTarget {
    // TODO: provide the target id in the iteration
    // pub target_id: u32,
    pub sessions: HashSet<u32>,
    pub channels: HashSet<u32>,
}

pub async fn get_status(State(state): State<AppStateRef>) -> Json<HashMap<u32, MumbleClient>> {
    Json(collect_status(&state))
}

fn collect_status(state: &AppStateRef) -> HashMap<u32, MumbleClient> {
    let guard = Guard::new();
    let now = Instant::now();

    state
        .server
        .clients
        .iter(&guard)
        .map(|(_, client)| {
            let channel_id = client.channel_id.load(Ordering::Relaxed);
            let channel = state.server.channels.peek_with(&channel_id, |_, c| c.name.clone());

            let (good, late, lost, resync, last_good) = {
                let crypt = client.crypt_state.lock();
                (crypt.good, crypt.late, crypt.lost, crypt.resync, crypt.last_good)
            };

            let targets = client
                .targets
                .iter()
                .map(|target| MumbleTarget {
                    sessions: target.sessions.iter(&guard).map(|(s, _)| *s).collect(),
                    channels: target.channels.iter(&guard).map(|(c, _)| *c).collect(),
                })
                .collect();

            let mumble_client = MumbleClient {
                name: client.get_name().as_ref().clone(),
                session_id: client.session_id,
                channel,
                mute: client.is_muted(),
                good,
                late,
                lost,
                resync,
                last_good_duration: now.duration_since(last_good).as_millis(),
                targets,
            };

            (client.session_id, mumble_client)
        })
        .collect()
}
