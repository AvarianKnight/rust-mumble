use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use scc::Guard;

use crate::client::ClientArc;
use crate::error::DisconnectReason;
use crate::message::ClientMessage;
use crate::server::constants::ConcurrentHashMap;
use crate::state::ServerStateRef;
use crate::voice::{ClientBound, VoicePacket};

use super::{Handler, MumbleResult};

impl Handler for VoicePacket<ClientBound> {
    async fn handle(&self, state: &ServerStateRef, client: &ClientArc) -> MumbleResult {
        if client.is_muted() {
            return Ok(());
        }

        let VoicePacket::Audio { target, session_id, .. } = self else {
            return Ok(());
        };

        // Loopback is the only path that awaits; handle it before collecting.
        if *target == 31 {
            client.send_voice_packet(self.clone()).await?;
            return Ok(());
        }

        let mut recipients = collect_recipients(state, client, *target);
        // remove the calling client so we don't send their own audio back to them
        recipients.remove(session_id);

        for cl in recipients.values() {
            if cl.is_deaf() {
                continue;
            }
            if cl.publisher.try_send(ClientMessage::SendVoicePacket(self.clone())).is_err() {
                state.add_client_to_disconnect_queue(cl.session_id, DisconnectReason::ClientMSPCFull);
            }
        }

        Ok(())
    }
}

/// Collects everyone who should receive a voice packet for `target`.
///
/// This should hopefully not run into the previous dead locking issues since `iter`
/// doesn't look to do any locking (unlike iter_async and iter_sync)
fn collect_recipients(state: &ServerStateRef, client: &ClientArc, target: u8) -> HashMap<u32, ClientArc> {
    let mut out = HashMap::new();
    let guard = Guard::new();

    match target {
        // Channel
        0 => {
            let channel_id = client.channel_id.load(Ordering::Relaxed);
            if let Some(channel) = state.get_channel_by_channel_id(channel_id) {
                extend(&mut out, &channel.clients, &guard);
            }
        }
        // Voice target (whisper)
        1..=30 => {
            let Some(target) = client.get_target(target) else {
                return out;
            };

            for (session, _) in target.sessions.iter(&guard) {
                if let Some(c) = state.clients.peek_with(session, |_, c| Arc::clone(c)) {
                    out.insert(*session, c);
                }
            }

            for (channel_id, _) in target.channels.iter(&guard) {
                if let Some(channel) = state.get_channel_by_channel_id(*channel_id) {
                    extend(&mut out, &channel.listeners, &guard);
                    extend(&mut out, &channel.clients, &guard);
                }
            }
        }
        _ => tracing::error!("invalid voice target: {}", target),
    }

    out
}

fn extend(out: &mut HashMap<u32, ClientArc>, map: &ConcurrentHashMap<u32, ClientArc>, guard: &Guard) {
    out.extend(map.iter(guard).map(|(k, v)| (*k, Arc::clone(v))));
}
