use scc::HashMap;
use tracing::Instrument;

use crate::client::{ClientArc, WeakClient};
use crate::error::DisconnectReason;
use crate::message::ClientMessage;
use crate::server::constants::ConcurrentHashMap;
use crate::state::ServerStateRef;
use crate::voice::{ClientBound, VoicePacket};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Handler, MumbleResult};

// shield your eyes
impl Handler for VoicePacket<ClientBound> {
    async fn handle(&self, state: &ServerStateRef, client: &ClientArc) -> MumbleResult {
        let mute = client.is_muted();

        if mute {
            return Ok(());
        }

        if let VoicePacket::<ClientBound>::Audio { target, session_id, .. } = self {
            // copy the data into an arc so we can reuse the packet for each client

            // TODO: maybe make this static
            let listening_clients: ConcurrentHashMap<u32, WeakClient> = ConcurrentHashMap::new();

            match *target {
                // Channel
                0 => {
                    let channel_id = client.channel_id.load(Ordering::Relaxed);

                    if let Some(c) = state.get_channel_by_channel_id(channel_id).await
                        && let Some(channel) = c.upgrade()
                    {
                        let mut iter = channel.clients.first_entry_async().await;
                        while let Some(entry) = iter {
                            let session_id = entry.key();
                            let client = entry.get();
                            let _ = listening_clients.insert_async(*session_id, Arc::downgrade(client)).await;
                            iter = entry.next_async().await;
                        }
                    }
                }
                // Voice target (whisper)
                1..=30 => {
                    let target = client.get_target(*target);

                    if let Some(target) = target {
                        {
                            let mut iter = target.sessions.first_entry_async().await;
                            while let Some(entry) = iter {
                                let session = entry.key();
                                if let Some(client) = state.clients.get_async(session).await {
                                    let _ = listening_clients.insert_async(*session, Arc::downgrade(client.get())).await;
                                }
                                iter = entry.next_async().await;
                            }
                        }

                        {
                            let mut iter = target.channels.first_entry_async().await;
                            while let Some(entry) = iter {
                                let channel_id = entry.key();
                                if let Some(target_channel) = state.channels.get_async(channel_id).await {
                                    {
                                        let mut listener_iter = target_channel.get().listeners.first_entry_async().await;
                                        while let Some(listener_entry) = listener_iter {
                                            let session_id = listener_entry.key();
                                            let client = listener_entry.get();
                                            let _ = listening_clients.insert_async(*session_id, Arc::downgrade(client)).await;
                                            listener_iter = listener_entry.next_async().await;
                                        }
                                    }

                                    {
                                        let mut client_iter = target_channel.get().clients.first_entry_async().await;
                                        while let Some(client_entry) = client_iter {
                                            let session_id = client_entry.key();
                                            let client = client_entry.get();
                                            let _ = listening_clients.insert_async(*session_id, Arc::downgrade(client)).await;
                                            client_iter = client_entry.next_async().await;
                                        }
                                    }
                                }
                                iter = entry.next_async().await;
                            }
                        }
                    }
                }
                // Loopback
                31 => {
                    client.send_voice_packet(self.clone()).await?;

                    return Ok(());
                }
                _ => {
                    tracing::error!("invalid voice target: {}", *target);
                }
            }

            // remove the calling client from the session list so we don't have to branch here.
            listening_clients.remove_async(session_id).await;

            let mut iter = listening_clients.first_entry_async().await;
            while let Some(entry) = iter {
                let cl = entry.get();
                if let Some(cl) = cl.upgrade() {
                    if !cl.is_deaf() {
                        let _ = cl.publisher.try_send(ClientMessage::SendVoicePacket(self.clone())).map_err(|_e| {
                            state.add_client_to_disconnect_queue(cl.session_id, DisconnectReason::ClientMSPCFull);
                        });
                    }
                }
                iter = entry.next_async().await;
            }
        }

        Ok(())
    }
}
