use std::sync::Arc;

use crate::client::ClientArc;
use crate::handler::Handler;
use crate::proto::mumble::UserState;
use crate::state::ServerStateRef;

use super::MumbleResult;

impl Handler for UserState {
    async fn handle(&self, state: &ServerStateRef, client: &ClientArc) -> MumbleResult {
        let session_id = { client.session_id };

        if self.get_session() != session_id {
            return Ok(());
        }

        client.update(self);

        if self.has_channel_id() {
            state.set_client_channel(client, self.get_channel_id()).await?;
        }

        for channel_id in self.get_listening_channel_add() {
            if let Some(channel) = state.channels.peek_with(channel_id, |_, v| Arc::clone(v)) {
                // if this errors we areadly listen to them, we use if let err here so that we still get .await warnings incase of future refactors
                if let Err(_e) = channel.listeners.insert_async(session_id, Arc::clone(client)).await {}
            }
        }

        for channel_id in self.get_listening_channel_remove() {
            if let Some(channel) = state.channels.peek_with(channel_id, |_, v| Arc::clone(v)) {
                channel.listeners.remove_async(&session_id).await;
            }
        }

        Ok(())
    }
}
