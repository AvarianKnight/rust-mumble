use std::sync::Arc;

use scc::Guard;

use crate::client::ClientArc;
use crate::handler::Handler;
use crate::proto::mumble::UserState;
use crate::state::ServerStateRef;

use super::MumbleResult;

impl Handler for UserState {
    async fn handle(&self, state: &ServerStateRef, client: &ClientArc) -> MumbleResult {
        let session_id = { client.session_id };

        if self.session() != session_id {
            return Ok(());
        }

        client.update(self);

        if self.has_channel_id() {
            state.set_client_channel(client, self.channel_id()).await?;
        }

        for channel_id in &self.listening_channel_add {
            let guard = Guard::new();
            if let Some(channel) = state.channels.peek(channel_id, &guard) {
                // if this errors it means our client is already in it, we can just ignore.
                let _ = channel.listeners.insert_sync(session_id, Arc::clone(client));
            }
        }

        for channel_id in &self.listening_channel_remove {
            let guard = Guard::new();
            if let Some(channel) = state.channels.peek(channel_id, &guard) {
                channel.listeners.remove_sync(&session_id);
            }
        }

        Ok(())
    }
}
