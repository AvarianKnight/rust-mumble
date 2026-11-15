use crate::error::{DisconnectReason, MumbleError};
use crate::state::{ServerState, ServerStateRef};
use scc::Guard;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

pub async fn handle_server_tick(state: ServerStateRef) {
    loop {
        tracing::trace!("Running client clean loop");

        match clean_run(&state).await {
            Ok(_) => (),
            Err(e) => {
                tracing::error!("error in clean loop: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn clean_run(state: &ServerState) -> Result<(), MumbleError> {
    // first reason recorded wins, so queued disconnects take priority over ones found by the scan
    let mut clients_to_remove: HashMap<u32, DisconnectReason> = HashMap::new();
    let mut clients_to_reset_crypt = Vec::new();

    {
        let mut iter = state.disconnect_queue.begin_sync();
        while let Some(client_data) = iter {
            clients_to_remove.entry(*client_data.key()).or_insert(*client_data.get());
            iter = client_data.remove_and_sync();
        }
    }

    {
        let guard = Guard::new();
        let now = Instant::now();

        for (_, client) in state.clients.iter(&guard) {
            // if we lost our publisher then we should just remove the client, we won't be able to handle anything in this state.
            if client.publisher.is_closed() {
                clients_to_remove
                    .entry(client.session_id)
                    .or_insert(DisconnectReason::LostReceivingChannel);
                continue;
            }

            let since_last_udp = now.duration_since(client.last_udp_ping.load());

            if since_last_udp.as_secs() > 30 {
                // resetting this will cause the client to be removed from the "good socket" list
                clients_to_reset_crypt.push(Arc::clone(client));
                continue;
            }

            let since_last_tcp = now.duration_since(client.last_tcp_ping.load());

            // if we haven't gotten a tcp ping in 10 seconds (which means they missed 2 mumble
            // pings, or 10 for FiveM) we should be safe to drop the client early.
            if since_last_tcp.as_secs() > 10 {
                clients_to_remove
                    .entry(client.session_id)
                    .or_insert(DisconnectReason::ClientTimedOutTcp);
                continue;
            }

            let last_good = { client.crypt_state.lock().last_good };

            if now.duration_since(last_good).as_millis() > 8000 {
                clients_to_reset_crypt.push(Arc::clone(client))
            }
        }
    }

    for client in clients_to_reset_crypt {
        let session_id = client.session_id;
        match state.reset_client_crypt(&client).await {
            Ok(true) => tracing::info!("Requesting {} crypt be reset", client),
            Ok(false) => (),
            Err(e) => tracing::error!("failed to send crypt setup for {}: {:?}", session_id, e),
        }
    }

    for (session_id, reason) in clients_to_remove {
        state.disconnect(session_id, reason).await;
    }

    Ok(())
}
