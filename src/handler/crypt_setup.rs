use crate::client::ClientArc;
use crate::handler::Handler;
use crate::proto::mumble::CryptSetup;
use crate::state::ServerStateRef;

use super::MumbleResult;

impl Handler for CryptSetup {
    async fn handle(&self, _state: &ServerStateRef, client: &ClientArc) -> MumbleResult {
        if self.has_client_nonce() {
            // the nonce is client controlled, a bad length must not reach a panic (release builds abort)
            let nonce = self
                .client_nonce()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid client nonce length: {}", self.client_nonce().len()))?;
            client.crypt_state.lock().set_decrypt_nonce(&nonce);
            Ok(())
        } else {
            client.send_crypt_setup(false).await.map_err(anyhow::Error::new)
        }
    }
}
