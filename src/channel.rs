use crate::client::ClientArc;
use crate::proto::mumble::ChannelState;
use crate::server::constants::ConcurrentHashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};

pub type WeakChannelRef = Weak<Channel>;
pub type ChannelRef = Arc<Channel>;

pub struct Channel {
    pub id: u32,
    // pub parent_id: Option<u32>,
    pub name: String,
    // unused, the client will get this via ChannelState anyways
    // pub description: String,
    pub temporary: bool,
    pub listeners: ConcurrentHashMap<u32, ClientArc>,
    pub clients: ConcurrentHashMap<u32, ClientArc>,
    // session id of the client that owns this channel when temporary channels are limited to a
    // single user, `0` means there is no occupant (session ids start at 1)
    occupant: AtomicU32,
    channel_state_cache: Arc<ChannelState>,
}

impl Channel {
    pub fn new(id: u32, parent_id: Option<u32>, name: String, description: String, temporary: bool, max_users: Option<u32>) -> Arc<Self> {
        let mut state = ChannelState::new();

        state.set_channel_id(id);
        state.set_name(name.clone());
        state.set_description(description.clone());

        if let Some(parent_id) = parent_id {
            state.set_parent(parent_id);
        }

        state.set_temporary(temporary);
        state.set_position(id as i32);

        if let Some(max_users) = max_users {
            state.set_max_users(max_users);
        }

        Arc::new(Self {
            id,
            channel_state_cache: Arc::new(state),
            // parent_id,
            name,
            // description,
            temporary,
            clients: ConcurrentHashMap::new(),
            listeners: ConcurrentHashMap::new(),
            occupant: AtomicU32::new(0),
        })
    }

    pub fn get_channel_state(&self) -> Arc<ChannelState> {
        Arc::clone(&self.channel_state_cache)
    }

    // pub fn get_listeners(&self) -> &ConcurrentHashMap<u32, ClientArc> {
    //     &self.listeners
    // }

    /// Atomically claims this channel for `session_id`, returns `false` if another client already
    /// occupies it
    pub fn try_claim(&self, session_id: u32) -> bool {
        match self.occupant.compare_exchange(0, session_id, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => true,
            Err(current) => current == session_id,
        }
    }

    /// Releases the claim on this channel if `session_id` currently holds it
    pub fn release(&self, session_id: u32) {
        let _ = self.occupant.compare_exchange(session_id, 0, Ordering::AcqRel, Ordering::Relaxed);
    }

    pub fn get_clients(&self) -> &ConcurrentHashMap<u32, ClientArc> {
        &self.clients
    }
}
