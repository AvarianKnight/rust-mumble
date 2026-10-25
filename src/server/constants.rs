/// TODO: Add these to a server.toml file so its easier to configure
/// The amount of players the server can support
pub const MAX_CLIENTS: usize = 4096;

/// the bandwidth (in bits) that the client can use
/// This mimics FiveM's current maximum
pub const MAX_BANDWIDTH_IN_BITS: u32 = 144_000;

/// The largest TCP message payload we accept, the length prefix is client controlled so this
/// bounds the allocation made before reading the body (same limit as murmur)
pub const MAX_MESSAGE_SIZE: u32 = 8 * 1024 * 1024;

// pub const MAX_BANDWIDTH_IN_BYTES: usize = MAX_BANDWIDTH_IN_BITS as usize / 8;

// So we can easily swap out the hash map if/when the need arises
pub type ConcurrentHashMap<K, V> = scc::HashIndex<K, V>;
