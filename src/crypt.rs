use crate::error::DecryptError;
use crate::proto::mumble::CryptSetup;
use crate::voice::{VoicePacket, VoicePacketDst, decode_voice_packet, encode_voice_packet};
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Block};
use bytes::BytesMut;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{Duration, Instant};

lazy_static! {
    static ref SYSTEM_RANDOM: SystemRandom = SystemRandom::new();
}

const KEY_SIZE: usize = 16;
const BLOCK_SIZE: usize = std::mem::size_of::<u128>();

/// The minimum amount of time between crypt resets, this doubles every time a reset doesn't result
/// in a good packet up to `MAX_RESET_COOLDOWN`
const BASE_RESET_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_RESET_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct CryptState {
    pub key: [u8; KEY_SIZE],
    // internally as native endianness, externally as little endian and during ocb_* as big endian
    encrypt_nonce: u128,
    decrypt_nonce: u128,
    decrypt_history: [u8; 0x100],
    aes: Aes128,

    pub good: u32,
    pub late: u32,
    pub lost: u32,
    pub resync: u32,
    pub last_good: Instant,
    last_reset: Option<Instant>,
    // the amount of resets we've done without getting a good packet in between
    failed_resets: u32,

    // Remote -> client
    pub remote_late: u32,
    pub remote_good: u32,
    pub remote_lost: u32,
    pub remote_resync: u32,
}

impl Default for CryptState {
    fn default() -> Self {
        let mut key = [0u8; KEY_SIZE];
        SYSTEM_RANDOM.fill(&mut key).expect("Failed to generate random key");

        Self {
            aes: Aes128::new(&key.into()),
            key,
            encrypt_nonce: 0,
            decrypt_nonce: 1 << 127,
            decrypt_history: [0; 0x100],

            good: 0,
            late: 0,
            lost: 0,
            resync: 0,
            last_good: Instant::now(),
            last_reset: None,
            failed_resets: 0,

            remote_late: 0,
            remote_good: 0,
            remote_lost: 0,
            remote_resync: 0,
        }
    }
}

impl CryptState {
    pub fn reset(&mut self) {
        self.encrypt_nonce = 0;
        self.decrypt_nonce = 1 << 127;
        self.decrypt_history = [0; 0x100];
        self.good = 0;
        self.late = 0;
        self.lost = 0;
        self.resync = 0;
        self.last_good = Instant::now();
    }

    /// Checks if we're allowed to reset the crypt state yet, and if we are marks the reset as
    /// started so concurrent callers won't also reset it.
    ///
    /// This prevents us from constantly sending crypt resets to clients that can't use UDP, or
    /// are currently in a bad network state.
    pub fn try_start_reset(&mut self) -> bool {
        let now = Instant::now();

        if let Some(last_reset) = self.last_reset {
            let cooldown = BASE_RESET_COOLDOWN
                .saturating_mul(1 << self.failed_resets.min(4))
                .min(MAX_RESET_COOLDOWN);

            if now.duration_since(last_reset) < cooldown {
                return false;
            }
        }

        self.last_reset = Some(now);
        self.failed_resets = self.failed_resets.saturating_add(1);

        true
    }

    /// Returns the nonce used for encrypting.
    pub fn get_encrypt_nonce(&self) -> [u8; BLOCK_SIZE] {
        self.encrypt_nonce.to_le_bytes()
    }

    /// Returns the nonce used for decrypting.
    pub fn get_decrypt_nonce(&self) -> [u8; BLOCK_SIZE] {
        self.decrypt_nonce.to_le_bytes()
    }

    pub fn set_decrypt_nonce(&mut self, nonce: &[u8; BLOCK_SIZE]) {
        self.decrypt_nonce = u128::from_le_bytes(*nonce);
        self.resync += 1;
    }

    pub fn get_crypt_setup(&self) -> CryptSetup {
        let mut crypt_setup = CryptSetup::new();

        crypt_setup.set_key(self.key.to_vec());
        crypt_setup.set_client_nonce(self.get_decrypt_nonce().to_vec());
        crypt_setup.set_server_nonce(self.get_encrypt_nonce().to_vec());

        crypt_setup
    }

    /// Encrypts an encoded voice packet and returns the resulting bytes.
    pub fn encrypt<EncodeDst: VoicePacketDst>(&mut self, packet: &VoicePacket<EncodeDst>, dst: &mut BytesMut) {
        self.encrypt_nonce = self.encrypt_nonce.wrapping_add(1);

        // Leave four bytes for header
        dst.resize(4, 0);
        let mut inner = dst.split_off(4);

        encode_voice_packet(packet, &mut inner);

        let tag = self.ocb_encrypt(inner.as_mut());
        dst.unsplit(inner);

        dst[0] = self.encrypt_nonce as u8;
        dst[1..4].copy_from_slice(&tag.to_be_bytes()[0..3]);
    }

    /// Decrypts a voice packet and (if successful) returns the `Result` of parsing the packet.
    pub fn decrypt<DecodeDst: VoicePacketDst>(&mut self, buf: &mut BytesMut) -> Result<VoicePacket<DecodeDst>, DecryptError> {
        if buf.len() < 4 {
            return Err(DecryptError::Eof);
        }
        let header = buf.split_to(4);
        let nonce_0 = header[0];

        // If we update our decrypt_nonce and the tag check fails or we've been processing late
        // packets, we need to revert it
        let saved_nonce = self.decrypt_nonce;
        let mut late = false; // will always restore nonce if this is the case
        let mut lost = 0; // for stats only

        if self.decrypt_nonce.wrapping_add(1) as u8 == nonce_0 {
            // in order
            self.decrypt_nonce = self.decrypt_nonce.wrapping_add(1);
        } else {
            // packet is late or repeated, or we lost a few packets in between
            let diff = nonce_0.wrapping_sub(self.decrypt_nonce as u8) as i8;
            self.decrypt_nonce = self.decrypt_nonce.wrapping_add(diff as u128);

            if diff > 0 {
                lost = i32::from(diff - 1); // lost a few packets in between this and the last one
            } else if diff > -30 {
                if self.decrypt_history[nonce_0 as usize] == (self.decrypt_nonce >> 8) as u8 {
                    self.decrypt_nonce = saved_nonce;

                    return Err(DecryptError::Repeat);
                }
                // just late
                late = true;
                lost = -1;
            } else {
                self.decrypt_nonce = saved_nonce;
                return Err(DecryptError::Late); // late by more than 30 packets
            }
        }

        let tag = self.ocb_decrypt(buf.as_mut());

        // we're not likely to upgrade our ring and i don't feel like trying to figure this out
        #[allow(deprecated)]
        if Ok(()) != ring::constant_time::verify_slices_are_equal(&header[1..4], &tag.to_be_bytes()[0..3]) {
            self.decrypt_nonce = saved_nonce;
            return Err(DecryptError::Mac);
        }

        self.decrypt_history[nonce_0 as usize] = (self.decrypt_nonce >> 8) as u8;
        self.good += 1;
        self.last_good = Instant::now();
        self.failed_resets = 0;

        if late {
            self.late += 1;
            self.decrypt_nonce = saved_nonce;
        }

        self.lost = (self.lost as i32 + lost) as u32;

        decode_voice_packet(buf)
    }

    /// Encrypt the provided buffer using AES-OCB, returning the tag.
    fn ocb_encrypt(&self, mut buf: &mut [u8]) -> u128 {
        let mut offset = self.aes_encrypt(self.encrypt_nonce.to_be());
        let mut checksum = 0u128;

        while buf.len() > BLOCK_SIZE {
            let (chunk, remainder) = buf.split_at_mut(BLOCK_SIZE);
            buf = remainder;
            let chunk: &mut [u8; BLOCK_SIZE] = chunk.try_into().expect("split_at works");

            offset = s2(offset);

            let plain = u128::from_be_bytes(*chunk);
            let encrypted = self.aes_encrypt(offset ^ plain) ^ offset;
            chunk.copy_from_slice(&encrypted.to_be_bytes());

            checksum ^= plain;
        }

        offset = s2(offset);

        let len = buf.len();
        assert!(len <= BLOCK_SIZE);
        let pad = self.aes_encrypt((len * 8) as u128 ^ offset);
        let mut block = pad.to_be_bytes();
        block[..len].copy_from_slice(buf);
        let plain = u128::from_be_bytes(block);
        let encrypted = pad ^ plain;
        buf.copy_from_slice(&encrypted.to_be_bytes()[..len]);

        checksum ^= plain;

        self.aes_encrypt(offset ^ s2(offset) ^ checksum)
    }

    /// Decrypt the provided buffer using AES-OCB, returning the tag.
    /// **Make sure to verify that the tag matches!**
    fn ocb_decrypt(&self, mut buf: &mut [u8]) -> u128 {
        let mut offset = self.aes_encrypt(self.decrypt_nonce.to_be());
        let mut checksum = 0u128;

        while buf.len() > BLOCK_SIZE {
            let (chunk, remainder) = buf.split_at_mut(BLOCK_SIZE);
            buf = remainder;
            let chunk: &mut [u8; BLOCK_SIZE] = chunk.try_into().expect("split_at works");

            offset = s2(offset);

            let encrypted = u128::from_be_bytes(*chunk);
            let plain = self.aes_decrypt(offset ^ encrypted) ^ offset;
            chunk.copy_from_slice(&plain.to_be_bytes());

            checksum ^= plain;
        }

        offset = s2(offset);

        let len = buf.len();
        assert!(len <= BLOCK_SIZE);
        let pad = self.aes_encrypt((len * 8) as u128 ^ offset);
        let mut block = [0; BLOCK_SIZE];
        block[..len].copy_from_slice(buf);
        let plain = u128::from_be_bytes(block) ^ pad;
        buf.copy_from_slice(&plain.to_be_bytes()[..len]);

        checksum ^= plain;

        self.aes_encrypt(offset ^ s2(offset) ^ checksum)
    }

    /// AES-128 encryption primitive.
    fn aes_encrypt(&self, data: u128) -> u128 {
        let mut block = Block::from(data.to_be_bytes());
        self.aes.encrypt_block(&mut block);

        u128::from_be_bytes(block.into())
    }

    /// AES-128 decryption primitive.
    fn aes_decrypt(&self, data: u128) -> u128 {
        let mut block = Block::from(data.to_be_bytes());
        self.aes.decrypt_block(&mut block);

        u128::from_be_bytes(block.into())
    }
}

#[inline]
fn s2(block: u128) -> u128 {
    let rot = block.rotate_left(1);
    let carry = rot & 1;
    rot ^ (carry * 0x86)
}

#[cfg(test)]
mod tests {
    use super::*;

    // vectors from draft-krovetz-ocb-00, same as mumble's TestCrypt::testvectors (FiveM's client uses this OCB2 too)
    fn test_state() -> CryptState {
        let raw: [u8; BLOCK_SIZE] = std::array::from_fn(|i| i as u8);
        let mut cs = CryptState::default();
        cs.key = raw;
        cs.aes = Aes128::new(&raw.into());
        cs.encrypt_nonce = u128::from_le_bytes(raw);
        cs.decrypt_nonce = u128::from_le_bytes(raw);
        cs
    }

    #[test]
    fn ocb2_test_vectors() {
        let cs = test_state();

        let blank_tag = cs.ocb_encrypt(&mut []);
        assert_eq!(blank_tag.to_be_bytes(), [0xBF, 0x31, 0x08, 0x13, 0x07, 0x73, 0xAD, 0x5E, 0xC7, 0x0E, 0xC6, 0x9E, 0x78, 0x75, 0xA7, 0xB0]);

        let source: [u8; 40] = std::array::from_fn(|i| i as u8);
        let mut buf = source;
        let tag = cs.ocb_encrypt(&mut buf);
        assert_eq!(tag.to_be_bytes(), [0x9D, 0xB0, 0xCD, 0xF8, 0x80, 0xF7, 0x3E, 0x3E, 0x10, 0xD4, 0xEB, 0x32, 0x17, 0x76, 0x66, 0x88]);
        assert_eq!(
            buf,
            [
                0xF7, 0x5D, 0x6B, 0xC8, 0xB4, 0xDC, 0x8D, 0x66, 0xB8, 0x36, 0xA2, 0xB0, 0x8B, 0x32, 0xA6, 0x36, 0x9F, 0x1C, 0xD3, 0xC5,
                0x22, 0x8D, 0x79, 0xFD, 0x6C, 0x26, 0x7F, 0x5F, 0x6A, 0xA7, 0xB2, 0x31, 0xC7, 0xDF, 0xB9, 0xD5, 0x99, 0x51, 0xAE, 0x9C,
            ]
        );

        assert_eq!(cs.ocb_decrypt(&mut buf), tag);
        assert_eq!(buf, source);
    }
}
