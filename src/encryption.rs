use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as base64_engine;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use hkdf::Hkdf;
use rand::Rng;
use rand::rng;
use sha2::Sha256;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SIGNATURE_SIZE: usize = 64;
const HKDF_SALT: &[u8] = b"baihua-encrypted-chat-v1";
const HKDF_INFO: &[u8] = b"baihua-e2e-session-key";

pub fn generate_identity_keypair() -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let mut private_bytes = [0_u8; KEY_SIZE];
    rng().fill_bytes(&mut private_bytes);
    let signing_key = SigningKey::from_bytes(&private_bytes);
    let public_key = signing_key.verifying_key().to_bytes();
    (private_bytes, public_key)
}

pub fn generate_ephemeral_keypair() -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let mut private_bytes = [0_u8; KEY_SIZE];
    rng().fill_bytes(&mut private_bytes);
    let static_secret = x25519_dalek::StaticSecret::from(private_bytes);
    let public_key = x25519_dalek::PublicKey::from(&static_secret).to_bytes();
    (private_bytes, public_key)
}

pub fn sign_public_key(identity_private: &[u8], public_key: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let signing_key = SigningKey::from_bytes(unwrap_array::<KEY_SIZE>(identity_private));
    signing_key.sign(public_key).to_bytes()
}

pub fn verify_public_key(identity_public: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    let verifying_key =
        match ed25519_dalek::VerifyingKey::from_bytes(unwrap_array::<KEY_SIZE>(identity_public)) {
            Ok(key) => key,
            Err(_) => return false,
        };
    let signature_bytes = match <[u8; SIGNATURE_SIZE]>::try_from(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    verifying_key
        .verify_strict(public_key, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

pub fn derive_shared_secret(private_key: &[u8], peer_public_key: &[u8]) -> [u8; KEY_SIZE] {
    let static_secret = x25519_dalek::StaticSecret::from(*unwrap_array::<KEY_SIZE>(private_key));
    let peer_public = x25519_dalek::PublicKey::from(*unwrap_array::<KEY_SIZE>(peer_public_key));
    static_secret.diffie_hellman(&peer_public).to_bytes()
}

pub fn derive_session_key(shared_secret: &[u8]) -> [u8; KEY_SIZE] {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut output = [0_u8; KEY_SIZE];
    hkdf.expand(HKDF_INFO, &mut output)
        .expect("HKDF expansion cannot fail for a valid output length");
    output
}

pub fn encrypt_message(key: &[u8], plaintext: &str) -> Result<String, String> {
    let key = Key::try_from(unwrap_array::<KEY_SIZE>(key).as_slice())
        .map_err(|_| "Invalid key length.".to_string())?;
    let cipher = ChaCha20Poly1305::new(&key);
    let mut nonce_bytes = [0_u8; NONCE_SIZE];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| "Invalid nonce length.".to_string())?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "Message encryption failed.".to_string())?;
    let mut payload = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    Ok(base64_engine.encode(payload))
}

pub fn decrypt_message(key: &[u8], encoded: &str) -> Result<String, String> {
    let payload = base64_engine
        .decode(encoded)
        .map_err(|_| "Invalid base64 ciphertext.".to_string())?;
    if payload.len() < NONCE_SIZE {
        return Err("Ciphertext too short.".to_string());
    }
    let key = Key::try_from(unwrap_array::<KEY_SIZE>(key).as_slice())
        .map_err(|_| "Invalid key length.".to_string())?;
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce =
        Nonce::try_from(&payload[..NONCE_SIZE]).map_err(|_| "Invalid nonce length.".to_string())?;
    let plaintext = cipher
        .decrypt(&nonce, &payload[NONCE_SIZE..])
        .map_err(|_| "Message decryption failed.".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "Decrypted data is not valid UTF-8.".to_string())
}

fn unwrap_array<const N: usize>(bytes: &[u8]) -> &[u8; N] {
    <&[u8; N]>::try_from(bytes).expect("Unexpected key length")
}
