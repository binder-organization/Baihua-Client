use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
// rand 0.10 移除了 rngs::OsRng：操作系统随机源改名为 rngs::SysRng，且只实现可失败的 TryCryptoRng，
// 须经 rand_core::UnwrapErr 包装成 dalek 系列要求的不可失败 CryptoRng（取熵失败即 panic，与原 OsRng 行为一致）；
// 填充字节的 fill_bytes 由 rand::Rng trait 提供（原 rand::RngCore）
use rand::Rng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// 加密模块错误类型
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("base64 数据解码失败: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("加密或解密失败")]
    CipherFailed,
    #[error("公钥数据无效")]
    InvalidKeyData,
    #[error("消息内容不是有效的 UTF-8 文本")]
    InvalidText,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// 登录凭据本地确定性加密：固定密钥 + 固定零值 nonce，同一密码恒定产生同一密文。
/// 注册与登录使用相同变换，服务端对密文做 bcrypt 存储与校验，明文密码不再经过网络。
/// 注意：密文本身即等效凭据，且此密钥内嵌于客户端，属于防窃听级别的凭据变换。
pub fn encrypt_login_password(password: &str) -> String {
    let key_bytes: [u8; 32] = Sha256::digest(b"baihua-client-login-credential-key-v1").into();
    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let nonce = XNonce::from([0u8; 24]);
    let ciphertext = cipher
        .encrypt(&nonce, password.as_bytes())
        .expect("固定密钥材料的确定性加密不会失败");
    // 保持与端到端消息一致的“nonce 前缀 + 密文”结构约定
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    BASE64.encode(blob)
}

/// 生成用户身份密钥对（Ed25519），每次程序启动生成一次，不持久化
pub fn generate_identity_key() -> SigningKey {
    SigningKey::generate(&mut UnwrapErr(SysRng))
}

/// 生成本次会话的 X25519 临时密钥对
pub fn generate_ephemeral_secret() -> EphemeralSecret {
    EphemeralSecret::random_from_rng(&mut UnwrapErr(SysRng))
}

/// 临时公钥编码为 base64
pub fn encode_x25519_public(secret: &EphemeralSecret) -> String {
    BASE64.encode(PublicKey::from(secret).as_bytes())
}

/// 身份公钥编码为 base64
pub fn encode_identity_public(identity: &SigningKey) -> String {
    BASE64.encode(identity.verifying_key().to_bytes())
}

/// 以身份私钥对临时公钥字节签名（服务端文档约定的签名对象）
pub fn sign_public_key(identity: &SigningKey, public_key_base64: &str) -> Result<String> {
    let public_bytes = BASE64.decode(public_key_base64)?;
    Ok(BASE64.encode(identity.sign(&public_bytes).to_bytes()))
}

/// 校验对端握手签名：对端身份公钥是否签署了其临时公钥
pub fn verify_handshake_signature(
    identity_key_base64: &str,
    public_key_base64: &str,
    signature_base64: &str,
) -> bool {
    let verified = (|| -> Result<()> {
        let identity_bytes = BASE64.decode(identity_key_base64)?;
        let identity_array: [u8; 32] = identity_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyData)?;
        let verifying_key =
            VerifyingKey::from_bytes(&identity_array).map_err(|_| CryptoError::InvalidKeyData)?;
        let signature_bytes = BASE64.decode(signature_base64)?;
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyData)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
        let public_bytes = BASE64.decode(public_key_base64)?;
        verifying_key
            .verify(&public_bytes, &signature)
            .map_err(|_| CryptoError::CipherFailed)
    })();
    verified.is_ok()
}

/// 消耗己方临时私钥与对端临时公钥完成 Diffie-Hellman，
/// 再经 HKDF-SHA256 派生出 32 字节对称会话密钥
pub fn derive_shared_key(
    ephemeral_secret: EphemeralSecret,
    peer_public_key_base64: &str,
) -> Result<[u8; 32]> {
    let peer_bytes = BASE64.decode(peer_public_key_base64)?;
    let peer_array: [u8; 32] = peer_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let shared_secret = ephemeral_secret.diffie_hellman(&PublicKey::from(peer_array));
    let mut output_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
        .expand(b"baihua-e2e-session-key-v1", &mut output_key)
        .map_err(|_| CryptoError::CipherFailed)?;
    Ok(output_key)
}

/// 加密聊天消息：24 字节随机 nonce + XChaCha20Poly1305 密文，拼接后 base64
pub fn encrypt_message(key: &[u8; 32], plaintext: &str) -> Result<String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    UnwrapErr(SysRng).fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::CipherFailed)?;
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(blob))
}

/// 解密聊天消息，为 encrypt_message 的逆过程
pub fn decrypt_message(key: &[u8; 32], blob_base64: &str) -> Result<String> {
    let blob = BASE64.decode(blob_base64)?;
    // nonce(24) + Poly1305 标签(16) 为最小长度
    if blob.len() < 40 {
        return Err(CryptoError::CipherFailed);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| CryptoError::CipherFailed)?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::CipherFailed)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidText)
}

/// 静态存储加解密密钥：由固定盐派生，供登录令牌写入配置文件时加密，防止明文落盘
fn at_rest_key() -> [u8; 32] {
    Sha256::digest(b"baihua-client-at-rest-key-v1").into()
}

/// 加密敏感配置（登录令牌）用于静态存储，解密经 decrypt_at_rest
pub fn encrypt_at_rest(plaintext: &str) -> String {
    encrypt_message(&at_rest_key(), plaintext).expect("加密静态配置不会失败")
}

/// 解密静态存储的敏感配置；数据损坏或密钥不符时返回 None
pub fn decrypt_at_rest(blob_base64: &str) -> Option<String> {
    decrypt_message(&at_rest_key(), blob_base64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_password_encryption_is_deterministic() {
        let first = encrypt_login_password("pass1234");
        let second = encrypt_login_password("pass1234");
        assert_eq!(first, second);
        assert_ne!(first, encrypt_login_password("different"));
    }

    #[test]
    fn message_round_trip() {
        let mut key = [0u8; 32];
        UnwrapErr(SysRng).fill_bytes(&mut key);
        let blob = encrypt_message(&key, "你好，Baihua！").unwrap();
        assert_eq!(decrypt_message(&key, &blob).unwrap(), "你好，Baihua！");
        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert!(decrypt_message(&wrong_key, &blob).is_err());
    }

    #[test]
    fn at_rest_round_trip() {
        let blob = encrypt_at_rest("some-jwt-token-value");
        assert_eq!(
            decrypt_at_rest(&blob),
            Some("some-jwt-token-value".to_string())
        );
        assert_ne!(blob, "some-jwt-token-value");
        assert!(decrypt_at_rest("not-valid-base64-blob").is_none());
        assert!(decrypt_at_rest("AA==").is_none());
    }

    #[test]
    fn handshake_signature_round_trip() {
        let identity = generate_identity_key();
        let ephemeral = generate_ephemeral_secret();
        let public_key_base64 = encode_x25519_public(&ephemeral);
        let signature = sign_public_key(&identity, &public_key_base64).unwrap();
        let identity_base64 = encode_identity_public(&identity);
        assert!(verify_handshake_signature(
            &identity_base64,
            &public_key_base64,
            &signature
        ));
        assert!(!verify_handshake_signature(
            &identity_base64,
            &encode_x25519_public(&generate_ephemeral_secret()),
            &signature
        ));
    }

    #[test]
    fn shared_key_agreement() {
        let alice_secret = generate_ephemeral_secret();
        let alice_public = encode_x25519_public(&alice_secret);
        let bob_secret = generate_ephemeral_secret();
        let bob_public = encode_x25519_public(&bob_secret);
        let alice_key = derive_shared_key(alice_secret, &bob_public).unwrap();
        let bob_key = derive_shared_key(bob_secret, &alice_public).unwrap();
        assert_eq!(alice_key, bob_key);
    }
}
