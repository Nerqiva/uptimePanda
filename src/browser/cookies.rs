//! Cookie-at-rest encryption: AES-256-GCM with a scrypt-derived key.
//!
//! Scheme (mirrors the previous project, adapted for the app's needs):
//!
//! - **Passphrase normalization**: the caller-supplied passphrase (the
//!   `ENCRYPTION_KEY` from the environment, received by these functions as a
//!   plain `&str` — this module never reads env itself) is normalized with
//!   `str::trim` before use. This is deliberately shallow: trailing newline /
//!   surrounding spaces from `.env` files are common and harmless to strip,
//!   while case folding or Unicode normalization would silently change the
//!   key. No other transformation is applied; document this for operators.
//! - **Salt**: the 32-byte SHA-256 digest of the app constant
//!   `b"uptimepanda-cookie-salt-v1"`. The salt is *not random* and is *not*
//!   stored per row: it exists so the derived key stays stable across
//!   restarts while the passphrase is unchanged, and so every build of the
//!   app derives the same key from the same passphrase. Per-message entropy
//!   comes from the random 12-byte nonce, never from the salt. Compromise of
//!   the salt does not weaken the KDF (scrypt's salt input only needs to be
//!   fixed-size and not adversarially chosen to collide with another KDF).
//! - **Key**: `scrypt(passphrase_normalized, salt, N = 2^14, r = 8, p = 1,
//!   output = 32 bytes)`.
//! - **Envelope**: `enc:v1:` + base64(nonce(12) ‖ ciphertext ‖ tag(16)) with
//!   the standard base64 alphabet. Anything not starting with `enc:v1:` is
//!   rejected with [`CookieCryptoError::InvalidEnvelope`]; decryption failure
//!   (bad base64, short buffer, authentication-tag mismatch) yields
//!   [`CookieCryptoError::DecryptionFailed`]. Neither error carries detail
//!   about *why* it failed — no padding/tag oracle.
//!
//! Plaintext format: the decrypted bytes are a UTF-8 JSON document —
//! one [`StoredDomainJar`] per `(profile_id, domain)` row in the `cookies`
//! table. Session cookies carry `expires = -1.0`; dated cookies carry seconds
//! since the Unix epoch as `f64`.
//!
//! Secrets policy: plaintext cookie bytes, cookie names and values, and the
//! passphrase are never logged. `Debug` for [`StoredCookie`] and
//! [`StoredDomainJar`] prints `[redacted]` instead of names/values.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use scrypt::Params as ScryptParams;
use sha2::{Digest, Sha256};

/// Every encrypted blob starts with this prefix. Blobs without it are
/// rejected outright — there is no plaintext fallback path.
pub const COOKIE_ENVELOPE_PREFIX: &str = "enc:v1:";

/// App constant hashed to produce the (stable, public) KDF salt.
const APP_SALT_CONSTANT: &[u8] = b"uptimepanda-cookie-salt-v1";
/// scrypt cost parameter as log2(N): N = 2^14 = 16384.
const SCRYPT_LOG_N: u8 = 14;
/// scrypt block size.
const SCRYPT_R: u32 = 8;
/// scrypt parallelism.
const SCRYPT_P: u32 = 1;
/// Derived key length (AES-256).
const KEY_LEN: usize = 32;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length.
const TAG_LEN: usize = 16;

/// Errors from cookie crypto. Deliberately carries no attacker-usable
/// detail: distinguishing *why* a blob failed would be a decryption oracle.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CookieCryptoError {
    /// The blob does not start with `enc:v1:`, is not valid base64, or is
    /// too short to hold nonce ‖ tag.
    #[error("invalid cookie envelope")]
    InvalidEnvelope,
    /// The blob was well-formed but could not be decrypted/authenticated
    /// (wrong passphrase, corrupted or tampered ciphertext).
    #[error("cookie decryption failed")]
    DecryptionFailed,
}

/// The KDF salt: SHA-256 of the app constant. Computed fresh each call
/// (32 bytes, negligible cost) so nothing derived is stored anywhere.
fn app_salt() -> [u8; 32] {
    Sha256::digest(APP_SALT_CONSTANT).into()
}

/// Normalize a passphrase before key derivation. See module docs.
fn normalize_passphrase(passphrase: &str) -> &str {
    passphrase.trim()
}

/// Derive the 32-byte AES-256-GCM key for `passphrase`.
fn derive_key(passphrase: &str) -> [u8; KEY_LEN] {
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .expect("scrypt parameters are compile-time valid");
    let salt = app_salt();
    let normalized = normalize_passphrase(passphrase);
    let mut key = [0u8; KEY_LEN];
    scrypt::scrypt(normalized.as_bytes(), &salt, &params, &mut key)
        .expect("scrypt output length is fixed and valid");
    key
}

/// Encrypt `plaintext` and return the `enc:v1:` envelope string.
///
/// A fresh random 12-byte nonce is used per call; never reuse nonces.
pub fn encrypt_cookie_blob(passphrase: &str, plaintext: &[u8]) -> String {
    let key = derive_key(passphrase);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("key length is fixed at 32 bytes");
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from(nonce_bytes);
    // aes-gcm appends the 16-byte authentication tag to the ciphertext.
    let ct_with_tag = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption cannot fail for in-memory buffers");
    let mut payload = Vec::with_capacity(NONCE_LEN + ct_with_tag.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ct_with_tag);
    format!("{COOKIE_ENVELOPE_PREFIX}{}", BASE64.encode(payload))
}

/// Decrypt an `enc:v1:` envelope. Rejects anything else with
/// [`CookieCryptoError::InvalidEnvelope`]; authentication failure yields
/// [`CookieCryptoError::DecryptionFailed`].
pub fn decrypt_cookie_blob(passphrase: &str, blob: &str) -> Result<Vec<u8>, CookieCryptoError> {
    let body = blob
        .strip_prefix(COOKIE_ENVELOPE_PREFIX)
        .ok_or(CookieCryptoError::InvalidEnvelope)?;
    let payload = BASE64
        .decode(body)
        .map_err(|_| CookieCryptoError::InvalidEnvelope)?;
    // nonce ‖ tag, with zero or more bytes of ciphertext in between
    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(CookieCryptoError::InvalidEnvelope);
    }
    let (nonce_bytes, ct_with_tag) = payload.split_at(NONCE_LEN);
    let key = derive_key(passphrase);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("key length is fixed at 32 bytes");
    cipher
        .decrypt(
            &Nonce::try_from(nonce_bytes).map_err(|_| CookieCryptoError::InvalidEnvelope)?,
            ct_with_tag,
        )
        .map_err(|_| CookieCryptoError::DecryptionFailed)
}

/// One cookie as stored inside an encrypted domain jar.
///
/// `expires` is seconds since the Unix epoch as `f64` (matching the CDP
/// `Cookie.expires` shape); `-1.0` marks a session cookie.
///
/// `Debug` redacts `name` and `value`.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    /// `Strict` | `Lax` | `None`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    /// Seconds since epoch, or `-1.0` for a session cookie.
    pub expires: f64,
}

impl std::fmt::Debug for StoredCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCookie")
            .field("name", &"[redacted]")
            .field("value", &"[redacted]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("expires", &self.expires)
            .finish()
    }
}

/// The plaintext document inside one encrypted `cookies` row.
///
/// `Debug` redacts the entire cookie vector — no names or values are shown.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredDomainJar {
    pub domain: String,
    pub cookies: Vec<StoredCookie>,
}

impl std::fmt::Debug for StoredDomainJar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredDomainJar")
            .field("domain", &self.domain)
            .field(
                "cookies",
                &format_args!("[{} cookie(s), redacted]", self.cookies.len()),
            )
            .finish()
    }
}

/// Serialize a domain jar to its plaintext JSON bytes (the input to
/// [`encrypt_cookie_blob`]).
pub fn encode_domain_jar(jar: &StoredDomainJar) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(jar)
}

/// Parse the plaintext bytes of a decrypted jar back into a
/// [`StoredDomainJar`].
pub fn decode_domain_jar(bytes: &[u8]) -> Result<StoredDomainJar, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct-horse-battery-staple";

    fn sample_jar() -> StoredDomainJar {
        StoredDomainJar {
            domain: ".example.com".to_string(),
            cookies: vec![
                StoredCookie {
                    name: "session".to_string(),
                    value: "supersecret-token".to_string(),
                    domain: ".example.com".to_string(),
                    path: "/".to_string(),
                    secure: true,
                    http_only: true,
                    same_site: Some("Lax".to_string()),
                    expires: -1.0,
                },
                StoredCookie {
                    name: "prefs".to_string(),
                    value: "lang=de".to_string(),
                    domain: ".example.com".to_string(),
                    path: "/".to_string(),
                    secure: false,
                    http_only: false,
                    same_site: None,
                    expires: 4_000_000_000.0,
                },
            ],
        }
    }

    #[test]
    fn roundtrip_restores_exact_bytes() {
        let plain = b"hello cookie jar";
        let blob = encrypt_cookie_blob(PASS, plain);
        assert!(blob.starts_with(COOKIE_ENVELOPE_PREFIX));
        let out = decrypt_cookie_blob(PASS, &blob).expect("decrypt");
        assert_eq!(out, plain);
    }

    #[test]
    fn roundtrip_domain_jar_json() {
        let jar = sample_jar();
        let plain = encode_domain_jar(&jar).expect("encode");
        let blob = encrypt_cookie_blob(PASS, &plain);
        let bytes = decrypt_cookie_blob(PASS, &blob).expect("decrypt");
        let back = decode_domain_jar(&bytes).expect("decode");
        assert_eq!(back, jar);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let plain = b"attack at dawn";
        let blob = encrypt_cookie_blob(PASS, plain);
        // Flip one byte inside the base64 payload (not the prefix).
        let body = &blob[COOKIE_ENVELOPE_PREFIX.len()..];
        let mut raw = BASE64.decode(body).expect("valid base64");
        raw[6] ^= 0x01;
        let tampered = format!("{COOKIE_ENVELOPE_PREFIX}{}", BASE64.encode(raw));
        let err = decrypt_cookie_blob(PASS, &tampered).expect_err("tamper must fail");
        assert_eq!(err, CookieCryptoError::DecryptionFailed);
    }

    #[test]
    fn tampered_tag_fails_authentication() {
        let plain = b"attack at dusk";
        let blob = encrypt_cookie_blob(PASS, plain);
        let mut raw = BASE64
            .decode(&blob[COOKIE_ENVELOPE_PREFIX.len()..])
            .expect("base64");
        let last = raw.len() - 1;
        raw[last] ^= 0x80;
        let tampered = format!("{COOKIE_ENVELOPE_PREFIX}{}", BASE64.encode(raw));
        assert_eq!(
            decrypt_cookie_blob(PASS, &tampered),
            Err(CookieCryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = encrypt_cookie_blob(PASS, b"top secret");
        assert_eq!(
            decrypt_cookie_blob("wrong-passphrase-123", &blob),
            Err(CookieCryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn missing_prefix_is_invalid_envelope() {
        assert_eq!(
            decrypt_cookie_blob(PASS, "aGVsbG8gd29ybGQh"),
            Err(CookieCryptoError::InvalidEnvelope)
        );
        assert_eq!(
            decrypt_cookie_blob(PASS, ""),
            Err(CookieCryptoError::InvalidEnvelope)
        );
    }

    #[test]
    fn invalid_base64_is_invalid_envelope() {
        assert_eq!(
            decrypt_cookie_blob(PASS, "enc:v1:!!!not-base64!!!"),
            Err(CookieCryptoError::InvalidEnvelope)
        );
    }

    #[test]
    fn truncated_blob_is_invalid_envelope() {
        let short = format!("{COOKIE_ENVELOPE_PREFIX}{}", BASE64.encode([0u8; 8]));
        assert_eq!(
            decrypt_cookie_blob(PASS, &short),
            Err(CookieCryptoError::InvalidEnvelope)
        );
    }

    #[test]
    fn two_encryptions_of_same_plaintext_differ() {
        let a = encrypt_cookie_blob(PASS, b"same");
        let b = encrypt_cookie_blob(PASS, b"same");
        assert_ne!(a, b, "nonce reuse would be catastrophic");
    }

    #[test]
    fn passphrase_is_trimmed_for_key_derivation() {
        // A trailing newline from .env must not change the derived key.
        assert_eq!(
            decrypt_cookie_blob(&format!("{PASS}\n"), &encrypt_cookie_blob(PASS, b"x")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn debug_never_prints_names_or_values() {
        let jar = sample_jar();
        let dbg = format!("{jar:?}");
        assert!(!dbg.contains("supersecret-token"), "value leaked: {dbg}");
        assert!(!dbg.contains("session"), "name leaked: {dbg}");
        assert!(dbg.contains("[redacted]") || dbg.contains("redacted"));
        let dbg = format!("{:?}", jar.cookies[0]);
        assert!(!dbg.contains("supersecret-token"));
    }

    #[test]
    fn envelope_contains_no_plaintext() {
        let blob = encrypt_cookie_blob(PASS, b"supersecret-token");
        assert!(!blob.contains("supersecret-token"));
        assert!(blob.starts_with(COOKIE_ENVELOPE_PREFIX));
    }
}
