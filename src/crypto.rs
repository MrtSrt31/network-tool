//! At-rest encryption primitives for the engagement store.
//!
//! The scheme:
//! - Operator passphrase + per-vault random salt → 256-bit key via Argon2id.
//! - Each encrypted payload is `nonce (12 B) || AES-256-GCM(ciphertext || tag)`.
//! - The master-key file `<data_dir>/.master` stores the Argon2 parameters,
//!   the salt, and a sentinel ciphertext so [`verify_passphrase`] can confirm
//!   a passphrase without needing to decrypt an engagement.
//!
//! Scope note (P0.8 iskelet): these primitives are shipped and tested, and
//! the CLI exposes `init` / `unlock` so operators can set up and verify a
//! vault, but [`store::save`] and [`store::load`] still write plaintext JSON
//! by default. Wiring the store to encrypt-on-save when a master key is
//! active is a P1 follow-up; the roadmap flags this split explicitly.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SENTINEL: &[u8] = b"ntool-master-key-sentinel-v1";
const MASTER_FILE_VERSION: u32 = 1;

/// A 32-byte Argon2id-derived key, zeroed on drop.
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub enum CryptoError {
    Io(io::Error),
    Argon2(String),
    Aead(String),
    MalformedFile(String),
    WrongPassphrase,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Io(e) => write!(f, "io: {e}"),
            CryptoError::Argon2(e) => write!(f, "argon2: {e}"),
            CryptoError::Aead(e) => write!(f, "aead: {e}"),
            CryptoError::MalformedFile(e) => write!(f, "master file is malformed: {e}"),
            CryptoError::WrongPassphrase => {
                write!(f, "wrong passphrase (sentinel decryption failed)")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        CryptoError::Io(e)
    }
}

/// Argon2id parameters stored next to the salt so a future upgrade can
/// migrate (increase cost) without losing existing vaults.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP-recommended minimum for Argon2id (2023): m=19 MiB, t=2, p=1.
    pub fn secure_default() -> Self {
        KdfParams {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }

    /// Faster parameters for tests only. Not safe for a real vault.
    #[cfg(test)]
    pub fn fast_test() -> Self {
        KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// On-disk layout of `.master`. Hex-encoded fields so the file stays
/// text-only and git-grep-friendly if someone peeks.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MasterFile {
    pub version: u32,
    pub kdf: KdfParams,
    pub salt_hex: String,
    pub sentinel_ciphertext_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, CryptoError> {
    if !s.len().is_multiple_of(2) {
        return Err(CryptoError::MalformedFile("odd-length hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CryptoError::MalformedFile(format!("hex decode: {e}")))
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|e| CryptoError::Argon2(format!("getrandom: {e}")))
}

/// Derive the master key from a passphrase and salt.
pub fn derive_key(
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<MasterKey, CryptoError> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(MasterKey(out))
}

/// Encrypt `plaintext` with the master key. Output: `nonce || ciphertext || tag`.
pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let n = Nonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|e| CryptoError::Aead(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt `nonce || ciphertext || tag`. A single flipped bit (tampering)
/// fails the GCM authentication tag and returns an error.
pub fn decrypt(key: &MasterKey, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::Aead("blob shorter than nonce".into()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: b"" })
        .map_err(|e| CryptoError::Aead(e.to_string()))
}

pub fn master_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".master")
}

/// First-run setup: generate a fresh salt, derive a key, encrypt the
/// sentinel, write `.master` with mode `0600`. Errors if `.master` already
/// exists (use `rotate` for key change — not implemented in P0.8 iskelet).
pub fn init_master(
    data_dir: &Path,
    passphrase: &str,
    params: KdfParams,
) -> Result<(), CryptoError> {
    fs::create_dir_all(data_dir)?;
    let path = master_file_path(data_dir);
    if path.exists() {
        return Err(CryptoError::MalformedFile(format!(
            "{} already exists; refusing to overwrite",
            path.display()
        )));
    }
    let mut salt = vec![0u8; SALT_LEN];
    random_bytes(&mut salt)?;
    let key = derive_key(passphrase, &salt, &params)?;
    let sentinel_ct = encrypt(&key, SENTINEL)?;
    let file = MasterFile {
        version: MASTER_FILE_VERSION,
        kdf: params,
        salt_hex: hex(&salt),
        sentinel_ciphertext_hex: hex(&sentinel_ct),
    };
    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| CryptoError::MalformedFile(e.to_string()))?;
    let mut opts = fs::OpenOptions::new();
    opts.create_new(true).write(true).mode(0o600);
    use std::io::Write;
    let mut f = opts.open(&path)?;
    f.write_all(json.as_bytes())?;
    salt.zeroize();
    Ok(())
}

/// Load `.master`, verify the passphrase against the sentinel, return the
/// derived key. `WrongPassphrase` if the sentinel does not decrypt.
pub fn unlock(data_dir: &Path, passphrase: &str) -> Result<MasterKey, CryptoError> {
    let path = master_file_path(data_dir);
    let json = fs::read_to_string(&path)?;
    let file: MasterFile =
        serde_json::from_str(&json).map_err(|e| CryptoError::MalformedFile(e.to_string()))?;
    if file.version != MASTER_FILE_VERSION {
        return Err(CryptoError::MalformedFile(format!(
            "unsupported master file version {}",
            file.version
        )));
    }
    let salt = unhex(&file.salt_hex)?;
    let key = derive_key(passphrase, &salt, &file.kdf)?;
    let sentinel_ct = unhex(&file.sentinel_ciphertext_hex)?;
    let decrypted = decrypt(&key, &sentinel_ct).map_err(|_| CryptoError::WrongPassphrase)?;
    if decrypted != SENTINEL {
        return Err(CryptoError::WrongPassphrase);
    }
    Ok(key)
}

/// Convenience: is a master key configured for this data dir?
pub fn is_initialised(data_dir: &Path) -> bool {
    master_file_path(data_dir).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ntool-crypto-{}-{}-{}",
            tag,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn derive_is_deterministic_with_same_inputs() {
        let salt = [0x11u8; 32];
        let p = KdfParams::fast_test();
        let k1 = derive_key("hunter2", &salt, &p).unwrap();
        let k2 = derive_key("hunter2", &salt, &p).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_passphrases_derive_different_keys() {
        let salt = [0x22u8; 32];
        let p = KdfParams::fast_test();
        let a = derive_key("alpha", &salt, &p).unwrap();
        let b = derive_key("beta", &salt, &p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let salt = [0x33u8; 32];
        let key = derive_key("pw", &salt, &KdfParams::fast_test()).unwrap();
        let msg = b"the quick brown fox";
        let ct = encrypt(&key, msg).unwrap();
        assert_ne!(ct.as_slice(), msg); // ciphertext differs
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    fn tampered_ciphertext_fails_gcm_tag() {
        let salt = [0x44u8; 32];
        let key = derive_key("pw", &salt, &KdfParams::fast_test()).unwrap();
        let mut ct = encrypt(&key, b"important").unwrap();
        // Flip one bit in the ciphertext body (past the nonce).
        ct[NONCE_LEN + 1] ^= 0x01;
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let salt = [0x55u8; 32];
        let right = derive_key("right", &salt, &KdfParams::fast_test()).unwrap();
        let wrong = derive_key("wrong", &salt, &KdfParams::fast_test()).unwrap();
        let ct = encrypt(&right, b"secret").unwrap();
        assert!(decrypt(&wrong, &ct).is_err());
    }

    #[test]
    fn init_then_unlock_round_trips() {
        let dir = tmpdir("init-unlock");
        init_master(&dir, "s3cret", KdfParams::fast_test()).unwrap();
        assert!(is_initialised(&dir));
        let key = unlock(&dir, "s3cret").unwrap();
        // Round-trip through the derived key to prove it actually works.
        let ct = encrypt(&key, b"payload").unwrap();
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt.as_slice(), b"payload");
    }

    #[test]
    fn unlock_rejects_wrong_passphrase() {
        let dir = tmpdir("wrong-pw");
        init_master(&dir, "right", KdfParams::fast_test()).unwrap();
        match unlock(&dir, "wrong") {
            Err(CryptoError::WrongPassphrase) => {}
            Err(other) => panic!("expected WrongPassphrase, got different error: {other}"),
            Ok(_) => panic!("expected WrongPassphrase, got Ok"),
        }
    }

    #[test]
    fn init_refuses_to_overwrite_existing_master() {
        let dir = tmpdir("no-overwrite");
        init_master(&dir, "a", KdfParams::fast_test()).unwrap();
        assert!(init_master(&dir, "b", KdfParams::fast_test()).is_err());
    }

    #[test]
    fn two_encryptions_of_same_plaintext_differ() {
        // AES-GCM uses a random nonce — two calls must produce different output.
        let salt = [0x66u8; 32];
        let key = derive_key("pw", &salt, &KdfParams::fast_test()).unwrap();
        let a = encrypt(&key, b"x").unwrap();
        let b = encrypt(&key, b"x").unwrap();
        assert_ne!(a, b);
    }
}
