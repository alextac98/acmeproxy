use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}
pub fn matches(value: &str, expected: &[u8]) -> bool {
    bool::from(hash(value).ct_eq(expected))
}

#[derive(Clone)]
pub struct Vault(XChaCha20Poly1305);
impl Vault {
    pub fn new(key: &str) -> anyhow::Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(key.trim())?;
        anyhow::ensure!(bytes.len() == 32, "master key must encode exactly 32 bytes");
        Ok(Self(
            XChaCha20Poly1305::new_from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid key"))?,
        ))
    }
    pub fn seal(&self, context: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = self
            .0
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        Ok([nonce.to_vec(), encrypted].concat())
    }
    pub fn open(&self, context: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(data.len() >= 40, "invalid encrypted data");
        self.0
            .decrypt(
                XNonce::from_slice(&data[..24]),
                Payload {
                    msg: &data[24..],
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("cannot decrypt credentials; check master key"))
    }
}

pub fn domain(input: &str) -> Result<String, &'static str> {
    let domain = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if domain.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("use an ASCII domain name (punycode for international domains)");
    }
    Ok(domain)
}

pub fn scope(input: &str) -> Result<String, &'static str> {
    if let Some(suffix) = input.strip_prefix("*.") {
        Ok(format!("*.{}", domain(suffix)?))
    } else {
        domain(input)
    }
}

pub fn within(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

// *.example.com grants descendant challenge names, but excludes the apex.
pub fn allowed(name: &str, scopes: &[String]) -> bool {
    scopes.iter().any(|scope| match scope.strip_prefix("*.") {
        Some(suffix) => name != suffix && within(name, suffix),
        None => name == scope,
    })
}

pub fn challenge(fqdn: &str, value: &str) -> Result<(String, String), &'static str> {
    let lower = fqdn.to_ascii_lowercase();
    let name = lower
        .strip_prefix("_acme-challenge.")
        .ok_or("only _acme-challenge TXT records are allowed")?;
    let name = domain(name)?;
    // RFC 8555 DNS-01 digest: unpadded base64url SHA-256, with canonical trailing bits.
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "value must be a base64url SHA-256 digest")?;
    if bytes.len() != 32 {
        return Err("value must be a base64url SHA-256 digest");
    }
    let record = format!("_acme-challenge.{name}");
    if record.len() > 253 {
        return Err("challenge name is too long");
    }
    Ok((record, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_enforce_label_boundaries() {
        assert!(allowed("a.b.example.com", &["*.example.com".into()]));
        for name in ["example.com", "badexample.com", "example.com.evil.org"] {
            assert!(!allowed(name, &["*.example.com".into()]));
        }
        assert!(!allowed("a.example.com", &["example.com".into()]));
        assert!(allowed("example.com", &["example.com".into()]));
    }
    #[test]
    fn rejects_non_challenge_records_and_shell_syntax() {
        let value = random_secret();
        assert_eq!(
            challenge("_ACME-CHALLENGE.App.Example.com.", &value)
                .unwrap()
                .1,
            "app.example.com"
        );
        for name in [
            "example.com",
            "_acme-challenge.*.example.com",
            "_acme-challenge.a..com",
            "_acme-challenge.$(id).com",
        ] {
            assert!(challenge(name, &value).is_err());
        }
        assert!(challenge("_acme-challenge.example.com", "arbitrary TXT").is_err());
    }
    #[test]
    fn vault_authenticates_ciphertext_and_identity() {
        let vault = Vault::new(&random_secret()).unwrap();
        let data = vault.seal("provider:one", b"secret").unwrap();
        assert_eq!(vault.open("provider:one", &data).unwrap(), b"secret");
        assert!(vault.open("provider:two", &data).is_err());
        assert!(
            Vault::new(&random_secret())
                .unwrap()
                .open("provider:one", &data)
                .is_err()
        );
        let mut corrupt = data;
        corrupt[25] ^= 1;
        assert!(vault.open("provider:one", &corrupt).is_err());
    }
}
