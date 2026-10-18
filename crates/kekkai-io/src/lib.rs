//! kekkai-io: the IO layer around `kekkai-core` (ADR 0004, 0023): configuration and key
//! loading, the UDP socket, the TUN device (`tun` feature, node only) and the loop that drives
//! the core's `Node`.

pub mod config;

use std::path::Path;

use kekkai_core::keys::StaticKey;

/// Reads a private key file (one line of standard base64, as `kekkai keygen` writes it) into
/// the opaque value the core takes (ADR 0017). Errors never quote the file's content.
pub fn load_key(path: &Path) -> std::io::Result<StaticKey> {
    let text = std::fs::read_to_string(path)?;
    StaticKey::from_text(&text).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: not a base64 32-byte key", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn load_key() {
        let dir = std::env::temp_dir().join(format!("kekkai-io-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        // keygen.json "rfc7748 alice", with the trailing newline keygen writes.
        std::fs::write(&path, "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\n").unwrap();
        let key = super::load_key(&path).unwrap();
        assert_eq!(
            kekkai_core::keys::public_key_to_text(&key.public()),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
        std::fs::write(&path, "secret-looking garbage").unwrap();
        let Err(err) = super::load_key(&path) else {
            panic!("garbage accepted")
        };
        let err = err.to_string();
        assert!(!err.contains("garbage"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
