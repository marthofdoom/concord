//! The listener's certificate: the operator's, or one generated on first run.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use concord_config::{lock_beside, read_private, write_private, Config, ConfigError};
use concord_pve::Fingerprint;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Certificate and key in one file, so a crash cannot leave a mismatched pair.
pub const SELF_SIGNED: &str = "tls-self-signed.pem";

pub struct Tls {
    pub config: Arc<ServerConfig>,
    pub fingerprint: Fingerprint,
}

/// `None` is plain HTTP, and only ever for a loopback listener.
pub fn setup(cfg: &Config) -> anyhow::Result<Option<Tls>> {
    if let (Some(cert), Some(key)) = (&cfg.tls_cert, &cfg.tls_key) {
        let chain = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
        let key = read_private(key)?;
        return build(&chain, key.as_bytes()).map(Some);
    }
    if cfg.listen.ip().to_canonical().is_loopback() {
        return Ok(None);
    }
    let pem = self_signed(&cfg.state_dir, cfg.listen)?;
    build(pem.as_bytes(), pem.as_bytes()).map(Some)
}

fn build(chain: &[u8], key: &[u8]) -> anyhow::Result<Tls> {
    let chain: Vec<_> = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<_, _>>()
        .context("parsing the TLS certificate")?;
    let leaf = chain.first().context("the TLS certificate file is empty")?;
    let fingerprint = Fingerprint::of_der(leaf);
    let key = PrivateKeyDer::from_pem_slice(key).context("parsing the TLS key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the TLS certificate and key do not match")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Tls {
        config: Arc::new(config),
        fingerprint,
    })
}

fn self_signed(dir: &Path, listen: SocketAddr) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating state_dir {}", dir.display()))?;
    let path = dir.join(SELF_SIGNED);
    // Two first runs at once must end up with one certificate.
    let _lock = lock_beside(&path)?;
    match read_private(&path) {
        Ok(pem) => return Ok(pem),
        // Any other fault stops here: replacing a key that merely could not be
        // read would break every client that pinned it.
        Err(ConfigError::Read { source, .. }) if source.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut names = vec!["concord".to_string(), "localhost".to_string()];
    if !listen.ip().is_unspecified() {
        names.push(listen.ip().to_string());
    }
    let made = rcgen::generate_simple_self_signed(names)?;
    let key = zeroize::Zeroizing::new(made.key_pair.serialize_pem());
    let pem = zeroize::Zeroizing::new(format!("{}{}", made.cert.pem(), key.as_str()));
    write_private(&path, &pem).with_context(|| format!("writing {}", path.display()))?;
    tracing::info!(path = %path.display(), "generated a self-signed certificate");
    Ok(pem)
}
