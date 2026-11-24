use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, OtherError, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::PveError;

/// A SHA-256 certificate fingerprint, the form PVE shows in its UI and in
/// `pvenode cert info`: 32 colon-separated hex bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of_der(der: &[u8]) -> Self {
        Fingerprint(Sha256::digest(der).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for Fingerprint {
    type Err = PveError;

    /// Accepts `AA:BB:..` (PVE's display form) in either case, or 64 bare hex
    /// digits. Anything else is rejected rather than guessed at: a pin that is
    /// silently truncated or padded would pin nothing.
    fn from_str(s: &str) -> Result<Self, PveError> {
        let s = s.trim();
        let bad = |why: &str| PveError::InvalidRequest(format!("invalid fingerprint: {why}"));
        let hex: Vec<u8> = if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 32 || parts.iter().any(|p| p.len() != 2) {
                return Err(bad("expected 32 colon-separated hex bytes"));
            }
            parts.concat().into_bytes()
        } else {
            s.as_bytes().to_vec()
        };
        if hex.len() != 64 {
            return Err(bad("expected 64 hex digits (SHA-256)"));
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.chunks(2).enumerate() {
            let hi = nibble(pair[0]).ok_or_else(|| bad("non-hex character"))?;
            let lo = nibble(pair[1]).ok_or_else(|| bad("non-hex character"))?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Fingerprint(out))
    }
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// A failed pin check, carried inside the `rustls::Error` the verifier
/// returns. It travels with that one handshake's error, so concurrent or
/// cancelled requests cannot see each other's mismatch.
#[derive(Debug)]
pub(crate) struct PinMismatch {
    pub(crate) expected: Fingerprint,
    pub(crate) actual: Fingerprint,
}

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("server certificate does not match pinned fingerprint")
    }
}

impl std::error::Error for PinMismatch {}

/// Finds a [`PinMismatch`] in a transport error's source chain.
///
/// `std::io::Error::source` skips the error it wraps and returns that error's
/// own source, and tokio-rustls hands handshake failures up as an `io::Error`
/// wrapping the `rustls::Error`; so each `io::Error` is opened with `get_ref`
/// as well as followed through `source`.
pub(crate) fn find_pin_mismatch<'a>(
    e: &'a (dyn std::error::Error + 'static),
) -> Option<&'a PinMismatch> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(m) = pin_mismatch_in(err) {
            return Some(m);
        }
        if let Some(inner) = err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            if let Some(m) = find_pin_mismatch(inner) {
                return Some(m);
            }
        }
        cur = err.source();
    }
    None
}

// Only the exact variant the verifier builds counts, so nothing else in the
// chain can be read as a pin failure.
fn pin_mismatch_in<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a PinMismatch> {
    match err.downcast_ref::<rustls::Error>()? {
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
            inner.downcast_ref::<PinMismatch>()
        }
        _ => None,
    }
}

/// Trusts exactly one certificate, identified by its SHA-256 fingerprint.
///
/// The CA chain and hostname are intentionally not checked. PVE is
/// self-signed by default (its own cluster CA, unknown to any trust store) and
/// is addressed by IP as often as by name, so those checks would either fail
/// always or be bypassed. The pin is the trust anchor: it names the one key we
/// accept, which is strictly stronger than "some CA vouched for a name".
/// Intermediates are ignored for the same reason.
#[derive(Debug)]
pub(crate) struct PinnedVerifier {
    pin: Fingerprint,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    pub(crate) fn new(pin: Fingerprint, provider: &CryptoProvider) -> Self {
        PinnedVerifier {
            pin,
            algs: provider.signature_verification_algorithms,
        }
    }
}

/// A TLS client configuration that trusts only the certificate `pin` names.
pub fn pinned_client_config(pin: Fingerprint) -> Result<ClientConfig, PveError> {
    // Named explicitly rather than taken from the process default so this
    // client's TLS behaviour does not depend on what else is linked in.
    let provider = Arc::new(default_provider());
    let verifier = PinnedVerifier::new(pin, &provider);
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| PveError::InvalidRequest(format!("TLS setup failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let seen = Fingerprint::of_der(end_entity.as_ref());
        // Constant time so a network attacker cannot learn the pin byte by byte
        // from response timing.
        if bool::from(seen.0.ct_eq(&self.pin.0)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(PinMismatch {
                    expected: self.pin,
                    actual: seen,
                })),
            )))
        }
    }

    // These two MUST really verify the handshake signature. The fingerprint
    // only proves the peer sent the right *public* certificate, which anyone
    // can replay; the signature proves it holds the matching private key.
    // Returning `HandshakeSignatureValid::assertion()` here unconditionally
    // would let anyone who has seen the cert impersonate the host.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
