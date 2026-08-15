//! TLS to the gateway: accept any server certificate at the TLS layer, then decide
//! trust at the application layer. RD Gateways are commonly self-signed, so trust is
//! established by trust-on-first-use (TOFU) pinning of the certificate fingerprint
//! rather than by a CA. The actual TLS handshake is delegated to `ironrdp-tls`.

use sha2::{Digest as _, Sha256};
use tokio::net::TcpStream;

use crate::error::{GatewayError, GatewayResult};

/// A pinned view of a gateway's TLS certificate, for trust-on-first-use.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// The gateway host this certificate was presented for (the TOFU key).
    pub host: String,
    /// Lower-hex SHA-256 of the certificate DER (no separators).
    pub sha256_hex: String,
}

impl CertInfo {
    /// Colon-grouped uppercase fingerprint, e.g. `AB:CD:...`, for display and pinning.
    pub fn fingerprint(&self) -> String {
        let mut out = String::with_capacity(self.sha256_hex.len() * 3 / 2);
        for (i, c) in self.sha256_hex.chars().enumerate() {
            if i != 0 && i % 2 == 0 {
                out.push(':');
            }
            out.extend(c.to_uppercase());
        }
        out
    }
}

/// The caller's trust decision for a gateway certificate, taken before any
/// credential is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuDecision {
    /// Trust this certificate and proceed.
    Pin,
    /// Reject it and abort the connection.
    Abort,
}

/// Upgrade an already-connected TCP stream to TLS, accepting any server certificate
/// at the TLS layer and returning its fingerprint for application-layer TOFU pinning.
/// TLS resumption is disabled by `ironrdp-tls` (CredSSP over the inner target forbids
/// it). The caller opens (and tunes) the TCP stream so that channel-specific socket
/// options are preserved.
pub(crate) async fn upgrade(
    tcp: TcpStream,
    host: &str,
) -> GatewayResult<(ironrdp_tls::TlsStream<TcpStream>, CertInfo)> {
    let (tls, cert) = ironrdp_tls::upgrade_with_certificate_validation(
        tcp,
        host,
        ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate,
    )
    .await
    .map_err(|e| GatewayError::Tls(e.to_string()))?;

    // Fingerprint the presented certificate for TOFU. Re-encoding the parsed
    // certificate yields canonical DER, which is backend-agnostic (both the rustls
    // and native-tls backends return a parsed `x509_cert::Certificate`).
    let der = {
        use x509_cert::der::Encode as _;
        cert.to_der()
            .map_err(|e| GatewayError::Tls(format!("certificate re-encode: {e}")))?
    };

    Ok((
        tls,
        CertInfo {
            host: host.to_owned(),
            sha256_hex: to_hex(&Sha256::digest(&der)),
        },
    ))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0x0f)] as char);
    }
    s
}
