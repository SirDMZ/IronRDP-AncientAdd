//! Error type for the RD Gateway RPC-over-HTTP transport.

/// Errors from the RD Gateway ([MS-TSGU]) RPC-over-HTTP ([MS-RPCH]) connect path.
///
/// [MS-TSGU]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188
/// [MS-RPCH]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/9a1d0f97-eac0-49ab-a197-f1a581c2d6a0
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// DNS/TCP failure reaching the gateway.
    #[error("network: {0}")]
    Network(#[from] std::io::Error),
    /// TLS handshake or certificate parsing failed.
    #[error("tls: {0}")]
    Tls(String),
    /// The gateway's TLS certificate was rejected (trust-on-first-use).
    #[error("gateway certificate rejected: {0}")]
    CertRejected(String),
    /// A gateway/RPC protocol step failed (HTTP, RTS, DCE/RPC bind, NDR, or sspi).
    #[error("gateway: {0}")]
    Protocol(String),
    /// Malformed input (bad host, empty username, and the like).
    #[error("{0}")]
    Invalid(String),
}

/// Convenience alias for a `Result` with a [`GatewayError`].
pub type GatewayResult<T> = Result<T, GatewayError>;
