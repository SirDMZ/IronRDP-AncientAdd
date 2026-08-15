//! Microsoft RD Gateway ([MS-TSGU]) client over the **RPC-over-HTTP** ([MS-RPCH])
//! transport.
//!
//! [`ironrdp-mstsgu`] implements the WebSocket gateway transport; this crate covers
//! the complementary RPC-over-HTTP transport - the universal MS-TSGU transport that
//! every gateway version speaks. No prior Rust crate implemented it, so it was built
//! referencing FreeRDP's `libfreerdp/core/gateway/{rpc,rts,tsg}.c` for the protocol
//! facts (see the provenance note below).
//!
//! It is a transport adapter: it yields an `AsyncRead + AsyncWrite` tunnel
//! ([`GatewayTunnel`]) to the internal RDP target, over which a caller runs the RDP
//! handshake (e.g. with `ironrdp-connector`). It is built in layers, each with a
//! `probe_*` entry point for diagnosing a real gateway one layer at a time:
//!   1. **auth** - HTTP + NTLM to `/rpc/rpcproxy.dll` ([`probe_auth`]),
//!   2. **RTS** - the RPC-over-HTTP virtual-connection handshake ([`probe_rts`]),
//!   3. **DCE/RPC bind** - bind the TSGU interface with NTLM SSP ([`probe_bind`]),
//!   4. **TSGU** - the NDR `TsProxy*` calls that open the tunnel ([`probe_tunnel`],
//!      [`probe_channel`], [`probe_pipe`]).
//!
//! # Provenance & attribution
//!
//! This crate is an **independent implementation** of Microsoft's open protocol
//! specifications - MS-RPCH (RPC-over-HTTP), MS-TSGU (Terminal Services Gateway),
//! and MS-RPCE / DCE-RPC C706 (the bind, NDR marshalling, and security-trailer
//! wire formats). No Rust crate implemented the RPC-over-HTTP TSGU path, so during
//! development FreeRDP's `libfreerdp/core/gateway/{http,ncacn_http,rpc,rpc_bind,
//! rts,tsg}.c` (Apache-2.0) was studied as a reference *for the protocol facts*
//! the specs don't spell out - chiefly interop constants a real Windows gateway
//! requires (e.g. the "undocumented" `TsProxyCreateTunnel` trailer bytes and
//! FreeRDP's advertised fragment/capability defaults). The per-module
//! `mirrors FreeRDP <file>` notes mark exactly where.
//!
//! What is shared with FreeRDP is only that unprotectable layer: opcodes, UUIDs,
//! NDR field order, wire byte-layouts, and interop-mandated constants (17 USC
//! section 102(b) - facts and methods of operation are not copyrightable). FreeRDP's
//! copyrightable *expression* - its function decomposition, symbol names,
//! comments, and control flow - is **not** reproduced here; this code is
//! structured differently throughout (flat `Vec` builders vs FreeRDP's `wStream` +
//! struct-serializer split, tail-parsing vs FreeRDP's NDR read-helper tree,
//! and it even emits different referent-ID bytes). It is therefore not a
//! derivative work and carries no Apache-2.0 obligation; the FreeRDP credit here
//! is kept as a good-faith courtesy.
//!
//! [MS-TSGU]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188
//! [MS-RPCH]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/9a1d0f97-eac0-49ab-a197-f1a581c2d6a0
//! [`ironrdp-mstsgu`]: https://docs.rs/ironrdp-mstsgu

// This crate is a faithful port of RPC-over-HTTP / DCE-RPC / NDR wire marshalling.
// Length, offset, and fragment-size fields are written with `as` casts where the
// value is bounded by construction (small header/string lengths), so the cast lints
// are relaxed crate-wide rather than annotated at each of the many marshalling sites.
// The protocol layers live in private modules whose `pub` items are crate-internal
// by intent, so `unreachable_pub` is relaxed likewise.
#![expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    unreachable_pub,
    reason = "faithful wire-marshalling port: bounded casts, crate-internal pub items in private modules"
)]

mod auth;
mod bind;
mod error;
mod http;
#[expect(dead_code, reason = "some RPC header constants are used by later TSGU calls")]
mod pdu;
mod request;
mod rts;
mod tls;
mod tsgu;
mod tunnel;

pub use auth::{NtlmAuth, authenticate};
pub use bind::{BoundRpc, secure_bind};
pub use error::{GatewayError, GatewayResult};
pub use http::{Channel, Response};
pub use rts::{VirtualConnection, open_virtual_connection};
pub use tls::{CertInfo, TofuDecision};
pub use tsgu::GatewayTunnel;
pub use tunnel::RdpTunnel;

use tracing::info;

/// Parameters to reach a target host through an RD Gateway.
#[derive(Clone)]
pub struct GatewayParams {
    /// Gateway hostname (HTTPS on `port`).
    pub host: String,
    /// Gateway TCP port (443).
    pub port: u16,
    /// Gateway account username.
    pub username: String,
    /// Gateway account password - consumed by NTLM, never stored.
    pub password: String,
    /// Optional gateway AD domain.
    pub domain: Option<String>,
    /// The internal RDP host the gateway should reach.
    pub target_host: String,
    /// The internal RDP port (3389).
    pub target_port: u16,
}

/// The RPC-proxy request URI.
///
/// The `?host:port` query is **not** the RDP target - it's the inner RPC endpoint
/// the proxy dials: the RD Gateway's own TS Gateway RPC service, co-located on the
/// gateway at `localhost:3388` (MS-TSGU; FreeRDP hardcodes the same literal). The
/// real RDP host (`target_host:target_port`) is named later, in the TSGU
/// `TsProxyCreateChannel` NDR call (Layer 4). Putting the RDP target here instead
/// makes the proxy try to reach 3389 as an RPC server and fail with
/// `503 RPC Error: 6ba` (RPC_S_SERVER_UNAVAILABLE).
fn rpc_uri() -> String {
    "/rpc/rpcproxy.dll?localhost:3388".to_owned()
}

/// Result of the Layer-1 auth probe.
#[derive(Debug)]
pub struct AuthProbe {
    /// The gateway's pinned TLS certificate.
    pub cert: CertInfo,
    /// HTTP status after the Type-3 token (200 => NTLM accepted).
    pub status: u16,
    /// The status reason phrase.
    pub reason: String,
    /// Whether the sspi NTLM handshake reported completion.
    pub complete: bool,
}

/// **Layer 1** - open an `RPC_IN_DATA` channel to the gateway and run the NTLM
/// handshake, returning whether auth cleared. This is the first slice testable
/// against a real gateway: it proves TLS + sspi-NTLM-over-HTTP end-to-end before
/// the RTS/DCE-RPC/TSGU layers stack on top.
pub async fn probe_auth(params: &GatewayParams) -> Result<AuthProbe, GatewayError> {
    info!(
        gateway = %params.host, port = params.port,
        target = %params.target_host, target_port = params.target_port,
        "gateway: probing RPC-over-HTTP NTLM auth"
    );
    let mut channel = Channel::connect(&params.host, params.port, rpc_uri()).await?;
    let mut auth = NtlmAuth::new(&params.username, params.domain.as_deref(), &params.password)?;

    // Auth probe: declare Content-Length 0 on the Type-3 request so the server
    // answers the auth result immediately (the real channel declares the big
    // data-channel length - that's Layer 2).
    let resp = authenticate(&mut channel, "RPC_IN_DATA", &mut auth, 0, &[]).await?;

    Ok(AuthProbe {
        cert: channel.cert().clone(),
        status: resp.status,
        reason: resp.reason,
        complete: auth.is_complete(),
    })
}

/// Result of the Layer-2 RTS handshake probe.
#[derive(Debug)]
pub struct RtsProbe {
    /// The gateway's pinned TLS certificate.
    pub cert: CertInfo,
    /// The server's ConnectionTimeout from CONN/C2 (ms).
    pub connection_timeout: u32,
    /// The server's receive window from CONN/C2.
    pub receive_window: u32,
}

/// Open both RPC channels, HTTP-authenticate each with NTLM, and run the RTS
/// handshake - the shared Layer-1+2 setup behind every higher probe. Returns the
/// pinned gateway cert and the OPENED virtual connection.
async fn open_gateway_connection(
    params: &GatewayParams,
    verify: &mut dyn FnMut(&CertInfo) -> TofuDecision,
) -> Result<(CertInfo, VirtualConnection), GatewayError> {
    // Two independent TLS channels to the same RPC-proxy URI: OUT then IN.
    let out_channel = Channel::connect(&params.host, params.port, rpc_uri()).await?;
    let in_channel = Channel::connect(&params.host, params.port, rpc_uri()).await?;
    let cert = out_channel.cert().clone();

    // Verify the gateway's own TLS cert BEFORE any credential is sent: a CA-signed
    // cert is trusted silently, otherwise it's a TOFU decision. NTLM below carries
    // the user's gateway/AD password, so a rejected or unknown gateway cert must
    // abort here - ahead of open_virtual_connection, which authenticates.
    match verify(&cert) {
        TofuDecision::Pin => {}
        TofuDecision::Abort => return Err(GatewayError::CertRejected(cert.fingerprint())),
    }

    // Each HTTP request authenticates separately, so each channel gets its own
    // NTLM context (built from the same credentials).
    let mut ntlm_out = NtlmAuth::new(&params.username, params.domain.as_deref(), &params.password)?;
    let mut ntlm_in = NtlmAuth::new(&params.username, params.domain.as_deref(), &params.password)?;

    let vc = open_virtual_connection(out_channel, in_channel, &mut ntlm_out, &mut ntlm_in).await?;
    Ok((cert, vc))
}

/// **Layer 2** - open both RPC channels, authenticate each with NTLM, and run the
/// RTS virtual-connection handshake (CONN/A1*B1*A3*C2). Proves the RPC-over-HTTP
/// transport is established end-to-end before the DCE/RPC bind (Layer 3) stacks on.
pub async fn probe_rts(params: &GatewayParams) -> Result<RtsProbe, GatewayError> {
    info!(
        gateway = %params.host, port = params.port,
        target = %params.target_host, target_port = params.target_port,
        "gateway: probing RTS virtual connection"
    );
    // Probing is a protocol diagnostic; certs aren't pinned here.
    let mut trust = |_: &CertInfo| TofuDecision::Pin;
    let (cert, vc) = open_gateway_connection(params, &mut trust).await?;
    Ok(RtsProbe {
        cert,
        connection_timeout: vc.connection_timeout,
        receive_window: vc.receive_window,
    })
}

/// Result of the Layer-3 secure-bind probe.
#[derive(Debug)]
pub struct BindProbe {
    /// The gateway's pinned TLS certificate.
    pub cert: CertInfo,
    /// CONN/C2 ConnectionTimeout carried through from Layer 2 (ms).
    pub connection_timeout: u32,
    /// Negotiated max send fragment after the bind.
    pub max_xmit_frag: u16,
    /// Negotiated max receive fragment after the bind.
    pub max_recv_frag: u16,
}

/// **Layer 3** - establish the virtual connection, then run the DCE/RPC secure
/// bind to the TSGU interface (bind -> bind_ack -> rpc_auth_3, DCE-style NTLM). On
/// success the RPC association is bound and authenticated; the negotiated frag
/// sizes come back for the `TsProxy*` calls (Layer 4) to build on.
pub async fn probe_bind(params: &GatewayParams) -> Result<BindProbe, GatewayError> {
    info!(
        gateway = %params.host, port = params.port,
        target = %params.target_host, target_port = params.target_port,
        "gateway: probing DCE/RPC secure bind"
    );
    // Probing is a protocol diagnostic; certs aren't pinned here.
    let mut trust = |_: &CertInfo| TofuDecision::Pin;
    let (cert, vc) = open_gateway_connection(params, &mut trust).await?;
    let connection_timeout = vc.connection_timeout;

    // A third NTLM context - DCE-style - for the RPC-level bind.
    let ntlm_rpc = NtlmAuth::new_dce(&params.username, params.domain.as_deref(), &params.password)?;
    let bound = secure_bind(vc, ntlm_rpc).await?;

    Ok(BindProbe {
        cert,
        connection_timeout,
        max_xmit_frag: bound.max_xmit_frag,
        max_recv_frag: bound.max_recv_frag,
    })
}

/// Result of the Layer-4a `TsProxyCreateTunnel` probe.
#[derive(Debug)]
pub struct TunnelProbe {
    /// The gateway's pinned TLS certificate.
    pub cert: CertInfo,
    /// The tunnel id returned by `TsProxyCreateTunnel`.
    pub tunnel_id: u32,
}

/// **Layer 4a** - bind, then issue the first signed RPC request:
/// `TsProxyCreateTunnel`. Success proves request signing (sspi NTLM at INTEGRITY),
/// NDR marshalling, and the credentials all work end-to-end - the tunnel context
/// it returns is what `AuthorizeTunnel`/`CreateChannel` (the rest of Layer 4)
/// build on.
pub async fn probe_tunnel(params: &GatewayParams) -> Result<TunnelProbe, GatewayError> {
    info!(
        gateway = %params.host, port = params.port,
        target = %params.target_host, target_port = params.target_port,
        "gateway: probing TsProxyCreateTunnel"
    );
    // Probing is a protocol diagnostic; certs aren't pinned here.
    let mut trust = |_: &CertInfo| TofuDecision::Pin;
    let (cert, vc) = open_gateway_connection(params, &mut trust).await?;
    let ntlm_rpc = NtlmAuth::new_dce(&params.username, params.domain.as_deref(), &params.password)?;
    let mut bound = secure_bind(vc, ntlm_rpc).await?;
    let tunnel = tsgu::create_tunnel(&mut bound).await?;
    Ok(TunnelProbe {
        cert,
        tunnel_id: tunnel.tunnel_id,
    })
}

/// Result of the Layer-4b `TsProxyCreateChannel` probe.
#[derive(Debug)]
pub struct ChannelProbe {
    /// The gateway's pinned TLS certificate.
    pub cert: CertInfo,
    /// The tunnel id from `TsProxyCreateTunnel`.
    pub tunnel_id: u32,
    /// The channel id from `TsProxyCreateChannel` (the gateway reached the target).
    pub channel_id: u32,
}

/// **Layer 4b** - the full `TsProxy*` chain up to the channel: CreateTunnel ->
/// AuthorizeTunnel -> CreateChannel (naming `target_host:target_port`). A channel
/// id back means the *gateway* connected to the internal RDP target - everything
/// but the byte-stream pipe (Layer 4c) is now proven.
pub async fn probe_channel(params: &GatewayParams) -> Result<ChannelProbe, GatewayError> {
    info!(
        gateway = %params.host, port = params.port,
        target = %params.target_host, target_port = params.target_port,
        "gateway: probing TsProxyCreateChannel"
    );
    // Probing is a protocol diagnostic; certs aren't pinned here.
    let mut trust = |_: &CertInfo| TofuDecision::Pin;
    let (cert, vc) = open_gateway_connection(params, &mut trust).await?;
    let ntlm_rpc = NtlmAuth::new_dce(&params.username, params.domain.as_deref(), &params.password)?;
    let mut bound = secure_bind(vc, ntlm_rpc).await?;

    let tunnel = tsgu::create_tunnel(&mut bound).await?;
    tsgu::authorize_tunnel(&mut bound, &tunnel).await?;
    let channel = tsgu::create_channel(&mut bound, &tunnel, &params.target_host, params.target_port).await?;

    Ok(ChannelProbe {
        cert,
        tunnel_id: tunnel.tunnel_id,
        channel_id: channel.channel_id,
    })
}

/// A standard RDP **X.224 Connection Request** (TPKT + X.224 CR + an RDP
/// Negotiation Request for TLS|CredSSP) - the first bytes any RDP client sends.
/// Used by the Layer-4c probe to prove the tunnel round-trips to the target.
const X224_CONNECTION_REQUEST: &[u8] = &[
    0x03, 0x00, 0x00, 0x13, // TPKT: version 3, total length 19
    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 Connection Request
    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ: TLS | CredSSP
];

/// Result of the Layer-4c data-pipe probe.
#[derive(Debug)]
pub struct PipeProbe {
    /// The gateway's pinned TLS certificate.
    pub cert: CertInfo,
    /// The channel id from `TsProxyCreateChannel`.
    pub channel_id: u32,
    /// The bytes read back from the target - the RDP X.224 Connection Confirm
    /// (starts with the TPKT header `03 00`) if the tunnel round-trips.
    pub response: Vec<u8>,
}

/// **Layer 4c** - the whole chain plus the data pipe: open the tunnel
/// (`SetupReceivePipe`), send an X.224 Connection Request via `SendToServer`, and
/// read the target's reply off the receive pipe. Bytes back (a `03 00` TPKT) prove
/// raw RDP data flows both ways through the gateway to the internal host.
pub async fn probe_pipe(params: &GatewayParams) -> Result<PipeProbe, GatewayError> {
    info!(
        gateway = %params.host, port = params.port,
        target = %params.target_host, target_port = params.target_port,
        "gateway: probing the RDP data pipe"
    );
    // Probing is a protocol diagnostic; certs aren't pinned here.
    let mut trust = |_: &CertInfo| TofuDecision::Pin;
    let (cert, mut pipe) = open_tunnel(params, &mut trust).await?;
    let channel_id = pipe.channel_id();
    pipe.write(X224_CONNECTION_REQUEST).await?;
    let response = pipe.read().await?;

    Ok(PipeProbe {
        cert,
        channel_id,
        response,
    })
}

/// Open the full RD Gateway tunnel to `params.target_host:target_port`: Layers 1-4c
/// end-to-end (auth + RTS + bind + CreateTunnel + AuthorizeTunnel + CreateChannel +
/// SetupReceivePipe). This is the primary entry point.
///
/// Returns the pinned gateway certificate and the live [`GatewayTunnel`], whose
/// [`GatewayTunnel::into_async`] yields an `AsyncRead + AsyncWrite` transport
/// ([`RdpTunnel`]) to run the RDP handshake over (e.g. with `ironrdp-connector`).
///
/// `verify` is called with the gateway's own TLS certificate before any credential
/// is sent; return [`TofuDecision::Abort`] to reject an untrusted gateway.
pub async fn open_tunnel(
    params: &GatewayParams,
    verify: &mut dyn FnMut(&CertInfo) -> TofuDecision,
) -> Result<(CertInfo, GatewayTunnel), GatewayError> {
    let (cert, vc) = open_gateway_connection(params, verify).await?;
    let ntlm_rpc = NtlmAuth::new_dce(&params.username, params.domain.as_deref(), &params.password)?;
    let mut bound = secure_bind(vc, ntlm_rpc).await?;

    let tunnel = tsgu::create_tunnel(&mut bound).await?;
    tsgu::authorize_tunnel(&mut bound, &tunnel).await?;
    let channel = tsgu::create_channel(&mut bound, &tunnel, &params.target_host, params.target_port).await?;
    let pipe = GatewayTunnel::open(bound, channel).await?;
    Ok((cert, pipe))
}
