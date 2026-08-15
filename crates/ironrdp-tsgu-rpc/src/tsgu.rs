//! MS-TSGU `TsProxy*` calls over the bound RPC association - Layer 4.
//!
//! The call chain that yields a tunnel to the internal RDP host:
//!   `TsProxyCreateTunnel` -> `TsProxyAuthorizeTunnel` -> `TsProxyCreateChannel`
//!   (names the target) -> `TsProxySetupReceivePipe` (+ `TsProxySendToServer`).
//! Each is an NDR-marshalled [`BoundRpc::call`] (signed request, plaintext
//! response). Layouts mirror FreeRDP `tsg.c`; NDR is little-endian.
//!
//! This module currently implements `TsProxyCreateTunnel` - the first signed
//! request, which validates request signing + NDR + the credentials end-to-end.

use tracing::info;

use crate::GatewayError;
use crate::auth::NtlmAuth;
use crate::bind::{BoundRpc, NDR_UUID, NDR_VERSION, TSGU_IF_VERSION, TSGU_UUID};
use crate::http::Channel;
use crate::pdu::{CommonHeader, pfc};
use crate::request::{check_response, response_stub};
use crate::tunnel::RdpTunnel;

/// Read a little-endian `i32` from a 4-byte slice, erroring on a truncated response.
fn read_i32_le(b: &[u8]) -> Result<i32, GatewayError> {
    b.try_into()
        .map(i32::from_le_bytes)
        .map_err(|_| GatewayError::Protocol("truncated NDR response".to_owned()))
}

/// Read a little-endian `u32` from a 4-byte slice, erroring on a truncated response.
fn read_u32_le(b: &[u8]) -> Result<u32, GatewayError> {
    b.try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| GatewayError::Protocol("truncated NDR response".to_owned()))
}

/// The raw pieces of an open tunnel the async adapter drives on its own tasks:
/// the IN channel + RPC signing state (writer) and the OUT channel + pipe id
/// (reader).
pub(crate) struct TunnelParts {
    pub in_channel: Channel,
    pub out_channel: Channel,
    pub ntlm: NtlmAuth,
    pub call_id: u32,
    pub channel: ContextHandle,
    pub pipe_call_id: u32,
    /// OUT-channel cookie - the tunnel reader/writer use it to send FlowControlAcks.
    pub out_cookie: crate::rts::Cookie,
    /// The server's CONN/C2 idle timeout (ms). The tunnel writer pings at half
    /// this interval so an idle tunnel isn't torn down. `0` means "use a default".
    pub connection_timeout: u32,
}

/// `TsProxyCreateTunnel` opnum.
const OP_CREATE_TUNNEL: u16 = 1;
/// `TsProxyAuthorizeTunnel` opnum.
const OP_AUTHORIZE_TUNNEL: u16 = 2;
/// `TsProxyCreateChannel` opnum.
const OP_CREATE_CHANNEL: u16 = 4;
/// `TsProxySetupReceivePipe` opnum.
const OP_SETUP_RECEIVE_PIPE: u16 = 8;
/// `TsProxySendToServer` opnum.
pub(crate) const OP_SEND_TO_SERVER: u16 = 9;

/// TSG packet type tag `"QR"` - TSG_PACKET_TYPE_QUARREQUEST.
const TSG_PACKET_QUARREQUEST: u32 = 0x0000_5152;
/// Channel protocol id for RDP.
const PROTOCOL_RDP: u16 = 3;

/// TSG packet type tag `"VC"` - TSG_PACKET_TYPE_VERSIONCAPS.
const TSG_PACKET_VERSIONCAPS: u32 = 0x0000_5643;
/// `tsgHeader.PacketId` for VERSIONCAPS (the u16 form of the tag).
const VERSIONCAPS_ID: u16 = 0x5643;
/// `tsgHeader.ComponentId` - TS_GATEWAY_TRANSPORT (`"TR"`).
const TS_GATEWAY_TRANSPORT: u16 = 0x5452;
/// Capability switch/union tag - TSG_CAPABILITY_TYPE_NAP.
const TSG_CAPABILITY_TYPE_NAP: u32 = 0x0000_0001;
/// NAP capability flags: IDLE_TIMEOUT|CONSENT_SIGN|SERVICE_MSG|REAUTH (no QUAR_SOH).
const TSG_NAP_CAPABILITIES: u32 = 0x0000_001E;

/// A 20-byte RPC context handle (`ContextType u32` + `ContextUuid[16]`), echoed as
/// the first argument of the later `TsProxy*` calls.
#[derive(Clone, Copy)]
pub struct ContextHandle(pub [u8; 20]);

/// The tunnel from `TsProxyCreateTunnel`: its context handle and id.
pub struct Tunnel {
    /// The tunnel context handle - echoed into the next `TsProxy*` calls.
    pub context: ContextHandle,
    pub tunnel_id: u32,
}

/// The channel from `TsProxyCreateChannel`: its context handle and id. The channel
/// is the gateway's connection to the internal target; `SetupReceivePipe` (Layer
/// 4c) turns it into a byte stream.
pub struct TargetChannel {
    /// The channel context handle - echoed into SetupReceivePipe/SendToServer (Layer 4c).
    pub context: ContextHandle,
    pub channel_id: u32,
}

/// Marshal the `TsProxyCreateTunnel` request stub (VERSIONCAPS), byte-exact per
/// FreeRDP `TsProxyCreateTunnelWriteRequest` - including the trailing 60-byte
/// "undocumented" block (a literal constant + the interface/transfer syntaxes).
fn create_tunnel_stub() -> Vec<u8> {
    let mut s = Vec::with_capacity(108);
    s.extend_from_slice(&TSG_PACKET_VERSIONCAPS.to_le_bytes()); // PacketId
    s.extend_from_slice(&TSG_PACKET_VERSIONCAPS.to_le_bytes()); // SwitchValue
    s.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // PacketVersionCapsPtr (referent 0)

    // TSG_PACKET_VERSIONCAPS
    s.extend_from_slice(&TS_GATEWAY_TRANSPORT.to_le_bytes()); // tsgHeader.ComponentId
    s.extend_from_slice(&VERSIONCAPS_ID.to_le_bytes()); // tsgHeader.PacketId
    s.extend_from_slice(&0x0002_0004u32.to_le_bytes()); // TsgCapsPtr (referent 1)
    s.extend_from_slice(&1u32.to_le_bytes()); // numCapabilities
    s.extend_from_slice(&1u16.to_le_bytes()); // majorVersion
    s.extend_from_slice(&1u16.to_le_bytes()); // minorVersion
    s.extend_from_slice(&0u16.to_le_bytes()); // quarantineCapabilities
    s.extend_from_slice(&0u16.to_le_bytes()); // pad (4-byte align)
    s.extend_from_slice(&1u32.to_le_bytes()); // MaxCount (tsgCaps[] conformant header)

    // TSG_PACKET_CAPABILITIES (NAP)
    s.extend_from_slice(&TSG_CAPABILITY_TYPE_NAP.to_le_bytes()); // capabilityType (switch)
    s.extend_from_slice(&TSG_CAPABILITY_TYPE_NAP.to_le_bytes()); // capabilityType (union tag)
    s.extend_from_slice(&TSG_NAP_CAPABILITIES.to_le_bytes()); // capabilities

    // The trailing "undocumented" block FreeRDP writes verbatim, then the TSGU
    // and NDR interface identifiers.
    s.extend_from_slice(&[0x8A, 0xE3, 0x13, 0x71, 0x02, 0xF4, 0x36, 0x71]);
    s.extend_from_slice(&0x0004_0001u32.to_le_bytes());
    s.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    s.push(0x02); // n_context_elem
    s.push(0x40); // reserved1
    s.extend_from_slice(&0x0028u16.to_le_bytes()); // reserved2
    s.extend_from_slice(&TSGU_UUID);
    s.extend_from_slice(&TSGU_IF_VERSION.to_le_bytes());
    s.extend_from_slice(&NDR_UUID);
    s.extend_from_slice(&NDR_VERSION.to_le_bytes());

    debug_assert_eq!(s.len(), 108, "CreateTunnel stub must be 108 bytes");
    s
}

/// Call `TsProxyCreateTunnel`: the first signed RPC request. On success the server
/// returns the tunnel context handle (echoed by every later call) and its id.
///
/// The `[out]` tunnel context (20 B), tunnel id (u32) and the DWORD return value
/// are the trailing fields of the response stub - parsed from the end, which is
/// robust to the variable CAPS_RESPONSE / QUARENC_RESPONSE body in between.
pub async fn create_tunnel(rpc: &mut BoundRpc) -> Result<Tunnel, GatewayError> {
    let stub = create_tunnel_stub();
    let resp = rpc.call(OP_CREATE_TUNNEL, &stub).await?;

    // Tail: [.. TunnelContext(20) TunnelId(u32) ReturnValue(i32)].
    if resp.len() < 28 {
        return Err(GatewayError::Protocol(format!(
            "CreateTunnel response too short: {} bytes",
            resp.len()
        )));
    }
    let n = resp.len();
    let ret = read_i32_le(&resp[n - 4..n])?;
    if ret != 0 {
        return Err(GatewayError::Protocol(format!(
            "TsProxyCreateTunnel returned {ret:#010x}"
        )));
    }
    let tunnel_id = read_u32_le(&resp[n - 8..n - 4])?;
    let mut context = [0u8; 20];
    context.copy_from_slice(&resp[n - 28..n - 8]);

    info!(tunnel_id, "tsgu: tunnel created");
    Ok(Tunnel {
        context: ContextHandle(context),
        tunnel_id,
    })
}

/// Encode `s` as NUL-terminated UTF-16LE; returns `(bytes, code-unit count incl.
/// the NUL)` - the count NDR strings advertise.
fn utf16z(s: &str) -> (Vec<u8>, u32) {
    let units: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
    let count = units.len() as u32;
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    (bytes, count)
}

/// Append an NDR conformant+varying string: `MaxCount, Offset(0), ActualCount`,
/// the UTF-16LE units, then a 2-byte pad when the count is odd (4-byte align).
fn push_ndr_string(out: &mut Vec<u8>, s: &str) {
    let (bytes, count) = utf16z(s);
    out.extend_from_slice(&count.to_le_bytes()); // MaxCount
    out.extend_from_slice(&0u32.to_le_bytes()); // Offset
    out.extend_from_slice(&count.to_le_bytes()); // ActualCount
    out.extend_from_slice(&bytes);
    if count % 2 == 1 {
        out.extend_from_slice(&[0, 0]);
    }
}

/// The client machine name for `TsProxyAuthorizeTunnel` - the local hostname
/// (`COMPUTERNAME`/`HOSTNAME`), or a stable fallback. Informational for basic auth.
fn client_machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "IronRDP".to_owned())
}

/// The DWORD return value at the tail of a response stub (NDR puts it last).
fn tail_return(resp: &[u8], what: &str) -> Result<i32, GatewayError> {
    let n = resp.len();
    if n < 4 {
        return Err(GatewayError::Protocol(format!("{what} response too short: {n} bytes")));
    }
    read_i32_le(&resp[n - 4..n])
}

/// Call `TsProxyAuthorizeTunnel` (opnum 2): present the tunnel context and a
/// QUARREQUEST with the client machine name (no NAP payload). Confirms the tunnel
/// is authorized before a channel can be created.
pub async fn authorize_tunnel(rpc: &mut BoundRpc, tunnel: &Tunnel) -> Result<(), GatewayError> {
    let machine = client_machine_name();
    let (_name_bytes, name_count) = utf16z(&machine);

    let mut stub = Vec::new();
    stub.extend_from_slice(&tunnel.context.0); // TunnelContext (20)
    stub.extend_from_slice(&TSG_PACKET_QUARREQUEST.to_le_bytes()); // PacketId
    stub.extend_from_slice(&TSG_PACKET_QUARREQUEST.to_le_bytes()); // SwitchValue
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // QuarRequest ptr (referent 0)
    stub.extend_from_slice(&0u32.to_le_bytes()); // flags = 0
    stub.extend_from_slice(&0x0002_0004u32.to_le_bytes()); // machineName ptr (referent 1)
    stub.extend_from_slice(&name_count.to_le_bytes()); // nameLength (incl NUL)
    stub.extend_from_slice(&0x0002_0008u32.to_le_bytes()); // data ptr (referent 2)
    stub.extend_from_slice(&0u32.to_le_bytes()); // dataLen = 0 (no SoH)
    push_ndr_string(&mut stub, &machine); // machineName string
    stub.extend_from_slice(&0u32.to_le_bytes()); // data conformant array: MaxCount 0

    let resp = rpc.call(OP_AUTHORIZE_TUNNEL, &stub).await?;
    let ret = tail_return(&resp, "TsProxyAuthorizeTunnel")?;
    if ret != 0 {
        return Err(GatewayError::Protocol(format!(
            "TsProxyAuthorizeTunnel returned {ret:#010x}"
        )));
    }
    info!(machine = %machine, "tsgu: tunnel authorized");
    Ok(())
}

/// Call `TsProxyCreateChannel` (opnum 4): name the internal RDP target
/// (`host:port`, protocol RDP) so the *gateway* connects to it. Returns the channel
/// context handle + id. Success means the gateway reached the target.
pub async fn create_channel(
    rpc: &mut BoundRpc,
    tunnel: &Tunnel,
    host: &str,
    port: u16,
) -> Result<TargetChannel, GatewayError> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&tunnel.context.0); // TunnelContext (20)
    // TSENDPOINTINFO
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // resourceName ptr (referent 0)
    stub.extend_from_slice(&1u32.to_le_bytes()); // numResourceNames
    stub.extend_from_slice(&0u32.to_le_bytes()); // alternateResourceNames ptr = NULL
    stub.extend_from_slice(&0u16.to_le_bytes()); // numAlternateResourceNames
    stub.extend_from_slice(&0u16.to_le_bytes()); // pad
    stub.extend_from_slice(&PROTOCOL_RDP.to_le_bytes()); // ProtocolId (RDP = 3)
    stub.extend_from_slice(&port.to_le_bytes()); // PortNumber
    stub.extend_from_slice(&1u32.to_le_bytes()); // resourceName[] conformant MaxCount
    stub.extend_from_slice(&0x0002_0004u32.to_le_bytes()); // resourceName[0] ptr (referent 1)
    push_ndr_string(&mut stub, host); // the target hostname (UTF-16)

    let resp = rpc.call(OP_CREATE_CHANNEL, &stub).await?;
    // Response: ChannelContext(20) + ChannelId(u32) + ReturnValue(u32).
    if resp.len() < 28 {
        return Err(GatewayError::Protocol(format!(
            "CreateChannel response too short: {} bytes",
            resp.len()
        )));
    }
    let ret = read_i32_le(&resp[24..28])?;
    if ret != 0 {
        return Err(GatewayError::Protocol(format!(
            "TsProxyCreateChannel returned {ret:#010x} (target {host}:{port} unreachable?)"
        )));
    }
    let mut context = [0u8; 20];
    context.copy_from_slice(&resp[0..20]);
    let channel_id = read_u32_le(&resp[20..24])?;
    info!(channel_id, target = %format!("{host}:{port}"), "tsgu: channel created to target");
    Ok(TargetChannel {
        context: ContextHandle(context),
        channel_id,
    })
}

/// A live tunnel to the internal RDP target through the gateway: outbound RDP
/// bytes go via `TsProxySendToServer`, inbound bytes arrive on the receive pipe.
/// Carries raw RDP - Layer 5 runs the RDP handshake over it.
pub struct GatewayTunnel {
    rpc: BoundRpc,
    channel: ContextHandle,
    channel_id: u32,
    /// Call id of the SetupReceivePipe request; the target's bytes stream back
    /// under this id (other ids on the OUT channel are SendToServer acks).
    pipe_call_id: u32,
    /// The pipe reported its terminal (4-byte) response - no more data.
    closed: bool,
}

impl GatewayTunnel {
    /// Open the tunnel: run `TsProxySetupReceivePipe` so the target's bytes begin
    /// streaming back on the OUT channel under the pipe call id.
    pub async fn open(mut rpc: BoundRpc, channel: TargetChannel) -> Result<Self, GatewayError> {
        let stub = channel.context.0.to_vec(); // ChannelContext (20)
        let pipe_call_id = rpc.send_request(OP_SETUP_RECEIVE_PIPE, &stub).await?;
        info!(pipe_call_id, "tsgu: receive pipe open - tunnel ready");
        Ok(GatewayTunnel {
            rpc,
            channel: channel.context,
            channel_id: channel.channel_id,
            pipe_call_id,
            closed: false,
        })
    }

    /// The `TsProxyCreateChannel` channel id.
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Send raw RDP `data` to the target via `TsProxySendToServer`. The RPC ack
    /// returns on the OUT channel under its own call id and is discarded by the
    /// next [`GatewayTunnel::read`], so we don't block on it here.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), GatewayError> {
        let stub = send_to_server_stub(&self.channel, data);
        self.rpc.send_request(OP_SEND_TO_SERVER, &stub).await?;
        Ok(())
    }

    /// Read the next chunk of RDP bytes from the receive pipe, skipping any
    /// non-pipe responses (SendToServer acks). An empty Vec means pipe EOF.
    pub async fn read(&mut self) -> Result<Vec<u8>, GatewayError> {
        loop {
            if self.closed {
                return Ok(Vec::new());
            }
            let pdu = self.rpc.vc.out_channel.read_pdu().await?;
            let h = CommonHeader::decode(&pdu)?;
            check_response(&h)?;
            if h.call_id != self.pipe_call_id {
                continue; // SendToServer ack (or other call) - discard.
            }
            let stub = response_stub(&pdu, &h)?;
            // The pipe's terminal PDU is a 4-byte LAST_FRAG return value.
            if stub.len() == 4 && h.pfc_flags & pfc::LAST_FRAG != 0 {
                self.closed = true;
                return Ok(Vec::new());
            }
            if !stub.is_empty() {
                return Ok(stub.to_vec());
            }
        }
    }

    /// Decompose into the raw pieces the async adapter runs on separate tasks.
    fn into_parts(self) -> TunnelParts {
        let BoundRpc { vc, ntlm, call_id, .. } = self.rpc;
        let out_cookie = vc.out_cookie;
        let connection_timeout = vc.connection_timeout;
        TunnelParts {
            in_channel: vc.in_channel,
            out_channel: vc.out_channel,
            ntlm,
            call_id,
            channel: self.channel,
            pipe_call_id: self.pipe_call_id,
            out_cookie,
            connection_timeout,
        }
    }

    /// Turn the tunnel into an `AsyncRead + AsyncWrite` transport `connect()` can
    /// run over: spawns the background reader/writer tasks bridging the pipe.
    pub fn into_async(self) -> RdpTunnel {
        RdpTunnel::spawn(self.into_parts())
    }
}

/// Marshal a `TsProxySendToServer` stub: the channel context, then one data buffer
/// with **big-endian** framing (this call, unusually, is big-endian).
pub(crate) fn send_to_server_stub(channel: &ContextHandle, data: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(32 + data.len());
    s.extend_from_slice(&channel.0); // ChannelContext (20)
    s.extend_from_slice(&((data.len() + 4) as u32).to_be_bytes()); // totalDataBytes
    s.extend_from_slice(&1u32.to_be_bytes()); // numBuffers = 1
    s.extend_from_slice(&(data.len() as u32).to_be_bytes()); // buffer1Length
    s.extend_from_slice(data); // buffer1
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_tunnel_stub_is_108_bytes() {
        let s = create_tunnel_stub();
        assert_eq!(s.len(), 108);
        // PacketId / SwitchValue = VERSIONCAPS.
        assert_eq!(&s[0..4], &TSG_PACKET_VERSIONCAPS.to_le_bytes());
        assert_eq!(&s[4..8], &TSG_PACKET_VERSIONCAPS.to_le_bytes());
        // First/second NDR pointer referents.
        assert_eq!(&s[8..12], &0x0002_0000u32.to_le_bytes());
        assert_eq!(&s[16..20], &0x0002_0004u32.to_le_bytes());
        // Undocumented block starts at offset 48.
        assert_eq!(&s[48..56], &[0x8A, 0xE3, 0x13, 0x71, 0x02, 0xF4, 0x36, 0x71]);
    }

    #[test]
    fn ndr_string_headers_and_4byte_alignment() {
        // "AB" -> 3 code units (A,B,NUL) = odd -> 6 bytes + 2 pad = 8; total = 12 hdr + 8.
        let mut out = Vec::new();
        push_ndr_string(&mut out, "AB");
        assert_eq!(&out[0..4], &3u32.to_le_bytes()); // MaxCount
        assert_eq!(&out[4..8], &0u32.to_le_bytes()); // Offset
        assert_eq!(&out[8..12], &3u32.to_le_bytes()); // ActualCount
        assert_eq!(&out[12..14], &[0x41, 0x00]); // 'A' as UTF-16LE
        assert_eq!(out.len() % 4, 0); // 4-aligned
        assert_eq!(out.len(), 12 + 6 + 2);

        // "ABC" -> 4 units (even) -> 8 bytes, no pad.
        let mut out = Vec::new();
        push_ndr_string(&mut out, "ABC");
        assert_eq!(out.len(), 12 + 8);
        assert_eq!(out.len() % 4, 0);
    }

    #[test]
    fn send_to_server_stub_is_big_endian() {
        let ctx = ContextHandle([0u8; 20]);
        let data = [0xAA, 0xBB, 0xCC];
        let s = send_to_server_stub(&ctx, &data);
        // 20 ctx + 4 total + 4 numBuffers + 4 len + 3 data.
        assert_eq!(s.len(), 20 + 12 + 3);
        // totalDataBytes = len + 4 = 7, big-endian.
        assert_eq!(&s[20..24], &7u32.to_be_bytes());
        assert_eq!(&s[24..28], &1u32.to_be_bytes()); // numBuffers
        assert_eq!(&s[28..32], &3u32.to_be_bytes()); // buffer1Length
        assert_eq!(&s[32..35], &data);
    }
}
