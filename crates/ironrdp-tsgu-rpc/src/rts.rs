//! RTS (RPC Transport Service) virtual-connection handshake - MS-RPCH Layer 2.
//!
//! RPC-over-HTTP tunnels a connection-oriented RPC association through two
//! long-lived HTTP requests: an **IN channel** (`RPC_IN_DATA`, a 1 GiB request
//! body the client streams into) and an **OUT channel** (`RPC_OUT_DATA`, whose
//! response body the server streams back). Before any RPC flows, the two are
//! correlated into one virtual connection by exchanging RTS PDUs:
//!
//!   1. client -> **CONN/A1** on the OUT channel (VirtualConnection + OUT cookies),
//!   2. client -> **CONN/B1** on the IN channel (+ IN cookie, keepalive, group),
//!   3. server -> **CONN/A3** on the OUT channel (ConnectionTimeout),
//!   4. server -> **CONN/C2** on the OUT channel (Version, window, timeout).
//!
//! After C2 the virtual connection is OPENED and the DCE/RPC bind (Layer 3) runs.
//! Byte layouts mirror FreeRDP `libfreerdp/core/gateway/rts.c` and MS-RPCH; every
//! integer is little-endian.

use tracing::{debug, info};

use crate::GatewayError;
use crate::auth::{NtlmAuth, authenticate_streaming};
use crate::http::Channel;
use crate::pdu::{CommonHeader, Cursor, PType, pfc};

// RTS command types (the leading u32 of each command).
const CMD_RECEIVE_WINDOW_SIZE: u32 = 0x0;
const CMD_CONNECTION_TIMEOUT: u32 = 0x2;
const CMD_COOKIE: u32 = 0x3;
const CMD_CHANNEL_LIFETIME: u32 = 0x4;
const CMD_CLIENT_KEEPALIVE: u32 = 0x5;
const CMD_VERSION: u32 = 0x6;
const CMD_ASSOCIATION_GROUP_ID: u32 = 0xC;

/// `Flags` value for every CONN PDU we send/expect (no ping/echo/channel bits).
const RTS_FLAG_NONE: u16 = 0x0;
/// `Flags` bit marking a Ping RTS PDU (the gateway's idle keepalive).
const RTS_FLAG_PING: u16 = 0x1;
/// `Flags` value for an RTS PDU carrying commands outside the CONN handshake
/// (e.g. a FlowControlAck): FreeRDP's `RTS_FLAG_OTHER_CMD`.
const RTS_FLAG_OTHER_CMD: u16 = 0x2;

/// RTS command types used after the handshake.
const CMD_FLOW_CONTROL_ACK: u32 = 0x1;
const CMD_DESTINATION: u32 = 0xD;
/// `Destination = FDOutProxy` - routes a FlowControlAck to the OUT channel's flow
/// controller (MS-RPCH `ForwardDestination`).
const FD_OUT_PROXY: u32 = 3;

/// Send a FlowControlAck once this many bytes have arrived on the OUT channel
/// since the last ack - half the advertised window, matching FreeRDP. Without
/// this the gateway stops streaming after it has sent one full window (64 KiB),
/// which starves the large full-desktop EGFX frame.
pub const FLOW_CONTROL_ACK_THRESHOLD: u32 = RECEIVE_WINDOW_SIZE / 2;

/// RTS protocol version (the only defined value).
const RTS_VERSION: u32 = 1;
/// Client receive-window advertised in CONN/A1 (FreeRDP default, 64 KiB).
const RECEIVE_WINDOW_SIZE: u32 = 0x0001_0000;
/// Channel lifetime advertised in CONN/B1 (FreeRDP default, 1 GiB).
const CHANNEL_LIFETIME: u32 = 0x4000_0000;
/// Client keepalive interval advertised in CONN/B1 (FreeRDP default, 5 min).
const CLIENT_KEEPALIVE: u32 = 300_000;

/// `Content-Length` the IN channel (`RPC_IN_DATA`) declares: 1 GiB. The request
/// body never actually reaches this - it's the ceiling on the streamed RPC bytes.
pub const IN_CHANNEL_CONTENT_LENGTH: u64 = 0x4000_0000;

/// A 16-byte RPC cookie / GUID: the VirtualConnection id, each channel's id, and
/// the association-group id. Unpredictable per MS-RPCH; we use OS randomness.
#[derive(Clone, Copy)]
pub struct Cookie([u8; 16]);

impl Cookie {
    /// 16 random bytes from the OS CSPRNG.
    pub fn random() -> Result<Self, GatewayError> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).map_err(|e| GatewayError::Protocol(format!("cookie rng: {e}")))?;
        Ok(Cookie(b))
    }
}

// ---- command encoders (each returns its full on-wire bytes) ----

fn cmd_u32(command: u32, value: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&command.to_le_bytes());
    v.extend_from_slice(&value.to_le_bytes());
    v
}

fn cmd_cookie(command: u32, cookie: &Cookie) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(&command.to_le_bytes());
    v.extend_from_slice(&cookie.0);
    v
}

/// Assemble an RTS PDU: common header (ptype=RTS, FIRST|LAST, call_id 0) + Flags +
/// NumberOfCommands + the concatenated commands.
fn rts_pdu(flags: u16, commands: &[Vec<u8>]) -> Vec<u8> {
    let body: usize = commands.iter().map(Vec::len).sum();
    let frag_length = (CommonHeader::LEN + 4 + body) as u16;
    let mut out = Vec::with_capacity(frag_length as usize);
    CommonHeader::new(PType::Rts, pfc::FIRST_FRAG | pfc::LAST_FRAG, frag_length, 0, 0).encode(&mut out);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(commands.len() as u16).to_le_bytes());
    for c in commands {
        out.extend_from_slice(c);
    }
    out
}

/// CONN/A1 (client -> OUT channel): Version, VC cookie, OUT-channel cookie,
/// ReceiveWindowSize. 76 bytes.
fn conn_a1(vc: &Cookie, out: &Cookie) -> Vec<u8> {
    rts_pdu(
        RTS_FLAG_NONE,
        &[
            cmd_u32(CMD_VERSION, RTS_VERSION),
            cmd_cookie(CMD_COOKIE, vc),
            cmd_cookie(CMD_COOKIE, out),
            cmd_u32(CMD_RECEIVE_WINDOW_SIZE, RECEIVE_WINDOW_SIZE),
        ],
    )
}

/// CONN/B1 (client -> IN channel): Version, VC cookie, IN-channel cookie,
/// ChannelLifetime, ClientKeepalive, AssociationGroupId. 104 bytes.
fn conn_b1(vc: &Cookie, in_ch: &Cookie, group: &Cookie) -> Vec<u8> {
    rts_pdu(
        RTS_FLAG_NONE,
        &[
            cmd_u32(CMD_VERSION, RTS_VERSION),
            cmd_cookie(CMD_COOKIE, vc),
            cmd_cookie(CMD_COOKIE, in_ch),
            cmd_u32(CMD_CHANNEL_LIFETIME, CHANNEL_LIFETIME),
            cmd_u32(CMD_CLIENT_KEEPALIVE, CLIENT_KEEPALIVE),
            cmd_cookie(CMD_ASSOCIATION_GROUP_ID, group),
        ],
    )
}

/// FlowControlAck command (28 bytes): CommandType, BytesReceived, AvailableWindow,
/// then the 16-byte OUT-channel ChannelCookie.
fn cmd_flow_control_ack(bytes_received: u32, available_window: u32, cookie: &Cookie) -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    v.extend_from_slice(&CMD_FLOW_CONTROL_ACK.to_le_bytes());
    v.extend_from_slice(&bytes_received.to_le_bytes());
    v.extend_from_slice(&available_window.to_le_bytes());
    v.extend_from_slice(&cookie.0);
    v
}

/// A FlowControlAck RTS PDU (56 bytes), sent on the **IN** channel to replenish the
/// gateway's OUT-channel send window. `bytes_received` is the cumulative count of
/// OUT-channel bytes we've consumed; we re-advertise the full receive window from
/// that point. Mirrors FreeRDP `rts_send_flow_control_ack_pdu`
/// (Destination[FDOutProxy] + FlowControlAck).
pub fn flow_control_ack(out_cookie: &Cookie, bytes_received: u32) -> Vec<u8> {
    rts_pdu(
        RTS_FLAG_OTHER_CMD,
        &[
            cmd_u32(CMD_DESTINATION, FD_OUT_PROXY),
            cmd_flow_control_ack(bytes_received, RECEIVE_WINDOW_SIZE, out_cookie),
        ],
    )
}

/// A Ping RTS PDU (20 bytes, no commands) - echoed on the **IN** channel when the
/// gateway sends a keepalive Ping, so an idle tunnel isn't torn down (~60 s bug).
pub fn ping() -> Vec<u8> {
    rts_pdu(RTS_FLAG_PING, &[])
}

/// Whether `pdu` (already known to be an RTS PDU) is a Ping - reads the `Flags`
/// u16 immediately after the common header.
pub fn is_ping(pdu: &[u8]) -> bool {
    pdu.get(CommonHeader::LEN..CommonHeader::LEN + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) & RTS_FLAG_PING != 0)
        .unwrap_or(false)
}

// ---- server PDU parsing ----

/// Validate the RTS header of `pdu` and return `(flags, number_of_commands, body
/// cursor positioned at the first command)`.
fn rts_header(pdu: &[u8]) -> Result<(u16, u16, Cursor<'_>), GatewayError> {
    let h = CommonHeader::decode(pdu)?;
    if h.ptype != PType::Rts {
        return Err(GatewayError::Protocol(format!("expected RTS PDU, got {:?}", h.ptype)));
    }
    let mut cur = Cursor::new(&pdu[CommonHeader::LEN..]);
    let flags = cur.u16_le()?;
    let num = cur.u16_le()?;
    Ok((flags, num, cur))
}

/// Parsed CONN/A3: the server's ConnectionTimeout.
#[derive(Debug)]
pub struct ConnA3 {
    pub connection_timeout: u32,
}

/// Parse CONN/A3 - one ConnectionTimeout command, Flags NONE.
pub fn parse_conn_a3(pdu: &[u8]) -> Result<ConnA3, GatewayError> {
    let (flags, num, mut cur) = rts_header(pdu)?;
    if flags != RTS_FLAG_NONE || num != 1 {
        return Err(GatewayError::Protocol(format!(
            "CONN/A3 shape mismatch: flags={flags:#06x} commands={num}"
        )));
    }
    expect_command(&mut cur, CMD_CONNECTION_TIMEOUT, "CONN/A3 ConnectionTimeout")?;
    Ok(ConnA3 {
        connection_timeout: cur.u32_le()?,
    })
}

/// Parsed CONN/C2: negotiated version, the server's receive window, timeout.
#[derive(Debug)]
pub struct ConnC2 {
    pub version: u32,
    pub receive_window_size: u32,
    pub connection_timeout: u32,
}

/// Parse CONN/C2 - Version, ReceiveWindowSize, ConnectionTimeout; Flags NONE.
pub fn parse_conn_c2(pdu: &[u8]) -> Result<ConnC2, GatewayError> {
    let (flags, num, mut cur) = rts_header(pdu)?;
    if flags != RTS_FLAG_NONE || num != 3 {
        return Err(GatewayError::Protocol(format!(
            "CONN/C2 shape mismatch: flags={flags:#06x} commands={num}"
        )));
    }
    expect_command(&mut cur, CMD_VERSION, "CONN/C2 Version")?;
    let version = cur.u32_le()?;
    expect_command(&mut cur, CMD_RECEIVE_WINDOW_SIZE, "CONN/C2 ReceiveWindowSize")?;
    let receive_window_size = cur.u32_le()?;
    expect_command(&mut cur, CMD_CONNECTION_TIMEOUT, "CONN/C2 ConnectionTimeout")?;
    let connection_timeout = cur.u32_le()?;
    Ok(ConnC2 {
        version,
        receive_window_size,
        connection_timeout,
    })
}

fn expect_command(cur: &mut Cursor<'_>, want: u32, what: &str) -> Result<(), GatewayError> {
    let got = cur.u32_le()?;
    if got != want {
        return Err(GatewayError::Protocol(format!(
            "{what}: expected command {want:#x}, got {got:#x}"
        )));
    }
    Ok(())
}

/// An established RPC-over-HTTP virtual connection: the two open channels plus the
/// negotiated parameters. Layer 3 (the DCE/RPC bind) writes requests on the IN
/// channel and reads responses off the OUT channel.
pub struct VirtualConnection {
    pub in_channel: Channel,
    pub out_channel: Channel,
    /// The server's ConnectionTimeout from CONN/C2 (ms).
    pub connection_timeout: u32,
    /// The server's receive window from CONN/C2.
    pub receive_window: u32,
    /// The OUT-channel cookie we sent in CONN/A1 - required to build the
    /// FlowControlAcks that keep the gateway streaming.
    pub out_cookie: Cookie,
}

/// Run the RTS handshake and return the OPENED virtual connection.
///
/// `out_channel`/`in_channel` are freshly TLS-connected `RPC_OUT_DATA`/`RPC_IN_DATA`
/// channels; `ntlm_out`/`ntlm_in` are independent NTLM contexts (one per channel -
/// each HTTP request authenticates separately). On return, both channels are open
/// and CONN/A3 + CONN/C2 have been consumed off the OUT channel.
pub async fn open_virtual_connection(
    mut out_channel: Channel,
    mut in_channel: Channel,
    ntlm_out: &mut NtlmAuth,
    ntlm_in: &mut NtlmAuth,
) -> Result<VirtualConnection, GatewayError> {
    let vc = Cookie::random()?;
    let out_cookie = Cookie::random()?;
    let in_cookie = Cookie::random()?;
    let group = Cookie::random()?;

    // OUT channel: NTLM, then CONN/A1 as the (76-byte) request body.
    let a1 = conn_a1(&vc, &out_cookie);
    authenticate_streaming(&mut out_channel, "RPC_OUT_DATA", ntlm_out, a1.len() as u64, &[]).await?;
    out_channel.write_pdu(&a1).await?;
    debug!(len = a1.len(), "RTS: sent CONN/A1 on OUT channel");

    // IN channel: NTLM, then CONN/B1 as the first bytes of the 1 GiB body.
    let b1 = conn_b1(&vc, &in_cookie, &group);
    authenticate_streaming(&mut in_channel, "RPC_IN_DATA", ntlm_in, IN_CHANNEL_CONTENT_LENGTH, &[]).await?;
    in_channel.write_pdu(&b1).await?;
    debug!(len = b1.len(), "RTS: sent CONN/B1 on IN channel");

    // OUT channel response: 200, then the CONN/A3 and CONN/C2 PDUs stream in.
    let head = out_channel.recv_head().await?;
    if head.status != 200 {
        return Err(GatewayError::Protocol(format!(
            "OUT channel not accepted: {} {}",
            head.status, head.reason
        )));
    }
    debug!("RTS: OUT channel 200 - reading CONN/A3, CONN/C2");

    let a3 = parse_conn_a3(&out_channel.read_pdu().await?)?;
    let c2 = parse_conn_c2(&out_channel.read_pdu().await?)?;
    info!(
        a3_timeout = a3.connection_timeout,
        c2_version = c2.version,
        c2_window = c2.receive_window_size,
        c2_timeout = c2.connection_timeout,
        "RTS: virtual connection OPENED"
    );

    Ok(VirtualConnection {
        in_channel,
        out_channel,
        connection_timeout: c2.connection_timeout,
        receive_window: c2.receive_window_size,
        out_cookie,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_cookie() -> Cookie {
        Cookie([0u8; 16])
    }

    #[test]
    fn conn_a1_is_76_bytes_with_4_commands() {
        let pdu = conn_a1(&zero_cookie(), &zero_cookie());
        assert_eq!(pdu.len(), 76);
        let (flags, num, _) = rts_header(&pdu).unwrap();
        assert_eq!(flags, RTS_FLAG_NONE);
        assert_eq!(num, 4);
        // frag_length in the header matches the actual length.
        let h = CommonHeader::decode(&pdu).unwrap();
        assert_eq!(h.frag_length as usize, pdu.len());
        assert_eq!(h.ptype, PType::Rts);
    }

    #[test]
    fn conn_b1_is_104_bytes_with_6_commands() {
        let pdu = conn_b1(&zero_cookie(), &zero_cookie(), &zero_cookie());
        assert_eq!(pdu.len(), 104);
        let (_, num, _) = rts_header(&pdu).unwrap();
        assert_eq!(num, 6);
    }

    #[test]
    fn parses_a_synthetic_conn_a3() {
        // Build a CONN/A3 the way a server would and round-trip it.
        let pdu = rts_pdu(RTS_FLAG_NONE, &[cmd_u32(CMD_CONNECTION_TIMEOUT, 240_000)]);
        let a3 = parse_conn_a3(&pdu).unwrap();
        assert_eq!(a3.connection_timeout, 240_000);
    }

    #[test]
    fn parses_a_synthetic_conn_c2() {
        let pdu = rts_pdu(
            RTS_FLAG_NONE,
            &[
                cmd_u32(CMD_VERSION, 1),
                cmd_u32(CMD_RECEIVE_WINDOW_SIZE, 0x0004_0000),
                cmd_u32(CMD_CONNECTION_TIMEOUT, 120_000),
            ],
        );
        let c2 = parse_conn_c2(&pdu).unwrap();
        assert_eq!(c2.version, 1);
        assert_eq!(c2.receive_window_size, 0x0004_0000);
        assert_eq!(c2.connection_timeout, 120_000);
    }

    #[test]
    fn flow_control_ack_is_56_bytes_well_formed() {
        let pdu = flow_control_ack(&zero_cookie(), 0x1234);
        assert_eq!(pdu.len(), 56);
        let h = CommonHeader::decode(&pdu).unwrap();
        assert_eq!(h.ptype, PType::Rts);
        assert_eq!(h.frag_length as usize, pdu.len());
        let (flags, num, mut cur) = rts_header(&pdu).unwrap();
        assert_eq!(flags, RTS_FLAG_OTHER_CMD);
        assert_eq!(num, 2);
        // Command 1: Destination = FDOutProxy.
        assert_eq!(cur.u32_le().unwrap(), CMD_DESTINATION);
        assert_eq!(cur.u32_le().unwrap(), FD_OUT_PROXY);
        // Command 2: FlowControlAck { BytesReceived, AvailableWindow, cookie }.
        assert_eq!(cur.u32_le().unwrap(), CMD_FLOW_CONTROL_ACK);
        assert_eq!(cur.u32_le().unwrap(), 0x1234);
        assert_eq!(cur.u32_le().unwrap(), RECEIVE_WINDOW_SIZE);
    }

    #[test]
    fn ping_is_20_bytes_and_detected() {
        let pdu = ping();
        assert_eq!(pdu.len(), 20);
        let (flags, num, _) = rts_header(&pdu).unwrap();
        assert_eq!(flags, RTS_FLAG_PING);
        assert_eq!(num, 0);
        assert!(is_ping(&pdu));
        // A CONN PDU (flags NONE) is not a ping.
        assert!(!is_ping(&conn_a1(&zero_cookie(), &zero_cookie())));
    }

    #[test]
    fn rejects_wrong_shape() {
        // A3 parser must reject a 3-command PDU.
        let pdu = rts_pdu(
            RTS_FLAG_NONE,
            &[
                cmd_u32(CMD_VERSION, 1),
                cmd_u32(CMD_VERSION, 1),
                cmd_u32(CMD_VERSION, 1),
            ],
        );
        assert!(parse_conn_a3(&pdu).is_err());
    }
}
