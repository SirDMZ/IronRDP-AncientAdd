//! DCE/RPC secure bind to the TSGU interface - MS-TSGU Layer 3.
//!
//! Over the OPENED virtual connection we establish an RPC association bound to the
//! TS Gateway interface, authenticated with a *third* NTLM context (DCE-style,
//! separate from the two HTTP-layer ones). The three-leg exchange mirrors the HTTP
//! NTLM but rides DCE/RPC PDUs:
//!
//!   1. client -> **bind** (Type-1) on the IN channel,
//!   2. server -> **bind_ack** (Type-2) on the OUT channel,
//!   3. client -> **rpc_auth_3** (Type-3) on the IN channel.
//!
//! Auth runs at **PKT_INTEGRITY** (not PRIVACY): request stubs are *signed*, never
//! sealed, and responses come back in cleartext - so Layer 4 only signs outgoing
//! PDUs and reads incoming stubs directly. Layouts mirror FreeRDP `rpc_bind.c`;
//! every integer is little-endian.

use tracing::{debug, info};

use crate::GatewayError;
use crate::auth::NtlmAuth;
use crate::pdu::{CommonHeader, PType, pfc};
use crate::rts::VirtualConnection;

/// Max transmit/receive fragment FreeRDP advertises (and the ceiling it enforces).
const MAX_FRAG: u16 = 0x0FF8;

/// `sec_trailer` auth_type: RPC_C_AUTHN_WINNT (NTLM).
const AUTH_TYPE_NTLM: u8 = 0x0A;
/// `sec_trailer` auth_level: RPC_C_AUTHN_LEVEL_PKT_INTEGRITY (sign, don't seal).
pub const AUTH_LEVEL_PKT_INTEGRITY: u8 = 0x05;

// Interface / transfer-syntax identifiers, in NDR (little-endian) wire order:
// the GUID's time_low/mid/hi are byte-swapped, the trailing clock/node bytes as-is.

/// TSGU (TsProxyRpcInterface) `44E265DD-7DAF-42CD-8560-3CDB6E7A2729`.
pub(crate) const TSGU_UUID: [u8; 16] = [
    0xDD, 0x65, 0xE2, 0x44, 0xAF, 0x7D, 0xCD, 0x42, 0x85, 0x60, 0x3C, 0xDB, 0x6E, 0x7A, 0x27, 0x29,
];
/// TSGU interface version 1.3 (major in low u16, minor in high u16).
pub(crate) const TSGU_IF_VERSION: u32 = 0x0003_0001;

/// NDR transfer syntax `8A885D04-1CEB-11C9-9FE8-08002B104860` v2.0.
pub(crate) const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
pub(crate) const NDR_VERSION: u32 = 2;

/// Bind-time feature negotiation `6CB71C2C-9812-4540-03...` v1.0.
const BTFN_UUID: [u8; 16] = [
    0x2C, 0x1C, 0xB7, 0x6C, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const BTFN_VERSION: u32 = 1;

/// A `p_syntax_id_t`: 16-byte interface UUID + 4-byte version = 20 bytes.
fn p_syntax(uuid: &[u8; 16], version: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(uuid);
    v.extend_from_slice(&version.to_le_bytes());
    v
}

/// The 8-byte `sec_trailer` header (NTLM, INTEGRITY, `auth_pad`, context id 0).
pub(crate) fn sec_trailer_header(auth_pad: u8) -> [u8; 8] {
    [
        AUTH_TYPE_NTLM,
        AUTH_LEVEL_PKT_INTEGRITY,
        auth_pad,
        0, // auth_reserved
        0,
        0,
        0,
        0, // auth_context_id (u32 = 0)
    ]
}

/// Append the 8-byte `sec_trailer` header + the auth token.
pub(crate) fn push_sec_trailer(pdu: &mut Vec<u8>, auth_pad: u8, token: &[u8]) {
    pdu.extend_from_slice(&sec_trailer_header(auth_pad));
    pdu.extend_from_slice(token);
}

/// Build the `bind` PDU carrying the NTLM Type-1 token. Two presentation
/// contexts: ctx 0 = TSGU->NDR, ctx 1 = TSGU->BTFN (feature negotiation).
fn build_bind(type1: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(100);
    body.extend_from_slice(&MAX_FRAG.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&MAX_FRAG.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id

    // p_cont_list: 2 context elements.
    body.push(2); // n_context_elem
    body.push(0); // reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved2

    // Context 0: id 0, TSGU -> NDR.
    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0); // reserved
    body.extend_from_slice(&p_syntax(&TSGU_UUID, TSGU_IF_VERSION));
    body.extend_from_slice(&p_syntax(&NDR_UUID, NDR_VERSION));

    // Context 1: id 1, TSGU -> BTFN.
    body.extend_from_slice(&1u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0); // reserved
    body.extend_from_slice(&p_syntax(&TSGU_UUID, TSGU_IF_VERSION));
    body.extend_from_slice(&p_syntax(&BTFN_UUID, BTFN_VERSION));

    // body is 100 bytes -> trailer starts at offset 116, already 4-aligned (pad 0).
    let frag_length = (CommonHeader::LEN + body.len() + 8 + type1.len()) as u16;
    let pfc_flags = pfc::FIRST_FRAG | pfc::LAST_FRAG | pfc::PENDING_CANCEL | pfc::CONC_MPX; // 0x17
    let mut pdu = Vec::with_capacity(frag_length as usize);
    CommonHeader::new(PType::Bind, pfc_flags, frag_length, type1.len() as u16, 2).encode(&mut pdu);
    pdu.extend_from_slice(&body);
    push_sec_trailer(&mut pdu, 0, type1);
    pdu
}

/// Build the `rpc_auth_3` PDU carrying the NTLM Type-3 token.
fn build_auth3(type3: &[u8]) -> Vec<u8> {
    // Body after the common header: max_xmit_frag + max_recv_frag (offset 20,
    // already 4-aligned), then the sec_trailer + token.
    let frag_length = (CommonHeader::LEN + 4 + 8 + type3.len()) as u16;
    let pfc_flags = pfc::FIRST_FRAG | pfc::LAST_FRAG | pfc::CONC_MPX; // 0x13 (no header-sign)
    let mut pdu = Vec::with_capacity(frag_length as usize);
    CommonHeader::new(PType::Auth3, pfc_flags, frag_length, type3.len() as u16, 2).encode(&mut pdu);
    pdu.extend_from_slice(&MAX_FRAG.to_le_bytes());
    pdu.extend_from_slice(&MAX_FRAG.to_le_bytes());
    push_sec_trailer(&mut pdu, 0, type3);
    pdu
}

/// Parsed `bind_ack`: the NTLM Type-2 token and the server's negotiated frag sizes.
struct BindAck {
    type2: Vec<u8>,
    max_xmit_frag: u16,
    max_recv_frag: u16,
}

/// Extract the auth token (last `auth_length` bytes) and the negotiated frag sizes
/// from a `bind_ack`. The token position is unambiguous via `auth_length`; the
/// variable p_result_list in between is not needed here.
fn parse_bind_ack(pdu: &[u8]) -> Result<BindAck, GatewayError> {
    let h = CommonHeader::decode(pdu)?;
    if h.ptype != PType::BindAck {
        return Err(GatewayError::Protocol(format!(
            "expected bind_ack, got {:?} (bind rejected?)",
            h.ptype
        )));
    }
    let frag = h.frag_length as usize;
    let auth = h.auth_length as usize;
    if auth == 0 {
        return Err(GatewayError::Protocol("bind_ack carried no NTLM challenge".into()));
    }
    if frag != pdu.len() || auth + CommonHeader::LEN + 8 > frag {
        return Err(GatewayError::Protocol(format!(
            "bind_ack lengths inconsistent: frag={frag} auth={auth} len={}",
            pdu.len()
        )));
    }
    // max_xmit_frag @ off 16, max_recv_frag @ off 18.
    let max_xmit_frag = u16::from_le_bytes([pdu[16], pdu[17]]);
    let max_recv_frag = u16::from_le_bytes([pdu[18], pdu[19]]);
    let type2 = pdu[frag - auth..frag].to_vec();
    Ok(BindAck {
        type2,
        max_xmit_frag,
        max_recv_frag,
    })
}

/// An RPC association bound to the TSGU interface: the virtual connection plus the
/// authenticated RPC NTLM context and the counters Layer 4 needs to sign and
/// sequence requests.
pub struct BoundRpc {
    pub vc: VirtualConnection,
    /// The RPC NTLM context - signs request PDUs (`encrypt_message`) at INTEGRITY.
    pub ntlm: NtlmAuth,
    /// Per-request call id (bind used 2; requests start after).
    pub call_id: u32,
    /// Our max send fragment, negotiated from the bind_ack (server's recv frag).
    pub max_xmit_frag: u16,
    /// Our max receive fragment (server's xmit frag).
    pub max_recv_frag: u16,
}

/// Run the DCE/RPC secure bind over `vc` with the DCE-style `ntlm` context.
///
/// On return the RPC association is bound to the TSGU interface and NTLM has
/// completed: the bind_ack confirmed the server accepted the bind + issued the
/// Type-2 challenge, and the Type-3 authenticate is on the wire. The first signed
/// request (Layer 4, `TsProxyCreateTunnel`) is what exercises the credentials
/// end-to-end.
pub async fn secure_bind(mut vc: VirtualConnection, mut ntlm: NtlmAuth) -> Result<BoundRpc, GatewayError> {
    // Leg 1 - bind (Type-1) on the IN channel.
    let type1 = ntlm.step(None)?;
    let bind = build_bind(&type1);
    vc.in_channel.write_pdu(&bind).await?;
    debug!(
        len = bind.len(),
        token = type1.len(),
        "bind: sent bind (Type-1) on IN channel"
    );

    // Leg 2 - bind_ack (Type-2) on the OUT channel.
    let ack_pdu = vc.out_channel.read_pdu().await?;
    let ack = parse_bind_ack(&ack_pdu)?;
    debug!(
        len = ack_pdu.len(),
        token = ack.type2.len(),
        max_xmit = ack.max_xmit_frag,
        max_recv = ack.max_recv_frag,
        "bind: bind_ack received (Type-2)"
    );

    // Leg 3 - rpc_auth_3 (Type-3) on the IN channel.
    let type3 = ntlm.step(Some(&ack.type2))?;
    if !ntlm.is_complete() {
        return Err(GatewayError::Protocol(
            "NTLM did not complete after the bind_ack challenge".into(),
        ));
    }
    let auth3 = build_auth3(&type3);
    vc.in_channel.write_pdu(&auth3).await?;
    debug!(
        len = auth3.len(),
        token = type3.len(),
        "bind: sent rpc_auth_3 (Type-3) on IN channel"
    );

    // FreeRDP swaps the negotiated sizes: our send ceiling is what the server can
    // receive, and vice versa.
    let max_xmit_frag = ack.max_recv_frag.min(MAX_FRAG);
    let max_recv_frag = ack.max_xmit_frag.min(MAX_FRAG);
    info!(
        max_xmit_frag,
        max_recv_frag, "bind: RPC association established (TSGU bound, NTLM complete)"
    );

    Ok(BoundRpc {
        vc,
        ntlm,
        call_id: 3,
        max_xmit_frag,
        max_recv_frag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_pdu_is_116_plus_token() {
        let token = vec![0xAAu8; 40];
        let pdu = build_bind(&token);
        // 116-byte body+header, 8-byte trailer, 40-byte token.
        assert_eq!(pdu.len(), 116 + 8 + 40);
        let h = CommonHeader::decode(&pdu).unwrap();
        assert_eq!(h.ptype, PType::Bind);
        assert_eq!(h.pfc_flags, 0x17);
        assert_eq!(h.auth_length as usize, token.len());
        assert_eq!(h.frag_length as usize, pdu.len());
        assert_eq!(h.call_id, 2);
        // n_context_elem at offset 24.
        assert_eq!(pdu[24], 2);
    }

    #[test]
    fn auth3_pdu_is_20_plus_token() {
        let token = vec![0x55u8; 120];
        let pdu = build_auth3(&token);
        assert_eq!(pdu.len(), 20 + 8 + 120);
        let h = CommonHeader::decode(&pdu).unwrap();
        assert_eq!(h.ptype, PType::Auth3);
        assert_eq!(h.pfc_flags, 0x13);
        assert_eq!(h.auth_length as usize, token.len());
    }

    #[test]
    fn parses_a_synthetic_bind_ack() {
        // Craft a bind_ack: header + minimal body + trailer + token.
        let token = vec![0x11u8; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0FF8u16.to_le_bytes()); // max_xmit @16
        body.extend_from_slice(&0x0FF8u16.to_le_bytes()); // max_recv @18
        body.extend_from_slice(&7u32.to_le_bytes()); // assoc_group_id
        body.extend_from_slice(&[0u8; 4]); // stand-in for sec_addr/results
        let frag = (CommonHeader::LEN + body.len() + 8 + token.len()) as u16;
        let mut pdu = Vec::new();
        CommonHeader::new(PType::BindAck, 0x03, frag, token.len() as u16, 2).encode(&mut pdu);
        pdu.extend_from_slice(&body);
        push_sec_trailer(&mut pdu, 0, &token);

        let ack = parse_bind_ack(&pdu).unwrap();
        assert_eq!(ack.type2, token);
        assert_eq!(ack.max_xmit_frag, 0x0FF8);
        assert_eq!(ack.max_recv_frag, 0x0FF8);
    }

    #[test]
    fn rejects_bind_nak() {
        let mut pdu = Vec::new();
        CommonHeader::new(PType::BindNak, 0x03, 16, 0, 2).encode(&mut pdu);
        assert!(parse_bind_ack(&pdu).is_err());
    }
}
