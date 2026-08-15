//! Signed DCE/RPC request/response over the bound association - the Layer-4
//! transport the `TsProxy*` calls ride on.
//!
//! At PKT_INTEGRITY the request stub travels in cleartext with a 16-byte NTLM
//! signature appended (`sec_trailer` + token); the response comes back the same
//! way and we read its stub directly - no decryption, no signature check on
//! responses (matching FreeRDP). Request goes out on the IN channel; the response
//! streams back on the OUT channel, reassembled across fragments. Layout mirrors
//! FreeRDP `rpc_client.c` `rpc_write_request_pdu` / `rpc_get_stub_data_info`.

use tracing::{debug, trace};

use crate::GatewayError;
use crate::auth::RPC_SIGNATURE_SIZE;
use crate::bind::{BoundRpc, sec_trailer_header};
use crate::pdu::{CommonHeader, PType, pfc};
use crate::rts::VirtualConnection;

/// Fixed size of the `request`/`response` PDU header before the (8-aligned) stub.
const STUB_OFFSET: usize = 24;

impl BoundRpc {
    /// Marshal, sign, and send a `request` for `opnum` carrying `stub`; return the
    /// reassembled response stub. Consumes one call id.
    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, GatewayError> {
        let call_id = self.send_request(opnum, stub).await?;
        let out = read_response(&mut self.vc, call_id).await?;
        debug!(opnum, call_id, stub = out.len(), "rpc: <<< response");
        Ok(out)
    }

    /// Marshal, sign, and send a `request` on the IN channel *without* reading a
    /// response; returns the call id used. The receive-pipe setup relies on this:
    /// its "response" is the open-ended stream of pipe data, not one reply.
    pub async fn send_request(&mut self, opnum: u16, stub: &[u8]) -> Result<u32, GatewayError> {
        let call_id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1);
        let pdu = build_and_sign_request(&mut self.ntlm, call_id, opnum, stub)?;
        trace!(opnum, call_id, len = pdu.len(), stub = stub.len(), "rpc: >>> request");
        self.vc.in_channel.write_pdu(&pdu).await?;
        Ok(call_id)
    }
}

/// Build a signed `request` PDU: `[16 common][alloc_hint u32][p_cont_id u16]
/// [opnum u16][stub][auth_pad][8-byte sec_trailer][16-byte signature]`. The stub
/// starts at offset 24 (already 8-aligned); the signature covers everything from
/// the header through the sec_trailer header (INTEGRITY = sign, not seal).
pub(crate) fn build_and_sign_request(
    ntlm: &mut crate::auth::NtlmAuth,
    call_id: u32,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, GatewayError> {
    // Pad the stub end to a 4-byte boundary before the sec_trailer.
    let after_stub = STUB_OFFSET + stub.len();
    let auth_pad = (4 - (after_stub % 4)) % 4;
    let frag_length = after_stub + auth_pad + 8 + RPC_SIGNATURE_SIZE;

    let mut pdu = Vec::with_capacity(frag_length);
    CommonHeader::new(
        PType::Request,
        pfc::FIRST_FRAG | pfc::LAST_FRAG,
        frag_length as u16,
        RPC_SIGNATURE_SIZE as u16,
        call_id,
    )
    .encode(&mut pdu);
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    pdu.extend_from_slice(&opnum.to_le_bytes()); // opnum
    pdu.extend_from_slice(stub);
    pdu.extend(core::iter::repeat_n(0u8, auth_pad));
    pdu.extend_from_slice(&sec_trailer_header(auth_pad as u8));

    // Sign the whole PDU-so-far (header + stub + pad + sec_trailer header), then
    // append the signature as the auth token.
    let signature = ntlm.sign(&pdu)?;
    pdu.extend_from_slice(&signature);
    Ok(pdu)
}

/// Read `response` fragments off the OUT channel until `PFC_LAST_FRAG`, returning
/// the concatenated stub bytes. A `fault` PDU surfaces as an error.
async fn read_response(vc: &mut VirtualConnection, call_id: u32) -> Result<Vec<u8>, GatewayError> {
    let mut stub = Vec::new();
    loop {
        let pdu = vc.out_channel.read_pdu().await?;
        let h = CommonHeader::decode(&pdu)?;
        check_response(&h)?;
        if h.call_id != call_id {
            return Err(GatewayError::Protocol(format!(
                "response call_id {} != request {call_id}",
                h.call_id
            )));
        }
        stub.extend_from_slice(response_stub(&pdu, &h)?);
        if h.pfc_flags & pfc::LAST_FRAG != 0 {
            break;
        }
    }
    Ok(stub)
}

/// Reject a `fault` PDU (with its status) and any non-`response` PDU.
pub(crate) fn check_response(h: &CommonHeader) -> Result<(), GatewayError> {
    match h.ptype {
        PType::Response => Ok(()),
        PType::Fault => Err(GatewayError::Protocol(format!("RPC fault on call_id {}", h.call_id))),
        other => Err(GatewayError::Protocol(format!("expected RPC response, got {other:?}"))),
    }
}

/// The stub payload of a `response` PDU: from offset 24 to the `sec_trailer`, less
/// its `auth_pad`. Shared by the request/response path and the receive pipe.
pub(crate) fn response_stub<'a>(pdu: &'a [u8], h: &CommonHeader) -> Result<&'a [u8], GatewayError> {
    let frag = h.frag_length as usize;
    let auth = h.auth_length as usize;
    let stub_end = if auth > 0 {
        let sec_trailer_offset = frag
            .checked_sub(auth + 8)
            .ok_or_else(|| GatewayError::Protocol("response auth_length overflows frag".into()))?;
        let auth_pad =
            *pdu.get(sec_trailer_offset + 2)
                .ok_or_else(|| GatewayError::Protocol("response sec_trailer truncated".into()))? as usize;
        sec_trailer_offset
            .checked_sub(auth_pad)
            .ok_or_else(|| GatewayError::Protocol("response auth_pad overflows stub".into()))?
    } else {
        frag
    };
    if stub_end < STUB_OFFSET || stub_end > pdu.len() {
        return Err(GatewayError::Protocol(format!(
            "response stub bounds invalid: end={stub_end} len={}",
            pdu.len()
        )));
    }
    Ok(&pdu[STUB_OFFSET..stub_end])
}
