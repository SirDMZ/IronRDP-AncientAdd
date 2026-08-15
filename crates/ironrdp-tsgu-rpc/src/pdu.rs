//! DCE/RPC PDU framing (MS-DCERPC / MS-RPCE): the 16-byte common header that
//! prefixes every connection-oriented PDU on the wire, plus the little cursor
//! helpers the RTS / bind / TSGU layers build on.
//!
//! Everything RPC-over-HTTP sends after the CONN handshake - RTS PDUs, the
//! DCE/RPC `bind`, the NDR-marshalled `TsProxy*` calls - is a stream of these
//! PDUs. We keep the framing in one place so the higher layers speak in terms of
//! typed headers, not byte offsets. Layout mirrors FreeRDP's
//! `rpcconn_common_hdr_t` (`libfreerdp/core/gateway/rpc.h`).

use crate::GatewayError;

/// RPC protocol version (connection-oriented DCE/RPC is always 5.0).
pub const RPC_VERS: u8 = 5;
pub const RPC_VERS_MINOR: u8 = 0;

/// Data representation: little-endian ints, ASCII chars, IEEE floats - the
/// `packed_drep` every Windows RPC PDU carries (`0x10 0x00 0x00 0x00`).
pub const PACKED_DREP: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

/// PDU types (`PTYPE`, byte 2 of the common header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PType {
    Request = 0,
    Ping = 1,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
    Auth3 = 16,
    Shutdown = 17,
    CoCancel = 18,
    Orphaned = 19,
    Rts = 20,
}

impl PType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => PType::Request,
            1 => PType::Ping,
            2 => PType::Response,
            3 => PType::Fault,
            11 => PType::Bind,
            12 => PType::BindAck,
            13 => PType::BindNak,
            14 => PType::AlterContext,
            15 => PType::AlterContextResp,
            16 => PType::Auth3,
            17 => PType::Shutdown,
            18 => PType::CoCancel,
            19 => PType::Orphaned,
            20 => PType::Rts,
            _ => return None,
        })
    }
}

/// `pfc_flags` bits (byte 3 of the common header).
pub mod pfc {
    pub const FIRST_FRAG: u8 = 0x01;
    pub const LAST_FRAG: u8 = 0x02;
    pub const PENDING_CANCEL: u8 = 0x04;
    pub const RESERVED_1: u8 = 0x08;
    pub const CONC_MPX: u8 = 0x10;
    pub const DID_NOT_EXECUTE: u8 = 0x20;
    pub const MAYBE: u8 = 0x40;
    pub const OBJECT_UUID: u8 = 0x80;
}

/// The 16-byte connection-oriented common header (`rpcconn_common_hdr_t`).
#[derive(Debug, Clone, Copy)]
pub struct CommonHeader {
    pub ptype: PType,
    pub pfc_flags: u8,
    /// Total PDU length including this header (little-endian on the wire).
    pub frag_length: u16,
    /// Length of the trailing `auth_verifier`, or 0 (little-endian).
    pub auth_length: u16,
    pub call_id: u32,
}

impl CommonHeader {
    pub const LEN: usize = 16;

    pub fn new(ptype: PType, pfc_flags: u8, frag_length: u16, auth_length: u16, call_id: u32) -> Self {
        CommonHeader {
            ptype,
            pfc_flags,
            frag_length,
            auth_length,
            call_id,
        }
    }

    /// Append the 16 header bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(RPC_VERS);
        out.push(RPC_VERS_MINOR);
        out.push(self.ptype as u8);
        out.push(self.pfc_flags);
        out.extend_from_slice(&PACKED_DREP);
        out.extend_from_slice(&self.frag_length.to_le_bytes());
        out.extend_from_slice(&self.auth_length.to_le_bytes());
        out.extend_from_slice(&self.call_id.to_le_bytes());
    }

    /// Parse the 16-byte header from the front of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, GatewayError> {
        if buf.len() < Self::LEN {
            return Err(GatewayError::Protocol(format!(
                "DCE/RPC header truncated: {} bytes",
                buf.len()
            )));
        }
        if buf[0] != RPC_VERS {
            return Err(GatewayError::Protocol(format!(
                "unexpected RPC version {}.{}",
                buf[0], buf[1]
            )));
        }
        let ptype =
            PType::from_u8(buf[2]).ok_or_else(|| GatewayError::Protocol(format!("unknown PDU type {}", buf[2])))?;
        Ok(CommonHeader {
            ptype,
            pfc_flags: buf[3],
            // buf[4..8] is packed_drep - assume little-endian (every Windows peer).
            frag_length: u16::from_le_bytes([buf[8], buf[9]]),
            auth_length: u16::from_le_bytes([buf[10], buf[11]]),
            call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

/// A forward-only reader over a PDU body, little-endian, with bounds checks that
/// surface as `GatewayError::Protocol` rather than panics.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], GatewayError> {
        if self.remaining() < n {
            return Err(GatewayError::Protocol(format!(
                "PDU underrun: need {n}, have {}",
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u16_le(&mut self) -> Result<u16, GatewayError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32_le(&mut self) -> Result<u32, GatewayError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], GatewayError> {
        self.take(n)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), GatewayError> {
        self.take(n).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_header_round_trips() {
        let h = CommonHeader::new(PType::Rts, pfc::FIRST_FRAG | pfc::LAST_FRAG, 76, 0, 0);
        let mut out = Vec::new();
        h.encode(&mut out);
        assert_eq!(out.len(), CommonHeader::LEN);
        assert_eq!(&out[4..8], &PACKED_DREP);
        let d = CommonHeader::decode(&out).unwrap();
        assert_eq!(d.ptype, PType::Rts);
        assert_eq!(d.frag_length, 76);
        assert_eq!(d.pfc_flags, 0x03);
    }

    #[test]
    fn rejects_short_header() {
        assert!(CommonHeader::decode(&[5, 0, 20]).is_err());
    }
}
