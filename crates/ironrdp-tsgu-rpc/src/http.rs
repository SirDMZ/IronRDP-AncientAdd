//! Minimal HTTP/1.1 over the gateway's TLS stream.
//!
//! RD Gateway's RPC transport uses non-standard HTTP - custom `RPC_IN_DATA` /
//! `RPC_OUT_DATA` methods, a huge declared `Content-Length` on the data channel,
//! and connection-oriented NTLM - so a general HTTP client (hyper) fights us
//! more than it helps. We hand-roll exactly what the transport needs, mirroring
//! FreeRDP's `http.c`/`ncacn_http.c`.

use std::net::ToSocketAddrs as _;

use ironrdp_tls::TlsStream;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use crate::GatewayError;
use crate::pdu::CommonHeader;
use crate::tls::CertInfo;

/// Minimal `ws2_32.dll` binding for the one Winsock ioctl we need. Hand-declared
/// (mirroring `windows-sys`'s own signature) so we don't take a whole
/// `windows-sys` dependency + feature set for a single call. Winsock is already
/// initialized by the time we get here - std/tokio ran `WSAStartup` to create the
/// socket - so no init is required.
#[cfg(windows)]
mod ws2_32 {
    use core::ffi::c_void;

    #[link(name = "ws2_32")]
    extern "system" {
        pub fn WSAIoctl(
            s: usize, // SOCKET (UINT_PTR)
            io_control_code: u32,
            in_buffer: *const c_void,
            in_buffer_len: u32,
            out_buffer: *mut c_void,
            out_buffer_len: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,         // LPWSAOVERLAPPED (unused -> null)
            completion_routine: *mut c_void, // completion callback (unused -> null)
        ) -> i32;

        pub fn WSAGetLastError() -> i32;
    }
}

/// Whether the experimental gateway ACK-latency tuning is enabled (env
/// `IRONRDP_TSGU_ACK_TUNING` set). Default OFF: on a Windows client
/// `SIO_TCP_SET_ACK_FREQUENCY = 1` was observed to *slow* the tunnel ~10x (one
/// PDU per ~2.4 s from the very first setup PDU), so the aggressive-ACK path is
/// gated behind an opt-in while we confirm whether it helps or hurts on a given
/// host. Read once and cached.
fn ack_tuning_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("IRONRDP_TSGU_ACK_TUNING").is_some())
}

/// Ask the OS to ACK every inbound TCP segment on `tcp` instead of using delayed
/// ACK. The gateway OUT channel is receive-only, so there is no outbound data to
/// piggyback an ACK on; a delayed ACK (200 ms on Windows; up to `TCP_DELACK_MAX`
/// = 200 ms on Linux) then holds the gateway's Nagle-throttled tail segment of
/// each RPC fragment, pacing the desktop to one PDU per round-trip (the observed
/// ~240 ms cadence). On Windows the setting is persistent per-socket
/// (`SIO_TCP_SET_ACK_FREQUENCY = 1`), so this once-at-connect call is enough; on
/// Linux `TCP_QUICKACK` self-clears after each use, so this is only the initial
/// arm and [`Channel::rearm_quickack`] re-arms it before every read. Best-effort:
/// any error is ignored, degrading only to the prior (slow) behavior.
fn set_low_latency_acks(tcp: &TcpStream) {
    if !ack_tuning_enabled() {
        return;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;
        // SIO_TCP_SET_ACK_FREQUENCY = _WSAIOW(IOC_VENDOR, 23) = 0x98000000 | 23.
        const SIO_TCP_SET_ACK_FREQUENCY: u32 = 0x9800_0017;
        let sock = tcp.as_raw_socket() as usize;
        let freq: u32 = 1; // ACK every segment
        let mut bytes_returned: u32 = 0;
        // SAFETY: `sock` is the live socket owned by `tcp`; `in_buffer` points at a
        // u32 of the declared length; out/overlapped/completion pointers are null,
        // as this ioctl is synchronous. Best-effort - a failure just leaves delayed
        // ACK in place; we log the outcome so we can tell "applied but didn't help"
        // from "silently failed" (SIO_TCP_SET_ACK_FREQUENCY isn't supported on every
        // Windows build / socket state).
        let (rc, err) = unsafe {
            let rc = ws2_32::WSAIoctl(
                sock,
                SIO_TCP_SET_ACK_FREQUENCY,
                std::ptr::addr_of!(freq).cast(),
                size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            (rc, if rc == 0 { 0 } else { ws2_32::WSAGetLastError() })
        };
        if rc == 0 {
            debug!("gateway: SIO_TCP_SET_ACK_FREQUENCY=1 applied (delayed-ACK disabled)");
        } else {
            debug!(
                rc,
                wsa_error = err,
                "gateway: SIO_TCP_SET_ACK_FREQUENCY FAILED - delayed-ACK still active"
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let fd = tcp.as_raw_fd();
        let enable: libc::c_int = 1;
        // SAFETY: `fd` is the live socket owned by `tcp`; the option value is a
        // `c_int` of the matching length. Best-effort; return ignored.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                std::ptr::addr_of!(enable).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = tcp;
    }
}

/// A parsed HTTP response head (+ any body read for a finite `Content-Length`).
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Case-insensitive header lookup (first match).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The base64 token from a `WWW-Authenticate: NTLM <token>` header, if any.
    /// A bare `NTLM` (no token) yields `Some("")` - the server's initial offer.
    pub fn www_authenticate_ntlm(&self) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("WWW-Authenticate"))
            .find_map(|(_, v)| v.trim().strip_prefix("NTLM").map(str::trim))
    }
}

/// One TLS connection to the gateway carrying an RPC channel (`RPC_IN_DATA` or
/// `RPC_OUT_DATA`). Owns a buffered reader so response bodies and, later, the
/// streamed RPC PDUs stay aligned across requests.
pub struct Channel {
    stream: BufReader<TlsStream<TcpStream>>,
    host: String,
    uri: String,
    /// The gateway's pinned certificate (captured at connect).
    cert: CertInfo,
}

impl Channel {
    /// The gateway's pinned TLS certificate, captured at connect.
    pub fn cert(&self) -> &CertInfo {
        &self.cert
    }

    /// Open a TLS connection to `host:port` for the RPC proxy `uri`
    /// (`/rpc/rpcproxy.dll?<target-host>:<target-port>`).
    pub async fn connect(host: &str, port: u16, uri: String) -> Result<Self, GatewayError> {
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(GatewayError::Network)?
            .next()
            .ok_or_else(|| GatewayError::Invalid(format!("no address for {host}:{port}")))?;
        debug!(%host, port, %uri, "gateway: TCP connect");
        let tcp = TcpStream::connect(addr).await.map_err(GatewayError::Network)?;
        let _ = tcp.set_nodelay(true);
        // Defeat delayed-ACK on this channel so the gateway isn't paced to one PDU
        // per round-trip (see `set_low_latency_acks`). Persistent on Windows;
        // re-armed per read on Linux via `Channel::rearm_quickack`.
        set_low_latency_acks(&tcp);

        // Accept any gateway certificate at the TLS layer and fingerprint it; the
        // caller's `verify` callback decides trust (TOFU) before any credential is
        // sent (see `open_gateway_connection`).
        let (tls, cert) = crate::tls::upgrade(tcp, host).await?;
        debug!(fingerprint = %cert.fingerprint(), "gateway: TLS up");

        Ok(Channel {
            stream: BufReader::new(tls),
            host: host.to_owned(),
            uri,
            cert,
        })
    }

    /// Send a request head (+ optional body). `headers` are extra lines beyond
    /// the mandatory `Host`/`Content-Length`.
    pub async fn send(
        &mut self,
        method: &str,
        content_length: u64,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<(), GatewayError> {
        self.send_head(method, content_length, headers).await?;
        if !body.is_empty() {
            self.write_pdu(body).await?;
        }
        Ok(())
    }

    /// Send only the request head (status line + headers), flushed - the caller
    /// then streams the declared `content_length` bytes with [`Channel::write_pdu`].
    /// The RPC transport uses this because the OUT channel's body is the CONN/A1
    /// PDU and the IN channel's body is a 1 GiB stream, neither a simple buffer.
    pub async fn send_head(
        &mut self,
        method: &str,
        content_length: u64,
        headers: &[(&str, String)],
    ) -> Result<(), GatewayError> {
        // Headers IIS's RPC proxy expects (FreeRDP's http_context): identify the
        // RPC resource, ask to keep the channel alive, no caching.
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\n\
             Accept: application/rpc\r\nCache-Control: no-cache\r\nUser-Agent: MSRPC\r\n\
             Pragma: ResourceTypeUuid=44e265dd-7daf-42cd-8560-3cdb6e7a2729\r\n",
            self.uri, self.host
        );
        for (k, v) in headers {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        head.push_str(&format!(
            "Content-Length: {content_length}\r\nConnection: keep-alive\r\n\r\n"
        ));

        trace!(%method, content_length, "gateway: >>> request head:\n{}", head.trim_end());
        self.stream
            .get_mut()
            .write_all(head.as_bytes())
            .await
            .map_err(GatewayError::Network)?;
        self.stream.get_mut().flush().await.map_err(GatewayError::Network)?;
        Ok(())
    }

    /// Write raw bytes (a DCE/RPC PDU, or a CONN body) to the channel and flush.
    pub async fn write_pdu(&mut self, bytes: &[u8]) -> Result<(), GatewayError> {
        trace!(len = bytes.len(), "gateway: >>> {} raw bytes", bytes.len());
        self.stream
            .get_mut()
            .write_all(bytes)
            .await
            .map_err(GatewayError::Network)?;
        self.stream.get_mut().flush().await.map_err(GatewayError::Network)?;
        Ok(())
    }

    /// Read one response: status line, headers, and (for a finite
    /// `Content-Length`) the body - leaving the stream positioned after it.
    pub async fn recv(&mut self) -> Result<Response, GatewayError> {
        let mut resp = self.recv_head().await?;
        let content_length: usize = resp.header("Content-Length").and_then(|v| v.parse().ok()).unwrap_or(0);
        if content_length > 0 {
            resp.body = vec![0u8; content_length];
            self.stream
                .read_exact(&mut resp.body)
                .await
                .map_err(GatewayError::Network)?;
        }
        trace!(body_len = resp.body.len(), "gateway: <<< response body read");
        Ok(resp)
    }

    /// Read only the response head - status line + headers - leaving the stream
    /// positioned at the first body byte. The RPC OUT channel uses this: its 200
    /// response body is a long-lived stream of DCE/RPC PDUs, not a fixed buffer,
    /// so the caller reads it with [`Channel::read_pdu`] instead.
    pub async fn recv_head(&mut self) -> Result<Response, GatewayError> {
        let mut line = String::new();
        self.read_line(&mut line).await?;
        let status_line = line.trim_end().to_owned();
        // "HTTP/1.1 401 Unauthorized"
        let mut parts = status_line.splitn(3, ' ');
        let _http = parts.next();
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| GatewayError::Protocol(format!("bad status line: {status_line:?}")))?;
        let reason = parts.next().unwrap_or("").to_owned();

        let mut headers = Vec::new();
        loop {
            line.clear();
            self.read_line(&mut line).await?;
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_owned(), v.trim().to_owned()));
            }
        }

        trace!(status, %reason, headers = ?headers, "gateway: <<< response head");
        Ok(Response {
            status,
            reason,
            headers,
            body: Vec::new(),
        })
    }

    /// Read one DCE/RPC PDU from the channel body: the 16-byte common header, then
    /// the rest of `frag_length`. Returns the whole PDU (header included). Used on
    /// the OUT channel to pull RTS PDUs (CONN/A3, CONN/C2, ...) out of the stream.
    pub async fn read_pdu(&mut self) -> Result<Vec<u8>, GatewayError> {
        let mut header = [0u8; CommonHeader::LEN];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(GatewayError::Network)?;
        let h = CommonHeader::decode(&header)?;
        let frag = h.frag_length as usize;
        if frag < CommonHeader::LEN {
            return Err(GatewayError::Protocol(format!(
                "PDU frag_length {frag} < header {}",
                CommonHeader::LEN
            )));
        }
        let mut pdu = vec![0u8; frag];
        pdu[..CommonHeader::LEN].copy_from_slice(&header);
        // Re-arm quick-ACK before blocking on the fragment body: this read waits on
        // the gateway's Nagle-held tail segment, which it only releases once our ACK
        // of the earlier segments lands. Acking immediately (not after the delayed-ACK
        // timer) is what keeps the fragment stream flowing.
        self.rearm_quickack();
        self.stream
            .read_exact(&mut pdu[CommonHeader::LEN..])
            .await
            .map_err(GatewayError::Network)?;
        trace!(ptype = ?h.ptype, frag, "gateway: <<< PDU");
        Ok(pdu)
    }

    /// Re-arm TCP quick-ACK on the underlying socket (Linux only).
    ///
    /// Linux clears `TCP_QUICKACK` after each use, reverting to delayed-ACK - which
    /// can stretch to `TCP_DELACK_MAX` (200 ms). The gateway OUT channel is
    /// receive-only, so there is no outbound data to piggyback an ACK on; a delayed
    /// ACK then holds the gateway's Nagle-throttled tail segment of each RPC
    /// fragment, pacing the desktop to one PDU per ~200 ms round-trip (the observed
    /// ~240 ms cadence). Acking immediately lets the gateway stream fragments
    /// back-to-back. FreeRDP gets away with NODELAY alone because it reads straight
    /// off the BIO; our buffered reader can pull a whole PDU in one socket read,
    /// suppressing the read-triggered ACK, so we re-arm quick-ACK before each read.
    /// Best-effort: any error is ignored (non-Linux is a no-op).
    #[cfg(target_os = "linux")]
    pub fn rearm_quickack(&self) {
        use std::os::fd::AsRawFd as _;

        if !ack_tuning_enabled() {
            return;
        }
        let fd = self.stream.get_ref().get_ref().0.as_raw_fd();
        let enable: libc::c_int = 1;
        // SAFETY: `fd` is the live socket owned by `self.stream`; the option value is
        // a `c_int` of the matching length, as TCP_QUICKACK expects. The return is
        // ignored deliberately - quick-ACK is a latency optimization, not required
        // for correctness.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                std::ptr::addr_of!(enable).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    /// No-op on non-Linux platforms (`TCP_QUICKACK` is Linux-specific).
    #[cfg(not(target_os = "linux"))]
    pub fn rearm_quickack(&self) {}

    async fn read_line(&mut self, buf: &mut String) -> Result<(), GatewayError> {
        buf.clear();
        let n = self.stream.read_line(buf).await.map_err(GatewayError::Network)?;
        if n == 0 {
            return Err(GatewayError::Protocol("gateway closed the connection".into()));
        }
        Ok(())
    }
}
