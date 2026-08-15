//! `AsyncRead + AsyncWrite` over the gateway tunnel - Layer 5's transport.
//!
//! The IN and OUT channels are independent TLS sockets, so reads and writes run
//! on separate background tasks and never contend:
//!   - the **reader** task pulls receive-pipe chunks off the OUT channel (skipping
//!     `SendToServer` acks by call id) and forwards them over an mpsc,
//!   - the **writer** task drains an mpsc of outbound buffers, each sent as one
//!     `TsProxySendToServer`.
//!
//! The poll methods talk to those tasks only through `mpsc::Receiver::poll_recv`
//! (a native poll API), so there are no self-referential futures. Outbound bytes
//! coalesce: `poll_write` buffers, `poll_flush` sends the buffer as a single
//! `SendToServer` - so one TLS record becomes one tunnel write.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, trace, warn};

use crate::auth::NtlmAuth;
use crate::http::Channel;
use crate::pdu::{CommonHeader, PType, pfc};
use crate::request::{build_and_sign_request, check_response, response_stub};
use crate::rts::{self, Cookie};
use crate::tsgu::{ContextHandle, OP_SEND_TO_SERVER, TunnelParts, send_to_server_stub};

/// Bounded backlog for write acks - small; these are drained fast.
const CHANNEL_DEPTH: usize = 16;
/// Backlog for inbound pipe chunks. This must be **deep**: the reader emits the
/// gateway's OUT-channel FlowControlAcks inline as it reads, and it blocks on this
/// channel when it's full - so a shallow buffer plus a momentarily-slow consumer
/// stops the acks and stalls the whole tunnel (the gateway pauses after one 64 KiB
/// window). A deep buffer lets the reader stay ahead, keep acking, and keep the
/// gateway streaming at full rate while the consumer drains at its own pace. Each
/// chunk is at most one max-size RPC fragment (~4 KiB), so this caps at a few MiB.
const READ_DEPTH: usize = 1024;

/// Bridge an [`GatewayError`](crate::GatewayError) into an `io::Error` for the tunnel's
/// poll methods. For a `Network` error, unwrap the underlying `io::Error` so its
/// `ErrorKind` survives (a rustls `UnexpectedEof` stays diagnosable) and it isn't
/// re-prefixed into the confusing "network: network:" when the session layer wraps
/// it again; other variants stringify.
fn other(e: crate::GatewayError) -> io::Error {
    match e {
        crate::GatewayError::Network(io) => io,
        e => io::Error::other(e.to_string()),
    }
}

/// An `AsyncRead + AsyncWrite` view of the gateway tunnel.
pub struct RdpTunnel {
    /// Receive-pipe chunks from the reader task (`None` sender-closed = pipe EOF).
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// Bytes from the current chunk not yet copied out.
    read_leftover: Vec<u8>,
    /// Outbound buffers to the writer task (one becomes one `SendToServer`).
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// One ack per completed `SendToServer`, for `poll_flush`.
    ack_rx: mpsc::Receiver<io::Result<()>>,
    /// Bytes buffered by `poll_write`, flushed as one `SendToServer`.
    write_buf: Vec<u8>,
    /// `SendToServer`s submitted but not yet acked (drained by `poll_flush`).
    pending: usize,
    _reader: JoinHandle<()>,
    _writer: JoinHandle<()>,
}

impl RdpTunnel {
    /// Spawn the reader/writer tasks over the tunnel's raw channels.
    pub(crate) fn spawn(parts: TunnelParts) -> Self {
        let TunnelParts {
            in_channel,
            out_channel,
            ntlm,
            call_id,
            channel,
            pipe_call_id,
            out_cookie,
            connection_timeout,
        } = parts;

        let (read_tx, read_rx) = mpsc::channel::<io::Result<Vec<u8>>>(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (ack_tx, ack_rx) = mpsc::channel::<io::Result<()>>(CHANNEL_DEPTH);
        // Reader -> writer control signals (FlowControlAck / Ping), emitted by the
        // writer on the IN channel. Unbounded so the reader never blocks on them.
        let (in_msg_tx, in_msg_rx) = mpsc::unbounded_channel::<InChannelMsg>();

        let reader = tokio::spawn(reader_task(out_channel, pipe_call_id, read_tx, in_msg_tx));
        let writer = tokio::spawn(writer_task(
            Writer {
                in_channel,
                ntlm,
                call_id,
                channel,
                out_cookie,
            },
            write_rx,
            in_msg_rx,
            ack_tx,
            connection_timeout,
        ));

        RdpTunnel {
            read_rx,
            read_leftover: Vec::new(),
            write_tx,
            ack_rx,
            write_buf: Vec::new(),
            pending: 0,
            _reader: reader,
            _writer: writer,
        }
    }
}

/// A control PDU the reader asks the writer to emit on the IN channel.
enum InChannelMsg {
    /// Replenish the gateway's OUT-channel send window; carries the cumulative
    /// count of OUT-channel bytes received so far.
    FlowControlAck(u32),
    /// Echo a gateway keepalive Ping so an idle tunnel isn't torn down.
    Ping,
}

/// OUT-channel flow-control accounting. The RD Gateway pauses streaming once it
/// has sent our advertised receive window (64 KiB) without an acknowledgement, so
/// we emit a FlowControlAck every half-window - the piece whose absence starved
/// the large full-desktop EGFX frame down to a 2-frame stub.
struct FlowState {
    total_received: u32,
    since_ack: u32,
    tx: mpsc::UnboundedSender<InChannelMsg>,
}

impl FlowState {
    fn new(tx: mpsc::UnboundedSender<InChannelMsg>) -> Self {
        FlowState {
            total_received: 0,
            since_ack: 0,
            tx,
        }
    }

    /// Count `n` RPC-response bytes toward the window; request a FlowControlAck at
    /// the half-window mark. Only `PTYPE_RESPONSE` bytes reach here (the caller
    /// excludes RTS PDUs) so our tally matches the gateway's `BytesSent`.
    fn on_received(&mut self, n: usize) {
        let n = u32::try_from(n).unwrap_or(u32::MAX);
        self.total_received = self.total_received.wrapping_add(n);
        self.since_ack = self.since_ack.saturating_add(n);
        if self.since_ack >= rts::FLOW_CONTROL_ACK_THRESHOLD {
            let _ = self.tx.send(InChannelMsg::FlowControlAck(self.total_received));
            self.since_ack = 0;
        }
    }

    fn echo_ping(&self) {
        let _ = self.tx.send(InChannelMsg::Ping);
    }
}

/// Reader task: forward receive-pipe chunks; end on EOF or error (dropping the
/// sender, which surfaces as EOF/last error on the read side).
async fn reader_task(
    mut out_channel: Channel,
    pipe_call_id: u32,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    in_msg_tx: mpsc::UnboundedSender<InChannelMsg>,
) {
    // Diagnostics: how much streamed and how long the OUT channel lived. On an
    // unclean close these discriminate an immediate protocol reject (elapsed ~ the
    // handshake, few/no chunks) from a timed teardown (elapsed ~ the gateway's
    // ConnectionTimeout) or a mid-stream flow-control stall.
    let started = std::time::Instant::now();
    let mut chunks: u64 = 0;
    let mut payload_bytes: u64 = 0;
    let mut flow = FlowState::new(in_msg_tx);
    loop {
        match next_pipe_chunk(&mut out_channel, pipe_call_id, &mut flow).await {
            Ok(Some(data)) => {
                chunks += 1;
                payload_bytes += data.len() as u64;
                if read_tx.send(Ok(data)).await.is_err() {
                    break; // consumer dropped
                }
            }
            Ok(None) => {
                info!(
                    chunks,
                    payload_bytes,
                    total_received = flow.total_received,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "tunnel reader: OUT pipe closed cleanly (server ended the session)"
                );
                break; // pipe EOF
            }
            Err(e) => {
                warn!(
                    chunks,
                    payload_bytes,
                    total_received = flow.total_received,
                    since_ack = flow.since_ack,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    error = %e,
                    "tunnel reader: OUT channel closed uncleanly - gateway dropped the tunnel"
                );
                let _ = read_tx.send(Err(other(e))).await;
                break;
            }
        }
    }
}

/// Read the next receive-pipe chunk, discarding non-pipe responses (acks) and
/// handling interleaved RTS PDUs. Every received PDU is counted toward the flow
/// window; a gateway Ping is echoed; other RTS PDUs are skipped. `None` = the
/// pipe's terminal 4-byte response (EOF).
async fn next_pipe_chunk(
    out_channel: &mut Channel,
    pipe_call_id: u32,
    flow: &mut FlowState,
) -> Result<Option<Vec<u8>>, crate::GatewayError> {
    loop {
        // Re-arm quick-ACK before every read: Linux clears TCP_QUICKACK after each
        // use, and a delayed ACK on this receive-only channel holds the gateway's
        // Nagle-throttled fragment tail, pacing the desktop to ~1 PDU per round-trip.
        out_channel.rearm_quickack();
        let pdu = out_channel.read_pdu().await?;
        let h = CommonHeader::decode(&pdu)?;
        // The gateway interleaves RTS PDUs (Ping keepalives, flow control) with the
        // RPC data on the OUT channel. Echo Pings so an idle tunnel survives, and
        // skip any other RTS PDU rather than mistaking it for an RPC response
        // (which is the old "expected RPC response, got Rts" failure at ~60 s).
        // RTS PDUs are deliberately NOT counted toward the flow window below: per
        // MS-RPCH the gateway counts only the RPC (PTYPE_RESPONSE) bytes it queues,
        // so counting RTS here would push our cumulative BytesReceived past the
        // gateway's BytesSent - making our next FlowControlAck advertise a window
        // larger than we granted, which the gateway treats as an invalid PDU and
        // tears the whole virtual connection down.
        if h.ptype == PType::Rts {
            if rts::is_ping(&pdu) {
                trace!("tunnel: <<< RTS Ping - echoing");
                flow.echo_ping();
            }
            continue;
        }
        check_response(&h)?;
        // Count only RPC-response bytes toward the gateway's send window - both the
        // receive-pipe data and the SendToServer acks are PTYPE_RESPONSE and both
        // count against its window, so replenish based on their cumulative total.
        flow.on_received(pdu.len());
        if h.call_id != pipe_call_id {
            continue; // SendToServer ack - counted above, but not pipe data
        }
        let stub = response_stub(&pdu, &h)?;
        if stub.len() == 4 && h.pfc_flags & pfc::LAST_FRAG != 0 {
            return Ok(None);
        }
        if !stub.is_empty() {
            trace!(len = stub.len(), "tunnel: <<< pipe chunk");
            return Ok(Some(stub.to_vec()));
        }
    }
}

/// Writer-side state: the IN channel plus the RPC signing context and the
/// OUT-channel cookie used to build FlowControlAcks.
struct Writer {
    in_channel: Channel,
    ntlm: NtlmAuth,
    call_id: u32,
    channel: ContextHandle,
    out_cookie: Cookie,
}

impl Writer {
    async fn send(&mut self, data: &[u8]) -> Result<(), crate::GatewayError> {
        let stub = send_to_server_stub(&self.channel, data);
        let call_id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1);
        let pdu = build_and_sign_request(&mut self.ntlm, call_id, OP_SEND_TO_SERVER, &stub)?;
        trace!(len = data.len(), call_id, "tunnel: >>> SendToServer");
        self.in_channel.write_pdu(&pdu).await
    }

    /// Emit a reader-requested control PDU on the IN channel as a raw (unsigned)
    /// RTS PDU - exactly how the CONN handshake PDUs are sent.
    async fn send_control(&mut self, msg: InChannelMsg) -> Result<(), crate::GatewayError> {
        let pdu = match msg {
            InChannelMsg::FlowControlAck(bytes) => {
                trace!(bytes, "tunnel: >>> FlowControlAck");
                rts::flow_control_ack(&self.out_cookie, bytes)
            }
            InChannelMsg::Ping => {
                trace!("tunnel: >>> RTS Ping (echo)");
                rts::ping()
            }
        };
        self.in_channel.write_pdu(&pdu).await
    }
}

/// Writer task: outbound RDP buffers become `SendToServer` requests; reader
/// control signals become raw RTS PDUs on the IN channel. Control signals are
/// biased ahead of data so the gateway's window is replenished promptly.
async fn writer_task(
    mut writer: Writer,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut in_msg_rx: mpsc::UnboundedReceiver<InChannelMsg>,
    ack_tx: mpsc::Sender<io::Result<()>>,
    connection_timeout: u32,
) {
    // Proactive keepalive: the gateway tears the tunnel down after its CONN/C2
    // ConnectionTimeout of IN-channel silence. During active use the constant
    // SendToServer traffic keeps it warm, but a lull in user input would otherwise
    // hit that timeout - so ping at half the interval (>=2 pings per window, robust
    // to a late/lost ping). Echoing gateway pings alone is not enough for a gateway
    // that doesn't ping first; this is what mstsc does that a plain echo doesn't.
    // `0` (server said "use default") and out-of-range values clamp to [15s, 5min].
    let period = Duration::from_millis((u64::from(connection_timeout) / 2).clamp(15_000, 300_000));
    let mut ping_timer = tokio::time::interval(period);
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_timer.tick().await; // consume the immediate first tick; first ping is one period out

    loop {
        tokio::select! {
            biased;
            maybe_msg = in_msg_rx.recv() => {
                let Some(msg) = maybe_msg else { break };
                if let Err(e) = writer.send_control(msg).await {
                    let _ = ack_tx.send(Err(other(e))).await;
                    break;
                }
            }
            maybe_data = write_rx.recv() => {
                let Some(data) = maybe_data else { break };
                let result = writer.send(&data).await.map_err(other);
                if ack_tx.send(result).await.is_err() {
                    break;
                }
            }
            // Idle keepalive - polled last (biased) so it never starves real traffic.
            _ = ping_timer.tick() => {
                if let Err(e) = writer.send_control(InChannelMsg::Ping).await {
                    let _ = ack_tx.send(Err(other(e))).await;
                    break;
                }
            }
        }
    }
}

impl AsyncRead for RdpTunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if me.read_leftover.is_empty() {
            match me.read_rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(data))) => me.read_leftover = data,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = buf.remaining().min(me.read_leftover.len());
        buf.put_slice(&me.read_leftover[..n]);
        me.read_leftover.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RdpTunnel {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Coalesce; the actual SendToServer is issued on flush.
        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        // Submit any buffered bytes as one SendToServer.
        if !me.write_buf.is_empty() {
            let data = core::mem::take(&mut me.write_buf);
            if me.write_tx.send(data).is_err() {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            me.pending += 1;
        }
        // Drain acks until every submitted SendToServer has completed.
        while me.pending > 0 {
            match me.ack_rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(()))) => me.pending -= 1,
                Poll::Ready(Some(Err(e))) => {
                    me.pending -= 1;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
