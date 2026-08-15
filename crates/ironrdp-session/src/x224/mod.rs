use ironrdp_bulk::BulkCompressor;
use ironrdp_core::{WriteBuf, decode};
use ironrdp_dvc::{DrdynvcClient, DvcClientProcessor, DynamicChannelRef};
use ironrdp_pdu::gcc::ChannelName;
use ironrdp_pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason, McsMessage, SendDataIndicationCtx};
use ironrdp_pdu::rdp::autodetect::{AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu};
use ironrdp_pdu::rdp::client_info::CompressionType;
use ironrdp_pdu::rdp::headers::{CompressionFlags, ShareDataCtx, ShareDataPdu};
use ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu;
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use ironrdp_pdu::rdp::session_info::{InfoData, SaveSessionInfoPdu, ServerAutoReconnect};
use ironrdp_pdu::x224::X224;
use ironrdp_svc::{
    StaticChannelSet, SvcMessage, SvcProcessor, SvcProcessorMessages, client_encode_svc_messages_with_max_chunk_len,
};
use tracing::debug;

use crate::{SessionError, SessionErrorExt as _, SessionResult, reason_err};

/// X224 Processor output
#[derive(Debug, Clone)]
pub enum ProcessorOutput {
    /// A buffer with encoded data to send to the server.
    ResponseFrame(Vec<u8>),
    /// A graceful disconnect notification. Client should close the connection upon receiving this.
    Disconnect(DisconnectDescription),
    /// Received a [`ironrdp_pdu::rdp::headers::ServerDeactivateAll`] PDU. Client should execute the
    /// [Deactivation-Reactivation Sequence].
    ///
    /// [Deactivation-Reactivation Sequence]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
    DeactivateAll,
    /// Server Save Session Info notification.
    ///
    /// `logon_complete` is only set for PDU variants that unambiguously report a completed
    /// logon; the source PDU is not retained because it can contain user details and
    /// auto-reconnect cookies.
    SaveSessionInfo { logon_complete: bool },
    /// Server Initiate Multitransport Request. The application should establish a
    /// sideband UDP transport using the request ID and security cookie, then send
    /// a [`MultitransportResponsePdu`] back on the IO channel.
    ///
    /// See [\[MS-RDPBCGR\] 2.2.15.1].
    ///
    /// [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
    /// [`MultitransportResponsePdu`]: ironrdp_pdu::rdp::multitransport::MultitransportResponsePdu
    MultitransportRequest(MultitransportRequestPdu),
    /// Server Auto-Reconnect Cookie from a Save Session Info PDU
    /// ([\[MS-RDPBCGR\] 2.2.4.2]).
    ///
    /// The client should hold onto this and pass it to
    /// `ClientConnector::with_auto_reconnect_cookie` if the connection drops
    /// ungracefully, which lets the server reattach the session without asking
    /// for credentials again ([\[MS-RDPBCGR\] 1.3.1.5]).
    ///
    /// The server replaces the cookie whenever a client connects and again at
    /// hourly intervals (MS-RDPBCGR 3.3.6.2, Auto-Reconnect Cookie Update), so
    /// this can arrive more than once in a session; keep the most recent and
    /// discard the previous one.
    ///
    /// [\[MS-RDPBCGR\] 2.2.4.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18f4f605-0ee3-4175-8a62-cf8775252547
    /// [\[MS-RDPBCGR\] 1.3.1.5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/15b0d1c9-2891-4adb-a45e-deb4aeeeab7c
    AutoReconnectCookie(ServerAutoReconnect),
    /// Server rejected a Client Auto-Reconnect Packet ([\[MS-RDPBCGR\] 2.2.4.1]).
    ///
    /// The client must discard its cookie and not report the reconnect as successful.
    ///
    /// [\[MS-RDPBCGR\] 2.2.4.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c
    AutoReconnectFailed,
    /// Auto-detect network characteristics from server ([\[MS-RDPBCGR\] 2.2.14]).
    ///
    /// Currently only surfaces [`AutoDetectRequest::NetworkCharacteristicsResult`].
    /// RTT requests are handled internally with automatic responses.
    ///
    /// [\[MS-RDPBCGR\] 2.2.14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dc672839-4f4e-40b1-a71c-cd6a959baa38
    AutoDetect(AutoDetectRequest),
    /// Slow-path graphics update ([MS-RDPBCGR] 2.2.9.1.1.3).
    /// Raw update payload starting with `updateType(u16)`.
    GraphicsUpdate(Vec<u8>),
    /// Slow-path pointer update ([MS-RDPBCGR] 2.2.9.1.1.4).
    /// Raw pointer payload starting with `messageType(u16) + pad(u16)`.
    PointerUpdate(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum DisconnectDescription {
    /// Includes the reason from the MCS Disconnect Provider Ultimatum.
    /// This is the least-specific disconnect reason and is only used
    /// when a more specific disconnect code is not available.
    McsDisconnect(DisconnectReason),

    /// Includes the error information sent by the RDP server when there
    /// is a connection or disconnection failure.
    ErrorInfo(ErrorInfo),
}

pub struct Processor {
    static_channels: StaticChannelSet,
    user_channel_id: u16,
    io_channel_id: u16,
    message_channel_id: Option<u16>,
    share_id: u32,
    /// Continuous network auto-detect ([MS-RDPBCGR] 2.2.14) bandwidth-measurement
    /// state. Between a Bandwidth Measure Start and Stop the server relies on the
    /// ambient inbound PDU traffic as the measurement payload, so the window is timed
    /// (`bw_measure_start`) and every inbound PDU's byte length is tallied
    /// (`bw_measure_bytes`) while `bw_measuring` is set, then reported on the Stop.
    /// Mirrors FreeRDP's `autodetect_recv_bandwidth_measure_*`.
    bw_measure_start: Option<std::time::Instant>,
    bw_measure_bytes: u32,
    bw_measuring: bool,
}

impl Processor {
    pub fn new(
        static_channels: StaticChannelSet,
        user_channel_id: u16,
        io_channel_id: u16,
        message_channel_id: Option<u16>,
        share_id: u32,
    ) -> Self {
        Self {
            static_channels,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            share_id,
            bw_measure_start: None,
            bw_measure_bytes: 0,
            bw_measuring: false,
        }
    }

    pub fn set_share_id(&mut self, share_id: u32) {
        self.share_id = share_id;
    }

    /// Whether a continuous network auto-detect bandwidth-measurement window is
    /// currently open (between a Bandwidth Measure Start and Stop). While open, the
    /// caller must feed every inbound PDU's byte length to [`count_bw_bytes`] so the
    /// Bandwidth Measure Results reflect real throughput.
    ///
    /// [`count_bw_bytes`]: Self::count_bw_bytes
    pub fn bw_measuring(&self) -> bool {
        self.bw_measuring
    }

    /// Tally `n` inbound bytes toward the open bandwidth-measurement window. A no-op
    /// unless [`bw_measuring`](Self::bw_measuring) is set. Counts both fast-path and
    /// X.224 traffic, mirroring FreeRDP which tallies every received PDU.
    pub fn count_bw_bytes(&mut self, n: usize) {
        if self.bw_measuring {
            self.bw_measure_bytes = self
                .bw_measure_bytes
                .saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        }
    }

    /// Updates the negotiated maximum payload length of outgoing static virtual channel chunks.
    pub fn set_static_channel_chunk_size(&mut self, maximum_chunk_size: usize) -> bool {
        self.static_channels.set_maximum_chunk_size(maximum_chunk_size)
    }

    /// Returns the negotiated maximum payload length of outgoing static virtual channel chunks.
    pub fn static_channel_chunk_size(&self) -> usize {
        self.static_channels.maximum_chunk_size()
    }

    pub fn get_svc_processor<T: SvcProcessor + 'static>(&self) -> Option<&T> {
        self.static_channels
            .get_by_type::<T>()
            .and_then(|svc| svc.channel_processor_downcast_ref())
    }

    pub fn get_svc_processor_mut<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.static_channels
            .get_by_type_mut::<T>()
            .and_then(|svc| svc.channel_processor_downcast_mut())
    }

    /// Completes user's SVC request with data, required to sent it over the network and returns
    /// a buffer with encoded data.
    pub fn process_svc_processor_messages<C: SvcProcessor + 'static>(
        &self,
        messages: SvcProcessorMessages<C>,
    ) -> SessionResult<Vec<u8>> {
        let channel_id = self
            .static_channels
            .get_channel_id_by_type::<C>()
            .ok_or_else(|| reason_err!("SVC", "channel not found"))?;

        process_svc_messages(
            messages.into(),
            channel_id,
            self.user_channel_id,
            self.static_channels.maximum_chunk_size(),
        )
    }

    /// Completes an SVC request for a runtime-defined channel name.
    pub fn process_svc_messages_by_name(
        &self,
        channel_name: &ChannelName,
        messages: Vec<SvcMessage>,
    ) -> SessionResult<Vec<u8>> {
        let channel_id = self
            .static_channels
            .get_channel_id_by_channel_name(channel_name)
            .ok_or_else(|| reason_err!("SVC", "channel not found"))?;

        process_svc_messages(
            messages,
            channel_id,
            self.user_channel_id,
            self.static_channels.maximum_chunk_size(),
        )
    }

    pub fn get_dvc<T: DvcClientProcessor + 'static>(&self) -> Option<DynamicChannelRef<'_, T>> {
        self.get_svc_processor::<DrdynvcClient>()?.get_dvc::<T>()
    }

    pub fn get_dvc_by_channel_id<T: DvcClientProcessor + 'static>(
        &self,
        channel_id: u32,
    ) -> Option<DynamicChannelRef<'_, T>> {
        self.get_svc_processor::<DrdynvcClient>()?
            .get_dvc_by_channel_id(channel_id)
    }

    /// Processes a received PDU. Returns a vector of [`ProcessorOutput`] that must be processed
    /// in the returned order.
    pub fn process(
        &mut self,
        frame: &[u8],
        bulk_decompressor: &mut Option<BulkCompressor>,
    ) -> SessionResult<Vec<ProcessorOutput>> {
        let data_ctx: SendDataIndicationCtx<'_> =
            ironrdp_pdu::mcs::decode_send_data_indication(frame).map_err(SessionError::decode)?;
        let channel_id = data_ctx.channel_id;

        if channel_id == self.io_channel_id {
            self.process_io_channel(data_ctx, bulk_decompressor)
        } else if self.message_channel_id == Some(channel_id) {
            self.process_message_channel(data_ctx)
        } else {
            let maximum_chunk_size = self.static_channels.maximum_chunk_size();
            if let Some(svc) = self.static_channels.get_by_channel_id_mut(channel_id) {
                let response_pdus = svc.process(data_ctx.user_data).map_err(SessionError::pdu)?;
                process_svc_messages(response_pdus, channel_id, data_ctx.initiator_id, maximum_chunk_size)
                    .map(|data| vec![ProcessorOutput::ResponseFrame(data)])
            } else {
                Err(reason_err!("X224", "unexpected channel received: ID {channel_id}"))
            }
        }
    }

    fn process_io_channel(
        &mut self,
        data_ctx: SendDataIndicationCtx<'_>,
        bulk_decompressor: &mut Option<BulkCompressor>,
    ) -> SessionResult<Vec<ProcessorOutput>> {
        debug_assert_eq!(data_ctx.channel_id, self.io_channel_id);

        let io_channel = ironrdp_pdu::rdp::headers::decode_io_channel(data_ctx).map_err(SessionError::decode)?;

        match io_channel {
            ironrdp_pdu::rdp::headers::IoChannelPdu::Data(ctx) => Self::process_share_data(ctx, bulk_decompressor),
            ironrdp_pdu::rdp::headers::IoChannelPdu::MultitransportRequest(pdu) => {
                debug!(
                    "Received Initiate Multitransport Request: request_id={}",
                    pdu.request_id
                );
                Ok(vec![ProcessorOutput::MultitransportRequest(pdu)])
            }
            ironrdp_pdu::rdp::headers::IoChannelPdu::DeactivateAll(_) => Ok(vec![ProcessorOutput::DeactivateAll]),
        }
    }

    fn process_share_data(
        ctx: ShareDataCtx,
        bulk_decompressor: &mut Option<BulkCompressor>,
    ) -> SessionResult<Vec<ProcessorOutput>> {
        let ShareDataCtx {
            compression_flags,
            compression_type,
            pdu,
            ..
        } = ctx;
        let (pdu, compression_flags) = match pdu {
            ShareDataPdu::Compressed { pdu_type, data } => {
                let data = Self::decompress_share_data(data, compression_flags, compression_type, bulk_decompressor)?;
                (
                    ShareDataPdu::decode_with_type(&data, pdu_type).map_err(SessionError::decode)?,
                    CompressionFlags::empty(),
                )
            }
            pdu => (pdu, compression_flags),
        };

        match pdu {
            ShareDataPdu::SaveSessionInfo(session_info) => {
                debug!("Got Session Save Info PDU: {session_info:?}");
                let mut outputs = vec![ProcessorOutput::SaveSessionInfo {
                    logon_complete: is_logon_complete(&session_info),
                }];

                // Surface the auto-reconnect cookie alongside the logon status so
                // the consumer can keep it for a later reconnect. Both come out of
                // this one PDU and neither supersedes the other.
                if let InfoData::LogonExtended(extended) = &session_info.info_data {
                    if let Some(cookie) = &extended.auto_reconnect {
                        outputs.push(ProcessorOutput::AutoReconnectCookie(cookie.clone()));
                    }
                }

                Ok(outputs)
            }
            ShareDataPdu::ArcStatusPdu(status) => {
                if status != [0; 4] {
                    return Err(reason_err!("IO channel", "invalid auto-reconnect status PDU"));
                }

                Ok(vec![ProcessorOutput::AutoReconnectFailed])
            }
            // FIXME: workaround fix to not terminate the session on "unhandled PDU: Set Keyboard Indicators PDU"
            ShareDataPdu::SetKeyboardIndicators(data) => {
                debug!("Got Keyboard Indicators PDU: {data:?}");
                Ok(Vec::new())
            }
            ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(ErrorInfo::ProtocolIndependentCode(
                ProtocolIndependentCode::None,
            ))) => {
                debug!("Received None server error");
                Ok(Vec::new())
            }
            ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(e)) => {
                // This is a part of server-side graceful disconnect procedure defined
                // in [MS-RDPBCGR].
                //
                // [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/149070b0-ecec-4c20-af03-934bbc48adb8
                let desc = DisconnectDescription::ErrorInfo(e);
                Ok(vec![ProcessorOutput::Disconnect(desc)])
            }
            ShareDataPdu::ShutdownDenied => {
                debug!("ShutdownDenied received, session will be closed");

                // As defined in [MS-RDPBCGR], when `ShareDataPdu::ShutdownDenied` is received, we
                // need to send a disconnect ultimatum to the server if we want to proceed with the
                // session shutdown.
                //
                // [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/27915739-8f77-487e-9927-55008af7fd68
                let ultimatum = McsMessage::DisconnectProviderUltimatum(DisconnectProviderUltimatum::from_reason(
                    DisconnectReason::UserRequested,
                ));

                let encoded_pdu = ironrdp_core::encode_vec(&X224(ultimatum)).map_err(SessionError::encode);

                Ok(vec![
                    ProcessorOutput::ResponseFrame(encoded_pdu?),
                    ProcessorOutput::Disconnect(DisconnectDescription::McsDisconnect(DisconnectReason::UserRequested)),
                ])
            }
            ShareDataPdu::Update(data) => {
                let data = Self::decompress_share_data(data, compression_flags, compression_type, bulk_decompressor)?;
                debug!("Got slow-path graphics update ({} bytes)", data.len());
                Ok(vec![ProcessorOutput::GraphicsUpdate(data)])
            }
            ShareDataPdu::Pointer(data) => {
                let data = Self::decompress_share_data(data, compression_flags, compression_type, bulk_decompressor)?;
                debug!("Got slow-path pointer update ({} bytes)", data.len());
                Ok(vec![ProcessorOutput::PointerUpdate(data)])
            }
            pdu => Err(reason_err!("IO channel", "unhandled PDU: {:?}", pdu.as_short_name())),
        }
    }

    fn decompress_share_data(
        data: Vec<u8>,
        compression_flags: CompressionFlags,
        compression_type: CompressionType,
        bulk_decompressor: &mut Option<BulkCompressor>,
    ) -> SessionResult<Vec<u8>> {
        if compression_flags.is_empty() {
            return Ok(data);
        }

        let decompressor = bulk_decompressor
            .as_mut()
            .ok_or_else(|| reason_err!("slow-path", "received compressed share data without a decompressor"))?;
        let flags = u32::from(compression_flags.bits()) | u32::from(compression_type.as_u8());
        let decompressed = decompressor
            .decompress(&data, flags)
            .map_err(|error| reason_err!("slow-path", "bulk decompression failed: {error}"))?
            .to_vec();
        debug!(
            compressed_size = data.len(),
            decompressed_size = decompressed.len(),
            ?compression_type,
            "Decompressed slow-path share data"
        );
        Ok(decompressed)
    }

    /// Process an auto-detect request received on the MCS message channel.
    ///
    /// During continuous auto-detection ([MS-RDPBCGR] 2.2.14) the server sends
    /// RTT (and bandwidth) requests on the message channel; the client answers
    /// RTT requests and surfaces the final Network Characteristics Result.
    fn process_message_channel(&mut self, data_ctx: SendDataIndicationCtx<'_>) -> SessionResult<Vec<ProcessorOutput>> {
        use ironrdp_pdu::rdp::autodetect::{BW_RESULTS_CONNECT_TIME, BW_RESULTS_CONTINUOUS, BW_STOP_CONNECT_TIME};

        let Some(message_channel_id) = self.message_channel_id else {
            return Err(reason_err!("message channel", "no message channel negotiated"));
        };

        let req = decode::<AutoDetectReqPdu>(data_ctx.user_data).map_err(SessionError::decode)?;

        match req.request {
            AutoDetectRequest::RttRequest { sequence_number, .. } => {
                debug!(sequence_number, "Responded to auto-detect RTT request");
                self.encode_autodetect_response(message_channel_id, AutoDetectResponse::RttResponse { sequence_number })
            }
            // Bandwidth Measure Start ([MS-RDPBCGR] 2.2.14.1.2): open the measurement
            // window. In continuous mode there is no payload PDU; the server relies on
            // the ambient inbound traffic between Start and Stop, so just latch the
            // clock and byte counter and count subsequent PDUs in `process`.
            AutoDetectRequest::BandwidthMeasureStart { sequence_number, .. } => {
                self.bw_measure_start = Some(std::time::Instant::now());
                self.bw_measure_bytes = 0;
                self.bw_measuring = true;
                debug!(sequence_number, "Auto-detect bandwidth measure started");
                Ok(Vec::new())
            }
            // Bandwidth Measure Payload ([MS-RDPBCGR] 2.2.14.1.3): connect-time only,
            // but count it if a server sends one mid-session.
            AutoDetectRequest::BandwidthMeasurePayload { payload, .. } => {
                self.bw_measure_bytes = self
                    .bw_measure_bytes
                    .saturating_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
                Ok(Vec::new())
            }
            // Bandwidth Measure Stop ([MS-RDPBCGR] 2.2.14.1.4): close the window and
            // reply with Bandwidth Measure Results so the server learns our throughput.
            // timeDelta = elapsed since Start; byteCount = bytes tallied in the window.
            AutoDetectRequest::BandwidthMeasureStop {
                sequence_number,
                request_type,
                payload,
            } => {
                if let Some(bytes) = payload {
                    self.bw_measure_bytes = self
                        .bw_measure_bytes
                        .saturating_add(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
                }
                let time_delta_ms = self
                    .bw_measure_start
                    .take()
                    .map(|start| u32::try_from(start.elapsed().as_millis()).unwrap_or(u32::MAX))
                    .unwrap_or(0);
                let byte_count = self.bw_measure_bytes;
                self.bw_measuring = false;
                let response_type = if request_type == BW_STOP_CONNECT_TIME {
                    BW_RESULTS_CONNECT_TIME
                } else {
                    BW_RESULTS_CONTINUOUS
                };
                debug!(
                    sequence_number,
                    time_delta_ms, byte_count, "Sent auto-detect bandwidth results"
                );
                self.encode_autodetect_response(
                    message_channel_id,
                    AutoDetectResponse::BandwidthMeasureResults {
                        sequence_number,
                        response_type,
                        time_delta_ms,
                        byte_count,
                    },
                )
            }
            req @ AutoDetectRequest::NetworkCharacteristicsResult { .. } => {
                debug!(?req, "Received network characteristics from server");
                Ok(vec![ProcessorOutput::AutoDetect(req)])
            }
        }
    }

    /// Encode an [`AutoDetectResponse`] as a Send Data Request on the message
    /// channel, returning it as a single [`ProcessorOutput::ResponseFrame`].
    fn encode_autodetect_response(
        &self,
        message_channel_id: u16,
        response: AutoDetectResponse,
    ) -> SessionResult<Vec<ProcessorOutput>> {
        let response = AutoDetectRspPdu::new(response);
        let mut frame = WriteBuf::new();
        ironrdp_pdu::mcs::encode_send_data_request(self.user_channel_id, message_channel_id, &response, &mut frame)
            .map_err(SessionError::encode)?;
        Ok(vec![ProcessorOutput::ResponseFrame(frame.into_inner())])
    }

    /// Send a pdu on the static global channel. Typically used to send input events
    pub fn encode_static(&self, output: &mut WriteBuf, pdu: ShareDataPdu) -> SessionResult<usize> {
        let written = ironrdp_pdu::rdp::headers::encode_share_data(
            self.user_channel_id,
            self.io_channel_id,
            self.share_id,
            pdu,
            output,
        )
        .map_err(SessionError::encode)?;
        Ok(written)
    }
}

fn is_logon_complete(session_info: &SaveSessionInfoPdu) -> bool {
    matches!(
        session_info.info_data,
        InfoData::LogonInfoV1(_) | InfoData::LogonInfoV2(_) | InfoData::PlainNotify
    )
}

/// Processes a vector of [`SvcMessage`] in preparation for sending them to the server on the `channel_id` channel.
///
/// This includes chunkifying the messages, adding MCS, x224, and tpkt headers, and encoding them into a buffer.
/// The messages returned here are ready to be sent to the server.
///
/// The caller is responsible for ensuring that the `channel_id` corresponds to the correct channel.
fn process_svc_messages(
    messages: Vec<SvcMessage>,
    channel_id: u16,
    initiator_id: u16,
    maximum_chunk_size: usize,
) -> SessionResult<Vec<u8>> {
    client_encode_svc_messages_with_max_chunk_len(messages, channel_id, initiator_id, maximum_chunk_size)
        .map_err(SessionError::encode)
}

#[cfg(test)]
mod tests {
    use ironrdp_bulk::{CompressionType as BulkCompressionType, flags};
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::rdp::headers::ShareDataPduType;
    use ironrdp_pdu::rdp::session_info::{InfoType, LogonExFlags, LogonInfoExtended};

    use super::*;

    #[test]
    fn processor_decompresses_slow_path_share_data() {
        let source = vec![b'A'; 1024];
        let mut compressor = BulkCompressor::new(BulkCompressionType::Rdp5);
        let (compressed_size, flags) = compressor.compress(&source).expect("source should compress");
        assert_ne!(flags & flags::PACKET_COMPRESSED, 0, "test data must be compressed");
        let compressed = compressor.compressed_data(compressed_size).to_vec();
        let mut bulk_decompressor = Some(BulkCompressor::new(BulkCompressionType::Rdp5));
        let compression_flags = CompressionFlags::from_bits_retain(
            u8::try_from(flags & !flags::COMPRESSION_TYPE_MASK).expect("bulk flags should fit in a byte"),
        );

        assert_eq!(
            Processor::decompress_share_data(
                compressed,
                compression_flags,
                CompressionType::K64,
                &mut bulk_decompressor
            )
            .expect("compressed slow-path data should decompress"),
            source
        );
    }

    #[test]
    fn processor_rejects_compressed_slow_path_data_without_a_decompressor() {
        let mut bulk_decompressor = None;

        assert!(
            Processor::decompress_share_data(
                vec![0],
                CompressionFlags::COMPRESSED,
                CompressionType::K64,
                &mut bulk_decompressor
            )
            .is_err()
        );
    }

    #[test]
    fn processor_decompresses_compressed_save_session_info() {
        let session_info = SaveSessionInfoPdu {
            info_type: InfoType::PlainNotify,
            info_data: InfoData::PlainNotify,
        };
        let source = encode_vec(&session_info).expect("encode save session info");
        let mut compressor = BulkCompressor::new(BulkCompressionType::Rdp5);
        let (compressed_size, flags) = compressor.compress(&source).expect("source should compress");
        assert_ne!(flags & flags::PACKET_COMPRESSED, 0, "test data must be compressed");
        let compressed = compressor.compressed_data(compressed_size).to_vec();
        let mut bulk_decompressor = Some(BulkCompressor::new(BulkCompressionType::Rdp5));
        let compression_flags = CompressionFlags::from_bits_retain(
            u8::try_from(flags & !flags::COMPRESSION_TYPE_MASK).expect("bulk flags should fit in a byte"),
        );
        let outputs = Processor::process_share_data(
            ShareDataCtx {
                initiator_id: 0,
                channel_id: 0,
                share_id: 0,
                pdu_source: 0,
                compression_flags,
                compression_type: CompressionType::K64,
                pdu: ShareDataPdu::Compressed {
                    pdu_type: ShareDataPduType::SaveSessionInfo,
                    data: compressed,
                },
            },
            &mut bulk_decompressor,
        )
        .expect("compressed save session info should be processed");

        assert!(matches!(
            outputs.as_slice(),
            [ProcessorOutput::SaveSessionInfo { logon_complete: true }]
        ));
    }

    #[test]
    fn extended_session_info_does_not_signal_login_completion() {
        let session_info = SaveSessionInfoPdu {
            info_type: InfoType::LogonExtended,
            info_data: InfoData::LogonExtended(LogonInfoExtended {
                present_fields_flags: LogonExFlags::AUTO_RECONNECT_COOKIE,
                auto_reconnect: None,
                errors_info: None,
            }),
        };

        assert!(!is_logon_complete(&session_info));
    }

    #[test]
    fn plain_notify_signals_login_completion() {
        let session_info = SaveSessionInfoPdu {
            info_type: InfoType::PlainNotify,
            info_data: InfoData::PlainNotify,
        };

        assert!(is_logon_complete(&session_info));
    }

    #[test]
    fn processor_surfaces_valid_auto_reconnect_status() {
        let mut bulk_decompressor = None;
        let outputs = Processor::process_share_data(
            ShareDataCtx {
                initiator_id: 0,
                channel_id: 0,
                share_id: 0,
                pdu_source: 0,
                compression_flags: CompressionFlags::empty(),
                compression_type: CompressionType::K64,
                pdu: ShareDataPdu::ArcStatusPdu(vec![0; 4]),
            },
            &mut bulk_decompressor,
        )
        .expect("valid auto-reconnect status PDU should be processed");

        assert!(matches!(outputs.as_slice(), [ProcessorOutput::AutoReconnectFailed]));
    }

    #[test]
    fn processor_rejects_invalid_auto_reconnect_status() {
        let mut bulk_decompressor = None;

        assert!(
            Processor::process_share_data(
                ShareDataCtx {
                    initiator_id: 0,
                    channel_id: 0,
                    share_id: 0,
                    pdu_source: 0,
                    compression_flags: CompressionFlags::empty(),
                    compression_type: CompressionType::K64,
                    pdu: ShareDataPdu::ArcStatusPdu(vec![0, 0, 0]),
                },
                &mut bulk_decompressor,
            )
            .is_err()
        );
    }
}
