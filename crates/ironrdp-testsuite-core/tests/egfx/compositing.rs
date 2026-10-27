use std::sync::{Arc, Mutex};

use ironrdp_core::encode_vec;
use ironrdp_dvc::{DvcMessage, DvcProcessor as _};
use ironrdp_egfx::client::{BitmapUpdate, GraphicsPipelineClient, GraphicsPipelineHandler, Surface};
use ironrdp_egfx::pdu::{
    CacheImportReplyPdu, CacheToSurfacePdu, CapabilitiesConfirmPdu, CapabilitiesV107Flags, CapabilitySet, Codec1Type,
    Color, CreateSurfacePdu, DeleteEncodingContextPdu, EndFramePdu, EvictCacheEntryPdu, GfxPdu, MapSurfaceToOutputPdu,
    MapSurfaceToScaledOutputPdu, MapSurfaceToScaledWindowPdu, MapSurfaceToWindowPdu, PixelFormat, Point,
    ResetGraphicsPdu, SolidFillPdu, StartFramePdu, SurfaceToCachePdu, SurfaceToSurfacePdu, Timestamp,
    WireToSurface1Pdu, WireToSurface2Pdu,
};
use ironrdp_graphics::clearcodec::ClearCodecEncoder;
use ironrdp_graphics::zgfx::wrap_uncompressed;
use ironrdp_pdu::geometry::ExclusiveRectangle;

const TIMESTAMP: Timestamp = Timestamp {
    milliseconds: 0,
    seconds: 0,
    minutes: 0,
    hours: 0,
};

/// Records every handler callback with its arguments.
struct CallLog(Arc<Mutex<Vec<String>>>);

impl CallLog {
    fn record(&self, call: String) {
        self.0.lock().expect("call log").push(call);
    }
}

impl GraphicsPipelineHandler for CallLog {
    fn capabilities(&self) -> Vec<CapabilitySet> {
        self.record("capabilities".to_owned());
        vec![CapabilitySet::V10_7 {
            flags: CapabilitiesV107Flags::empty(),
        }]
    }
    fn on_capabilities_confirmed(&mut self, caps: &CapabilitySet) {
        self.record(format!("capabilities_confirmed {caps:?}"));
    }
    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        self.record(format!("reset_graphics {width}x{height}"));
    }
    fn on_reset_graphics_rejected(&mut self, width: u32, height: u32) {
        self.record(format!("reset_graphics_rejected {width}x{height}"));
    }
    fn on_surface_created(&mut self, surface: &Surface) {
        self.record(format!("surface_created {surface:?}"));
    }
    fn on_surface_deleted(&mut self, surface_id: u16) {
        self.record(format!("surface_deleted {surface_id}"));
    }
    fn on_surface_mapped(&mut self, surface_id: u16, origin_x: u32, origin_y: u32) {
        self.record(format!("surface_mapped {surface_id} {origin_x},{origin_y}"));
    }
    fn on_bitmap_updated(&mut self, update: &BitmapUpdate) {
        self.record(format!("bitmap_updated {update:?}"));
    }
    fn on_frame_complete(&mut self, frame_id: u32) {
        self.record(format!("frame_complete {frame_id}"));
    }
    fn on_close(&mut self) {
        self.record("close".to_owned());
    }
    fn on_solid_fill(&mut self, pdu: &SolidFillPdu) {
        self.record(format!("solid_fill {pdu:?}"));
    }
    fn on_surface_to_surface(&mut self, pdu: &SurfaceToSurfacePdu) {
        self.record(format!("surface_to_surface {pdu:?}"));
    }
    fn on_surface_to_cache(&mut self, pdu: &SurfaceToCachePdu) {
        self.record(format!("surface_to_cache {pdu:?}"));
    }
    fn on_cache_to_surface(&mut self, pdu: &CacheToSurfacePdu) {
        self.record(format!("cache_to_surface {pdu:?}"));
    }
    fn on_evict_cache_entry(&mut self, pdu: &EvictCacheEntryPdu) {
        self.record(format!("evict_cache_entry {pdu:?}"));
    }
    fn on_map_surface_to_window(&mut self, pdu: &MapSurfaceToWindowPdu) {
        self.record(format!("map_surface_to_window {pdu:?}"));
    }
    fn on_map_surface_to_scaled_output(&mut self, pdu: &MapSurfaceToScaledOutputPdu) {
        self.record(format!("map_surface_to_scaled_output {pdu:?}"));
    }
    fn on_map_surface_to_scaled_window(&mut self, pdu: &MapSurfaceToScaledWindowPdu) {
        self.record(format!("map_surface_to_scaled_window {pdu:?}"));
    }
    fn on_wire_to_surface2(&mut self, pdu: &WireToSurface2Pdu) {
        self.record(format!("wire_to_surface2 {pdu:?}"));
    }
    fn on_delete_encoding_context(&mut self, pdu: &DeleteEncodingContextPdu) {
        self.record(format!("delete_encoding_context {pdu:?}"));
    }
    fn on_cache_import_reply(&mut self, pdu: &CacheImportReplyPdu) {
        self.record(format!("cache_import_reply {pdu:?}"));
    }
    fn on_unhandled_pdu(&mut self, pdu: &GfxPdu) {
        self.record(format!("unhandled_pdu {pdu:?}"));
    }
}

fn rect(left: u16, top: u16, right: u16, bottom: u16) -> ExclusiveRectangle {
    ExclusiveRectangle {
        left,
        top,
        right,
        bottom,
    }
}

/// One frame whose commands reach every compositor path: surfaces and their mapping, a decoded
/// bitmap, a fill, a surface copy, and a bitmap-cache store and paste.
fn commands() -> Vec<GfxPdu> {
    let bgra: Vec<u8> = (0..16).flat_map(|_| [0x00, 0x00, 0xFF, 0xFF]).collect();
    vec![
        GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V10_7 {
            flags: CapabilitiesV107Flags::empty(),
        })),
        GfxPdu::ResetGraphics(ResetGraphicsPdu {
            width: 64,
            height: 64,
            monitors: vec![],
        }),
        GfxPdu::CreateSurface(CreateSurfacePdu {
            surface_id: 1,
            width: 16,
            height: 16,
            pixel_format: PixelFormat::XRgb,
        }),
        GfxPdu::CreateSurface(CreateSurfacePdu {
            surface_id: 2,
            width: 16,
            height: 16,
            pixel_format: PixelFormat::XRgb,
        }),
        GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu {
            surface_id: 1,
            output_origin_x: 0,
            output_origin_y: 0,
        }),
        GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu {
            surface_id: 2,
            output_origin_x: 16,
            output_origin_y: 0,
        }),
        GfxPdu::StartFrame(StartFramePdu {
            timestamp: TIMESTAMP,
            frame_id: 1,
        }),
        GfxPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id: 1,
            codec_id: Codec1Type::ClearCodec,
            pixel_format: PixelFormat::XRgb,
            destination_rectangle: rect(0, 0, 4, 4),
            bitmap_data: ClearCodecEncoder::new().encode(&bgra, 4, 4),
        }),
        GfxPdu::SolidFill(SolidFillPdu {
            surface_id: 1,
            fill_pixel: Color {
                r: 0,
                g: 255,
                b: 0,
                xa: 255,
            },
            rectangles: vec![rect(4, 4, 8, 8)],
        }),
        GfxPdu::SurfaceToSurface(SurfaceToSurfacePdu {
            source_surface_id: 1,
            destination_surface_id: 2,
            source_rectangle: rect(0, 0, 8, 8),
            destination_points: vec![Point { x: 8, y: 8 }],
        }),
        GfxPdu::SurfaceToCache(SurfaceToCachePdu {
            surface_id: 1,
            cache_key: 7,
            cache_slot: 0,
            source_rectangle: rect(0, 0, 8, 8),
        }),
        GfxPdu::CacheToSurface(CacheToSurfacePdu {
            surface_id: 2,
            cache_slot: 0,
            destination_points: vec![Point { x: 0, y: 0 }],
        }),
        GfxPdu::EndFrame(EndFramePdu { frame_id: 1 }),
    ]
}

/// Run [`commands`] through a client and return it with its handler calls and encoded responses.
fn run(compositing: bool) -> (GraphicsPipelineClient, Vec<String>, Vec<Vec<u8>>) {
    let encode = |messages: Vec<DvcMessage>| -> Vec<Vec<u8>> {
        messages
            .iter()
            .map(|message| encode_vec(message.as_ref()).expect("encode response"))
            .collect()
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut client =
        GraphicsPipelineClient::new(Box::new(CallLog(Arc::clone(&calls))), None).with_compositing(compositing);
    let mut responses = encode(client.start(0).expect("start"));
    for pdu in commands() {
        let payload = wrap_uncompressed(&encode_vec(&pdu).expect("encode PDU"));
        responses.extend(encode(client.process(0, &payload).expect("process")));
    }
    let calls = calls.lock().expect("call log").clone();
    (client, calls, responses)
}

// oracle: reference GraphicsPipelineClient with compositing on, run on the same commands
#[test]
fn compositing_off_keeps_every_handler_call_and_response() {
    let (_, calls_on, responses_on) = run(true);
    let (_, calls_off, responses_off) = run(false);

    for call in [
        "bitmap_updated",
        "solid_fill",
        "surface_to_surface",
        "surface_to_cache",
        "cache_to_surface",
        "frame_complete",
    ] {
        assert!(
            calls_on.iter().any(|recorded| recorded.starts_with(call)),
            "the commands must reach {call}"
        );
    }
    assert_eq!(calls_off, calls_on);
    assert_eq!(responses_off, responses_on);
}

// oracle: reference GraphicsPipelineClient with compositing on, which draws the same commands into its output
#[test]
fn compositing_off_produces_no_output() {
    let (mut on, _, _) = run(true);
    assert!(!on.drain_output().is_empty(), "the commands draw into the output");
    assert!(on.take_output_reset().is_some(), "the commands reset the output");

    let (mut off, _, _) = run(false);
    assert!(off.drain_output().is_empty());
    assert!(off.drain_window_updates().is_empty());
    assert!(off.take_output_reset().is_none());
}
