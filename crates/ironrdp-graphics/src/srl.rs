//! SRL (Simplified Run-Length) entropy codec for progressive upgrade passes.
//!
//! Used during progressive TILE_UPGRADE decoding where the tri-state sign
//! array (DAS) indicates zero-valued coefficients. SRL encodes/decodes
//! magnitudes for coefficients that were previously zero.
//!
//! The algorithm is similar to RLGR's zero-run mode with a simpler structure:
//! adaptive K parameter controlling zero-run lengths, followed by unary-coded
//! magnitudes with sign bits.

/// Decode SRL data for a set of zero-valued (DAS=0) coefficient positions.
///
/// `data` is the SRL byte stream (terminated by a 0x00 sentinel).
/// `num_values` is the number of coefficients to decode.
/// `num_bits` is the bit width for each magnitude value.
///
/// Returns a vector of decoded signed coefficient values. Zero entries
/// mean the coefficient remains zero after this upgrade pass.
pub fn decode_srl(data: &[u8], num_values: usize, num_bits: u8) -> Vec<i16> {
    if num_values == 0 || data.is_empty() {
        return vec![0; num_values];
    }

    let mut output = vec![0i16; num_values];
    let mut reader = BitReader::new(data);
    let mut kp: u32 = 0;
    let mut out_idx = 0;
    let mut nz: u32 = 0; // remaining zeros in current run

    while out_idx < num_values {
        let k = kp >> 3;

        if nz > 0 {
            // Still emitting zeros from a previous run
            nz -= 1;
            output[out_idx] = 0;
            out_idx += 1;
            continue;
        }

        // Zero-run mode: chunk_size = 1 << k (1 when k=0).
        // read_bits(0) returns 0, so k=0 degenerates to single-zero runs.
        {
            let bit = reader.read_bit();
            if !bit {
                nz = 1u32.checked_shl(k).unwrap_or(0);
                kp = kp.saturating_add(4).min(80);
                nz -= 1;
                output[out_idx] = 0;
                out_idx += 1;
                continue;
            }
            let zeros = reader.read_bits(k);
            if zeros > 0 {
                nz = zeros;
                nz -= 1;
                output[out_idx] = 0;
                out_idx += 1;
                continue;
            }
            // Fall through to unary mode (no more zeros)
        }

        // Unary mode: decode a non-zero magnitude
        kp = kp.saturating_sub(6);

        if num_bits == 0 {
            // No bits to decode, just emit +/-1 from sign bit
            let sign = reader.read_bit();
            output[out_idx] = if sign { -1 } else { 1 };
            out_idx += 1;
            continue;
        }

        // Read sign bit
        let sign = reader.read_bit();

        if num_bits == 1 {
            output[out_idx] = if sign { -1 } else { 1 };
            out_idx += 1;
            continue;
        }

        // Decode unary quotient: count 0-bits before the terminating 1-bit.
        // magnitude = (quotient << extra_bits) | remainder.
        let mut quotient: u32 = 0;
        loop {
            let bit = reader.read_bit();
            if bit || quotient >= 0x8000 {
                break;
            }
            quotient += 1;
        }

        let extra_bits = u32::from(num_bits).saturating_sub(1);
        let magnitude = if extra_bits > 0 && extra_bits < 16 {
            let remainder = reader.read_bits(extra_bits);
            (quotient << extra_bits) | remainder
        } else {
            quotient
        };

        let value = i16::try_from(magnitude.min(0x7FFF)).unwrap_or(i16::MAX);
        output[out_idx] = if sign { -value } else { value };
        out_idx += 1;
    }

    output
}

/// A stateful SRL decoder that threads its bit position **and** adaptive `kp`/`nz`
/// run state across successive [`next_value`](SrlReader::next_value) calls.
///
/// This matters for RFX Progressive TILE_UPGRADE: a component (Y/Cb/Cr) carries a
/// **single** SRL stream shared by all ten DWT subbands, and the adaptive state
/// and a zero-run may straddle subband boundaries (FreeRDP threads one
/// `RFX_PROGRESSIVE_UPGRADE_STATE` through every band). Decoding each band with a
/// fresh [`decode_srl`] call — restarting the bit position and `kp`/`nz` at zero —
/// re-consumes the same leading bytes for every band and corrupts every subband
/// after the first refined one. Keep one `SrlReader` for the whole component.
///
/// This is the threaded reader used by the v2/v3 progressive upgrade variants; the
/// standalone [`decode_srl`] above is the v1 baseline (fresh per band).
///
/// `num_bits` is supplied per call because it is the *current band's* magnitude
/// width and differs between bands; only the non-zero magnitude decode uses it,
/// while the zero-run machinery is driven entirely by the persistent `kp`.
pub struct SrlReader<'a> {
    reader: BitReader<'a>,
    kp: u32,
    nz: u32, // remaining zeros in the current run
    /// Escape state: `true` once a `'1'` zero-run escape has been read, meaning the
    /// next value (after any remainder zeros drain) is a magnitude, not a fresh
    /// zero-run. FreeRDP's `RFX_PROGRESSIVE_UPGRADE_STATE.mode` — without it, the
    /// remainder-zeros-then-magnitude case desyncs the stream.
    mode: bool,
}

impl<'a> SrlReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            reader: BitReader::new(data),
            // FreeRDP inits `state.kp = 8` (progressive.c:1272) → initial Golomb
            // k = kp>>3 = 1 (chunk size 2), mirroring RLGR1's `kp = k<<3`. Starting
            // at 0 parses every leading zero-run with the wrong chunk size and
            // desyncs the stream from the first value.
            kp: 8,
            nz: 0,
            mode: false,
        }
    }

    /// Decode one coefficient magnitude (signed), advancing the shared state.
    /// A returned `0` means the coefficient stays zero after this upgrade pass.
    pub fn next_value(&mut self, num_bits: u8) -> i16 {
        // Still emitting zeros from a previous run.
        if self.nz > 0 {
            self.nz -= 1;
            return 0;
        }

        let k = self.kp >> 3;

        if !self.mode {
            // Zero-encoding block.
            if !self.reader.read_bit() {
                // '0': a full run of `1 << k` zeros; emit the first, hold the rest.
                self.nz = 1u32.checked_shl(k).unwrap_or(0);
                self.kp = (self.kp + 4).min(80);
                self.nz = self.nz.saturating_sub(1);
                return 0;
            }
            // '1' escape: a short run of `read_bits(k)` zeros, then a magnitude.
            // Setting `mode` is what makes the *next* value (after these zeros
            // drain) a magnitude instead of a fresh zero-run — the FreeRDP state
            // machine (progressive.c L1108-1133).
            self.mode = true;
            self.nz = self.reader.read_bits(k);
            if self.nz > 0 {
                self.nz -= 1;
                return 0;
            }
            // No remainder zeros — fall through to the magnitude in this call.
        }

        // Value (magnitude) block; clear `mode` so the next value starts a new run.
        self.mode = false;
        let sign = self.reader.read_bit();
        self.kp = self.kp.saturating_sub(6);
        if num_bits <= 1 {
            return if sign { -1 } else { 1 };
        }

        // Truncated unary magnitude (FreeRDP progressive.c L1150-1159): count from
        // 1 up to `max = (1 << numBits) - 1`, one bit per step, no remainder bits —
        // NOT Golomb-Rice. The terminating 1-bit is omitted once `mag == max`.
        let max = (1u32 << u32::from(num_bits).min(16)) - 1;
        let mut mag: u32 = 1;
        while mag < max {
            if self.reader.read_bit() {
                break;
            }
            mag += 1;
        }
        let value = i16::try_from(mag.min(0x7FFF)).unwrap_or(i16::MAX);
        if sign { -value } else { value }
    }
}

/// Encode coefficient magnitudes using the SRL algorithm.
///
/// `values` contains signed coefficient values (non-zero = needs encoding,
/// zero = contributes to zero runs).
/// `num_bits` is the bit width for magnitude encoding.
///
/// Returns the encoded SRL byte stream (with trailing 0x00 sentinel).
pub fn encode_srl(values: &[i16], num_bits: u8) -> Vec<u8> {
    if values.is_empty() {
        return vec![0x00];
    }

    let mut writer = BitWriter::new();
    let mut kp: u32 = 0;
    let mut idx = 0;

    while idx < values.len() {
        // Count leading zeros (may be 0)
        let mut zero_count: u32 = 0;
        while idx + usize::try_from(zero_count).unwrap_or(usize::MAX) < values.len()
            && values[idx + usize::try_from(zero_count).unwrap_or(usize::MAX)] == 0
        {
            zero_count += 1;
        }

        // Encode zero run one chunk at a time, recomputing k after
        // each kp update to stay in sync with the decoder.
        while zero_count > 0 {
            let cur_k = kp >> 3;
            let chunk_size = 1u32.checked_shl(cur_k).unwrap_or(u32::MAX);
            if zero_count >= chunk_size {
                writer.write_bit(false);
                kp = kp.saturating_add(4).min(80);
                zero_count -= chunk_size;
                idx += usize::try_from(chunk_size).unwrap_or(usize::MAX);
            } else {
                // Remaining zeros < chunk: escape bit + count
                writer.write_bit(true);
                writer.write_bits(zero_count, cur_k);
                idx += usize::try_from(zero_count).unwrap_or(usize::MAX);
                zero_count = 0;
                continue;
            }
        }
        // No remaining zeros: write escape with zero count
        let cur_k = kp >> 3;
        writer.write_bit(true);
        writer.write_bits(0, cur_k);

        if idx >= values.len() {
            break;
        }

        // Encode non-zero value
        kp = kp.saturating_sub(6);
        let value = values[idx];
        let sign = value < 0;
        let magnitude = u32::from(value.unsigned_abs());

        writer.write_bit(sign);

        if num_bits <= 1 {
            idx += 1;
            continue;
        }

        // Unary encode: quotient zeros + terminator + remainder bits.
        // magnitude = (quotient << extra_bits) | remainder.
        let extra_bits = u32::from(num_bits).saturating_sub(1);
        if extra_bits > 0 && extra_bits < 16 {
            let quotient = magnitude >> extra_bits;
            let remainder = magnitude & ((1u32 << extra_bits) - 1);

            for _ in 0..quotient {
                writer.write_bit(false);
            }
            writer.write_bit(true);
            writer.write_bits(remainder, extra_bits);
        }

        idx += 1;
    }

    // Trailing sentinel
    let mut result = writer.finish();
    result.push(0x00);
    result
}

// ---------------------------------------------------------------------------
// Bit-level I/O helpers
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8, // 0..7, MSB first
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    fn read_bit(&mut self) -> bool {
        if self.byte_idx >= self.data.len() {
            return false;
        }
        let bit = (self.data[self.byte_idx] >> (7 - self.bit_idx)) & 1 != 0;
        self.bit_idx += 1;
        if self.bit_idx >= 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        bit
    }

    fn read_bits(&mut self, count: u32) -> u32 {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit());
        }
        value
    }
}

struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    bit_count: u8, // bits written in current byte (0..7)
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            bit_count: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.current = (self.current << 1) | u8::from(bit);
        self.bit_count += 1;
        if self.bit_count >= 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bit_count = 0;
        }
    }

    fn write_bits(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            // Pad remaining bits with zeros (MSB aligned)
            self.current <<= 8 - self.bit_count;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty() {
        let result = decode_srl(&[], 0, 1);
        assert!(result.is_empty());
    }

    #[test]
    fn decode_empty_data() {
        // With no data (empty slice), all positions default to zero
        let result = decode_srl(&[], 5, 1);
        assert_eq!(result, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_empty() {
        let encoded = encode_srl(&[], 1);
        assert_eq!(encoded, vec![0x00]); // just sentinel
    }

    #[test]
    fn encode_all_zeros() {
        let encoded = encode_srl(&[0, 0, 0], 1);
        // Sentinel must be present
        assert_eq!(*encoded.last().unwrap(), 0x00);
        // Round-trip: all zeros must survive
        let decoded = decode_srl(&encoded, 3, 1);
        assert_eq!(decoded, vec![0, 0, 0]);
    }

    #[test]
    fn round_trip_single_positive() {
        let original = vec![1];
        let encoded = encode_srl(&original, 1);
        let decoded = decode_srl(&encoded, 1, 1);
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_single_negative() {
        let original = vec![-1];
        let encoded = encode_srl(&original, 1);
        let decoded = decode_srl(&encoded, 1, 1);
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_mixed_zeros() {
        // Zeros at the start (where k=0) must survive the round-trip
        let original = vec![0, 0, 1, -1, 0, 3];
        let encoded = encode_srl(&original, 4);
        let decoded = decode_srl(&encoded, original.len(), 4);
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_nonzero_only() {
        let original = vec![1, -1, 2, -3, 1];
        let encoded = encode_srl(&original, 4);
        let decoded = decode_srl(&encoded, original.len(), 4);
        assert_eq!(decoded, original);
    }

    #[test]
    fn srl_reader_decodes_single_positive_magnitude() {
        // Bits 1001 (num_bits=2): '1' escape, '0' no remainder zeros, '0' sign +,
        // truncated-unary magnitude terminates immediately -> +1.
        let mut reader = SrlReader::new(&[0b1001_0000]);
        assert_eq!(reader.next_value(2), 1);
    }

    #[test]
    fn srl_reader_threads_bit_position_across_values() {
        // A single reader must advance its bit position across successive values
        // (kp=8 init, truncated-unary). A per-value restart would decode the first
        // magnitude (+1) again instead of draining the trailing zeros.
        let mut reader = SrlReader::new(&[0b1001_0000, 0x00]);
        let values: Vec<i16> = core::iter::repeat_with(|| reader.next_value(2)).take(6).collect();
        assert_eq!(values, vec![1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn bit_reader_basic() {
        let data = [0b10110000];
        let mut reader = BitReader::new(&data);
        assert!(reader.read_bit()); // 1
        assert!(!reader.read_bit()); // 0
        assert!(reader.read_bit()); // 1
        assert!(reader.read_bit()); // 1
    }

    #[test]
    fn bit_writer_basic() {
        let mut writer = BitWriter::new();
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(true);
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(false);
        writer.write_bit(false);
        writer.write_bit(false);
        let result = writer.finish();
        assert_eq!(result, vec![0b10110000]);
    }

    #[test]
    fn bit_writer_multi_byte() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xFF, 8);
        writer.write_bits(0x00, 8);
        let result = writer.finish();
        assert_eq!(result, vec![0xFF, 0x00]);
    }
}
