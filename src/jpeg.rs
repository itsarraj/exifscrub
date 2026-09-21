//! JPEG segment-level parsing: enough to enumerate metadata-carrying
//! segments, decode the common EXIF/GPS tags out of an APP1 payload, and
//! losslessly strip metadata segments while leaving every other byte —
//! including all entropy-coded scan data — untouched.

use anyhow::{bail, Context, Result};

const SOS: u8 = 0xDA;
const EOI: u8 = 0xD9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JpegSegment {
    pub marker: u8,
    /// Offset of the 0xFF marker byte within the file.
    pub offset: usize,
    /// Total length in bytes: the 2 marker bytes plus (for markers that
    /// carry one) the 2-byte length field and its payload.
    pub total_len: usize,
}

pub fn marker_name(marker: u8) -> &'static str {
    match marker {
        0xD8 => "SOI",
        0xD9 => "EOI",
        0xDA => "SOS",
        0xDB => "DQT",
        0xC4 => "DHT",
        0xDD => "DRI",
        0xFE => "COM",
        0xC0 => "SOF0",
        0xC1 => "SOF1",
        0xC2 => "SOF2",
        0xC3 => "SOF3",
        0xE0 => "APP0",
        0xE1 => "APP1",
        0xE2 => "APP2",
        0xED => "APP13",
        0xEE => "APP14",
        m if (0xD0..=0xD7).contains(&m) => "RSTn",
        m if (0xE0..=0xEF).contains(&m) => "APPn",
        _ => "?",
    }
}

/// Marker bytes with no length-prefixed payload of their own.
fn is_payload_free(marker: u8) -> bool {
    marker == 0xD8 || marker == 0xD9 || marker == 0x01 || (0xD0..=0xD7).contains(&marker)
}

/// Enumerates every segment from SOI up to and including the SOS
/// segment's own header (SOS carries a short length-prefixed header
/// naming which scan components follow, before the unbounded
/// entropy-coded data begins). Returns an error if `bytes` doesn't
/// start with a JPEG SOI marker or a segment's length runs past EOF.
pub fn list_segments(bytes: &[u8]) -> Result<Vec<JpegSegment>> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        bail!("not a JPEG file (missing SOI marker)");
    }
    let mut segments = vec![JpegSegment {
        marker: 0xD8,
        offset: 0,
        total_len: 2,
    }];
    let mut pos = 2usize;

    loop {
        if pos >= bytes.len() {
            bail!("truncated JPEG: ran out of bytes looking for the next marker");
        }
        if bytes[pos] != 0xFF {
            bail!("malformed JPEG: expected marker byte 0xFF at offset {pos}");
        }
        let marker_start = pos;
        pos += 1;
        while pos < bytes.len() && bytes[pos] == 0xFF {
            pos += 1;
        }
        if pos >= bytes.len() {
            bail!("truncated JPEG: marker byte cut off at EOF");
        }
        let marker = bytes[pos];
        pos += 1;

        if marker == EOI {
            segments.push(JpegSegment {
                marker,
                offset: marker_start,
                total_len: pos - marker_start,
            });
            break;
        }
        if is_payload_free(marker) {
            segments.push(JpegSegment {
                marker,
                offset: marker_start,
                total_len: pos - marker_start,
            });
            continue;
        }

        if pos + 2 > bytes.len() {
            bail!("truncated JPEG: missing length field for marker 0x{marker:02X}");
        }
        let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if seg_len < 2 {
            bail!(
                "malformed JPEG: segment length {seg_len} for marker 0x{marker:02X} is too short"
            );
        }
        let end = pos + seg_len;
        if end > bytes.len() {
            bail!("truncated JPEG: segment for marker 0x{marker:02X} extends past EOF");
        }
        segments.push(JpegSegment {
            marker,
            offset: marker_start,
            total_len: end - marker_start,
        });
        pos = end;

        if marker == SOS {
            // Everything after this is entropy-coded scan data (with
            // byte-stuffed 0xFF00 and restart markers inside it) —
            // stop segment-level parsing here; the caller copies the
            // remainder verbatim.
            break;
        }
    }

    Ok(segments)
}

/// Byte offset where entropy-coded scan data (or, if the file has no
/// SOS, nothing) begins — i.e. just past the last segment `list_segments`
/// returned.
pub fn scan_data_start(segments: &[JpegSegment]) -> usize {
    segments.last().map(|s| s.offset + s.total_len).unwrap_or(0)
}

const METADATA_MARKERS: &[u8] = &[0xE1, 0xED, 0xFE]; // APP1 (Exif/XMP), APP13 (Photoshop/IPTC), COM

pub fn is_metadata_marker(marker: u8) -> bool {
    METADATA_MARKERS.contains(&marker)
}

/// Rebuilds the file with every metadata segment (APP1/APP13/COM)
/// removed. All other bytes — including APP0/APP2/APP14, quantization
/// and Huffman tables, and every byte of entropy-coded scan data — are
/// copied through unchanged, so the decoded image is bit-identical.
pub fn strip_metadata(bytes: &[u8]) -> Result<Vec<u8>> {
    let segments = list_segments(bytes).context("parsing JPEG segments")?;
    let mut out = Vec::with_capacity(bytes.len());
    for seg in &segments {
        if is_metadata_marker(seg.marker) {
            continue;
        }
        out.extend_from_slice(&bytes[seg.offset..seg.offset + seg.total_len]);
    }
    out.extend_from_slice(&bytes[scan_data_start(&segments)..]);
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExifSummary {
    pub make: Option<String>,
    pub model: Option<String>,
    pub software: Option<String>,
    pub datetime: Option<String>,
    pub orientation: Option<u16>,
    /// (latitude, longitude) in signed decimal degrees.
    pub gps: Option<(f64, f64)>,
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u16(self, b: &[u8]) -> u16 {
        match self {
            ByteOrder::Little => u16::from_le_bytes([b[0], b[1]]),
            ByteOrder::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        match self {
            ByteOrder::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            ByteOrder::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
}

fn type_size(type_code: u16) -> Option<usize> {
    match type_code {
        1 | 2 | 6 | 7 => Some(1), // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => Some(2),         // SHORT, SSHORT
        4 | 9 | 11 => Some(4),    // LONG, SLONG, FLOAT
        5 | 10 | 12 => Some(8),   // RATIONAL, SRATIONAL, DOUBLE
        _ => None,
    }
}

struct IfdEntry {
    tag: u16,
    type_code: u16,
    count: u32,
    value_bytes: [u8; 4],
    value_offset_if_indirect: Option<u32>,
}

fn read_ifd(tiff: &[u8], ifd_offset: u32, order: ByteOrder) -> Result<(Vec<IfdEntry>, u32)> {
    let start = ifd_offset as usize;
    if start + 2 > tiff.len() {
        bail!("IFD offset {start} out of range");
    }
    let count = order.u16(&tiff[start..start + 2]) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut pos = start + 2;
    for _ in 0..count {
        if pos + 12 > tiff.len() {
            bail!("IFD entry at offset {pos} out of range");
        }
        let tag = order.u16(&tiff[pos..pos + 2]);
        let type_code = order.u16(&tiff[pos + 2..pos + 4]);
        let count = order.u32(&tiff[pos + 4..pos + 8]);
        let mut value_bytes = [0u8; 4];
        value_bytes.copy_from_slice(&tiff[pos + 8..pos + 12]);

        let total_size = type_size(type_code).unwrap_or(0) as u64 * count as u64;
        let value_offset_if_indirect = if total_size > 4 {
            Some(order.u32(&value_bytes))
        } else {
            None
        };

        entries.push(IfdEntry {
            tag,
            type_code,
            count,
            value_bytes,
            value_offset_if_indirect,
        });
        pos += 12;
    }
    let next_ifd = if pos + 4 <= tiff.len() {
        order.u32(&tiff[pos..pos + 4])
    } else {
        0
    };
    Ok((entries, next_ifd))
}

fn ascii_value(tiff: &[u8], entry: &IfdEntry, order: ByteOrder) -> Option<String> {
    if entry.type_code != 2 {
        return None;
    }
    let bytes = match entry.value_offset_if_indirect {
        Some(off) => {
            let start = off as usize;
            let end = start + entry.count as usize;
            tiff.get(start..end)?
        }
        None => &entry.value_bytes[..entry.count.min(4) as usize],
    };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let _ = order;
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn short_value(entry: &IfdEntry, order: ByteOrder) -> Option<u16> {
    if entry.type_code != 3 {
        return None;
    }
    Some(order.u16(&entry.value_bytes[..2]))
}

fn long_value(entry: &IfdEntry, order: ByteOrder) -> Option<u32> {
    match entry.type_code {
        3 => Some(order.u16(&entry.value_bytes[..2]) as u32),
        4 => Some(order.u32(&entry.value_bytes)),
        _ => None,
    }
}

fn rational_triplet(tiff: &[u8], entry: &IfdEntry, order: ByteOrder) -> Option<[f64; 3]> {
    if entry.type_code != 5 || entry.count != 3 {
        return None;
    }
    let off = entry.value_offset_if_indirect?;
    let start = off as usize;
    let bytes = tiff.get(start..start + 24)?;
    let mut out = [0.0f64; 3];
    for i in 0..3 {
        let num = order.u32(&bytes[i * 8..i * 8 + 4]) as f64;
        let den = order.u32(&bytes[i * 8 + 4..i * 8 + 8]) as f64;
        out[i] = if den == 0.0 { 0.0 } else { num / den };
    }
    Some(out)
}

/// Parses the payload of an APP1 segment (starting with the 6-byte
/// `"Exif\0\0"` header) into a human-readable summary of the tags most
/// relevant to privacy: camera make/model/software, capture timestamp,
/// orientation, and GPS coordinates.
pub fn parse_exif(app1_payload: &[u8]) -> Option<ExifSummary> {
    if app1_payload.len() < 8 || &app1_payload[0..6] != b"Exif\0\0" {
        return None;
    }
    parse_exif_tiff(&app1_payload[6..])
}

/// Same as [`parse_exif`] but for a bare TIFF-structured EXIF blob with
/// no `"Exif\0\0"` prefix — the form PNG's `eXIf` chunk uses.
pub fn parse_exif_tiff(tiff: &[u8]) -> Option<ExifSummary> {
    if tiff.len() < 8 {
        return None;
    }
    let order = match &tiff[0..2] {
        b"II" => ByteOrder::Little,
        b"MM" => ByteOrder::Big,
        _ => return None,
    };
    if order.u16(&tiff[2..4]) != 42 {
        return None;
    }
    let ifd0_offset = order.u32(&tiff[4..8]);
    let (entries, _next) = read_ifd(tiff, ifd0_offset, order).ok()?;

    let mut summary = ExifSummary::default();
    let mut gps_ifd_offset: Option<u32> = None;
    for entry in &entries {
        match entry.tag {
            0x010F => summary.make = ascii_value(tiff, entry, order),
            0x0110 => summary.model = ascii_value(tiff, entry, order),
            0x0131 => summary.software = ascii_value(tiff, entry, order),
            0x0132 => summary.datetime = ascii_value(tiff, entry, order),
            0x0112 => summary.orientation = short_value(entry, order),
            0x8825 => gps_ifd_offset = long_value(entry, order),
            _ => {}
        }
    }

    if let Some(gps_offset) = gps_ifd_offset {
        if let Ok((gps_entries, _)) = read_ifd(tiff, gps_offset, order) {
            let mut lat: Option<f64> = None;
            let mut lat_ref: Option<String> = None;
            let mut lon: Option<f64> = None;
            let mut lon_ref: Option<String> = None;
            for entry in &gps_entries {
                match entry.tag {
                    0x0001 => lat_ref = ascii_value(tiff, entry, order),
                    0x0002 => {
                        if let Some([d, m, s]) = rational_triplet(tiff, entry, order) {
                            lat = Some(d + m / 60.0 + s / 3600.0);
                        }
                    }
                    0x0003 => lon_ref = ascii_value(tiff, entry, order),
                    0x0004 => {
                        if let Some([d, m, s]) = rational_triplet(tiff, entry, order) {
                            lon = Some(d + m / 60.0 + s / 3600.0);
                        }
                    }
                    _ => {}
                }
            }
            if let (Some(mut la), Some(mut lo)) = (lat, lon) {
                if lat_ref.as_deref() == Some("S") {
                    la = -la;
                }
                if lon_ref.as_deref() == Some("W") {
                    lo = -lo;
                }
                summary.gps = Some((la, lo));
            }
        }
    }

    Some(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_jpeg_no_metadata() -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI
        out.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x01]); // fake DQT, 2-byte payload
        out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00]); // fake SOS header
        out.extend_from_slice(&[0x12, 0x34, 0x56]); // fake entropy data
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    fn jpeg_with_app1(app1_payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI
        let seg_len = (app1_payload.len() + 2) as u16;
        out.extend_from_slice(&[0xFF, 0xE1]);
        out.extend_from_slice(&seg_len.to_be_bytes());
        out.extend_from_slice(app1_payload);
        out.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x06, b'h', b'i', b'!', b'!']); // COM segment
        out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00]); // fake SOS
        out.extend_from_slice(&[0xAB, 0xCD]); // fake scan data
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    fn build_exif_payload_little_endian(
        entries: &[(u16, u16, u32, [u8; 4])],
        extra: &[u8],
    ) -> Vec<u8> {
        // TIFF header: "II", 42, IFD0 offset = 8
        let mut tiff = vec![b'I', b'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
        tiff.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (tag, type_code, count, value) in entries {
            tiff.extend_from_slice(&tag.to_le_bytes());
            tiff.extend_from_slice(&type_code.to_le_bytes());
            tiff.extend_from_slice(&count.to_le_bytes());
            tiff.extend_from_slice(value);
        }
        tiff.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
        tiff.extend_from_slice(extra);
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&tiff);
        payload
    }

    #[test]
    fn list_segments_rejects_non_jpeg() {
        assert!(list_segments(b"not a jpeg").is_err());
    }

    #[test]
    fn list_segments_finds_soi_and_stops_after_sos() {
        let jpeg = minimal_jpeg_no_metadata();
        let segments = list_segments(&jpeg).unwrap();
        assert_eq!(segments.first().unwrap().marker, 0xD8);
        assert_eq!(segments.last().unwrap().marker, 0xDA);
    }

    #[test]
    fn strip_metadata_removes_app1_and_com_but_keeps_scan_data() {
        let exif_payload = build_exif_payload_little_endian(&[], &[]);
        let jpeg = jpeg_with_app1(&exif_payload);
        let stripped = strip_metadata(&jpeg).unwrap();

        assert!(!stripped.windows(2).any(|w| w == [0xFF, 0xE1]));
        assert!(!stripped.windows(2).any(|w| w == [0xFF, 0xFE]));
        // The entropy-coded scan data and EOI must survive untouched.
        assert!(stripped.windows(2).any(|w| w == [0xAB, 0xCD]));
        assert_eq!(&stripped[stripped.len() - 2..], &[0xFF, 0xD9]);
    }

    #[test]
    fn strip_metadata_is_a_no_op_on_a_file_with_no_metadata() {
        let jpeg = minimal_jpeg_no_metadata();
        let stripped = strip_metadata(&jpeg).unwrap();
        assert_eq!(stripped, jpeg);
    }

    #[test]
    fn parse_exif_rejects_payload_without_exif_header() {
        assert!(parse_exif(b"not exif").is_none());
    }

    #[test]
    fn parse_exif_reads_make_and_model_ascii_tags() {
        let make = b"Canon\0";
        let model = b"EOS R5\0\0";
        // Values >4 bytes go after the IFD; offsets computed manually.
        // IFD0: 2 entries -> header(8) + count(2) + 2*12 + next(4) = 38
        let ifd_end = 8 + 2 + 2 * 12 + 4;
        let make_off = ifd_end as u32;
        let model_off = (ifd_end + make.len()) as u32;
        let entries = [
            (0x010Fu16, 2u16, make.len() as u32, make_off.to_le_bytes()),
            (0x0110u16, 2u16, model.len() as u32, model_off.to_le_bytes()),
        ];
        let mut extra = Vec::new();
        extra.extend_from_slice(make);
        extra.extend_from_slice(model);
        let payload = build_exif_payload_little_endian(&entries, &extra);

        let summary = parse_exif(&payload).unwrap();
        assert_eq!(summary.make.as_deref(), Some("Canon"));
        assert_eq!(summary.model.as_deref(), Some("EOS R5"));
    }

    #[test]
    fn parse_exif_reads_inline_short_orientation() {
        let entries = [(
            0x0112u16,
            3u16,
            1u32,
            6u16.to_le_bytes()
                .into_iter()
                .chain([0, 0])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )];
        let payload = build_exif_payload_little_endian(&entries, &[]);
        let summary = parse_exif(&payload).unwrap();
        assert_eq!(summary.orientation, Some(6));
    }

    #[test]
    fn parse_exif_reads_gps_coordinates_with_hemisphere_signs() {
        // GPS IFD placed right after IFD0. IFD0 has one entry pointing to it.
        let ifd0_end = 8 + 2 + 12 + 4;
        let gps_ifd_offset = ifd0_end as u32;

        // GPS IFD: 4 entries (LatRef, Lat, LonRef, Lon)
        let gps_ifd_header_len = 2 + 4 * 12 + 4;
        let lat_rationals_off = gps_ifd_offset as usize + gps_ifd_header_len;
        let lon_rationals_off = lat_rationals_off + 24;

        let mut gps_ifd = Vec::new();
        gps_ifd.extend_from_slice(&4u16.to_le_bytes());
        // GPSLatitudeRef = "S\0" (ASCII, count 2, fits inline)
        gps_ifd.extend_from_slice(&0x0001u16.to_le_bytes());
        gps_ifd.extend_from_slice(&2u16.to_le_bytes());
        gps_ifd.extend_from_slice(&2u32.to_le_bytes());
        gps_ifd.extend_from_slice(&[b'S', 0, 0, 0]);
        // GPSLatitude = 3 rationals (indirect)
        gps_ifd.extend_from_slice(&0x0002u16.to_le_bytes());
        gps_ifd.extend_from_slice(&5u16.to_le_bytes());
        gps_ifd.extend_from_slice(&3u32.to_le_bytes());
        gps_ifd.extend_from_slice(&(lat_rationals_off as u32).to_le_bytes());
        // GPSLongitudeRef = "E\0"
        gps_ifd.extend_from_slice(&0x0003u16.to_le_bytes());
        gps_ifd.extend_from_slice(&2u16.to_le_bytes());
        gps_ifd.extend_from_slice(&2u32.to_le_bytes());
        gps_ifd.extend_from_slice(&[b'E', 0, 0, 0]);
        // GPSLongitude = 3 rationals (indirect)
        gps_ifd.extend_from_slice(&0x0004u16.to_le_bytes());
        gps_ifd.extend_from_slice(&5u16.to_le_bytes());
        gps_ifd.extend_from_slice(&3u32.to_le_bytes());
        gps_ifd.extend_from_slice(&(lon_rationals_off as u32).to_le_bytes());
        gps_ifd.extend_from_slice(&0u32.to_le_bytes()); // next IFD

        // 33 deg 51 min 32 sec S, 151 deg 12 min 40 sec E (Sydney-ish)
        let mut lat_rationals = Vec::new();
        for (num, den) in [(33u32, 1u32), (51, 1), (32, 1)] {
            lat_rationals.extend_from_slice(&num.to_le_bytes());
            lat_rationals.extend_from_slice(&den.to_le_bytes());
        }
        let mut lon_rationals = Vec::new();
        for (num, den) in [(151u32, 1u32), (12, 1), (40, 1)] {
            lon_rationals.extend_from_slice(&num.to_le_bytes());
            lon_rationals.extend_from_slice(&den.to_le_bytes());
        }

        let mut extra = gps_ifd;
        extra.extend_from_slice(&lat_rationals);
        extra.extend_from_slice(&lon_rationals);

        let entries = [(0x8825u16, 4u16, 1u32, gps_ifd_offset.to_le_bytes())];
        let payload = build_exif_payload_little_endian(&entries, &extra);

        let summary = parse_exif(&payload).unwrap();
        let (lat, lon) = summary.gps.unwrap();
        assert!((lat - (-(33.0 + 51.0 / 60.0 + 32.0 / 3600.0))).abs() < 1e-6);
        assert!((lon - (151.0 + 12.0 / 60.0 + 40.0 / 3600.0)).abs() < 1e-6);
    }

    #[test]
    fn parse_exif_handles_big_endian_byte_order() {
        let mut tiff = vec![b'M', b'M', 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08];
        tiff.extend_from_slice(&1u16.to_be_bytes());
        // Orientation, SHORT, count 1, value 3 (inline, big-endian-justified)
        tiff.extend_from_slice(&0x0112u16.to_be_bytes());
        tiff.extend_from_slice(&3u16.to_be_bytes());
        tiff.extend_from_slice(&1u32.to_be_bytes());
        tiff.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
        tiff.extend_from_slice(&0u32.to_be_bytes());
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&tiff);

        let summary = parse_exif(&payload).unwrap();
        assert_eq!(summary.orientation, Some(3));
    }

    #[test]
    fn is_metadata_marker_covers_app1_app13_and_com_only() {
        assert!(is_metadata_marker(0xE1));
        assert!(is_metadata_marker(0xED));
        assert!(is_metadata_marker(0xFE));
        assert!(!is_metadata_marker(0xE0)); // APP0/JFIF must be kept
        assert!(!is_metadata_marker(0xDB)); // DQT must be kept
    }
}
