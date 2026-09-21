//! PNG chunk-level parsing and lossless metadata stripping. PNG's chunk
//! format (length + 4-byte type + data + CRC) makes this simpler than
//! JPEG: metadata always lives in whole, self-contained ancillary
//! chunks that can be dropped without touching pixel data at all.

use anyhow::{bail, Result};

pub const SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PngChunk {
    pub chunk_type: [u8; 4],
    /// Offset of the chunk's length field (start of the whole chunk) within the file.
    pub offset: usize,
    /// Total length in bytes: 4 (length) + 4 (type) + data + 4 (CRC).
    pub total_len: usize,
}

impl PngChunk {
    pub fn type_str(&self) -> String {
        String::from_utf8_lossy(&self.chunk_type).into_owned()
    }
}

/// Ancillary chunk types that carry metadata rather than pixel data or
/// information required to decode the image correctly.
const METADATA_CHUNK_TYPES: &[&[u8; 4]] = &[b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"];

pub fn is_metadata_chunk(chunk_type: &[u8; 4]) -> bool {
    METADATA_CHUNK_TYPES.contains(&chunk_type)
}

pub fn list_chunks(bytes: &[u8]) -> Result<Vec<PngChunk>> {
    if bytes.len() < 8 || bytes[0..8] != SIGNATURE {
        bail!("not a PNG file (missing signature)");
    }
    let mut chunks = Vec::new();
    let mut pos = 8usize;
    loop {
        if pos + 8 > bytes.len() {
            bail!("truncated PNG: incomplete chunk header at offset {pos}");
        }
        let data_len =
            u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        let mut chunk_type = [0u8; 4];
        chunk_type.copy_from_slice(&bytes[pos + 4..pos + 8]);
        let total_len = 8 + data_len + 4;
        if pos + total_len > bytes.len() {
            bail!(
                "truncated PNG: chunk '{}' extends past EOF",
                String::from_utf8_lossy(&chunk_type)
            );
        }
        chunks.push(PngChunk {
            chunk_type,
            offset: pos,
            total_len,
        });
        pos += total_len;
        if &chunk_type == b"IEND" {
            break;
        }
    }
    Ok(chunks)
}

/// Rebuilds the file with every metadata chunk (tEXt/zTXt/iTXt/eXIf/tIME)
/// removed. Every other chunk — including its original CRC — is copied
/// through byte-for-byte, so IDAT pixel data is untouched.
pub fn strip_metadata(bytes: &[u8]) -> Result<Vec<u8>> {
    let chunks = list_chunks(bytes)?;
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&SIGNATURE);
    for chunk in &chunks {
        if is_metadata_chunk(&chunk.chunk_type) {
            continue;
        }
        out.extend_from_slice(&bytes[chunk.offset..chunk.offset + chunk.total_len]);
    }
    Ok(out)
}

/// Decodes a `tEXt` chunk's data into (keyword, text). `tEXt` stores the
/// keyword, a NUL separator, then the text — both Latin-1, uncompressed.
pub fn decode_text_chunk(bytes: &[u8], chunk: &PngChunk) -> Option<(String, String)> {
    if &chunk.chunk_type != b"tEXt" {
        return None;
    }
    let data = &bytes[chunk.offset + 8..chunk.offset + chunk.total_len - 4];
    let nul = data.iter().position(|&b| b == 0)?;
    let keyword = String::from_utf8_lossy(&data[..nul]).into_owned();
    let text = String::from_utf8_lossy(&data[nul + 1..]).into_owned();
    Some((keyword, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk_type);
        out.extend_from_slice(data);
        out.extend_from_slice(&[0, 0, 0, 0]); // CRC not validated by this tool
        out
    }

    fn minimal_png(extra_chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = SIGNATURE.to_vec();
        out.extend_from_slice(&chunk(b"IHDR", &[0u8; 13]));
        for c in extra_chunks {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&chunk(b"IDAT", &[1, 2, 3, 4]));
        out.extend_from_slice(&chunk(b"IEND", &[]));
        out
    }

    #[test]
    fn list_chunks_rejects_non_png() {
        assert!(list_chunks(b"not a png at all!").is_err());
    }

    #[test]
    fn list_chunks_finds_ihdr_idat_iend_in_order() {
        let png = minimal_png(&[]);
        let chunks = list_chunks(&png).unwrap();
        let types: Vec<String> = chunks.iter().map(|c| c.type_str()).collect();
        assert_eq!(types, vec!["IHDR", "IDAT", "IEND"]);
    }

    #[test]
    fn list_chunks_stops_at_iend_even_with_trailing_garbage() {
        let mut png = minimal_png(&[]);
        png.extend_from_slice(b"trailing junk after IEND");
        let chunks = list_chunks(&png).unwrap();
        assert_eq!(chunks.last().unwrap().type_str(), "IEND");
    }

    #[test]
    fn strip_metadata_removes_text_chunk_but_keeps_idat() {
        let text_chunk = chunk(b"tEXt", b"Author\0Jane Doe");
        let png = minimal_png(&[text_chunk]);
        let stripped = strip_metadata(&png).unwrap();
        let chunks = list_chunks(&stripped).unwrap();
        let types: Vec<String> = chunks.iter().map(|c| c.type_str()).collect();
        assert_eq!(types, vec!["IHDR", "IDAT", "IEND"]);
    }

    #[test]
    fn strip_metadata_removes_exif_time_and_itxt_chunks() {
        let chunks_in = [
            chunk(b"eXIf", &[0x49, 0x49, 0x2A, 0x00]),
            chunk(b"tIME", &[0u8; 7]),
            chunk(b"iTXt", b"Comment\0\0\0\0\0hello"),
            chunk(b"zTXt", b"Description\0\0compressed-ish"),
        ];
        let png = minimal_png(&chunks_in);
        let stripped = strip_metadata(&png).unwrap();
        let chunks = list_chunks(&stripped).unwrap();
        let types: Vec<String> = chunks.iter().map(|c| c.type_str()).collect();
        assert_eq!(types, vec!["IHDR", "IDAT", "IEND"]);
    }

    #[test]
    fn strip_metadata_is_a_no_op_on_a_file_with_no_metadata() {
        let png = minimal_png(&[]);
        let stripped = strip_metadata(&png).unwrap();
        assert_eq!(stripped, png);
    }

    #[test]
    fn strip_metadata_preserves_idat_bytes_exactly() {
        let text_chunk = chunk(b"tEXt", b"Software\0GIMP");
        let png = minimal_png(&[text_chunk]);
        let stripped = strip_metadata(&png).unwrap();
        let chunks = list_chunks(&stripped).unwrap();
        let idat = chunks.iter().find(|c| c.type_str() == "IDAT").unwrap();
        let data = &stripped[idat.offset + 8..idat.offset + idat.total_len - 4];
        assert_eq!(data, &[1, 2, 3, 4]);
    }

    #[test]
    fn decode_text_chunk_splits_keyword_and_text_on_nul() {
        let text_chunk_bytes = chunk(b"tEXt", b"Author\0Jane Doe");
        let png = minimal_png(&[text_chunk_bytes]);
        let chunks = list_chunks(&png).unwrap();
        let text = chunks.iter().find(|c| c.type_str() == "tEXt").unwrap();
        let (keyword, value) = decode_text_chunk(&png, text).unwrap();
        assert_eq!(keyword, "Author");
        assert_eq!(value, "Jane Doe");
    }

    #[test]
    fn decode_text_chunk_returns_none_for_non_text_chunk() {
        let png = minimal_png(&[]);
        let chunks = list_chunks(&png).unwrap();
        let idat = chunks.iter().find(|c| c.type_str() == "IDAT").unwrap();
        assert!(decode_text_chunk(&png, idat).is_none());
    }

    #[test]
    fn is_metadata_chunk_keeps_ihdr_idat_and_iend() {
        assert!(!is_metadata_chunk(b"IHDR"));
        assert!(!is_metadata_chunk(b"IDAT"));
        assert!(!is_metadata_chunk(b"IEND"));
        assert!(is_metadata_chunk(b"tEXt"));
        assert!(is_metadata_chunk(b"eXIf"));
    }
}
