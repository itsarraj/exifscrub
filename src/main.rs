use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use exifscrub::jpeg;
use exifscrub::png;

#[derive(Parser)]
#[command(
    name = "exifscrub",
    about = "Views and losslessly strips EXIF/GPS and other metadata from JPEG and PNG images"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show every metadata-carrying segment/chunk found in the file.
    View { file: PathBuf },
    /// Write a copy of the file with all metadata segments/chunks removed.
    Scrub {
        file: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

enum Format {
    Jpeg,
    Png,
}

fn detect_format(bytes: &[u8]) -> Option<Format> {
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        Some(Format::Jpeg)
    } else if bytes.len() >= 8 && bytes[0..8] == png::SIGNATURE {
        Some(Format::Png)
    } else {
        None
    }
}

fn view_jpeg(bytes: &[u8]) -> anyhow::Result<()> {
    let segments = jpeg::list_segments(bytes)?;
    let mut found_metadata = false;
    for seg in &segments {
        let name = jpeg::marker_name(seg.marker);
        if jpeg::is_metadata_marker(seg.marker) {
            found_metadata = true;
            println!(
                "{name} (0x{:02X}) — {} bytes at offset {}",
                seg.marker, seg.total_len, seg.offset
            );
            if seg.marker == 0xE1 {
                let payload = &bytes[seg.offset + 4..seg.offset + seg.total_len];
                if let Some(exif) = jpeg::parse_exif(payload) {
                    print_exif_summary(&exif);
                }
            }
        } else {
            println!(
                "{name} (0x{:02X}) — {} bytes at offset {} [kept]",
                seg.marker, seg.total_len, seg.offset
            );
        }
    }
    if !found_metadata {
        println!("exifscrub: no metadata segments found");
    }
    Ok(())
}

fn print_exif_summary(exif: &jpeg::ExifSummary) {
    if let Some(v) = &exif.make {
        println!("  Make: {v}");
    }
    if let Some(v) = &exif.model {
        println!("  Model: {v}");
    }
    if let Some(v) = &exif.software {
        println!("  Software: {v}");
    }
    if let Some(v) = &exif.datetime {
        println!("  DateTime: {v}");
    }
    if let Some(v) = exif.orientation {
        println!("  Orientation: {v}");
    }
    if let Some((lat, lon)) = exif.gps {
        println!("  GPS: {lat:.6}, {lon:.6}  (https://maps.google.com/?q={lat:.6},{lon:.6})");
    }
}

fn view_png(bytes: &[u8]) -> anyhow::Result<()> {
    let chunks = png::list_chunks(bytes)?;
    let mut found_metadata = false;
    for chunk in &chunks {
        if png::is_metadata_chunk(&chunk.chunk_type) {
            found_metadata = true;
            println!(
                "{} — {} bytes at offset {}",
                chunk.type_str(),
                chunk.total_len,
                chunk.offset
            );
            if let Some((keyword, text)) = png::decode_text_chunk(bytes, chunk) {
                println!("  {keyword}: {text}");
            }
            if &chunk.chunk_type == b"eXIf" {
                let data = &bytes[chunk.offset + 8..chunk.offset + chunk.total_len - 4];
                if let Some(exif) = jpeg::parse_exif_tiff(data) {
                    print_exif_summary(&exif);
                }
            }
        }
    }
    if !found_metadata {
        println!("exifscrub: no metadata chunks found");
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::View { file } => {
            let bytes = match std::fs::read(&file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("exifscrub: reading {}: {e}", file.display());
                    return ExitCode::FAILURE;
                }
            };
            let result = match detect_format(&bytes) {
                Some(Format::Jpeg) => view_jpeg(&bytes),
                Some(Format::Png) => view_png(&bytes),
                None => {
                    eprintln!(
                        "exifscrub: {}: not a recognized JPEG or PNG file",
                        file.display()
                    );
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = result {
                eprintln!("exifscrub: {}: {e}", file.display());
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Command::Scrub { file, output } => {
            let bytes = match std::fs::read(&file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("exifscrub: reading {}: {e}", file.display());
                    return ExitCode::FAILURE;
                }
            };
            let stripped = match detect_format(&bytes) {
                Some(Format::Jpeg) => jpeg::strip_metadata(&bytes),
                Some(Format::Png) => png::strip_metadata(&bytes),
                None => {
                    eprintln!(
                        "exifscrub: {}: not a recognized JPEG or PNG file",
                        file.display()
                    );
                    return ExitCode::FAILURE;
                }
            };
            let stripped = match stripped {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("exifscrub: {}: {e}", file.display());
                    return ExitCode::FAILURE;
                }
            };
            let saved = bytes.len().saturating_sub(stripped.len());
            if let Err(e) = std::fs::write(&output, &stripped) {
                eprintln!("exifscrub: writing {}: {e}", output.display());
                return ExitCode::FAILURE;
            }
            println!(
                "exifscrub: wrote {} ({} bytes, {} bytes of metadata removed)",
                output.display(),
                stripped.len(),
                saved
            );
            ExitCode::SUCCESS
        }
    }
}
