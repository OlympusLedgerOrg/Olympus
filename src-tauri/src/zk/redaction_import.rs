//! Document importers + tiling for rasterized tile redaction (ADR-0023, step 2).
//!
//! The redaction core ([`super::redaction_tile`]) is format-agnostic: it commits
//! opaque tile byte-slices. This module is the bridge — it turns a source
//! document of *any* importable format into canonical **raster page images**,
//! then splits each page into fixed-size tiles ready for
//! [`super::redaction_tile::seal`].
//!
//! Rasterization is the universal normalizer (ADR-0023): once a document is page
//! images, the commitment scheme is identical regardless of source format, and
//! hidden text / metadata / prior revisions are stripped. Adding a new format is
//! therefore just adding a [`DocumentImporter`] — the crypto never changes.
//!
//! **Phase 1** (this module): the pure-Rust [`ImageImporter`] (PNG/JPEG/BMP/TIFF/
//! WebP via the `image` crate — no native dependency). **Phase 2/3** (later): an
//! Office importer (LibreOffice subprocess) and a PDF importer (pdfium, a native
//! BSD library) plug into the same [`DocumentImporter`] trait.
//!
//! Gated behind the `redaction-import` cargo feature so default builds skip the
//! codec stack until the redactor is wired to an endpoint/UI.

use thiserror::Error;

use super::redaction_tile::TileCoord;

/// Pinned tile edge length in pixels (ADR-0023). A change is a
/// commitment-format/migration-class event: it alters every tile's byte content
/// and therefore every leaf and root.
pub const REDACTION_TILE_PX: u32 = 32;

/// Pinned canonical render DPI for vector formats (PDF/Office) — consumed by the
/// Phase-2/3 importers, declared here so the constant lives with its siblings.
pub const REDACTION_DPI: u32 = 300;

/// Bytes per pixel in the canonical raster representation (RGBA8).
pub const BYTES_PER_PIXEL: usize = 4;

/// Decode guard: maximum width/height (px) accepted from an untrusted raster
/// import. Generous for high-DPI scans (A0 @ 300 DPI ≈ 9933×14043) while
/// bounding a crafted huge-dimension header. Paired with
/// [`MAX_IMAGE_ALLOC_BYTES`].
pub const MAX_IMAGE_EDGE_PX: u32 = 30_000;
/// Decode guard: maximum decoder allocation (bytes) for an untrusted raster
/// import. Matches `image`'s own default but is pinned here explicitly rather
/// than relying on the upstream default.
pub const MAX_IMAGE_ALLOC_BYTES: u64 = 512 * 1024 * 1024;

/// A canonical raster page: tightly-packed row-major RGBA8 pixels.
#[derive(Debug, Clone)]
pub struct PageImage {
    pub width: u32,
    pub height: u32,
    /// `width * height * 4` bytes, row-major, RGBA8.
    pub pixels: Vec<u8>,
}

impl PageImage {
    /// Construct from raw RGBA8, validating the buffer length.
    pub fn from_rgba8(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self, ImportError> {
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(BYTES_PER_PIXEL))
            .ok_or(ImportError::DimensionsOverflow)?;
        if pixels.len() != expected {
            return Err(ImportError::PixelBufferLen {
                got: pixels.len(),
                expected,
            });
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("failed to decode document: {0}")]
    Decode(String),
    #[error("document produced no pages")]
    EmptyDocument,
    #[error("page dimensions overflow usize")]
    DimensionsOverflow,
    #[error("pixel buffer length {got} does not match width*height*4 = {expected}")]
    PixelBufferLen { got: usize, expected: usize },
    #[error("tile size must be non-zero")]
    ZeroTileSize,
}

/// A pluggable importer: source document bytes → one or more canonical pages.
///
/// Implementations MUST be deterministic on a given machine (ADR-0023: only the
/// issuer renders, once, at seal time; the recipient never re-renders).
pub trait DocumentImporter {
    /// Decode `bytes` into canonical raster pages in document order.
    fn import(&self, bytes: &[u8]) -> Result<Vec<PageImage>, ImportError>;
}

/// Phase-1 importer for raster image formats via the `image` crate. Decodes a
/// single page to RGBA8. No native dependency.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImageImporter;

impl DocumentImporter for ImageImporter {
    fn import(&self, bytes: &[u8]) -> Result<Vec<PageImage>, ImportError> {
        // Untrusted input: decode through an ImageReader with EXPLICIT limits so a
        // crafted header can't drive a huge allocation. (`image` already caps
        // allocation at 512 MiB by default but imposes no dimension bound; we pin
        // both here rather than depend on the upstream default.)
        let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
            .with_guessed_format()
            .map_err(|e| ImportError::Decode(e.to_string()))?;
        // `Limits` is #[non_exhaustive]; build via default + field assignment.
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(MAX_IMAGE_EDGE_PX);
        limits.max_image_height = Some(MAX_IMAGE_EDGE_PX);
        limits.max_alloc = Some(MAX_IMAGE_ALLOC_BYTES);
        reader.limits(limits);

        // Both LimitError (dimensions/alloc exceeded) and DecodeError surface as
        // ImageError here and map to ImportError::Decode.
        let img = reader
            .decode()
            .map_err(|e| ImportError::Decode(e.to_string()))?
            .to_rgba8();
        let (w, h) = (img.width(), img.height());
        if w == 0 || h == 0 {
            return Err(ImportError::EmptyDocument);
        }
        Ok(vec![PageImage::from_rgba8(w, h, img.into_raw())?])
    }
}

/// Split one page into `tile_px`-square tiles in canonical `(page, y, x)` order.
///
/// The page is covered by `ceil(width/tile_px) * ceil(height/tile_px)` tiles;
/// edge tiles that extend past the image are **zero-padded** (the safe
/// direction — a redaction box covering a partial tile blanks the whole tile).
/// Each tile's bytes are the `tile_px*tile_px*4` row-major RGBA8 block, so the
/// content is deterministic and self-delimiting.
pub fn tile_page(
    page_index: u32,
    page: &PageImage,
    tile_px: u32,
) -> Result<Vec<(TileCoord, Vec<u8>)>, ImportError> {
    if tile_px == 0 {
        return Err(ImportError::ZeroTileSize);
    }
    // Unchecked usize arithmetic below (`row_stride`, `tile_len`, the `out`
    // capacity, and the `dst_off`/`n` slice offsets) is intentional: in every
    // callpath `tile_px` is the pinned `REDACTION_TILE_PX` (32), and
    // `PageImage::from_rgba8` already rejects any page whose `width*height*4`
    // overflows `usize` — so `row_stride ≤ width*4`, `tile_len = 32*32*4 = 4096`,
    // and the per-tile offsets all stay within the validated pixel buffer. These
    // products therefore cannot overflow here; checked arithmetic would add noise
    // without guarding anything reachable.
    let tp = tile_px as usize;
    let row_stride = page.width as usize * BYTES_PER_PIXEL;
    let cols = page.width.div_ceil(tile_px);
    let rows = page.height.div_ceil(tile_px);
    let tile_len = tp * tp * BYTES_PER_PIXEL;

    let mut out = Vec::with_capacity((cols as usize) * (rows as usize));
    for ty in 0..rows {
        for tx in 0..cols {
            let mut tile = vec![0u8; tile_len];
            // Copy each in-bounds pixel row of this tile.
            for row in 0..tp {
                let src_y = ty as usize * tp + row;
                if src_y >= page.height as usize {
                    break; // remaining rows stay zero-padded
                }
                let src_x0 = tx as usize * tp;
                if src_x0 >= page.width as usize {
                    break;
                }
                let copy_px = tp.min(page.width as usize - src_x0);
                let src_off = src_y * row_stride + src_x0 * BYTES_PER_PIXEL;
                let dst_off = row * tp * BYTES_PER_PIXEL;
                let n = copy_px * BYTES_PER_PIXEL;
                tile[dst_off..dst_off + n].copy_from_slice(&page.pixels[src_off..src_off + n]);
            }
            out.push((
                TileCoord {
                    page: page_index,
                    x: tx,
                    y: ty,
                },
                tile,
            ));
        }
    }
    Ok(out)
}

/// Import a document and tile every page, producing the `(coord, bytes)` list
/// that [`super::redaction_tile::seal`] consumes. Pages are numbered in document
/// order; tiles within a page are in canonical `(y, x)` order.
pub fn import_and_tile(
    importer: &dyn DocumentImporter,
    bytes: &[u8],
    tile_px: u32,
) -> Result<Vec<(TileCoord, Vec<u8>)>, ImportError> {
    let pages = importer.import(bytes)?;
    if pages.is_empty() {
        return Err(ImportError::EmptyDocument);
    }
    let mut tiles = Vec::new();
    for (i, page) in pages.iter().enumerate() {
        tiles.extend(tile_page(i as u32, page, tile_px)?);
    }
    Ok(tiles)
}

// ── PDF importer (native libpdfium, feature `redaction-pdf`) ──────────────────

#[cfg(feature = "redaction-pdf")]
mod pdf {
    use super::{DocumentImporter, ImportError, PageImage, REDACTION_DPI};
    use pdfium_render::prelude::*;
    use std::path::PathBuf;

    /// PDF user-space unit: 1 point = 1/72 inch. Render scale = DPI / 72.
    const POINTS_PER_INCH: f32 = 72.0;
    /// Cap on rendered page edge (px): guards against a malicious PDF declaring a
    /// huge MediaBox OOMing the renderer at [`REDACTION_DPI`].
    const MAX_PAGE_PX: i32 = 6000;

    /// PDF → canonical raster pages via a dynamically-loaded native libpdfium.
    ///
    /// libpdfium is resolved at construction with precedence:
    ///   1. `OLYMPUS_PDFIUM_PATH` (full library path, or a directory containing
    ///      the platform library name),
    ///   2. exe-relative (the bundled binary shipped next to the app),
    ///   3. the system library.
    ///
    /// Sandboxing note (ADR-0023): this binds libpdfium **in-process**. Hardening
    /// to a sandboxed subprocess (untrusted-PDF parsing is an RCE surface) is a
    /// follow-up; the importer trait boundary keeps that swap local.
    pub struct PdfImporter {
        pdfium: Pdfium,
    }

    impl PdfImporter {
        pub fn new() -> Result<Self, ImportError> {
            Ok(Self {
                pdfium: Pdfium::new(Self::resolve_bindings()?),
            })
        }

        fn resolve_bindings() -> Result<Box<dyn PdfiumLibraryBindings>, ImportError> {
            // 1. Explicit override (file path or directory).
            if let Ok(p) = std::env::var("OLYMPUS_PDFIUM_PATH") {
                let path = PathBuf::from(&p);
                let lib = if path.is_dir() {
                    Pdfium::pdfium_platform_library_name_at_path(&path)
                } else {
                    path
                };
                if let Ok(b) = Pdfium::bind_to_library(&lib) {
                    return Ok(b);
                }
            }
            // 2. Exe-relative (bundled alongside the binary).
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let lib = Pdfium::pdfium_platform_library_name_at_path(dir);
                    if let Ok(b) = Pdfium::bind_to_library(&lib) {
                        return Ok(b);
                    }
                }
            }
            // 3. System library.
            Pdfium::bind_to_system_library().map_err(|e| {
                ImportError::Decode(format!(
                    "libpdfium not found (set OLYMPUS_PDFIUM_PATH): {e}"
                ))
            })
        }
    }

    impl DocumentImporter for PdfImporter {
        fn import(&self, bytes: &[u8]) -> Result<Vec<PageImage>, ImportError> {
            let doc = self
                .pdfium
                .load_pdf_from_byte_slice(bytes, None)
                .map_err(|e| ImportError::Decode(format!("pdf load: {e}")))?;
            let config = PdfRenderConfig::new()
                .scale_page_by_factor(REDACTION_DPI as f32 / POINTS_PER_INCH)
                .set_maximum_width(MAX_PAGE_PX)
                .set_maximum_height(MAX_PAGE_PX);

            let mut pages = Vec::new();
            for page in doc.pages().iter() {
                let bitmap = page
                    .render_with_config(&config)
                    .map_err(|e| ImportError::Decode(format!("pdf render: {e}")))?;
                let (w, h) = (bitmap.width(), bitmap.height());
                if w <= 0 || h <= 0 {
                    return Err(ImportError::EmptyDocument);
                }
                // as_rgba_bytes() yields tightly-packed row-major RGBA8.
                pages.push(PageImage::from_rgba8(
                    w as u32,
                    h as u32,
                    bitmap.as_rgba_bytes(),
                )?);
            }
            if pages.is_empty() {
                return Err(ImportError::EmptyDocument);
            }
            Ok(pages)
        }
    }
}

#[cfg(feature = "redaction-pdf")]
pub use pdf::PdfImporter;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a deterministic RGBA8 page where each pixel encodes its position,
    /// so tile-content checks are meaningful.
    fn gradient_page(w: u32, h: u32) -> PageImage {
        let mut px = Vec::with_capacity((w * h) as usize * BYTES_PER_PIXEL);
        for y in 0..h {
            for x in 0..w {
                px.push((x & 0xff) as u8);
                px.push((y & 0xff) as u8);
                px.push(((x + y) & 0xff) as u8);
                px.push(0xff);
            }
        }
        PageImage::from_rgba8(w, h, px).unwrap()
    }

    #[test]
    fn from_rgba8_validates_length() {
        assert!(PageImage::from_rgba8(2, 2, vec![0u8; 16]).is_ok());
        assert!(matches!(
            PageImage::from_rgba8(2, 2, vec![0u8; 15]),
            Err(ImportError::PixelBufferLen { .. })
        ));
    }

    #[test]
    fn tile_count_covers_page_with_ceil() {
        // 40x20 at tile_px=16 → cols=ceil(40/16)=3, rows=ceil(20/16)=2 → 6 tiles.
        let page = gradient_page(40, 20);
        let tiles = tile_page(0, &page, 16).unwrap();
        assert_eq!(tiles.len(), 6);
        // Each tile is exactly tile_px^2 * 4 bytes.
        for (_, b) in &tiles {
            assert_eq!(b.len(), 16 * 16 * 4);
        }
    }

    #[test]
    fn tiles_are_in_canonical_y_then_x_order() {
        let page = gradient_page(40, 20);
        let tiles = tile_page(7, &page, 16).unwrap();
        let coords: Vec<_> = tiles.iter().map(|(c, _)| (c.page, c.y, c.x)).collect();
        let mut sorted = coords.clone();
        sorted.sort();
        assert_eq!(coords, sorted, "tiles must already be in (page,y,x) order");
        assert!(coords.iter().all(|(p, _, _)| *p == 7));
    }

    #[test]
    fn edge_tiles_are_zero_padded() {
        // Width 40, tile 16 → last column (tx=2) covers x in [32,48); only x<40
        // exist, so the right 8 columns of that tile must be zero.
        let page = gradient_page(40, 20);
        let tiles = tile_page(0, &page, 16).unwrap();
        let (_, last_col) = tiles
            .iter()
            .find(|(c, _)| c.x == 2 && c.y == 0)
            .expect("tile (x=2,y=0)");
        // Row 0 of the tile: first 8 px (x=32..40) are real, next 8 px (x=40..48)
        // are padding → all-zero RGBA.
        let pad_start = 8 * BYTES_PER_PIXEL;
        let pad_end = 16 * BYTES_PER_PIXEL;
        assert!(
            last_col[pad_start..pad_end].iter().all(|&b| b == 0),
            "out-of-bounds columns must be zero-padded"
        );
        // And a real pixel (x=32,y=0) carries its gradient value (R = 32 & 0xff).
        assert_eq!(last_col[0], 32u8);
    }

    #[test]
    fn tiling_is_deterministic() {
        let page = gradient_page(33, 17);
        assert_eq!(
            tile_page(0, &page, 16).unwrap(),
            tile_page(0, &page, 16).unwrap()
        );
    }

    #[test]
    fn zero_tile_size_is_rejected() {
        let page = gradient_page(8, 8);
        assert!(matches!(
            tile_page(0, &page, 0),
            Err(ImportError::ZeroTileSize)
        ));
    }

    #[test]
    fn image_importer_decodes_png_roundtrip() {
        // Encode a small RGBA PNG in-memory, import it back, check dimensions.
        let page = gradient_page(20, 12);
        let buf = image::RgbaImage::from_raw(20, 12, page.pixels.clone()).unwrap();
        let mut png = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("encode png");

        let pages = ImageImporter.import(&png).expect("import png");
        assert_eq!(pages.len(), 1);
        assert_eq!((pages[0].width, pages[0].height), (20, 12));
        assert_eq!(pages[0].pixels, page.pixels, "RGBA round-trips losslessly");
    }

    #[test]
    fn image_importer_rejects_garbage() {
        assert!(matches!(
            ImageImporter.import(&[0u8; 16]),
            Err(ImportError::Decode(_))
        ));
    }

    // ── PDF importer (feature `redaction-pdf`; needs libpdfium to actually run) ──
    //
    // A minimal one-page PDF (72×72 pt MediaBox). pdfium's FPDF_LoadMemDocument
    // recovers a missing xref, so this loads without hand-computed offsets.
    #[cfg(feature = "redaction-pdf")]
    const MINIMAL_PDF: &[u8] = b"%PDF-1.7\n\
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 72 72]>>endobj\n\
trailer<</Root 1 0 R>>\n%%EOF\n";

    #[cfg(feature = "redaction-pdf")]
    #[test]
    fn pdf_importer_renders_and_tiles() {
        // Skips (does not fail) when libpdfium can't be bound, so CI without the
        // native lib stays green. Set OLYMPUS_PDFIUM_PATH to exercise it.
        let importer = match PdfImporter::new() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("skipping pdf_importer test — libpdfium unavailable: {e}");
                return;
            }
        };
        let pages = importer.import(MINIMAL_PDF).expect("import minimal pdf");
        assert_eq!(pages.len(), 1, "one-page PDF");
        // 72 pt at 300 DPI → ~300 px (allow rounding slack).
        assert!(
            pages[0].width >= 290 && pages[0].width <= 310,
            "rendered width {} not ~300px",
            pages[0].width
        );

        let tiles = tile_page(0, &pages[0], REDACTION_TILE_PX).expect("tile pdf page");
        assert!(!tiles.is_empty());
        let mut rng = rand::thread_rng();
        let (root, sealed) =
            super::super::redaction_tile::seal(&tiles, &mut rng).expect("seal pdf tiles");
        assert_eq!(sealed.len(), tiles.len());
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn import_and_tile_feeds_seal() {
        // End-to-end: PNG → import → tile → seal yields a non-empty root, with
        // tile count matching the page's tiling.
        let page = gradient_page(40, 20);
        let buf = image::RgbaImage::from_raw(40, 20, page.pixels.clone()).unwrap();
        let mut png = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("encode png");

        let tiles = import_and_tile(&ImageImporter, &png, REDACTION_TILE_PX).expect("import+tile");
        // 40x20 at 32px → cols=2, rows=1 → 2 tiles.
        assert_eq!(tiles.len(), 2);

        let mut rng = rand::thread_rng();
        let (root, sealed) = super::super::redaction_tile::seal(&tiles, &mut rng).expect("seal");
        assert_eq!(sealed.len(), tiles.len());
        assert_ne!(root, [0u8; 32], "root must be a real commitment");
    }
}
