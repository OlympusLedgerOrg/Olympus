//! Issuer pipeline for rasterized tile redaction (ADR-0023, step 3 backend).
//!
//! Ties the pieces together into the single operation the redactor performs:
//! an importable source document + the operator's redaction rectangles →
//! a **redacted artifact** (page images with the redacted tiles overwritten)
//! plus the **signed, recipient-bound bundle**.
//!
//! Pipeline:
//!   1. import → canonical raster pages ([`super::redaction_import`]);
//!   2. tile every page and **seal** the *original* tile content
//!      ([`super::redaction_tile::seal`]) — the commitment binds the original,
//!      not the blanked output;
//!   3. map each pixel-space [`RedactionBox`] to the set of tiles it touches
//!      (whole-tile granularity — a box covering part of a tile redacts the
//!      whole tile; over-redaction is the safe direction);
//!   4. **overwrite** the pixels of those tiles with solid black (not an
//!      overlay — the original pixels are destroyed in the artifact);
//!   5. build the bundle, revealing every non-redacted tile's blinding and
//!      withholding the redacted ones ([`super::redaction_tile::build_bundle`]).
//!
//! Revealed tiles are left byte-identical to the original, so when a recipient
//! re-tiles the artifact their leaves match the sealed commitments; redacted
//! tiles are blanked in the artifact and hidden (Pedersen) in the bundle.
//!
//! Gated behind `redaction-import` (needs the importer + tiling layer).

use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use thiserror::Error;

use super::redaction_import::{
    tile_page, DocumentImporter, ImportError, PageImage, BYTES_PER_PIXEL,
};
use super::redaction_tile::{self, RedactionBundle, RedactionTileError, TileCoord};

/// A pixel-space rectangle on one page that the operator marked for redaction.
/// `(x, y)` is the top-left corner; the rectangle is `width × height` pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionBox {
    pub page: u32,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// The output of [`issue`]: the redacted artifact pages and the signed bundle.
#[derive(Debug, Clone)]
pub struct IssuedRedaction {
    /// Redacted page images (redacted tiles overwritten with solid black).
    pub pages: Vec<PageImage>,
    /// The signed, recipient-bound redaction bundle.
    pub bundle: RedactionBundle,
}

#[derive(Debug, Error)]
pub enum IssueError {
    #[error(transparent)]
    Import(#[from] ImportError),
    #[error(transparent)]
    Tile(#[from] RedactionTileError),
    #[error("no redaction boxes supplied — nothing to redact")]
    NoBoxes,
    #[error("redaction box references page {0}, but the document has {1} page(s)")]
    BoxPageOutOfRange(u32, usize),
    #[error("redaction would blank every tile — the disclosure would reveal nothing")]
    AllRedacted,
}

/// Run the full issuer pipeline. See module docs.
///
/// `tile_px` MUST be the same pinned value used everywhere
/// ([`super::redaction_import::REDACTION_TILE_PX`]); it is a parameter only so
/// tests can exercise small grids.
pub fn issue<R: rand::RngCore + rand::CryptoRng>(
    importer: &dyn DocumentImporter,
    bytes: &[u8],
    tile_px: u32,
    boxes: &[RedactionBox],
    recipient_id: &str,
    signing_key: &SigningKey,
    rng: &mut R,
) -> Result<IssuedRedaction, IssueError> {
    if boxes.is_empty() {
        return Err(IssueError::NoBoxes);
    }

    let mut pages = importer.import(bytes)?;
    if pages.is_empty() {
        return Err(ImportError::EmptyDocument.into());
    }

    // Validate box page indices up front.
    for b in boxes {
        if b.page as usize >= pages.len() {
            return Err(IssueError::BoxPageOutOfRange(b.page, pages.len()));
        }
    }

    // 1. Tile every page; seal the ORIGINAL tile content.
    let mut all_tiles: Vec<(TileCoord, Vec<u8>)> = Vec::new();
    for (i, page) in pages.iter().enumerate() {
        all_tiles.extend(tile_page(i as u32, page, tile_px)?);
    }
    let total_tiles = all_tiles.len();
    let (root, sealed) = redaction_tile::seal(&all_tiles, rng)?;

    // 2. Map boxes → redacted tile coords.
    let redacted = boxes_to_tiles(boxes, &pages, tile_px);
    if redacted.len() == total_tiles {
        return Err(IssueError::AllRedacted);
    }

    // 3. Overwrite redacted tiles in the page pixel buffers (destroy originals).
    for coord in &redacted {
        if let Some(page) = pages.get_mut(coord.page as usize) {
            blank_tile(page, coord.x, coord.y, tile_px);
        }
    }

    // 4. Build the signed bundle.
    let bundle = redaction_tile::build_bundle(root, recipient_id, &sealed, &redacted, signing_key);

    Ok(IssuedRedaction { pages, bundle })
}

/// Every tile (by coord) that any redaction box overlaps, clamped to each
/// page's tile grid. Whole-tile granularity: a box touching one pixel of a tile
/// redacts the whole tile.
fn boxes_to_tiles(boxes: &[RedactionBox], pages: &[PageImage], tile_px: u32) -> HashSet<TileCoord> {
    let mut set = HashSet::new();
    for b in boxes {
        let Some(page) = pages.get(b.page as usize) else {
            continue;
        };
        if b.width == 0 || b.height == 0 || page.width == 0 || page.height == 0 {
            continue;
        }
        // Clamp the box to the page, then to the inclusive last covered pixel.
        let x0 = b.x.min(page.width - 1);
        let y0 = b.y.min(page.height - 1);
        let x1 = b.x.saturating_add(b.width - 1).min(page.width - 1);
        let y1 = b.y.saturating_add(b.height - 1).min(page.height - 1);
        let (tx0, tx1) = (x0 / tile_px, x1 / tile_px);
        let (ty0, ty1) = (y0 / tile_px, y1 / tile_px);
        for ty in ty0..=ty1 {
            for tx in tx0..=tx1 {
                set.insert(TileCoord {
                    page: b.page,
                    x: tx,
                    y: ty,
                });
            }
        }
    }
    set
}

/// Overwrite a single tile's pixels with solid opaque black, clamped to the
/// page bounds. Destroys the original pixels (not an overlay).
fn blank_tile(page: &mut PageImage, tx: u32, ty: u32, tile_px: u32) {
    let x0 = tx * tile_px;
    let y0 = ty * tile_px;
    let x_end = (x0 + tile_px).min(page.width);
    let y_end = (y0 + tile_px).min(page.height);
    for yy in y0..y_end {
        for xx in x0..x_end {
            let off = (yy as usize * page.width as usize + xx as usize) * BYTES_PER_PIXEL;
            page.pixels[off..off + BYTES_PER_PIXEL].copy_from_slice(&[0, 0, 0, 255]);
        }
    }
}

/// Encode a [`PageImage`] to PNG bytes (convenience for shipping/persisting the
/// redacted artifact). Lossless, so a recipient re-decoding it recovers the
/// exact RGBA the bundle was built against.
pub fn encode_png(page: &PageImage) -> Result<Vec<u8>, ImportError> {
    let buf = image::RgbaImage::from_raw(page.width, page.height, page.pixels.clone())
        .ok_or(ImportError::DimensionsOverflow)?;
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(buf)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|e| ImportError::Decode(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::redaction_import::{ImageImporter, REDACTION_TILE_PX};
    use std::collections::HashMap;

    fn gradient_png(w: u32, h: u32) -> Vec<u8> {
        let mut px = Vec::with_capacity((w * h) as usize * BYTES_PER_PIXEL);
        for y in 0..h {
            for x in 0..w {
                px.push((x & 0xff) as u8);
                px.push((y & 0xff) as u8);
                px.push(((x + y) & 0xff) as u8);
                px.push(0xff);
            }
        }
        let buf = image::RgbaImage::from_raw(w, h, px).unwrap();
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    /// Re-tile the redacted artifact and verify the bundle end-to-end.
    fn verify_round_trip(issued: &IssuedRedaction, vk: &ed25519_dalek::VerifyingKey) {
        let mut artifact: HashMap<TileCoord, Vec<u8>> = HashMap::new();
        for (i, page) in issued.pages.iter().enumerate() {
            for (coord, bytes) in tile_page(i as u32, page, REDACTION_TILE_PX).unwrap() {
                artifact.insert(coord, bytes);
            }
        }
        // The redacted artifact contains *all* tiles, but verify only consults
        // revealed ones; redacted-tile bytes are blanked and never checked.
        redaction_tile::verify_bundle(&issued.bundle, &artifact, vk)
            .expect("issued bundle must verify against its own artifact");
    }

    #[test]
    fn issue_blanks_box_and_bundle_verifies() {
        // 64x64 → at 32px tiles a 2x2 grid (4 tiles). Redact the top-left tile.
        let png = gradient_png(64, 64);
        let sk = key();
        let mut rng = rand::thread_rng();
        let boxes = [RedactionBox {
            page: 0,
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        }];

        let issued = issue(
            &ImageImporter,
            &png,
            REDACTION_TILE_PX,
            &boxes,
            "recipient-1",
            &sk,
            &mut rng,
        )
        .expect("issue");

        // The top-left tile (pixels [0,32)x[0,32)) must be solid black.
        let page = &issued.pages[0];
        for y in 0..32u32 {
            for x in 0..32u32 {
                let off = (y as usize * 64 + x as usize) * BYTES_PER_PIXEL;
                assert_eq!(
                    &page.pixels[off..off + 4],
                    &[0, 0, 0, 255],
                    "redacted px ({x},{y})"
                );
            }
        }
        // A revealed tile (e.g. pixel (40,40)) keeps its gradient value.
        let off = (40usize * 64 + 40) * BYTES_PER_PIXEL;
        assert_eq!(page.pixels[off], 40u8, "revealed pixel must be untouched");

        verify_round_trip(&issued, &sk.verifying_key());
        // Exactly one tile redacted → 3 revealed of 4.
        let redacted = issued
            .bundle
            .tiles
            .iter()
            .filter(|t| t.revealed_blinding.is_none())
            .count();
        assert_eq!(redacted, 1);
        assert_eq!(issued.bundle.tiles.len(), 4);
    }

    #[test]
    fn box_spanning_tiles_redacts_all_touched() {
        // A box straddling the vertical tile boundary at x=32 must redact both
        // top tiles (whole-tile granularity).
        let png = gradient_png(64, 64);
        let sk = key();
        let mut rng = rand::thread_rng();
        let boxes = [RedactionBox {
            page: 0,
            x: 28,
            y: 0,
            width: 8,
            height: 4,
        }]; // x 28..36 crosses 32
        let issued = issue(
            &ImageImporter,
            &png,
            REDACTION_TILE_PX,
            &boxes,
            "r",
            &sk,
            &mut rng,
        )
        .unwrap();
        let redacted: Vec<_> = issued
            .bundle
            .tiles
            .iter()
            .filter(|t| t.revealed_blinding.is_none())
            .map(|t| (t.coord.x, t.coord.y))
            .collect();
        assert!(
            redacted.contains(&(0, 0)) && redacted.contains(&(1, 0)),
            "both top tiles redacted: {redacted:?}"
        );
        verify_round_trip(&issued, &sk.verifying_key());
    }

    #[test]
    fn no_boxes_is_rejected() {
        let png = gradient_png(32, 32);
        let mut rng = rand::thread_rng();
        assert!(matches!(
            issue(
                &ImageImporter,
                &png,
                REDACTION_TILE_PX,
                &[],
                "r",
                &key(),
                &mut rng
            ),
            Err(IssueError::NoBoxes)
        ));
    }

    #[test]
    fn box_on_missing_page_is_rejected() {
        let png = gradient_png(32, 32);
        let mut rng = rand::thread_rng();
        let boxes = [RedactionBox {
            page: 5,
            x: 0,
            y: 0,
            width: 4,
            height: 4,
        }];
        assert!(matches!(
            issue(
                &ImageImporter,
                &png,
                REDACTION_TILE_PX,
                &boxes,
                "r",
                &key(),
                &mut rng
            ),
            Err(IssueError::BoxPageOutOfRange(5, 1))
        ));
    }

    #[test]
    fn redacting_every_tile_is_rejected() {
        // 32x32 = a single tile; a box covering it redacts 1/1 → AllRedacted.
        let png = gradient_png(32, 32);
        let mut rng = rand::thread_rng();
        let boxes = [RedactionBox {
            page: 0,
            x: 0,
            y: 0,
            width: 32,
            height: 32,
        }];
        assert!(matches!(
            issue(
                &ImageImporter,
                &png,
                REDACTION_TILE_PX,
                &boxes,
                "r",
                &key(),
                &mut rng
            ),
            Err(IssueError::AllRedacted)
        ));
    }

    #[test]
    fn artifact_png_round_trips_through_decode() {
        // Encode the redacted artifact to PNG, decode it back, and verify — the
        // shippable form must still bind.
        let png = gradient_png(64, 64);
        let sk = key();
        let mut rng = rand::thread_rng();
        let boxes = [RedactionBox {
            page: 0,
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        }];
        let issued = issue(
            &ImageImporter,
            &png,
            REDACTION_TILE_PX,
            &boxes,
            "r",
            &sk,
            &mut rng,
        )
        .unwrap();

        let artifact_png = encode_png(&issued.pages[0]).expect("encode png");
        let decoded = ImageImporter.import(&artifact_png).expect("re-decode");
        let mut artifact: HashMap<TileCoord, Vec<u8>> = HashMap::new();
        for (coord, bytes) in tile_page(0, &decoded[0], REDACTION_TILE_PX).unwrap() {
            artifact.insert(coord, bytes);
        }
        redaction_tile::verify_bundle(&issued.bundle, &artifact, &sk.verifying_key())
            .expect("bundle must verify against the re-decoded PNG artifact");
    }
}
