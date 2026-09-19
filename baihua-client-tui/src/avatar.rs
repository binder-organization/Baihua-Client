//! Terminal avatar rendering.
//!
//! The terminal has no image layer; the smallest common unit available is true-color foreground/background plus the half-character `▀`:
//! the top half-pixels of a character cell take the foreground color and the bottom half-pixels take the background color, so 1 cell can carry 2 rows of pixels,
//! a 2-column × 2-row cell can hold a 2×4 avatar thumbnail. This approach does not depend on the kitty graphics protocol or sixel,
//! it can produce images in any terminal supporting true color (including macOS's built-in Terminal.app),
//! when the terminal does not support true color, the terminal itself degrades to the closest color, and no garbled characters appear.

use image::imageops::FilterType;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
};

/// Decoded and scaled avatar pixel block: RGBA bytes in row-major order, width by columns, height by pixel rows (= cell row count × 2).
#[derive(Debug, Clone, PartialEq)]
pub struct AvatarPixels {
    columns: usize,
    pixel_rows: usize,
    rgba: Vec<[u8; 4]>,
}

impl AvatarPixels {
    /// Cell size occupied (cell height is half the pixel row count)
    pub fn cell_size(&self) -> (usize, usize) {
        (self.columns, self.pixel_rows / 2)
    }

    /// Paint the avatar into cells at the top-left of the area: transparent pixels are blended with the application background color provided by the caller,
    /// so no black border is left at the avatar edge under either light or dark themes.
    pub fn paint(&self, frame: &mut Frame, area: Rect, background: Color) {
        let base_background = match background {
            Color::Rgb(red, green, blue) => [red, green, blue],
            _ => [0, 0, 0],
        };
        let (columns, rows) = self.cell_size();
        if columns == 0 || rows == 0 {
            return;
        }
        let buffer = frame.buffer_mut();
        for cell_row in 0..rows.min(usize::from(area.height)) {
            for cell_column in 0..columns.min(usize::from(area.width)) {
                let x = area.x + cell_column as u16;
                let y = area.y + cell_row as u16;
                let Some(cell) = buffer.cell_mut((x, y)) else {
                    continue;
                };
                let upper = self.blended(cell_row * 2, cell_column, base_background);
                let lower = self.blended(cell_row * 2 + 1, cell_column, base_background);
                cell.set_symbol("▀");
                cell.set_style(Style::default().fg(upper).bg(lower));
            }
        }
    }

    /// Get the color at the specified pixel row and column, and blend with alpha against the background. Out-of-bounds is handled as the background color (no holes when the image is cropped to the target size).
    fn blended(&self, pixel_row: usize, column: usize, base: [u8; 3]) -> Color {
        let Some(pixel) = self.rgba.get(pixel_row * self.columns + column) else {
            return Color::Rgb(base[0], base[1], base[2]);
        };
        let alpha = u32::from(pixel[3]);
        if alpha == 255 {
            return Color::Rgb(pixel[0], pixel[1], pixel[2]);
        }
        let mix = |source: u8, background: u8| -> u8 {
            ((u32::from(source) * alpha + u32::from(background) * (255 - alpha)) / 255) as u8
        };
        Color::Rgb(
            mix(pixel[0], base[0]),
            mix(pixel[1], base[1]),
            mix(pixel[2], base[2]),
        )
    }
}

/// Decode any image bytes into an avatar pixel block of `columns` columns × `rows` rows:
/// first crop to a square centered on the short side (to avoid stretching distortion for non-square avatars), then scale to the target pixel size.
/// Return None when decoding fails (not a supported image, content corrupted); the caller falls back to placeholder display.
pub fn build_avatar_pixels(
    image_bytes: &[u8],
    columns: usize,
    rows: usize,
) -> Option<AvatarPixels> {
    if columns == 0 || rows == 0 {
        return None;
    }
    let decoded = image::load_from_memory(image_bytes).ok()?;
    let square = cropped_to_square(&decoded);
    let resized = resample_to_cells(&square, columns as u32, (rows * 2) as u32);
    let rgba: Vec<[u8; 4]> = resized.pixels().map(|pixel| pixel.0).collect();
    Some(AvatarPixels {
        columns,
        pixel_rows: rows * 2,
        rgba,
    })
}

/// Scale the square original image to the exact pixel size of the avatar block.
///
/// The original avatar image is often one to two orders of magnitude larger than the target (hundreds of pixels squeezed into dozens). Such a shrink ratio, if
/// using Lanczos directly, the sampling kernel cannot cover the entire source area, causing pixels to be missed and ringing (bright dots at the edge that were not in the original),
/// so when the shrink ratio exceeds two, use image's thumbnail path -- it does area-weighted sampling over the entire source region,
/// which is exactly "low-pass then sample". For small ratios, use Lanczos directly to avoid unnecessary smoothing and loss of sharpness.
fn resample_to_cells(
    square: &image::RgbaImage,
    target_columns: u32,
    target_pixel_rows: u32,
) -> image::RgbaImage {
    let (width, height) = square.dimensions();
    let largest_target = target_columns.max(target_pixel_rows);
    let source_side = width.min(height);
    if source_side > largest_target * 2 && largest_target > 0 {
        return image::imageops::thumbnail(square, target_columns, target_pixel_rows);
    }
    image::imageops::resize(
        square,
        target_columns,
        target_pixel_rows,
        FilterType::Lanczos3,
    )
}

/// Crop a square RGBA image centered with side length equal to the short side.
fn cropped_to_square(decoded: &image::DynamicImage) -> image::RgbaImage {
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();
    let side = width.min(height).max(1);
    let left = (width - side) / 2;
    let top = (height - side) / 2;
    image::imageops::crop_imm(&rgba, left, top, side, side).to_image()
}

/// Placeholder color when the avatar is unavailable (not set, download failed, format unsupported): stably hashed by user ID to a set of medium-brightness colors,
/// the same user looks the same every time, different users are easily distinguishable, and it is not so bright as to overwhelm the body text.
pub fn placeholder_color(seed: &str) -> Color {
    let mut hash: u64 = 5381;
    for byte in seed.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    let hue_index = (hash % 6) as u8;
    let palette: [(u8, u8, u8); 6] = [
        (86, 156, 214),
        (102, 187, 140),
        (214, 164, 86),
        (180, 120, 200),
        (200, 120, 120),
        (120, 190, 190),
    ];
    let (red, green, blue) = palette[hue_index as usize];
    Color::Rgb(red, green, blue)
}

/// Get the first character of the username for placeholder display (Latin letters are uppercased, other scripts take one character as-is); use a question mark when empty.
pub fn placeholder_initial(username: &str) -> String {
    username
        .chars()
        .next()
        .map(|character| {
            if character.is_ascii_alphabetic() {
                character.to_ascii_uppercase().to_string()
            } else {
                character.to_string()
            }
        })
        .unwrap_or_else(|| "?".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test image with solid color and transparent corners (PNG bytes)
    fn synthetic_png(width: u32, height: u32) -> Vec<u8> {
        let mut image_buffer =
            image::RgbaImage::from_pixel(width, height, image::Rgba([220, 30, 30, 255]));
        image_buffer.put_pixel(0, 0, image::Rgba([0, 0, 0, 0]));
        let mut encoded = std::io::Cursor::new(Vec::new());
        image_buffer
            .write_to(&mut encoded, image::ImageFormat::Png)
            .expect("Test image should be encodable");
        encoded.into_inner()
    }

    #[test]
    fn avatar_pixels_have_exactly_two_pixel_rows_per_cell_row() {
        let pixels = build_avatar_pixels(&synthetic_png(64, 64), 3, 2)
            .expect("Test image should be decodable as an avatar");
        assert_eq!(pixels.cell_size(), (3, 2));
        assert_eq!(pixels.rgba.len(), 3 * 4);
    }

    #[test]
    fn large_source_is_downsampled_in_two_stages_and_still_lands_on_the_exact_grid() {
        // 512×512 is far larger than the target, it will go through the two-stage path of "area averaging + Lanczos",
        // but the output size must still be exactly columns × rows×2 pixels
        let pixels = build_avatar_pixels(&synthetic_png(512, 512), 16, 8)
            .expect("Large image should be able to shrink to an avatar block");
        assert_eq!(pixels.cell_size(), (16, 8));
        assert_eq!(pixels.rgba.len(), 16 * 16);
    }

    #[test]
    fn non_square_source_is_center_cropped_before_scaling() {
        // A 12×3 horizontal bar is cropped to 3×3 on the short side then scaled; width and height both reach the target, it will not be stretched
        let pixels = build_avatar_pixels(&synthetic_png(12, 3), 2, 2)
            .expect("Horizontal bar image should be cropable and scalable");
        assert_eq!(pixels.cell_size(), (2, 2));
    }

    #[test]
    fn undecodable_bytes_yield_no_avatar_instead_of_panicking() {
        assert!(build_avatar_pixels(b"not an image at all", 2, 2).is_none());
        assert!(build_avatar_pixels(&synthetic_png(8, 8), 0, 2).is_none());
    }

    #[test]
    fn placeholder_is_stable_per_user_and_uppercases_latin_initial() {
        assert_eq!(placeholder_color("alice"), placeholder_color("alice"));
        assert_ne!(placeholder_color("alice"), placeholder_color("bob"));
        assert_eq!(placeholder_initial("alice"), "A");
        assert_eq!(placeholder_initial("白露"), "白");
        assert_eq!(placeholder_initial(""), "?");
    }

    #[test]
    fn painting_writes_half_block_cells_with_truecolor_pair() {
        use ratatui::{Terminal, backend::TestBackend};
        let pixels =
            build_avatar_pixels(&synthetic_png(16, 16), 2, 2).expect("should decode avatar");
        let mut terminal =
            Terminal::new(TestBackend::new(8, 4)).expect("test terminal should be created");
        terminal
            .draw(|frame| pixels.paint(frame, frame.area(), Color::Rgb(10, 10, 10)))
            .expect("avatar drawing should not fail");
        let buffer = terminal.backend().buffer().clone();
        let cell = buffer.cell((0, 0)).expect("first cell should exist");
        assert_eq!(cell.symbol(), "▀");
        assert!(matches!(cell.fg, Color::Rgb(_, _, _)));
        assert!(matches!(cell.bg, Color::Rgb(_, _, _)));
    }
}
