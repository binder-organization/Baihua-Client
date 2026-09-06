//! 终端头像渲染。
//!
//! 终端没有图片层，能用的最小公共单元是真色前景/背景加半块字符 `▀`：
//! 一个字符格的上半像素走前景色、下半像素走背景色，于是 1 格可承载 2 行像素，
//! 2 列 × 2 行的格子就能放下 2×4 的头像缩略图。该写法不依赖 kitty 图形协议或 sixel，
//! 在任何支持真色的终端（含 macOS 自带 Terminal.app）里都能出图，
//! 终端不支持真色时由终端自行降级为最接近的色，不会出现乱码。

use image::imageops::FilterType;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
};

/// 已解码并缩放到位的头像像素块：行主序的 RGBA 字节，宽度按列、高度按像素行（= 单元格行数 × 2）。
#[derive(Debug, Clone, PartialEq)]
pub struct AvatarPixels {
    columns: usize,
    pixel_rows: usize,
    rgba: Vec<[u8; 4]>,
}

impl AvatarPixels {
    /// 占用的单元格宽高（单元格高度是像素行数的一半）
    pub fn cell_size(&self) -> (usize, usize) {
        (self.columns, self.pixel_rows / 2)
    }

    /// 把头像画进区域左上角的若干单元格：透明像素按调用方给的应用背景色混合，
    /// 因此浅色主题与深色主题下都不会在头像边缘留下黑边。
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

    /// 取指定像素行与列的颜色，并按 alpha 与底色混合。越界按底色处理（图片被目标尺寸截断时不留空洞）。
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

/// 把任意图片字节解码成 `columns` 列 × `rows` 行的头像像素块：
/// 先按短边居中裁成正方形（避免非正方形头像被拉伸变形），再缩放到目标像素尺寸。
/// 解码失败（不是受支持的图片、内容损坏）时返回 None，由调用方退回占位显示。
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

/// 把正方形原图缩到头像块的精确像素尺寸。
///
/// 头像原图往往比目标大一到两个数量级（几百像素压到几十像素）。这种倍率的缩小如果
/// 直接上 Lanczos，采样核覆盖不到整个源区域，会漏掉像素并起振铃（边缘出现原图没有的亮点），
/// 所以超过两倍缩率时走 image 的 thumbnail 路径 —— 它按整块源区域做面积加权取样，
/// 正是"先低通再采样"。缩率不大时直接 Lanczos，避免多余的平滑损失锐度。
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

/// 居中裁出边长等于短边的正方形 RGBA 图。
fn cropped_to_square(decoded: &image::DynamicImage) -> image::RgbaImage {
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();
    let side = width.min(height).max(1);
    let left = (width - side) / 2;
    let top = (height - side) / 2;
    image::imageops::crop_imm(&rgba, left, top, side, side).to_image()
}

/// 头像不可用时（未设置、下载失败、格式不支持）的占位色：按用户 ID 稳定哈希到一组中等亮度色，
/// 同一用户每次显示一致，不同用户能一眼区分，且不会亮到盖过正文。
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

/// 取用户名用于占位显示的首字符（拉丁字母转大写，其它文字原样取一个字），无内容时用问号。
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

    /// 造一张纯色带透明角的测试图（PNG 字节）
    fn synthetic_png(width: u32, height: u32) -> Vec<u8> {
        let mut image_buffer =
            image::RgbaImage::from_pixel(width, height, image::Rgba([220, 30, 30, 255]));
        image_buffer.put_pixel(0, 0, image::Rgba([0, 0, 0, 0]));
        let mut encoded = std::io::Cursor::new(Vec::new());
        image_buffer
            .write_to(&mut encoded, image::ImageFormat::Png)
            .expect("测试图片应能编码");
        encoded.into_inner()
    }

    #[test]
    fn avatar_pixels_have_exactly_two_pixel_rows_per_cell_row() {
        let pixels =
            build_avatar_pixels(&synthetic_png(64, 64), 3, 2).expect("测试图片应能解码为头像");
        assert_eq!(pixels.cell_size(), (3, 2));
        assert_eq!(pixels.rgba.len(), 3 * 4);
    }

    #[test]
    fn large_source_is_downsampled_in_two_stages_and_still_lands_on_the_exact_grid() {
        // 512×512 远大于目标，会走"面积平均 + Lanczos"的两段路径，
        // 但输出尺寸必须仍是精确的 列 × 行×2 像素
        let pixels =
            build_avatar_pixels(&synthetic_png(512, 512), 16, 8).expect("大图应能缩成头像块");
        assert_eq!(pixels.cell_size(), (16, 8));
        assert_eq!(pixels.rgba.len(), 16 * 16);
    }

    #[test]
    fn non_square_source_is_center_cropped_before_scaling() {
        // 12×3 的横条按短边裁成 3×3 后缩放，宽高都取到目标值，不会被拉扁
        let pixels =
            build_avatar_pixels(&synthetic_png(12, 3), 2, 2).expect("横条图应能裁切并缩放");
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
        let pixels = build_avatar_pixels(&synthetic_png(16, 16), 2, 2).expect("应能解码头像");
        let mut terminal = Terminal::new(TestBackend::new(8, 4)).expect("测试终端应能创建");
        terminal
            .draw(|frame| pixels.paint(frame, frame.area(), Color::Rgb(10, 10, 10)))
            .expect("绘制头像不应失败");
        let buffer = terminal.backend().buffer().clone();
        let cell = buffer.cell((0, 0)).expect("首格应存在");
        assert_eq!(cell.symbol(), "▀");
        assert!(matches!(cell.fg, Color::Rgb(_, _, _)));
        assert!(matches!(cell.bg, Color::Rgb(_, _, _)));
    }
}
