//! Theme conversion and avatar texturing. Both are a thin layer of glue that "turns session-layer data into interface resources".
//! Also responsible for installing CJK fonts: egui's built-in fonts only have Latin glyphs, so a set of CJK fonts must be added,
//! otherwise all Chinese text on the interface would be tofu blocks.

use baihua_core::config::{Palette, ThemeColor};
use egui::epaint::text::{FontData, FontInsert, FontPriority, FontTweak, InsertFontFamily};
use egui::{
    Color32, Context, FontFamily, FontId, Stroke, TextureHandle, TextureOptions, Theme, Visuals,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// The name of the CJK fallback font installed into egui (used as a key in the font table)
fn cjk_font_name() -> &'static str {
    "baihua-cjk"
}

/// Warm up one empty frame. `Context`'s font table only builds up after running a frame (querying the font table before the first frame will panic),
/// and fonts added via `Context::add_font` only take effect at the start of the next frame, so "run a frame before and after installing fonts"
/// is the fixed prerequisite here.
fn run_one_empty_frame(context: &Context) {
    context
        .run_ui(egui::RawInput::default(), |_ui| {})
        .drop_without_applying_deltas();
}

/// Temporary font table key name used when probing the baseline. Only measured once before "installing fonts for the real interface use",
/// then discard together with the temporary context.
fn probe_font_name() -> &'static str {
    "baihua-cjk-probe"
}

/// Font size used when probing the baseline (in points). What matters is the "ratio of offset to font size"; the actual font size doesn't affect the result.
fn probe_font_size() -> f32 {
    14.0
}

/// Place one character, get back its baseline Y coordinate (relative to the top of that line).
/// egui treats each glyph's `pos.y` as the baseline (glyph bitmaps are placed relative to this line via `uv_rect.offset`);
/// returns None when the character can't be placed in the current font family.
fn glyph_baseline(context: &Context, family: FontFamily, character: char) -> Option<f32> {
    let font_id = FontId::new(probe_font_size(), family);
    context.fonts_mut(|fonts| {
        let galley = fonts.layout_no_wrap(character.to_string(), font_id, Color32::WHITE);
        galley
            .rows
            .iter()
            .flat_map(|row| row.glyphs.iter())
            .next()
            .map(|glyph| glyph.pos.y)
    })
}

/// How much higher CJK glyphs are than Latin letters in the same font family, converted to a "vertical offset ratio scaled by font size".
///
/// When egui places fallback font glyphs, the baseline is taken as `ascent + (main font line height - ascent line height) / 2`:
/// CJK font line height is significantly larger than egui's built-in Latin font (on the dev machine, Dongqing Heiti is 1.5x font size,
/// while Ubuntu-Light is only 1.15x) — this "centering difference" pushes the entire CJK text upward —
/// at 14pt the CJK baseline is actually raised by 3 points, glyphs even protrude beyond the line box,
/// mixed Chinese-English text makes CJK characters noticeably higher. This is the root cause of "CJK characters display shifted upward".
///
/// The fix is to first install the same font in a temporary context, measure the baseline difference between Latin letters and CJK characters in the same family,
/// then pass it to `FontTweak::y_offset_factor`: egui will place CJK glyphs on the same baseline.
/// The proportional and monospace families share this ratio: the Latin fonts of both families (Ubuntu-Light and Hack) have very similar vertical proportions
/// (differing by less than 0.02x font size), and the test asserts baseline alignment for both families.
/// The probe must happen before "installing fonts for the real interface use", so the temporary context must occupy its own font bytes,
/// measure and immediately release; the one used by the interface is unaffected.
fn cjk_baseline_offset_factor(bytes: &[u8], face_index: u32) -> f32 {
    let probe = Context::default();
    run_one_empty_frame(&probe);
    probe.add_font(FontInsert::new(
        probe_font_name(),
        FontData {
            font: Cow::Owned(bytes.to_vec()),
            index: face_index,
            tweak: FontTweak::default(),
        },
        vec![InsertFontFamily {
            family: FontFamily::Proportional,
            priority: FontPriority::Lowest,
        }],
    ));
    run_one_empty_frame(&probe);
    let latin = glyph_baseline(&probe, FontFamily::Proportional, 'A');
    let chinese = glyph_baseline(&probe, FontFamily::Proportional, '你');
    match (latin, chinese) {
        (Some(latin), Some(chinese)) => (latin - chinese) / probe_font_size(),
        // This font cannot render the probe characters: better to have no offset than to add an offset out of thin air
        _ => 0.0,
    }
}

/// Add CJK fonts to egui's font table.
///
/// The approach is to append a set of "lowest priority" fallback fonts via `Context::add_font`: egui's built-in default font
/// is still checked first, Latin letters, numbers, and symbols keep their default appearance; only when a glyph (CJK,
/// full-width punctuation) cannot be found in the previous sets, it falls back to this CJK font.
/// This is more stable than replacing everything with `set_fonts`: it neither requires rebuilding the default font table nor breaks egui's built-in appearance.
///
/// The fallback font is "foreign"; egui determines its baseline by its own rules, which would push CJK characters above Latin letters,
/// so before installing we measure the difference and use `FontTweak::y_offset_factor` to bring CJK back to the same baseline.
///
/// If no candidate is found in the system, return directly; the interface starts normally (Chinese would display as placeholder boxes,
/// but it won't fail to start due to missing fonts). Fonts are installed only once, called in `BaihuaApp::new()`.
pub fn install_cjk_font(context: &Context) {
    let Some((bytes, face_index)) = baihua_core::fonts::discover_cjk_font() else {
        return;
    };
    let offset_factor = cjk_baseline_offset_factor(&bytes, face_index);
    let font_data = FontData {
        font: Cow::Owned(bytes),
        index: face_index,
        tweak: FontTweak {
            y_offset_factor: offset_factor,
            ..Default::default()
        },
    };
    // Both CJK font slots must be registered: Proportional for body text, Monospace for monospace areas,
    // without the monospace one, CJK characters in the monospace family would still be boxes
    context.add_font(FontInsert::new(
        cjk_font_name(),
        font_data,
        vec![
            InsertFontFamily {
                family: FontFamily::Proportional,
                priority: FontPriority::Lowest,
            },
            InsertFontFamily {
                family: FontFamily::Monospace,
                priority: FontPriority::Lowest,
            },
        ],
    ));
}

/// After installing fonts, do a self-check: whether the current egui font table has that CJK font.
/// Only used in tests (not checked during normal operation), used to assert "the font installation actually worked".
#[cfg(test)]
pub fn cjk_font_is_installed(context: &Context) -> bool {
    let definitions: egui::FontDefinitions = context.fonts(|fonts| fonts.definitions().clone());
    definitions.font_data.contains_key(cjk_font_name())
}

fn to_color32(color: ThemeColor) -> Color32 {
    match color {
        ThemeColor::Default => Color32::from_gray(24),
        other => {
            let (red, green, blue) = other.to_rgb();
            Color32::from_rgb(red, green, blue)
        }
    }
}

/// Is this color light when used as a background: light backgrounds need dark text, dark backgrounds need light text,
/// and also determines whether the baseline visuals applied to egui use light or dark colors.
/// The weighted formula matches `ThemeColor::brightness` in `baihua-session`,
/// so both sides won't disagree on "light or dark".
fn is_light_background(color: Color32) -> bool {
    let brightness =
        (color.r() as u32 * 299 + color.g() as u32 * 587 + color.b() as u32 * 114) / 1000;
    brightness >= 128
}

/// Pick a readable foreground color for a color "used as a background". Theme slot background colors, search match backgrounds,
/// only guarantee the background looks good; using them directly as text colors would result in light-on-light or dark-on-dark,
/// so text colors are always derived from the background brightness here.
pub(crate) fn contrasting_foreground(background: Color32) -> Color32 {
    if is_light_background(background) {
        Color32::BLACK
    } else {
        Color32::WHITE
    }
}

/// Color set for interface rendering. Fields correspond one-to-one with theme slots; missing items are fallbacks from `Palette::built_in`.
#[derive(Clone)]
pub struct Skin {
    pub app_background: Color32,
    pub message_border: Color32,
    pub room_border: Color32,
    pub overlay_border: Color32,
    pub message_text: Color32,
    pub selected_text: Color32,
    pub other_username_text: Color32,
    pub own_username_text: Color32,
    pub time_text: Color32,
    pub hint_text: Color32,
    pub notice_hint_border: Color32,
    pub notice_error_border: Color32,
    pub input_border: Color32,
    pub input_text: Color32,
    pub command_border: Color32,
    pub search_border: Color32,
    pub selection_background: Color32,
    pub search_match_background: Color32,
    pub search_current_match_background: Color32,
}

impl Skin {
    pub fn from(palette: &Palette) -> Self {
        Self {
            app_background: to_color32(palette.app_background),
            message_border: to_color32(palette.message_border),
            room_border: to_color32(palette.room_border),
            overlay_border: to_color32(palette.overlay_border),
            message_text: to_color32(palette.message_text),
            selected_text: to_color32(palette.selected_text),
            other_username_text: to_color32(palette.other_username_text),
            own_username_text: to_color32(palette.own_username_text),
            time_text: to_color32(palette.time_text),
            hint_text: to_color32(palette.hint_text),
            notice_hint_border: to_color32(palette.notice_hint_border),
            notice_error_border: to_color32(palette.notice_error_border),
            input_border: to_color32(palette.input_border),
            input_text: to_color32(palette.input_text),
            command_border: to_color32(palette.command_border),
            search_border: to_color32(palette.search_border),
            selection_background: to_color32(palette.selection_background),
            search_match_background: to_color32(palette.search_match_background),
            search_current_match_background: to_color32(palette.search_current_match_background),
        }
    }

    /// Apply the theme to egui's visuals: panel backgrounds, widget backgrounds, and text colors all come from the user-selected theme.
    ///
    /// Baseline visuals are chosen by theme background brightness: dark backgrounds use egui's dark baseline, light backgrounds use light baseline.
    /// When only the dark baseline is used, "derived" colors like button backgrounds in light themes remain dark,
    /// so dark text on dark backgrounds becomes unreadable on light backgrounds.
    pub fn apply_to(&self, context: &Context) {
        let mut visuals = if is_light_background(self.app_background) {
            Visuals::light()
        } else {
            Visuals::dark()
        };
        visuals.panel_fill = self.app_background;
        visuals.window_fill = self.app_background;
        visuals.extreme_bg_color = self.app_background;
        visuals.faint_bg_color = self.app_background;
        visuals.override_text_color = Some(self.message_text);
        visuals.selection.bg_fill = self.selection_background;
        // The foreground color of selected text must contrast with the selection background: previously this used the app background color directly,
        // and the input field background color source is the app background color, so "the selected text in the input field matches the input field background exactly",
        // the selected text is directly invisible (the input field border on focus also uses this color, so it disappears too)
        visuals.selection.stroke.color = contrasting_foreground(self.selection_background);
        // Widget (button, input field) backgrounds and borders also come from the theme, and retain three states: "normal/hover/pressed":
        // previously button backgrounds were the egui default theme's (dark text on dark background in light themes),
        // while hardcoding a `fill` for a specific button would also eliminate the hover and click feedback.
        // the normal state `bg_stroke` is "buttons must have a border by default": width 1.0,
        // hover and press only change the border color, not "whether there is a border", so there is a frame even when the mouse is not over it.
        for (widget, fill, stroke_color) in [
            (
                &mut visuals.widgets.inactive,
                self.app_background,
                self.room_border,
            ),
            (
                &mut visuals.widgets.hovered,
                widget_hover_fill(self.app_background),
                self.overlay_border,
            ),
            (
                &mut visuals.widgets.active,
                widget_active_fill(self.app_background),
                self.overlay_border,
            ),
        ] {
            widget.weak_bg_fill = fill;
            // `bg_fill` is the background color source for checkboxes (the "switches" in the settings panel): egui's default is its own gray,
            // when the theme only writes `weak_bg_fill` the checkbox still has egui's gray background, and the border and background collide so "no border is visible".
            // background colors all follow the theme; the only visible boundary left for the checkbox in its normal state is this border given by the theme.
            widget.bg_fill = fill;
            widget.bg_stroke = Stroke::new(1.0, stroke_color);
        }
        // theme colors must be written into egui's **both dark and light style variants** simultaneously, not just "the current one".
        //
        // the default theme preference is "follow system", but the program doesn't know if the system is light or dark on startup
        // (`Context::theme()` gets the fallback dark one first), the variant written by `set_visuals`
        // might not be the one that actually takes effect later: the other variant is still egui default appearance,
        // so buttons only have borders on hover, and the input field background collides with the text color in the theme (white on white),
        // and isn't corrected until the user switches language or appearance for the first time (at which point it gets rewritten once).
        // write both variants as this theme's settings, so no matter which variant egui picks, the interface appearance is determined by the theme.
        for theme in [Theme::Dark, Theme::Light] {
            context.set_visuals_of(theme, visuals.clone());
        }
    }
}

/// Button hover fill: a slight brightness change on the app background (darken light backgrounds, brighten dark backgrounds),
/// matching the meaning of egui's built-in widgets "brighter/darker on hover".
fn widget_hover_fill(background: Color32) -> Color32 {
    if is_light_background(background) {
        background.gamma_multiply(0.94)
    } else {
        background.gamma_multiply(1.35)
    }
}

/// Button active fill: slightly more pronounced than hover
fn widget_active_fill(background: Color32) -> Color32 {
    if is_light_background(background) {
        background.gamma_multiply(0.86)
    } else {
        background.gamma_multiply(1.7)
    }
}

/// What an avatar image needs to do to go from "has bytes" to "can be drawn": decode + scale proportionally.
/// This is pure CPU work (scaling a large image to 32×32 with Lanczos takes milliseconds to tens of milliseconds),
/// leaving it in the render thread would make the interface stutter, so it's uniformly handed to the decoder thread pool below.
struct AvatarDecodeJob {
    /// Cache key: (user ID, side length in pixels)
    key: (String, usize),
    /// Byte fingerprint: if the avatar bytes have changed the fingerprint won't match, so the result is invalidated
    fingerprint: u64,
    /// Original avatar bytes (image file content)
    bytes: Vec<u8>,
    /// Target side length (pixels)
    side: usize,
}

/// Result returned by the decode thread
struct AvatarDecodeResult {
    /// Which image this is (user ID and side length)
    key: (String, usize),
    /// Corresponding byte fingerprint
    fingerprint: u64,
    /// Decoded image; None if the image is corrupted or format is unrecognized
    image: Option<egui::ColorImage>,
}

/// Avatar decoder thread pool: fixed number of threads take tasks from the same queue, decode and send results back to the render thread.
/// Thread count is machine parallelism (max 4); blocks when queue is empty, exits when channel closes (client exits).
struct AvatarDecoder {
    /// Job sender: render thread only submits, doesn't wait for results
    jobs: std::sync::mpsc::Sender<AvatarDecodeJob>,
    /// Result receiver: render thread receives non-blocking every frame
    results: std::sync::mpsc::Receiver<AvatarDecodeResult>,
}

impl AvatarDecoder {
    fn start() -> Self {
        let (job_sender, job_receiver) = std::sync::mpsc::channel::<AvatarDecodeJob>();
        let (result_sender, result_receiver) = std::sync::mpsc::channel::<AvatarDecodeResult>();
        let shared_jobs = std::sync::Arc::new(std::sync::Mutex::new(job_receiver));
        for _ in 0..avatar_decode_worker_count() {
            let jobs = std::sync::Arc::clone(&shared_jobs);
            let results = result_sender.clone();
            std::thread::spawn(move || {
                loop {
                    let job = {
                        let Ok(receiver) = jobs.lock() else {
                            return;
                        };
                        match receiver.recv() {
                            Ok(job) => job,
                            Err(_) => return,
                        }
                    };
                    let result = AvatarDecodeResult {
                        key: job.key,
                        fingerprint: job.fingerprint,
                        image: load_rgba_image(&job.bytes, job.side),
                    };
                    if results.send(result).is_err() {
                        return;
                    }
                }
            });
        }
        Self {
            jobs: job_sender,
            results: result_receiver,
        }
    }
}

/// Number of decode threads: machine parallelism, max 4, min 1
fn avatar_decode_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get().min(4))
        .unwrap_or(1)
}

/// Lifecycle state of an avatar texture
enum AvatarTextureState {
    /// Queued for decoding, not returned yet (interface draws placeholder first)
    Decoding(u64),
    /// Decoded but not yet uploaded as a texture (attached to egui on next texture() call)
    Decoded(u64, egui::ColorImage),
    /// Uploaded as a texture, ready to use
    Uploaded(u64, TextureHandle),
    /// Bytes can't decode (unknown format or corrupted file): don't re-queue, interface keeps drawing placeholders
    Unavailable(u64),
}

/// Avatar texture cache: key is (user ID, side length in pixels). Changed bytes (avatar swap) use "byte fingerprint" to decide whether to reload.
/// Decoding happens in background thread; render thread each frame only does two light tasks: receiving results, looking up cache (uploading decoded image when needed).
#[derive(Default)]
pub struct AvatarTextures {
    /// Which step of the lifecycle each avatar is currently in
    entries: HashMap<(String, usize), AvatarTextureState>,
    /// decoder thread pool; threads are only started when actual decoding is needed
    decoder: Option<AvatarDecoder>,
}

impl AvatarTextures {
    /// Get the texture for a user at side pixels; returns None if no avatar, still decoding, or decode failed (interface draws placeholder letter).
    /// When seeing bytes for the first time, only queue for decoding and return immediately; never decode the image in this frame.
    pub fn texture(
        &mut self,
        context: &Context,
        user_id: &str,
        bytes: Option<&[u8]>,
        side: usize,
    ) -> Option<TextureHandle> {
        self.collect_decoded_images();
        let bytes = bytes?;
        let fingerprint = fingerprint(bytes);
        let key = (user_id.to_string(), side);
        if let Some(state) = self.entries.get_mut(&key) {
            match state {
                AvatarTextureState::Uploaded(cached, handle) if *cached == fingerprint => {
                    return Some(handle.clone());
                }
                AvatarTextureState::Decoded(cached, image) if *cached == fingerprint => {
                    let handle = context.load_texture(
                        format!("baihua-avatar-{user_id}-{side}"),
                        image.clone(),
                        TextureOptions::LINEAR,
                    );
                    *state = AvatarTextureState::Uploaded(fingerprint, handle.clone());
                    return Some(handle);
                }
                // still decoding: let the interface draw a placeholder first
                AvatarTextureState::Decoding(cached) if *cached == fingerprint => return None,
                // bytes can't decode to an image: don't re-queue
                AvatarTextureState::Unavailable(cached) if *cached == fingerprint => return None,
                _ => {}
            }
        }
        self.entries
            .insert(key.clone(), AvatarTextureState::Decoding(fingerprint));
        let decoder = self.decoder.get_or_insert_with(AvatarDecoder::start);
        let _ = decoder.jobs.send(AvatarDecodeJob {
            key,
            fingerprint,
            bytes: bytes.to_vec(),
            side,
        });
        None
    }

    /// No need to clear cache when theme or directory changes: avatars use byte fingerprint; size changes create a new cache entry
    pub fn forget(&mut self, user_id: &str) {
        self.entries
            .retain(|(cached_user, _), _| cached_user != user_id);
    }

    /// collect results returned by the decode thread into the table (once per frame, non-blocking)
    fn collect_decoded_images(&mut self) {
        let Some(decoder) = &self.decoder else {
            return;
        };
        while let Ok(result) = decoder.results.try_recv() {
            let state = match result.image {
                Some(image) => AvatarTextureState::Decoded(result.fingerprint, image),
                None => AvatarTextureState::Unavailable(result.fingerprint),
            };
            self.entries.insert(result.key, state);
        }
    }
}

/// Lightweight byte fingerprint: length + first and last few bytes, enough to determine "has the avatar changed"
fn fingerprint(bytes: &[u8]) -> u64 {
    let mut value = bytes.len() as u64;
    for byte in bytes.iter().take(8).chain(bytes.iter().rev().take(8)) {
        value = value.wrapping_mul(131).wrapping_add(*byte as u64);
    }
    value
}

/// Decode and scale to side×side RGBA image (crop to square centered on short side first, then scale; avatar won't deform)
fn load_rgba_image(bytes: &[u8], side: usize) -> Option<egui::ColorImage> {
    use image::GenericImageView;
    let decoded = image::load_from_memory(bytes).ok()?;
    let (width, height) = decoded.dimensions();
    let side_source = width.min(height);
    let cropped = decoded.crop_imm(
        (width - side_source) / 2,
        (height - side_source) / 2,
        side_source,
        side_source,
    );
    let resized = cropped.resize_to_fill(
        side as u32,
        side as u32,
        image::imageops::FilterType::Lanczos3,
    );
    let rgba = resized.to_rgba8().into_raw();
    Some(egui::ColorImage::from_rgba_unmultiplied(
        [side, side],
        &rgba,
    ))
}

#[cfg(test)]
mod font_tests {
    use super::{cjk_font_is_installed, install_cjk_font, probe_font_size, run_one_empty_frame};
    use egui::epaint::text::{FontData, FontInsert, FontPriority, FontTweak, InsertFontFamily};
    use egui::{Color32, Context, FontFamily, FontId};
    use std::borrow::Cow;

    /// A character that "definitely has no glyph": Unicode non-character code point, no font should accept it.
    /// Use the glyph rendered by it as the baseline for "replacement box".
    fn guaranteed_missing_character() -> char {
        '\u{10FFFD}'
    }

    /// Quantifiable drawing features of a glyph: advance width, texture rectangle size and offset.
    ///
    /// Comparing only advance width isn't stable: the width of the replacement box drawn by egui sometimes happens to be close to the CJK character's body width
    /// (measured: PingFang at 14pt renders "you" as 14.0, box as 14.396, difference only 0.4).
    /// But the replacement box's texture size and offset are identical to missing-character glyphs, while real glyphs each have their own bitmaps,
    /// so "whether the drawing features match the missing-character baseline" is the reliable criterion.
    ///
    /// Deliberately excludes the character itself: characters are obviously different; including it would make every character "different from the baseline",
    /// which would invalidate the criterion.
    #[derive(Debug, PartialEq)]
    struct GlyphSignature {
        advance_width: f32,
        texture_size: [f32; 2],
        texture_offset: [f32; 2],
    }

    /// place one character, get back its glyph features; return None if it can't be placed
    fn glyph_signature(
        context: &Context,
        family: FontFamily,
        character: char,
    ) -> Option<GlyphSignature> {
        let font_id = FontId::new(14.0, family);
        context.fonts_mut(|fonts| {
            let galley =
                fonts.layout_no_wrap(character.to_string(), font_id.clone(), egui::Color32::WHITE);
            let glyph = galley
                .rows
                .iter()
                .flat_map(|row| row.glyphs.iter())
                .next()?;
            Some(GlyphSignature {
                advance_width: glyph.advance_width,
                texture_size: [glyph.uv_rect.size.x, glyph.uv_rect.size.y],
                texture_offset: [glyph.uv_rect.offset.x, glyph.uv_rect.offset.y],
            })
        })
    }

    /// whether a character in a certain font family is rendered as a real glyph (not a replacement box identical to the missing-character glyph)
    fn character_is_rendered_with_a_real_glyph(
        context: &Context,
        family: FontFamily,
        character: char,
    ) -> bool {
        let Some(character_glyph) = glyph_signature(context, family.clone(), character) else {
            return false;
        };
        let Some(missing_glyph) = glyph_signature(context, family, guaranteed_missing_character())
        else {
            return false;
        };
        character_glyph != missing_glyph
    }

    /// A context that has installed CJK fonts and run a frame for the fonts to take effect
    fn context_with_cjk_font_installed() -> Context {
        let context = warmed_up_context();
        install_cjk_font(&context);
        run_one_empty_frame(&context);
        context
    }

    /// A context that has already initialized the font table
    fn warmed_up_context() -> Context {
        let context = Context::default();
        run_one_empty_frame(&context);
        context
    }

    /// Regression for this round's feedback "default font can't display Chinese": after installing fonts,
    /// every Chinese character must be rendered as a real glyph (not a replacement box).
    #[test]
    fn chinese_text_gets_real_glyphs_after_installing_the_font() {
        if baihua_core::fonts::discover_cjk_font().is_none() {
            // this machine has no CJK font candidates: this is an allowed degradation, skip the assertion
            return;
        }
        let context = context_with_cjk_font_installed();
        assert!(
            cjk_font_is_installed(&context),
            "装过字体之后字体表里应当有汉字字体"
        );
        for character in "你好百花客户端".chars() {
            assert!(
                character_is_rendered_with_a_real_glyph(
                    &context,
                    FontFamily::Proportional,
                    character
                ),
                "装过字体后 {character:?} 应当排成真实字形，而不是替代方框"
            );
        }
    }

    /// Without fonts installed, Chinese is just replacement boxes: this conversely proves the assertion above is actually testing fonts,
    /// not that egui can draw Chinese by default (otherwise this regression test would be a sham)
    #[test]
    fn chinese_text_is_just_a_replacement_box_without_installing_the_font() {
        let context = warmed_up_context();
        assert!(
            !cjk_font_is_installed(&context),
            "默认字体表里不该有我们那套汉字字体"
        );
        for character in "你好".chars() {
            assert!(
                !character_is_rendered_with_a_real_glyph(
                    &context,
                    FontFamily::Proportional,
                    character
                ),
                "{character:?} 在没装汉字字体时应当与替代方框同宽"
            );
        }
    }

    /// Must also render real glyphs in the monospace family: Chinese rendered in monospace must not be boxes
    #[test]
    fn chinese_text_gets_real_glyphs_in_the_monospace_family_too() {
        if baihua_core::fonts::discover_cjk_font().is_none() {
            return;
        }
        let context = context_with_cjk_font_installed();
        for character in "你好".chars() {
            assert!(
                character_is_rendered_with_a_real_glyph(&context, FontFamily::Monospace, character),
                "等宽族里的 {character:?} 也应当排成真实字形"
            );
        }
    }

    /// Installing CJK fonts must not affect Latin letters: egui's built-in font is still checked first,
    /// English and numbers keep their original glyphs and widths
    #[test]
    fn latin_text_keeps_the_default_font_after_installing() {
        if baihua_core::fonts::discover_cjk_font().is_none() {
            return;
        }
        let before = warmed_up_context();
        let after = context_with_cjk_font_installed();
        for character in "Hello123".chars() {
            let before_glyph = glyph_signature(&before, FontFamily::Proportional, character);
            let after_glyph = glyph_signature(&after, FontFamily::Proportional, character);
            assert_eq!(
                before_glyph, after_glyph,
                "拉丁字母与数字的字形不该被汉字兜底字体改变，出问题的是 {character:?}"
            );
        }
    }

    /// Where a glyph is placed: baseline Y coordinate and top of glyph bitmap Y coordinate (both relative to top of line).
    /// The difference is "how far above the baseline the ink top is", which is determined only by the font itself,
    /// so it can be measured in an unaligned arrangement and then used in the aligned one.
    struct GlyphPlacement {
        baseline: f32,
        ink_top: f32,
    }

    /// place one character, get back its position; return None if it can't be placed
    fn glyph_placement(
        context: &Context,
        family: FontFamily,
        character: char,
    ) -> Option<GlyphPlacement> {
        let font_id = FontId::new(probe_font_size(), family);
        context.fonts_mut(|fonts| {
            let galley = fonts.layout_no_wrap(character.to_string(), font_id, Color32::WHITE);
            let glyph = galley
                .rows
                .iter()
                .flat_map(|row| row.glyphs.iter())
                .next()?;
            Some(GlyphPlacement {
                baseline: glyph.pos.y,
                ink_top: glyph.pos.y + glyph.uv_rect.offset.y,
            })
        })
    }

    /// Install CJK font without baseline correction: as a "before fix" control to measure how much CJK was pushed up.
    /// Returns None if no CJK font on the system (skip assertions on this machine).
    fn context_with_unaligned_cjk_font() -> Option<Context> {
        let (bytes, face_index) = baihua_core::fonts::discover_cjk_font()?;
        let context = warmed_up_context();
        context.add_font(FontInsert::new(
            "baihua-cjk-unaligned",
            FontData {
                font: Cow::Owned(bytes),
                index: face_index,
                tweak: FontTweak::default(),
            },
            vec![
                InsertFontFamily {
                    family: FontFamily::Proportional,
                    priority: FontPriority::Lowest,
                },
                InsertFontFamily {
                    family: FontFamily::Monospace,
                    priority: FontPriority::Lowest,
                },
            ],
        ));
        run_one_empty_frame(&context);
        Some(context)
    }

    /// Regression for feedback "CJK characters display shifted upward": when installing fonts must shift CJK glyphs down,
    /// so its baseline lands on the same line as the Latin baseline of the same family.
    ///
    /// How far the CJK ink top is from the baseline is determined only by the font itself; first measure this distance in the "without correction" control,
    /// then add it back to the ink top after the fix, which reverse-engineers where the CJK baseline should be after the fix.
    #[test]
    fn chinese_glyphs_share_the_latin_baseline() {
        let Some(unaligned) = context_with_unaligned_cjk_font() else {
            return;
        };
        let aligned = context_with_cjk_font_installed();
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            let latin = glyph_placement(&aligned, family.clone(), 'A')
                .expect("拉丁字母在任何字体表里都排得出来");
            let unaligned_chinese = glyph_placement(&unaligned, family.clone(), '你')
                .expect("装过汉字字体后应当排得出汉字");
            let aligned_chinese = glyph_placement(&aligned, family.clone(), '你')
                .expect("装过汉字字体后应当排得出汉字");
            let ink_top_above_baseline = unaligned_chinese.ink_top - unaligned_chinese.baseline;
            let chinese_baseline = aligned_chinese.ink_top - ink_top_above_baseline;
            assert!(
                (chinese_baseline - latin.baseline).abs() <= 0.5,
                "{family:?} 里汉字的基线应当与拉丁字母齐平：拉丁 {}，汉字 {}",
                latin.baseline,
                chinese_baseline
            );
        }
    }

    /// Intuitive consequence of "shifted upward": CJK glyphs are pushed beyond the line box.
    /// First confirm the control (without correction) actually protrudes beyond the line box, otherwise it means this machine's font combination
    /// doesn't have this phenomenon, so the assertion is meaningless — skip it.
    #[test]
    fn chinese_glyphs_stay_inside_the_line_box_after_the_fix() {
        let Some(unaligned) = context_with_unaligned_cjk_font() else {
            return;
        };
        let aligned = context_with_cjk_font_installed();
        let before = glyph_placement(&unaligned, FontFamily::Proportional, '你')
            .expect("装过汉字字体后应当排得出汉字");
        if before.ink_top >= 0.0 {
            return;
        }
        let after = glyph_placement(&aligned, FontFamily::Proportional, '你')
            .expect("装过汉字字体后应当排得出汉字");
        assert!(
            after.ink_top >= 0.0,
            "修好之后汉字不该冒出到行框上沿之外，实际位图上沿 {}",
            after.ink_top
        );
    }

    /// The settings entry uses the gear character (the button to the right of the room title).
    /// It must be renderable as a real glyph in the font table, otherwise it would be a tofu block on the interface.
    /// Skip if this machine has no CJK font (allowed degradation).
    #[test]
    fn settings_button_character_has_a_real_glyph() {
        if baihua_core::fonts::discover_cjk_font().is_none() {
            return;
        }
        let context = context_with_cjk_font_installed();
        for character in crate::app::settings_button_text().chars() {
            assert!(
                character_is_rendered_with_a_real_glyph(
                    &context,
                    FontFamily::Proportional,
                    character
                ),
                "设置按钮上的 {character:?} 必须画出真字形，而不是豆腐块"
            );
        }
    }
}

#[cfg(test)]
mod theme_contrast_tests {
    use super::{Skin, contrasting_foreground};
    use baihua_core::config::{Palette, ThemeColor};
    use egui::{Color32, Context};

    /// weighted grayscale brightness: used when asserting "are these two colors bright enough", formula matches the table in the implementation
    fn brightness(color: Color32) -> u32 {
        (color.r() as u32 * 299 + color.g() as u32 * 587 + color.b() as u32 * 114) / 1000
    }

    /// light theme (same values as light.json in the repo: light cream background + dark gray text)
    fn light_palette() -> Palette {
        let mut palette = Palette::built_in();
        palette.app_background = ThemeColor::Rgb(0xEF, 0xEB, 0xE2);
        palette.message_text = ThemeColor::Rgb(0x2B, 0x2B, 0x2B);
        palette.input_text = ThemeColor::Rgb(0x2B, 0x2B, 0x2B);
        palette.selection_background = ThemeColor::Rgb(0xFF, 0xD5, 0x4F);
        palette
    }

    /// dark theme
    fn dark_palette() -> Palette {
        let mut palette = Palette::built_in();
        palette.app_background = ThemeColor::Rgb(0x1E, 0x1F, 0x22);
        palette.message_text = ThemeColor::Rgb(0xDB, 0xDE, 0xE1);
        palette.input_text = ThemeColor::Rgb(0xF2, 0xF3, 0xF5);
        palette.selection_background = ThemeColor::Rgb(0x4A, 0x6F, 0xA5);
        palette
    }

    /// regression for feedback "text in the input field matches the input field background color, making it hard to read".
    ///
    /// the input field background color is the app background color, and egui uses `selection.stroke.color` as "the color of selected text",
    /// previously this was filled with the app background color directly, so the selected text in the input field was identical to the input field background, making it directly invisible.
    #[test]
    fn selected_text_never_blends_into_its_background() {
        for (name, palette) in [("light", light_palette()), ("dark", dark_palette())] {
            let skin = Skin::from(&palette);
            let context = Context::default();
            skin.apply_to(&context);
            // `set_visuals` writes to "the current theme" variant; reads back should also read the same variant
            let visuals = context.style_of(context.theme()).visuals.clone();
            let selected_text = visuals.selection.stroke.color;
            let selection_background = visuals.selection.bg_fill;
            let difference = brightness(selected_text).abs_diff(brightness(selection_background));
            assert!(
                difference >= 128,
                "{name} 主题里选中文字与选中底色太接近：文字 {selected_text:?}、底色 {selection_background:?}"
            );
            assert_ne!(
                selected_text, skin.app_background,
                "{name} 主题里选中文字不能再用应用背景色（那就是输入框底色）"
            );
        }
    }

    /// light themes must use the light baseline: otherwise "derived" colors like button backgrounds and widget text are still from the dark theme,
    /// resulting in dark text on dark backgrounds (before the fix, the light theme button background was #3C3C3C and text was #2B2B2B)
    #[test]
    fn light_theme_uses_light_widgets_and_dark_theme_uses_dark_ones() {
        for (name, palette, want_light) in [
            ("light", light_palette(), true),
            ("dark", dark_palette(), false),
        ] {
            let skin = Skin::from(&palette);
            let context = Context::default();
            skin.apply_to(&context);
            let widget_background = context
                .style_of(context.theme())
                .visuals
                .widgets
                .inactive
                .weak_bg_fill;
            let is_light = brightness(widget_background) >= 128;
            assert_eq!(
                is_light, want_light,
                "{name} 主题的控件底色明暗不对：实际 {widget_background:?}"
            );
        }
    }

    /// pick a foreground color for colors "used as backgrounds": light backgrounds pair with black text, dark backgrounds pair with white text
    #[test]
    fn contrasting_foreground_picks_readable_text() {
        assert_eq!(
            contrasting_foreground(Color32::from_rgb(0xFF, 0xD5, 0x4F)),
            Color32::BLACK
        );
        assert_eq!(
            contrasting_foreground(Color32::from_rgb(0x4A, 0x6F, 0xA5)),
            Color32::WHITE
        );
    }

    /// regression fix for "buttons still use egui default appearance before the first language or appearance theme switch" and the issues it causes
    /// "buttons only have borders on hover" and "input field text matches input field background color".
    ///
    /// root cause is the theme only writes into egui's current variant: on startup the theme preference is "follow system" and the system brightness isn't known yet,
    /// the dark variant gets written in, and what really takes effect later might switch to the light variant (still egui default appearance).
    /// here we assert both dark and light variants: panel background, input field background (`extreme_bg_color`), and
    /// button normal background all come from the theme, and the button normal border width is greater than 0 (border is present by default).
    #[test]
    fn theme_is_written_into_both_styles_and_buttons_keep_their_border() {
        for (name, palette) in [("light", light_palette()), ("dark", dark_palette())] {
            let skin = Skin::from(&palette);
            let context = Context::default();
            skin.apply_to(&context);
            for theme in [egui::Theme::Dark, egui::Theme::Light] {
                let visuals = context.style_of(theme).visuals.clone();
                assert_eq!(
                    visuals.panel_fill, skin.app_background,
                    "{name} 主题在 {theme:?} 那一份样式里没生效"
                );
                assert_eq!(
                    visuals.extreme_bg_color, skin.app_background,
                    "输入框底色要跟主题走，否则会和主题里的文字色撞成一片"
                );
                assert_eq!(
                    visuals.widgets.inactive.weak_bg_fill, skin.app_background,
                    "{name} 主题的按钮常态底色要来自主题"
                );
                assert_eq!(
                    visuals.widgets.inactive.bg_fill, skin.app_background,
                    "{name} 主题的复选框（设置里的开关）底色也要来自主题，\
                     否则它还是 egui 自己的灰底，和主题给的边框撞在一起就看不见边框"
                );
                assert!(
                    visuals.widgets.inactive.bg_stroke.width > 0.0,
                    "{name} 主题在 {theme:?} 那一份样式里按钮常态没有边框（只剩悬停才有）"
                );
                assert_eq!(
                    visuals.widgets.inactive.bg_stroke.color, skin.room_border,
                    "按钮常态边框的颜色要来自主题"
                );
            }
        }
    }

    /// render-level counterpart: after applying the theme, a button with the **mouse not over it** must draw a border this frame.
    ///
    /// the assertion above checks "whether there is a border in the style"; this one checks "whether it is actually drawn":
    /// button normal background is the same as panel background, so the only thing distinguishing the button from the background is this border.
    /// when asserting only at the style level, regressions like "style is correct but didn't take effect in the actual variant" would be missed.
    #[test]
    fn a_button_paints_its_border_without_being_hovered() {
        fn stroked_rect_colors(context: &Context) -> Vec<Color32> {
            let mut output = context.run_ui(egui::RawInput::default(), |ui| {
                let _ = ui.button("确认");
            });
            // `run_ui` returns the result directly, with no other consumer for the texture delta;
            // if not cleared, `TexturesDelta` panics on drop (egui's convention).
            output.textures_delta.clear();
            output
                .shapes
                .into_iter()
                .filter_map(|clipped| match clipped.shape {
                    egui::Shape::Rect(rect) if rect.stroke.width > 0.0 => Some(rect.stroke.color),
                    _ => None,
                })
                .collect()
        }
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        skin.apply_to(&context);
        let colors = stroked_rect_colors(&context);
        assert!(
            colors.contains(&skin.room_border),
            "常态按钮这一帧应当画出主题色的描边（实际描边颜色 {colors:?}，期望含 {:?}）",
            skin.room_border
        );
    }

    /// the display switches in the settings panel (`ui.checkbox`) must also draw a border this frame with the **mouse not over them**.
    ///
    /// checkbox box background takes `bg_fill`, border takes `bg_stroke`: previously the theme only wrote `weak_bg_fill`,
    /// the box background is still egui's own gray, looking "no border". This assertion both verifies the theme border is truly drawn,
    /// and also asserts the box background is indeed from the theme (when the background doesn't match, the border has no contrast to be visible).
    #[test]
    fn a_settings_switch_paints_its_border_without_being_hovered() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        skin.apply_to(&context);
        let mut checked = false;
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            let _ = ui.checkbox(&mut checked, "显示 UID");
        });
        // same convention as the button one: clear the texture delta before letting the output drop when there is no other consumer
        output.textures_delta.clear();
        let mut painted_borders: Vec<Color32> = Vec::new();
        let mut painted_fills: Vec<Color32> = Vec::new();
        for clipped in output.shapes {
            let egui::Shape::Rect(rect) = clipped.shape else {
                continue;
            };
            if rect.stroke.width > 0.0 {
                painted_borders.push(rect.stroke.color);
                painted_fills.push(rect.fill);
            }
        }
        assert!(
            painted_borders.contains(&skin.room_border),
            "常态开关这一帧应当画出主题色的描边（实际描边颜色 {painted_borders:?}，期望含 {:?}）",
            skin.room_border
        );
        assert!(
            painted_fills.contains(&skin.app_background),
            "开关方框的底色要来自主题（实际 {painted_fills:?}，期望含 {:?}）",
            skin.app_background
        );
    }
}

#[cfg(test)]
mod avatar_decode_tests {
    use super::AvatarTextures;
    use egui::Context;

    /// create a real image as an avatar: an 8×8 solid color PNG (encoded with the image crate itself, no extra dependencies)
    fn sample_png() -> Vec<u8> {
        let pixels = image::RgbaImage::from_pixel(8, 8, image::Rgba([200, 40, 40, 255]));
        let mut encoded: Vec<u8> = Vec::new();
        pixels
            .write_to(
                &mut std::io::Cursor::new(&mut encoded),
                image::ImageFormat::Png,
            )
            .expect("内存里编码 PNG 不会失败");
        encoded
    }

    /// regression for feedback "loading images blocks the main thread": the frame when bytes are first received **does not decode** —
    /// only queue and return None (interface draws placeholder), and the texture is given only after the background thread finishes decoding.
    #[test]
    fn decoding_happens_off_the_render_thread() {
        let context = Context::default();
        let bytes = sample_png();
        let mut textures = AvatarTextures::default();
        assert!(
            textures
                .texture(&context, "user-1", Some(&bytes), 32)
                .is_none(),
            "第一次遇到一份头像字节时应当先画占位块，不能在渲染线程里解码"
        );
        // keep drawing the placeholder until the background thread finishes; after it finishes (wait up to 5 seconds) the texture should be available
        let mut handle = None;
        for _ in 0..500 {
            if let Some(texture) = textures.texture(&context, "user-1", Some(&bytes), 32) {
                handle = Some(texture);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            handle.is_some(),
            "后台线程解码完成后应当给出贴图（同尺寸只解一次）"
        );
    }

    /// bytes that can't decode (bad files) must not be re-queued every frame, and must not cause the interface to error:
    /// keep giving the placeholder, and the second call does not re-queue
    #[test]
    fn broken_image_stays_a_placeholder_without_requeueing() {
        let context = Context::default();
        let bytes = "这不是图片".as_bytes().to_vec();
        let mut textures = AvatarTextures::default();
        assert!(
            textures
                .texture(&context, "user-2", Some(&bytes), 32)
                .is_none()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            textures
                .texture(&context, "user-2", Some(&bytes), 32)
                .is_none(),
            "坏图片永远只有占位块"
        );
    }
}
