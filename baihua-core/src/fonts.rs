//! CJK font discovery.
//!
//! egui's default fonts (the ones bundled with the `default_fonts` feature) only have Latin glyphs, so Chinese characters in the interface will
//! all show as tofu blocks. This module is responsible for finding a font with CJK glyphs on the system and reading it into bytes,
//! and handing them to the GUI to install into egui's font table.
//!
//! This module is "shared code": it only deals with paths and bytes, not recognizing any interface type (no egui/epaint),
//! so both the TUI and GUI can use it and it's easy to test separately. The GUI converts the bytes obtained here into
//! `egui::FontData` and appends it as a fallback font; the TUI does not need this at the moment (the TUI relies on the system terminal's own font selection).

use std::path::PathBuf;

/// 一个字体候选：文件路径与字号索引。
///
/// 一个字体文件可能是 `.ttc` 字体集合，里面顺序排着多套字面（如多字重的黑体）。
/// 索引 `0` 通常是最常规的那一套，与 egui 的 `FontData::index` 语义一致。
pub struct FontFile {
    /// 字体文件在磁盘上的完整路径
    pub path: PathBuf,
    /// 取文件里的第几套字面（`.ttf`/`.otf` 用 0，`.ttc` 按字体集合的顺序取）
    pub face_index: u32,
}

/// 按平台给出带汉字的字体候选（优先级从高到低）。
///
/// 只列文件名，不判断是否存在；实际可用的那一份由 `discover_cjk_font` 挑。
/// 选择原则是"系统自带的常见正文字体优先"：macOS 先苹方后冬青黑体，Windows 先微软雅黑
/// 后等线，Linux 先思源黑体后文泉驿正黑；再往后放几套几乎必装的兜底字体。
pub fn cjk_font_candidates() -> Vec<FontFile> {
    let mut candidates: Vec<FontFile> = Vec::new();

    // macOS：苹方是系统界面字，字形最全；冬青黑体与华文黑体依次兜底
    for (path, face_index) in [
        ("/System/Library/Fonts/PingFang.ttc", 0),
        ("/System/Library/Fonts/Hiragino Sans GB.ttc", 0),
        ("/System/Library/Fonts/STHeiti Light.ttc", 0),
        ("/System/Library/Fonts/STHeiti Medium.ttc", 0),
        ("/System/Library/Fonts/Supplemental/Songti.ttc", 0),
    ] {
        candidates.push(FontFile {
            path: PathBuf::from(path),
            face_index,
        });
    }

    // Windows：微软雅黑覆盖最广，等线与黑体兜底
    for (path, face_index) in [
        ("C:/Windows/Fonts/msyh.ttc", 0),
        ("C:/Windows/Fonts/msyh.ttf", 0),
        ("C:/Windows/Fonts/deng.ttf", 0),
        ("C:/Windows/Fonts/simhei.ttf", 0),
        ("C:/Windows/Fonts/simsun.ttc", 0),
    ] {
        candidates.push(FontFile {
            path: PathBuf::from(path),
            face_index,
        });
    }

    // Linux：思源黑体最常见，文泉驿正黑与已安装的 Noto 依次兜底
    for (path, face_index) in [
        ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
        ("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", 0),
        (
            "/usr/share/fonts/opentype/source-han-sans/SourceHanSans-Regular.otf",
            0,
        ),
        ("/usr/share/fonts/truetype/arphic/uming.ttc", 0),
        ("/usr/local/share/fonts/NotoSansCJK-Regular.ttc", 0),
    ] {
        candidates.push(FontFile {
            path: PathBuf::from(path),
            face_index,
        });
    }

    candidates
}

/// 在候选里挑出第一份真实存在且读得进来的汉字字体，返回它的字节与字号索引。
///
/// 读盘失败（权限、文件被占用）不当作致命错误：继续试下一份候选。
/// 一份都拿不到时返回 None，界面按"没有汉字字体"降级处理（中文显示为占位方框），
/// 不会因为字体缺失而启动失败。
pub fn discover_cjk_font() -> Option<(Vec<u8>, u32)> {
    for candidate in cjk_font_candidates() {
        if !candidate.path.is_file() {
            continue;
        }
        match std::fs::read(&candidate.path) {
            Ok(bytes) if !bytes.is_empty() => return Some((bytes, candidate.face_index)),
            _ => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 候选表必须按平台排好且不重复，免得把同一个文件读两遍
    #[test]
    fn candidates_are_not_empty_and_unique() {
        let candidates = cjk_font_candidates();
        assert!(!candidates.is_empty(), "每个平台上至少要有几个汉字字体候选");
        let mut seen: Vec<PathBuf> = Vec::new();
        for candidate in &candidates {
            assert!(
                !seen.contains(&candidate.path),
                "候选里出现了重复的字体路径: {:?}",
                candidate.path
            );
            seen.push(candidate.path.clone());
        }
    }

    /// 在开发机上按真实情况探测：找到了就必须是非空字节，没找到也不该 panic
    #[test]
    fn discovery_returns_readable_bytes_or_nothing() {
        match discover_cjk_font() {
            Some((bytes, _face_index)) => assert!(!bytes.is_empty(), "读到的字体字节不能为空"),
            None => {
                // 这台机器一套候选都没有：属于允许的降级情况，函数本身不该出错
            }
        }
    }
}
