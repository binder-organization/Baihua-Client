//! 客户端版本更新：查询发布页、比对版本、下载并校验安装包。
//!
//! 发布物托管在 GitHub Releases（仓库 binder-organization/Baihua-Client）。
//! 约定：
//! - TUI 的发布标签形如 `tui-v0.1.0-alpha.3`，前缀 `tui-` 用于把界面端发布与服务端发布区分开；
//! - 每个平台一个压缩包，文件名形如 `baihua-<版本>-<目标平台>.tar.gz`（Windows 为 `.zip`），
//!   包里那个可执行文件本身就叫 `baihua`；
//! - 每个压缩包旁放一个同名 `.sha256` 附属文件，内容就是十六进制摘要（可带 `算法 文件名` 后缀），
//!   下载后必须先比对摘要再落地，摘要不符即丢弃——发布页可被替换而摘要文件与包同时被替换的概率极低，
//!   这层校验是"自动更新不被中间人换包"的最低保障。

use crate::paths;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// 发布页上一个安装包的必要信息。
#[derive(Debug, Clone, PartialEq)]
pub struct ReleasePackage {
    /// 去掉 `tui-v` 前缀后的版本号，用于与内置版本直接比较
    pub version: String,
    pub tag: String,
    pub file_name: String,
    pub download_url: String,
    pub size_bytes: u64,
}

/// 一次更新检查的结果。
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateCheck {
    /// 已是最新：带上发布页上看到的最新标签与该标签下的安装包文件名，
    /// 便于 `update --check` 直接回答"到底看到了什么、为什么判成没有更新"
    UpToDate {
        newest_tag: String,
        newest_assets: Vec<String>,
    },
    /// 有可用更新
    Available(ReleasePackage),
    /// 无法完成检查（网络、解析、平台上没有对应包），携带可直接展示的原因
    Unavailable(String),
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    /// 草稿态发布对 API 之外的用户不可见，绝不能再客户端里被当成可用版本
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// 发布标签前缀：只认这个前缀的标签是本客户端的发布，其余（例如服务端标签）忽略。
fn release_tag_prefix() -> String {
    "tui-v".to_string()
}

/// 发布页地址。GitHub API 要求带 User-Agent（否则直接 403），已在请求里给。
/// 设了 `BAIHUA_RELEASE_FEED` 就改用该地址（本地假发布页或内网镜像），
/// 目的是在不往正式仓库发版的情况下，也能把"检查→下载→校验→解包→安装"整条链路验证一遍。
fn releases_api_url() -> String {
    if let Some(override_url) = std::env::var_os("BAIHUA_RELEASE_FEED") {
        let url = override_url.to_string_lossy().trim().to_string();
        if !url.is_empty() {
            return url;
        }
    }
    "https://api.github.com/repos/binder-organization/Baihua-Client/releases?per_page=10"
        .to_string()
}

/// 当前平台在安装包文件名里出现的片段（与 BUILDING.md 的产物命名一致）。
fn current_platform_token() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin".to_string(),
        ("macos", "x86_64") => "x86_64-apple-darwin".to_string(),
        ("windows", "x86_64") => "x86_64-pc-windows-msvc".to_string(),
        ("windows", "aarch64") => "aarch64-pc-windows-msvc".to_string(),
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu".to_string(),
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu".to_string(),
        (operating_system, architecture) => format!("{architecture}-{operating_system}"),
    }
}

/// 比较两个版本号：先按点分主/次/修订号比数值，再比预发布标记（预发布早于正式版）。
/// 解析不了的片段按 0 处理，因此 "0.1.0-alpha.2" < "0.1.0"。
pub fn is_version_newer(candidate: &str, current: &str) -> bool {
    fn split(text: &str) -> (Vec<u64>, Option<String>) {
        let (numeric, pre_release) = match text.split_once('-') {
            Some((numeric, pre_release)) => (numeric, Some(pre_release.to_string())),
            None => (text, None),
        };
        let numbers = numeric
            .split('.')
            .map(|segment| segment.parse::<u64>().unwrap_or(0))
            .collect();
        (numbers, pre_release)
    }
    let (candidate_numbers, candidate_pre) = split(candidate.trim_start_matches('v'));
    let (current_numbers, current_pre) = split(current.trim_start_matches('v'));
    // 位数不一致时短的那边按 0 补齐比较（"0.1" 与 "0.1.0" 视为相等）
    let digit_count = candidate_numbers.len().max(current_numbers.len());
    for position in 0..digit_count {
        let candidate_value = *candidate_numbers.get(position).unwrap_or(&0);
        let current_value = *current_numbers.get(position).unwrap_or(&0);
        if candidate_value != current_value {
            return candidate_value > current_value;
        }
    }
    match (&candidate_pre, &current_pre) {
        (Some(candidate_marker), Some(current_marker)) => {
            pre_release_order(candidate_marker, current_marker)
        }
        // 同一版本号下，带预发布标记的一版早于正式版
        (Some(_), None) => false,
        (None, Some(_)) => true,
        (None, None) => false,
    }
}

/// 预发布标记逐段比较："alpha.10" 要大于 "alpha.2"（纯按字符串比会反过来），
/// 因此两侧都能读成数字的段按数值比，其余段按文本比。
fn pre_release_order(candidate_marker: &str, current_marker: &str) -> bool {
    let candidate_parts: Vec<&str> = candidate_marker.split('.').collect();
    let current_parts: Vec<&str> = current_marker.split('.').collect();
    for position in 0..candidate_parts.len().max(current_parts.len()) {
        let candidate_part = candidate_parts.get(position).copied().unwrap_or_default();
        let current_part = current_parts.get(position).copied().unwrap_or_default();
        let candidate_number = candidate_part.parse::<u64>().ok();
        let current_number = current_part.parse::<u64>().ok();
        let ordering = match (candidate_number, current_number) {
            (Some(candidate_value), Some(current_value)) => candidate_value.cmp(&current_value),
            _ => candidate_part.cmp(current_part),
        };
        if ordering != std::cmp::Ordering::Equal {
            return ordering == std::cmp::Ordering::Greater;
        }
    }
    false
}

/// 查询发布页，返回相对 `current_version` 更新的、且本平台有包的最新发布版本。
pub fn check_for_update(current_version: &str) -> UpdateCheck {
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("baihua-client/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return UpdateCheck::Unavailable(format!("cannot create the downloader: {error}"));
        }
    };
    let response = match client.get(releases_api_url()).send() {
        Ok(response) => response,
        Err(error) => {
            return UpdateCheck::Unavailable(format!("release feed request failed: {error}"));
        }
    };
    if !response.status().is_success() {
        return UpdateCheck::Unavailable(format!("release feed answered {}", response.status()));
    }
    let releases: Vec<GitHubRelease> = match response.json() {
        Ok(releases) => releases,
        Err(error) => {
            return UpdateCheck::Unavailable(format!("release feed parse failed: {error}"));
        }
    };
    let prefix = release_tag_prefix();
    let mut newest_tag = String::new();
    let mut newest_assets: Vec<String> = Vec::new();
    for release in releases {
        // 草稿是作者自己还没发布的东西，跳过；预发布不跳——客户端正处在 alpha，
        // 带包的就是这类发布，过滤掉等于把唯一的更新通道关掉
        if release.draft {
            continue;
        }
        let Some(version) = release.tag_name.strip_prefix(&prefix) else {
            continue;
        };
        if newest_tag.is_empty() {
            newest_tag = release.tag_name.clone();
            newest_assets = release
                .assets
                .iter()
                .map(|asset| asset.name.clone())
                .collect();
        }
        if !is_version_newer(version, current_version) {
            continue;
        }
        let platform_token = current_platform_token();
        let Some(asset) = release.assets.iter().find(|asset| {
            asset.name.contains(&platform_token)
                && (asset.name.ends_with(".tar.gz") || asset.name.ends_with(".zip"))
        }) else {
            // 新版本已发布但本平台包还没传上去：继续看更早的版本没有意义，直接说明原因
            return UpdateCheck::Unavailable(format!(
                "release {version} (tag {}) has no package for this platform ({platform_token}); assets found: {:?}",
                release.tag_name,
                release
                    .assets
                    .iter()
                    .map(|asset| asset.name.clone())
                    .collect::<Vec<String>>()
            ));
        };
        return UpdateCheck::Available(ReleasePackage {
            version: version.to_string(),
            tag: release.tag_name,
            file_name: asset.name.clone(),
            download_url: asset.browser_download_url.clone(),
            size_bytes: asset.size,
        });
    }
    UpdateCheck::UpToDate {
        newest_tag,
        newest_assets,
    }
}

/// 下载安装包并校验摘要，成功后返回本地文件路径；任何一步失败都不留下可用的半成品。
pub fn download_package(package: &ReleasePackage) -> Result<std::path::PathBuf, String> {
    let directory = paths::update_directory().ok_or_else(|| {
        "cannot locate the update directory; check BAIHUA_DIR and HOME".to_string()
    })?;
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("failed to create the update directory: {error}"))?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .user_agent(concat!("baihua-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| format!("cannot create the downloader: {error}"))?;
    let archive_path = directory.join(&package.file_name);
    let bytes = client
        .get(&package.download_url)
        .send()
        .map_err(|error| format!("download failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("download failed: {error}"))?
        .bytes()
        .map_err(|error| format!("download interrupted: {error}"))?;
    let expected = client
        .get(format!("{}.sha256", package.download_url))
        .send()
        .map_err(|error| format!("failed to fetch the digest file: {error}"))?
        .error_for_status()
        .map_err(|error| format!("failed to fetch the digest file: {error}"))?
        .text()
        .map_err(|error| format!("摘要文件读取失败: {error}"))?;
    if sha256_hex_of(&bytes) != normalize_digest_text(&expected) {
        return Err("package verification failed: the SHA-256 digest does not match the published one, refusing to install".to_string());
    }
    std::fs::write(&archive_path, &bytes)
        .map_err(|error| format!("failed to write the update package: {error}"))?;
    Ok(archive_path)
}

/// 计算字节串的 SHA-256 十六进制摘要（与 `sha256sum` 输出同形，便于人工核对）。
pub fn sha256_hex_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// 摘要附属文件允许写成 `sha256sum` 的 "<digest>  <filename>" 形式，取前导摘要字段并小写化。
fn normalize_digest_text(text: &str) -> String {
    text.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_handles_prerelease_markers() {
        assert!(is_version_newer("0.1.1", "0.1.0"));
        assert!(is_version_newer("0.2.0-alpha.1", "0.1.9"));
        assert!(is_version_newer("0.1.0", "0.1.0-alpha.2"));
        assert!(!is_version_newer("0.1.0-alpha.1", "0.1.0"));
        assert!(!is_version_newer("0.1.0", "0.1.0"));
        assert!(is_version_newer("0.1.0-alpha.3", "0.1.0-alpha.2"));
        assert!(!is_version_newer("0.1.0-alpha.2", "0.1.0-alpha.3"));
        // 预发布序号超过一位数时不能按字符串比较
        assert!(is_version_newer("0.1.0-alpha.10", "0.1.0-alpha.2"));
        assert!(!is_version_newer("0.1.0-alpha.2", "0.1.0-alpha.10"));
        assert!(is_version_newer("0.1.0-beta.1", "0.1.0-alpha.9"));
        // 位数不同的版本号按零补齐比较
        assert!(is_version_newer("0.1.0.1", "0.1.0"));
        assert!(!is_version_newer("0.1", "0.1.0"));
    }

    #[test]
    fn digest_text_accepts_checksum_tool_output() {
        let digest = sha256_hex_of(b"baihua");
        assert_eq!(
            normalize_digest_text(&format!("{digest}  file.tar.gz")),
            digest
        );
        assert_eq!(normalize_digest_text(&format!("{digest}\n")), digest);
        assert_ne!(sha256_hex_of(b"baihua"), sha256_hex_of(b"BAIHUA"));
    }
}
