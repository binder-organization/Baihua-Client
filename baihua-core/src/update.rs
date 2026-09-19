//! 客户端版本更新：查发布页、比版本、下载并校验安装包。
//!
//! 发布产物放在 GitHub Releases（仓库 binder-organization/Baihua-Client）。约定：
//! - 三端各有各的更新通道，标签前缀分别是 `cli-v`（命令行版 `baihua`）、`gui-v`（图形版 `baihua-gui`）、
//!   `tui-v`（终端版 `baihua-tui`）；三端版本号各自走，互不牵连，检查与更新也是各查各的；
//! - 每个平台一个压缩包，文件名 = 包名前缀 + 版本号 + 目标平台三元组；
//!   包名前缀是 `baihua-cli-`、`baihua-gui-`、`baihua-tui-`（终端版还兼容历史包名 `baihua-<版本>-<平台>`，
//!   因为发布页上已有的包是这个名字），Windows 用 `.zip`，其余平台用 `.tar.gz`；
//! - 每个包旁边必须放一个同名加 `.sha256` 的摘要文件（允许 `sha256sum` 那种
//!   `<摘要>  <文件名>` 两列写法），落地之前先核对摘要，不符就丢弃——发布页被整体换包时
//!   摘要文件与包一起被换掉的概率极低，这道校验是"自动更新不会被中间人换包"的最低保障；
//! - 选包时**从新到旧逐版回退**：最新一版没有本平台的包（发布页被旧工作流传坏过，
//!   例如 `tui-v0.1.0` 的资产名里版本号为空、包内可执行文件还是旧名 `baihua`），
//!   就继续看更早的版本，装"能装上的最新一版"，而不是整条通道卡死；
//!   认不出的包名（如 `baihua--<平台>`）绝不认领——那种包解出来的可执行文件会装错端。

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

/// 发布通道：命令行版、图形版、终端版各自一条更新流。标签前缀不同（`cli-v`、`gui-v`、`tui-v`），
/// 安装包名前缀也不同，因此几个包放进同一个发布里也不会互相装错程序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseChannel {
    /// 命令行版：标签 `cli-v<版本>`，包名 `baihua-cli-<版本>-<平台>.tar.gz`
    CommandLine,
    /// 图形版：标签 `gui-v<版本>`，包名 `baihua-gui-<版本>-<平台>.tar.gz`
    Graphical,
    /// 终端版：标签 `tui-v<版本>`，包名 `baihua-tui-<版本>-<平台>.tar.gz`（兼容历史包名 `baihua-<版本>-<平台>`）
    Terminal,
}

impl ReleaseChannel {
    /// 只认这个前缀的标签是本通道的发布，其余（例如服务端标签或另一侧客户端）忽略
    fn tag_prefix(self) -> String {
        match self {
            ReleaseChannel::CommandLine => "cli-v".to_string(),
            ReleaseChannel::Graphical => "gui-v".to_string(),
            ReleaseChannel::Terminal => "tui-v".to_string(),
        }
    }

    /// 某个附件名是不是本通道的安装包。选包时必须按通道分辨，否则各端的包会互相认错。
    /// 终端版额外接受历史包名 `baihua-<版本>-<平台>`：`baihua-` 后面紧跟版本号数字才算，
    /// 这样 `baihua-cli-...`、`baihua-gui-...` 不会被终端版认领。
    fn package_name_matches(self, name: &str) -> bool {
        match self {
            ReleaseChannel::CommandLine => name.starts_with("baihua-cli-"),
            ReleaseChannel::Graphical => name.starts_with("baihua-gui-"),
            ReleaseChannel::Terminal => {
                name.starts_with("baihua-tui-")
                    || name
                        .strip_prefix("baihua-")
                        .and_then(|remainder| remainder.chars().next())
                        .is_some_and(|character| character.is_ascii_digit())
            }
        }
    }

    /// 命令行与界面里显示这条通道时用的名字（`baihua update` 的逐端报告用）
    pub fn display_name(self) -> &'static str {
        match self {
            ReleaseChannel::CommandLine => "command line",
            ReleaseChannel::Graphical => "graphical",
            ReleaseChannel::Terminal => "terminal",
        }
    }
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

/// 拉取发布页 JSON。与"怎么挑包"分开，挑包逻辑就能在测试里喂假发布页验证。
fn fetch_releases() -> Result<Vec<GitHubRelease>, String> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("baihua-client/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return Err(format!("cannot create the downloader: {error}"));
        }
    };
    let response = match client.get(releases_api_url()).send() {
        Ok(response) => response,
        Err(error) => {
            return Err(format!("release feed request failed: {error}"));
        }
    };
    if !response.status().is_success() {
        return Err(format!("release feed answered {}", response.status()));
    }
    response
        .json()
        .map_err(|error| format!("release feed parse failed: {error}"))
}

/// 查询发布页，返回相对 `current_version` 更新的、且本平台有包的最新发布版本。
/// `channel` 决定看哪一串标签、认哪一种包名。
pub fn check_for_update(current_version: &str, channel: ReleaseChannel) -> UpdateCheck {
    match fetch_releases() {
        Err(reason) => UpdateCheck::Unavailable(reason),
        Ok(releases) => select_package_from_releases(
            &releases,
            current_version,
            channel,
            &current_platform_token(),
        ),
    }
}

/// 在已解析的发布列表里挑要装的包（发布页按创建时间倒序返回，这里按同一顺序从新到旧走）。
/// 只看带本通道标签前缀、且版本比 `current_version` 新的发布；**最新一版没有本平台包时
/// 不回退失败，而是继续看更早的版本**——发布页上真实出现过名字传坏的最新版
/// （`tui-v0.1.0`，资产名 `baihua--<平台>` 且包内可执行文件是旧名），一版坏包不该锁死整条通道。
/// 所有比当前新的版本都没有本平台包时，用最新那一版的信息解释原因。
fn select_package_from_releases(
    releases: &[GitHubRelease],
    current_version: &str,
    channel: ReleaseChannel,
    platform_token: &str,
) -> UpdateCheck {
    let prefix = channel.tag_prefix();
    let mut newest_tag = String::new();
    let mut newest_assets: Vec<String> = Vec::new();
    // (版本号, 标签, 资产名) —— 第一条"版本更新但没有本平台包"的记录，用于最终解释
    let mut newest_missing_package: Option<(String, String, Vec<String>)> = None;
    for release in releases {
        // 草稿是作者自己还没发布的东西，跳过；预发布不跳——客户端正处在 alpha，
        // 带包的就是这类发布，过滤掉等于把唯一的更新通道关掉
        if release.draft {
            continue;
        }
        let Some(version) = release.tag_name.strip_prefix(&prefix) else {
            continue;
        };
        let asset_names: Vec<String> = release
            .assets
            .iter()
            .map(|asset| asset.name.clone())
            .collect();
        if newest_tag.is_empty() {
            newest_tag = release.tag_name.clone();
            newest_assets = asset_names.clone();
        }
        if !is_version_newer(version, current_version) {
            continue;
        }
        let Some(asset) = release.assets.iter().find(|asset| {
            channel.package_name_matches(&asset.name)
                && asset.name.contains(platform_token)
                && (asset.name.ends_with(".tar.gz") || asset.name.ends_with(".zip"))
        }) else {
            if newest_missing_package.is_none() {
                newest_missing_package =
                    Some((version.to_string(), release.tag_name.clone(), asset_names));
            }
            continue;
        };
        return UpdateCheck::Available(ReleasePackage {
            version: version.to_string(),
            tag: release.tag_name.clone(),
            file_name: asset.name.clone(),
            download_url: asset.browser_download_url.clone(),
            size_bytes: asset.size,
        });
    }
    if let Some((version, tag, asset_names)) = newest_missing_package {
        return UpdateCheck::Unavailable(format!(
            "release {version} (tag {tag}) has no package for this platform ({platform_token}); assets found: {asset_names:?}, and no older release of this channel provides one either"
        ));
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
        .map_err(|error| format!("failed to read the digest file: {error}"))?;
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

    /// 造一条发布页记录：标签 + 一组资产名（下载地址与大小对选包逻辑无意义，给占位值）。
    fn fake_release(tag: &str, draft: bool, asset_names: &[&str]) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.to_string(),
            draft,
            assets: asset_names
                .iter()
                .map(|name| GitHubAsset {
                    name: (*name).to_string(),
                    browser_download_url: format!("https://example.invalid/{name}"),
                    size: 1,
                })
                .collect(),
        }
    }

    /// 发布页真实出现过的坏包：`tui-v0.1.0` 的资产名里版本号为空（`baihua--<平台>`），
    /// 包内可执行文件还是旧名。这样的最新发布不能锁死通道，必须回退到
    /// 更早但包名端正、本平台有包的发布。
    #[test]
    fn a_mislabelled_newest_release_falls_back_to_an_older_installable_one() {
        let releases = vec![
            fake_release(
                "tui-v0.1.0",
                false,
                &[
                    "baihua",
                    "baihua--aarch64-apple-darwin.tar.gz",
                    "baihua--aarch64-apple-darwin.tar.gz.sha256",
                    "baihua.exe",
                ],
            ),
            fake_release("tui-v0.1.0-alpha.2", false, &[]),
            fake_release(
                "tui-v0.1.0-alpha.1",
                false,
                &["baihua-tui-0.1.0-alpha.1-aarch64-apple-darwin.tar.gz"],
            ),
        ];
        let check = select_package_from_releases(
            &releases,
            "0",
            ReleaseChannel::Terminal,
            "aarch64-apple-darwin",
        );
        match check {
            UpdateCheck::Available(package) => {
                assert_eq!(package.version, "0.1.0-alpha.1");
                assert_eq!(package.tag, "tui-v0.1.0-alpha.1");
                assert_eq!(
                    package.file_name,
                    "baihua-tui-0.1.0-alpha.1-aarch64-apple-darwin.tar.gz"
                );
            }
            other => panic!("expected a fallback to the older installable release, got {other:?}"),
        }
    }

    /// 所有比当前新的发布都没有本平台包时，报**最新那一条**的资产清单，
    /// 并说明更早的发布也救不了（而不是静默回退成"已是最新"）。
    #[test]
    fn a_channel_without_any_installable_package_explains_the_newest_release() {
        let releases = vec![
            fake_release(
                "tui-v0.1.0",
                false,
                &["baihua--aarch64-apple-darwin.tar.gz", "baihua"],
            ),
            fake_release("tui-v0.1.0-alpha.2", false, &[]),
        ];
        let check = select_package_from_releases(
            &releases,
            "0",
            ReleaseChannel::Terminal,
            "aarch64-apple-darwin",
        );
        match check {
            UpdateCheck::Unavailable(reason) => {
                assert!(reason.contains("tag tui-v0.1.0"), "{reason}");
                assert!(reason.contains("no older release"), "{reason}");
            }
            other => panic!("expected an explaining failure, got {other:?}"),
        }
    }

    /// 回退不能变成降级：候选版本仍然要先通过"比当前版本新"的闸门；
    /// 通道里全是旧版或根本没有本通道的发布时，照旧回 UpToDate。
    #[test]
    fn fallback_never_downgrades_and_keeps_up_to_date_report() {
        let releases = vec![
            fake_release(
                "tui-v0.1.0",
                false,
                &["baihua-tui-0.1.0-x86_64-unknown-linux-gnu.tar.gz"],
            ),
            fake_release(
                "gui-v0.1.0",
                false,
                &["baihua-gui-0.1.0-aarch64-apple-darwin.tar.gz"],
            ),
        ];
        // 已装 0.1.1：0.1.0 不比它新，哪怕"能回退"也不能装旧版
        match select_package_from_releases(
            &releases,
            "0.1.1",
            ReleaseChannel::Terminal,
            "aarch64-apple-darwin",
        ) {
            UpdateCheck::UpToDate { newest_tag, .. } => assert_eq!(newest_tag, "tui-v0.1.0"),
            other => panic!("expected up-to-date, got {other:?}"),
        }
        // 终端版通道一条发布都没有：UpToDate 且不带标签（安装路径据此给出"通道还没发布过"的说明）
        match select_package_from_releases(
            &releases,
            "0",
            ReleaseChannel::CommandLine,
            "aarch64-apple-darwin",
        ) {
            UpdateCheck::UpToDate {
                newest_tag,
                newest_assets,
            } => {
                assert!(newest_tag.is_empty());
                assert!(newest_assets.is_empty());
            }
            other => panic!("expected an empty-channel up-to-date report, got {other:?}"),
        }
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

    /// 三端的包名前缀互相是前缀关系（`baihua-` 也是 `baihua-cli-`、`baihua-gui-` 的前缀），
    /// 选包必须按通道分辨：某一端只能认自己那种包名，历史包名只有终端版接受。
    #[test]
    fn package_names_are_matched_per_channel() {
        let command_line_package = "baihua-cli-0.1.0-aarch64-apple-darwin.tar.gz";
        let graphical_package = "baihua-gui-0.1.0-x86_64-pc-windows-msvc.zip";
        let terminal_package = "baihua-tui-0.1.1-aarch64-apple-darwin.tar.gz";
        let legacy_terminal_package = "baihua-0.1.0-alpha.3-aarch64-apple-darwin.tar.gz";

        assert!(ReleaseChannel::CommandLine.package_name_matches(command_line_package));
        assert!(ReleaseChannel::Graphical.package_name_matches(graphical_package));
        assert!(ReleaseChannel::Terminal.package_name_matches(terminal_package));
        // 发布页上已有的终端版包是 `baihua-<版本>-<平台>`，终端版通道仍然要认
        assert!(ReleaseChannel::Terminal.package_name_matches(legacy_terminal_package));

        assert!(!ReleaseChannel::Terminal.package_name_matches(command_line_package));
        assert!(!ReleaseChannel::Terminal.package_name_matches(graphical_package));
        assert!(!ReleaseChannel::CommandLine.package_name_matches(terminal_package));
        assert!(!ReleaseChannel::Graphical.package_name_matches(terminal_package));
        assert!(!ReleaseChannel::CommandLine.package_name_matches(legacy_terminal_package));
        assert!(!ReleaseChannel::Graphical.package_name_matches(legacy_terminal_package));
    }
}
