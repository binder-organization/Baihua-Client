//! Installer: puts client files into a specified directory, shared by initial install and auto-update.
//!
//! Design constraints:
//! - No interaction with the user throughout. Do whatever the caller gives as parameters; print the install path when done.
//! - Only use the standard library and built-in system tools, so the same code runs on macOS / Windows / Linux,
//!   when translating this file to `.sh` and `.bat` later, just compare function by function; no extra dependency knowledge needed.
//! - In update scenarios the old process is still running; overwriting itself directly will inevitably fail on Windows,
//!   so `wait_for_process` is supported: the new program waits as an independent process for the old one to exit before committing.

use crate::paths;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Input for one installation (or update).
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// Directory containing the content to install: should have an executable file, optionally with a `config` subdirectory
    pub source_directory: PathBuf,
    /// Install prefix; final layout is `<prefix>/bin/<executable_name>` and `<prefix>/config`
    pub prefix: PathBuf,
    /// ID of the old process to wait for (pass own process ID during auto-update); None means install immediately
    pub wait_for_process: Option<u32>,
}

/// Install result, used to report to the user where files land, and explanations for additional actions like PATH.
#[derive(Debug, Clone)]
pub struct InstallReport {
    /// Executables actually placed under `<prefix>/bin`, in end order: command line, graphical, terminal.
    /// A package may only carry one end, so this list can be shorter than the three ends.
    pub executable_paths: Vec<PathBuf>,
    pub config_directory: PathBuf,
    pub copied_file_count: usize,
    /// Additional notes to relay to the user (whether PATH was written, where the pending package came from, etc.)
    pub notes: Vec<String>,
}

/// Pending install record: `/update` or `update` writes the packaged content here,
/// then the detached installer process reads it with parameterless `install`.
/// A file is used instead of command-line arguments because the install command does not expose parameters like --from.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingInstall {
    /// The unpacked directory (contains executable files, possibly config too)
    pub staged_directory: String,
    /// Which prefix to install to. Must be written by the initiator: during self-update in target/debug the build directory is replaced,
    /// but `install` running standalone uses the default prefix; the two must not be mixed
    pub prefix: String,
    /// ID of the old process to wait for; None means install immediately
    pub wait_for_process: Option<u32>,
}

/// Default install prefix: `<$BAIHUA_DIR|~/.baihua>/client`, installed in a user-writable location, no admin rights needed.
pub fn default_prefix() -> Option<PathBuf> {
    paths::install_directory().map(|directory| {
        directory
            .parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or(directory)
    })
}

/// The install prefix belonging to the currently running instance: when the executable is at `<prefix>/bin/<name>` take two levels up,
/// otherwise (e.g. running directly from target/debug) take its own directory as the prefix, ensuring "updating itself" always lands in the right place.
pub fn current_prefix() -> Option<PathBuf> {
    let executable = paths::current_executable()?;
    let binary_directory = executable.parent()?;
    if binary_directory
        .file_name()
        .map(|name| name == "bin")
        .unwrap_or(false)
    {
        return binary_directory.parent().map(|parent| parent.to_path_buf());
    }
    Some(binary_directory.to_path_buf())
}

/// Unpack and install a verified update package. The CLI `update` calls it directly (the process is not running, so it can replace immediately);
/// the interface's /update uses spawn_detached_installer instead, letting the new process wait for this process to exit before replacing.
pub fn apply_downloaded_archive(
    archive_path: &Path,
    new_version: &str,
) -> Result<InstallReport, String> {
    let staging_root = paths::update_directory()
        .ok_or_else(|| "cannot locate the update directory".to_string())?;
    let staged_directory = staging_root.join(format!("staged-{new_version}"));
    extract_archive(archive_path, &staged_directory)?;
    let prefix = current_prefix()
        .or_else(default_prefix)
        .ok_or_else(|| "cannot determine the installation prefix".to_string())?;
    install(&InstallRequest {
        source_directory: staged_directory,
        prefix,
        wait_for_process: None,
    })
}

// 客户端的三个"端"。三端各自的包只带自己那一个可执行文件，但装进的是同一个 `<前缀>/bin`。
//
// 名字与发布通道的对应关系（BUILDING.md 与 `.github/workflows/build-release.yml` 必须与此一致）：
// - 命令行版：可执行文件 `baihua`（本程序，包 `baihua-cli`，标签 `cli-v<版本>`）；
// - 图形版：可执行文件 `baihua-gui`（包 `baihua-client-gui`，标签 `gui-v<版本>`）；
// - 终端版：可执行文件 `baihua-tui`（包 `baihua-client-tui`，标签 `tui-v<版本>`）。
//
// 安装时按名字判断源目录里带了哪几端：包名与可执行文件名一一对应，不猜"当前进程叫什么"。

/// 命令行版（本程序）安装后的文件名；Windows 带 `.exe`
pub fn command_line_executable_name() -> String {
    executable_name("baihua")
}

/// 图形版安装后的文件名；Windows 带 `.exe`
pub fn graphical_executable_name() -> String {
    executable_name("baihua-gui")
}

/// 终端版安装后的文件名；Windows 带 `.exe`
pub fn terminal_executable_name() -> String {
    executable_name("baihua-tui")
}

/// 三端的可执行文件名，顺序固定为命令行版、图形版、终端版（安装、卸载、版本报告都按这个顺序走）
pub fn installed_executable_names() -> Vec<String> {
    vec![
        command_line_executable_name(),
        graphical_executable_name(),
        terminal_executable_name(),
    ]
}

/// 三端各自的可执行文件名与它对应的发布通道，安装时"缺哪端补哪端"要用
fn installed_ends() -> Vec<(String, crate::update::ReleaseChannel)> {
    use crate::update::ReleaseChannel;
    vec![
        (command_line_executable_name(), ReleaseChannel::CommandLine),
        (graphical_executable_name(), ReleaseChannel::Graphical),
        (terminal_executable_name(), ReleaseChannel::Terminal),
    ]
}

/// 可执行文件名：Windows 需要 `.exe` 后缀，其余平台就是裸名字
fn executable_name(base_name: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{base_name}.exe")
    } else {
        base_name.to_string()
    }
}

/// 执行一次安装：需要时先等旧进程退出，然后把这个源目录里带了的每一端可执行文件与配置拷进前缀。
///
/// 源目录里带哪几端就装哪几端（发布包按端分包：命令行版包只带 `baihua`，图形版包只带 `baihua-gui`，
/// 终端版包只带 `baihua-tui`）；一端都没有才算失败。这样界面内的 `/update` 只替换自己那一端，
/// 而首次安装用的命令行版包如果想一次装上三端，由 `install_from_command_line` 再去补齐缺的那两端。
pub fn install(request: &InstallRequest) -> Result<InstallReport, String> {
    if let Some(process_id) = request.wait_for_process {
        wait_for_process_to_exit(process_id);
    }
    let binary_directory = request.prefix.join("bin");
    let target_config_directory = request.prefix.join("config");
    std::fs::create_dir_all(&binary_directory)
        .map_err(|error| format!("failed to create {}: {error}", binary_directory.display()))?;

    let mut executable_paths: Vec<PathBuf> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut copied_file_count = 0usize;
    for executable_name in installed_executable_names() {
        let source_executable = request.source_directory.join(&executable_name);
        if !source_executable.is_file() {
            continue;
        }
        let target_executable = binary_directory.join(&executable_name);
        // 从安装目录里再跑一次 install 时源与目标可能是同一个文件：这时直接跳过。
        // 判断必须按"是不是同一个文件"来做，而不是按路径字符串：macOS 上 /tmp 是指向 /private/tmp 的
        // 符号链接，同一个文件会有两种写法（`current_exe()` 给规范路径，`BAIHUA_DIR` 给用户写的那条路径），
        // 只字符串比较会让拷贝落到自己头上——`fs::copy` 先截断目标再读源，
        // 装好的可执行文件会变成空文件（Windows 上则是"文件正被占用"失败）。
        if is_same_file(&source_executable, &target_executable) {
            notes.push(format!(
                "{} already runs from the installation directory; not copied again",
                target_executable.display()
            ));
            executable_paths.push(target_executable);
            continue;
        }
        std::fs::copy(&source_executable, &target_executable).map_err(|error| {
            format!(
                "failed to copy {} to {}: {error}",
                source_executable.display(),
                target_executable.display()
            )
        })?;
        mark_executable(&target_executable)?;
        copied_file_count += 1;
        executable_paths.push(target_executable);
    }
    if executable_paths.is_empty() {
        return Err(format!(
            "no installable executable found in {} (expected one of: {})",
            request.source_directory.display(),
            installed_executable_names().join(", ")
        ));
    }

    // Config directory: just fill in missing files; never overwrite an existing preferences.json (that is the user's settings and login session).
    // When the source directory has no config, fall back to the config directory the current process actually uses: running directly from target/debug
    // install can produce a complete layout with its own language and theme, rather than just one executable that won't run
    let source_config = {
        let beside_binary = request.source_directory.join("config");
        if beside_binary.is_dir() {
            beside_binary
        } else {
            paths::config_directory()
        }
    };
    if source_config.is_dir() && !is_same_file(&source_config, &target_config_directory) {
        copied_file_count +=
            copy_missing_files_recursively(&source_config, &target_config_directory)?;
        copied_file_count +=
            merge_missing_language_entries(&source_config, &target_config_directory)?;
    }
    Ok(InstallReport {
        executable_paths,
        config_directory: target_config_directory,
        copied_file_count,
        notes,
    })
}

/// 两个路径是不是同一个文件。先比字符串，字符串不同再比规范路径（解析符号链接与 `.` / `..`）：
/// 目标还不存在、父目录不可达等情况下 `canonicalize` 会失败，那时两者本来就不可能是同一个文件。
fn is_same_file(first: &Path, second: &Path) -> bool {
    if first == second {
        return true;
    }
    match (std::fs::canonicalize(first), std::fs::canonicalize(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
}

/// 命令行版 `install`（对外不带参数）：
/// - 有"待安装记录"时按记录安装（界面内的 `/update` 拉起的那条路，不提问）；
/// - 否则把当前可执行文件所在目录里带了的每一端装进默认前缀，缺的那几端若还没装过，
///   再去各自发布通道取最新包补上，最后问一次要不要写 PATH。
pub fn install_from_command_line() -> Result<InstallReport, String> {
    let fallback_prefix =
        default_prefix().ok_or_else(|| "cannot determine the installation prefix".to_string())?;
    if let Some(pending) = read_pending_install() {
        let report = install(&InstallRequest {
            source_directory: PathBuf::from(&pending.staged_directory),
            prefix: PathBuf::from(&pending.prefix),
            wait_for_process: pending.wait_for_process,
        });
        // The record is only invalidated after a successful install; on failure it stays so the user can re-run install and still succeed
        if report.is_ok()
            && let Some(path) = pending_install_path()
        {
            let _ = std::fs::remove_file(path);
        }
        let mut report = report?;
        report.notes.push(format!(
            "this install came from the update package {} (prefix {})",
            pending.staged_directory, pending.prefix
        ));
        return Ok(report);
    }
    let prefix = fallback_prefix;
    let source_directory = paths::current_executable()
        .and_then(|executable| executable.parent().map(|parent| parent.to_path_buf()))
        .ok_or_else(|| "cannot locate the running executable; nothing installed".to_string())?;
    let mut report = install(&InstallRequest {
        source_directory: source_directory.clone(),
        prefix: prefix.clone(),
        wait_for_process: None,
    })?;
    // 发布包按端分包，命令行版包里只有 `baihua`：另外两端如果本地没有、前缀里也没有，
    // 就从它们各自的发布通道取最新包补上，做到"一次安装同时装上三端"。
    report
        .notes
        .extend(install_missing_ends(&source_directory, &prefix));
    let binary_directory = prefix.join("bin");
    if !interactive() {
        // 没人能回答问题的场合擅自改 shell 配置是不合适的：只报告该加哪一行
        report.notes.push(format!(
            "(non-interactive run, PATH untouched) add it yourself when needed: export PATH=\"{}:$PATH\"",
            binary_directory.display()
        ));
    } else if ask_yes_no(
        &format!("Add {} to PATH?", binary_directory.display()),
        true,
    ) {
        report.notes.push(add_directory_to_path(&binary_directory));
    } else {
        report.notes.push(format!(
            "PATH left unchanged; add {} to PATH to run {} directly.",
            binary_directory.display(),
            command_line_executable_name()
        ));
    }
    Ok(report)
}

/// 源目录里没带、安装前缀里也还没有的那几端：从各自发布通道下载最新安装包补上。
/// 每一端的失败都只换成一句说明，不中断其它端与配置的安装。
fn install_missing_ends(source_directory: &Path, prefix: &Path) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    for (executable_name, channel) in installed_ends() {
        if source_directory.join(&executable_name).is_file() {
            continue;
        }
        if prefix.join("bin").join(&executable_name).is_file() {
            notes.push(format!(
                "{executable_name} is already installed; left untouched (use `baihua update` to upgrade it)"
            ));
            continue;
        }
        notes.push(install_latest_release_of(channel, prefix, &executable_name));
    }
    notes
}

/// 取某一条通道上最新的安装包，下载、校验、解包后装进前缀。
fn install_latest_release_of(
    channel: crate::update::ReleaseChannel,
    prefix: &Path,
    executable_name: &str,
) -> String {
    use crate::update::{UpdateCheck, check_for_update, download_package};
    let Some(staging_root) = paths::update_directory() else {
        return format!(
            "{executable_name} was not installed: cannot locate the update directory; run `baihua install` again later"
        );
    };
    // 当前版本传 "0"：这一端还没装过，发布页上最新那个包就是要装的那个
    match check_for_update("0", channel) {
        UpdateCheck::Available(package) => match download_package(&package) {
            Ok(archive_path) => {
                let staged_directory =
                    staging_root.join(format!("staged-{executable_name}-{}", package.version));
                let install_result =
                    extract_archive(&archive_path, &staged_directory).and_then(|directory| {
                        install(&InstallRequest {
                            source_directory: directory,
                            prefix: prefix.to_path_buf(),
                            wait_for_process: None,
                        })
                        .map(|_| ())
                    });
                match install_result {
                    Ok(()) => format!(
                        "{executable_name} {} installed from the {} release",
                        package.version,
                        channel.display_name()
                    ),
                    Err(error) => format!("{executable_name} was not installed: {error}"),
                }
            }
            Err(error) => format!("{executable_name} was not installed: {error}"),
        },
        UpdateCheck::UpToDate { newest_tag, .. } => {
            if newest_tag.is_empty() {
                // 这条通道还从来没有发布过（例如刚拆分的命令行版/图形版）
                format!(
                    "{executable_name} was not installed: the {} release channel has no published release yet",
                    channel.display_name()
                )
            } else {
                format!(
                    "{executable_name} was not installed: the {newest_tag} release has no package for this platform"
                )
            }
        }
        UpdateCheck::Unavailable(reason) => {
            format!("{executable_name} was not installed: {reason}")
        }
    }
}

/// 命令行版 `uninstall`：删掉装好的三端可执行文件，并问一次要不要连同配置与缓存一起删。
pub fn uninstall_from_command_line() -> Result<Vec<String>, String> {
    let prefix =
        default_prefix().ok_or_else(|| "cannot determine the installation prefix".to_string())?;
    let binary_directory = prefix.join("bin");
    let mut notes: Vec<String> = Vec::new();
    for executable_name in installed_executable_names() {
        let executable_path = binary_directory.join(&executable_name);
        if executable_path.is_file() {
            std::fs::remove_file(&executable_path).map_err(|error| {
                format!("failed to remove {}: {error}", executable_path.display())
            })?;
            notes.push(format!("removed {}", executable_path.display()));
        } else {
            notes.push(format!(
                "no installed executable found at {}",
                executable_path.display()
            ));
        }
    }
    // 只清理我们自己写进去的那几行，别碰用户自己的 PATH 配置
    if let Some(removed) = remove_directory_from_path(&binary_directory) {
        notes.push(removed);
    }
    // 一次询问覆盖所有"装出来的与攒出来的"文件：配置目录与可再生缓存（消息、头像）
    let mut removable: Vec<PathBuf> = Vec::new();
    let config_directory = prefix.join("config");
    if config_directory.is_dir() {
        removable.push(config_directory);
    }
    if let Some(cache_directory) = crate::paths::cache_directory()
        && cache_directory.is_dir()
    {
        removable.push(cache_directory);
    }
    if removable.is_empty() {
        return Ok(notes);
    }
    let listed = removable
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<String>>()
        .join(", ");
    if interactive() && ask_yes_no(&format!("Also remove these files? {listed}"), false) {
        for path in &removable {
            std::fs::remove_dir_all(path)
                .map_err(|error| format!("failed to remove {}: {error}", path.display()))?;
            notes.push(format!("removed {}", path.display()));
        }
    } else {
        notes.push(format!("kept: {listed}"));
    }
    Ok(notes)
}

/// The paragraph marker we wrote into the shell startup file; on uninstall the whole paragraph is removed per the marker,
/// never touch the PATH lines the user wrote themselves.
#[cfg(not(windows))]
fn path_block_marker() -> String {
    "baihua PATH (managed by baihua install/uninstall)".to_string()
}

/// Which shell startup file to write to: determines zsh / bash / other based on `$SHELL` (POSIX fallback ~/.profile).
#[cfg(not(windows))]
fn shell_profile_path() -> Option<PathBuf> {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = dirs_home()?;
    let file_name = if shell.contains("zsh") {
        ".zshrc"
    } else if shell.contains("bash") {
        ".bashrc"
    } else {
        ".profile"
    };
    Some(home.join(file_name))
}

/// User's home directory (same determination as baihua-core, additionally recognizes standard variables besides BAIHUA_DIR).
#[cfg(not(windows))]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Write the directory containing the executable to PATH. macOS/Linux writes to the shell startup file,
/// Windows writes to the current user's user-level PATH (does not touch system-level). Explanation shown to the user.
fn add_directory_to_path(directory: &Path) -> String {
    let display = directory.display().to_string();
    #[cfg(windows)]
    {
        let script = format!(
            "$user=[Environment]::GetEnvironmentVariable('Path','User'); if ($user -notlike '*{display}*') {{ [Environment]::SetEnvironmentVariable('Path', \"$user;{display}\", 'User'); 'added' }} else {{ 'already' }}"
        );
        return match Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
        {
            Ok(output) if output.status.success() => {
                let replied = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if replied == "already" {
                    format!("{display} is already in the user PATH; nothing added")
                } else {
                    format!("added {display} to the user PATH; it takes effect in a new terminal")
                }
            }
            _ => format!("failed to write the PATH; add {display} manually"),
        };
    }
    #[cfg(not(windows))]
    {
        let Some(profile_path) = shell_profile_path() else {
            return format!("no home directory found; add {display} to PATH manually");
        };
        match append_path_block(&profile_path, directory) {
            Ok(true) => format!(
                "added {display} to {}; restart the shell (or source {}) to take effect",
                profile_path.display(),
                profile_path.display()
            ),
            Ok(false) => format!(
                "{display} is already in {}; nothing added",
                profile_path.display()
            ),
            Err(error) => format!(
                "failed to write {}: {error}; add {display} to PATH manually",
                profile_path.display()
            ),
        }
    }
}

/// Append a marked PATH setting to the end of the shell startup file; returns false unchanged when the marker already exists,
/// so repeated installs will not pile up the same export line.
#[cfg(not(windows))]
fn append_path_block(profile_path: &Path, directory: &Path) -> Result<bool, String> {
    let display = directory.display().to_string();
    let existing = std::fs::read_to_string(profile_path).unwrap_or_default();
    if existing.contains(&path_block_marker()) || existing.contains(&display) {
        return Ok(false);
    }
    let block = format!(
        "\n# {marker}\nexport PATH=\"{display}:$PATH\"\n# end {marker}\n",
        marker = path_block_marker()
    );
    append_text(profile_path, &block).map(|()| true)
}

/// Remove the paragraph we wrote; does nothing when the marker is not in the file.
#[cfg(not(windows))]
fn remove_path_block(profile_path: &Path) -> Result<bool, String> {
    let content = std::fs::read_to_string(profile_path).map_err(|error| error.to_string())?;
    let marker = format!("# {}", path_block_marker());
    let Some(start) = content.find(&marker) else {
        return Ok(false);
    };
    let end_marker = format!("# end {}", path_block_marker());
    let Some(offset) = content[start..].find(&end_marker) else {
        return Err("the block has no end marker; the file was left untouched".to_string());
    };
    let end = start + offset + end_marker.len();
    // The blank lines before and after the paragraph were left by us when appending; take them together too, user's original content continues as-is
    let head = content[..start].trim_end_matches('\n');
    let tail = content[end..].trim_start_matches('\n');
    let rebuilt = match (head.is_empty(), tail.is_empty()) {
        (true, true) => String::new(),
        (true, false) => tail.to_string(),
        (false, true) => format!("{head}\n"),
        (false, false) => format!("{head}\n{tail}"),
    };
    std::fs::write(profile_path, rebuilt).map_err(|error| error.to_string())?;
    Ok(true)
}

/// Append text to the end of a file (creates the file if it does not exist).
#[cfg(not(windows))]
fn append_text(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("{error}"))?;
    file.write_all(text.as_bytes())
        .map_err(|error| format!("{error}"))
}

/// On uninstall, remove the paragraph we wrote; returning None means we never wrote anything, do not touch the user's files.
#[cfg(not(windows))]
fn remove_directory_from_path(_directory: &Path) -> Option<String> {
    let profile_path = shell_profile_path()?;
    if !remove_path_block(&profile_path).ok()? {
        return None;
    }
    Some(format!(
        "removed our PATH block from {}",
        profile_path.display()
    ))
}

/// On uninstall, remove the paragraph we wrote (on Windows, remove the one item in the user's PATH).
/// 返回 None 表示根本没写过，不去动用户的文件。
#[cfg(windows)]
fn remove_directory_from_path(directory: &Path) -> Option<String> {
    let display = directory.display().to_string();
    let script = format!(
        "$user=[Environment]::GetEnvironmentVariable('Path','User'); if ($user -like '*{display}*') {{ $kept=($user -split ';' | Where-Object {{ $_ -ne '{display}' }}) -join ';'; [Environment]::SetEnvironmentVariable('Path', $kept, 'User'); 'removed' }} else {{ 'none' }}"
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;
    let replied = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (replied == "removed").then(|| format!("removed {display} from the user PATH"))
}

/// Is anyone available to answer questions: there is no one in detached process, piped input, or redirected output scenarios.
/// When there is no one, never擅自 modify the user's shell config, and never block on read input.
fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Y/n prompt: pressing Enter takes the default value. Use `interactive()` first to confirm someone is actually there.
fn ask_yes_no(question: &str, default_yes: bool) -> bool {
    use std::io::Write;
    let suffix = if default_yes { "[Y/n] " } else { "[y/N] " };
    print!("{question} {suffix}");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return default_yes;
    }
    match answer.trim().to_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        "n" | "no" => false,
        other => {
            println!("  did not understand {other:?}; using the default");
            default_yes
        }
    }
}

/// Unpack and install a downloaded and verified archive, shared by `baihua-client update` and /update in the interface.
/// Return the unpack directory; the caller (the interface) uses it before exit to start an installer process that waits for itself to exit.
pub fn extract_archive(archive_path: &Path, destination: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create the unpack directory: {error}"))?;
    let name = archive_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let command_result = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        // tar comes with macOS/Linux; Windows 10 and later also have bsdtar built in
        Command::new("tar")
            .args(["-xzf"])
            .arg(archive_path)
            .arg("-C")
            .arg(destination)
            .status()
    } else if name.ends_with(".zip") {
        #[cfg(target_os = "windows")]
        {
            Command::new("powershell")
                .args(["-NoProfile", "-Command", "Expand-Archive", "-LiteralPath"])
                .arg(archive_path)
                .args(["-DestinationPath"])
                .arg(destination)
                .status()
        }
        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows, zip is handed to bsdtar (macOS's tar is bsdtar), falling back to unzip on failure
            match Command::new("tar")
                .arg("-xf")
                .arg(archive_path)
                .arg("-C")
                .arg(destination)
                .status()
            {
                Ok(status) if status.success() => Ok(status),
                _ => Command::new("unzip")
                    .arg("-o")
                    .arg(archive_path)
                    .arg("-d")
                    .arg(destination)
                    .status(),
            }
        }
    } else {
        return Err(format!("unsupported archive format: {name}"));
    };
    match command_result {
        Ok(status) if status.success() => Ok(destination.to_path_buf()),
        Ok(status) => Err(format!("unpacking failed, exit status {status}")),
        Err(error) => Err(format!("unpack tool unavailable: {error}")),
    }
}

/// Pending install record file path.
fn pending_install_path() -> Option<PathBuf> {
    paths::update_directory().map(|directory| directory.join("pending-install.json"))
}

/// Write the pending install record (called by /update before exiting).
fn write_pending_install(pending: &PendingInstall) -> Result<(), String> {
    let path =
        pending_install_path().ok_or_else(|| "cannot locate the update directory".to_string())?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    serde_json::to_string_pretty(pending)
        .map_err(|error| format!("failed to serialise the pending install record: {error}"))
        .and_then(|text| {
            std::fs::write(path, text).map_err(|error| format!("failed to write: {error}"))
        })
}

/// Read the pending install record; return None when the file does not exist or is corrupted (a corrupted record is treated as "no pending package" and cleared).
fn read_pending_install() -> Option<PendingInstall> {
    let path = pending_install_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let parsed: PendingInstall = match serde_json::from_str(&content) {
        Ok(parsed) => parsed,
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };
    if PathBuf::from(&parsed.staged_directory).is_dir() {
        Some(parsed)
    } else {
        let _ = std::fs::remove_file(&path);
        None
    }
}

/// Install log path: the installer process waiting for the old process to exit is started detached from the terminal,
/// the printed content must go to a file so users and developers can see the result.
fn install_log_path() -> Option<PathBuf> {
    paths::update_directory().map(|directory| directory.join("install.log"))
}

/// Start the installer process detached from the terminal: the pending content is first written to the pending install record,
/// then launch `baihua-client install` (without any parameters) to let it wait for the old process to exit before committing.
pub fn spawn_detached_installer(request: &InstallRequest) -> Result<(), String> {
    // 真正执行安装的是命令行版 `baihua`：图形版与终端版自己不处理命令行参数，
    // 只能把"待安装记录"写下来，再拉起同目录（或 PATH 上）的命令行版来做替换。
    let command_line_executable = locate_command_line_executable().ok_or_else(|| {
        format!(
            "cannot locate the command line executable `{}`; the installer was not started",
            command_line_executable_name()
        )
    })?;
    write_pending_install(&PendingInstall {
        staged_directory: request.source_directory.to_string_lossy().to_string(),
        prefix: request.prefix.to_string_lossy().to_string(),
        wait_for_process: request.wait_for_process,
    })?;
    let mut command = Command::new(&command_line_executable);
    command.arg("install");
    // The detached process has no terminal to write to; results only go into the install log
    if let Some(log_path) = install_log_path()
        && let Ok(file) = std::fs::File::create(log_path)
    {
        use std::process::Stdio;
        command.stdout(
            file.try_clone()
                .map(|_| Stdio::from(file))
                .unwrap_or(Stdio::null()),
        );
    }
    command
        .spawn()
        .map_err(|error| format!("failed to start the installer process: {error}"))?;
    Ok(())
}

/// 命令行版可执行文件的位置：安装之后三端同在 `<前缀>/bin`，所以先看当前进程所在目录，
/// 再退回默认前缀的 `bin/`，最后看 PATH。界面内的 `/update` 与命令行版自己的更新都走它。
fn locate_command_line_executable() -> Option<PathBuf> {
    let file_name = command_line_executable_name();
    if let Some(current_executable) = paths::current_executable()
        && let Some(directory) = current_executable.parent()
        && directory.join(&file_name).is_file()
    {
        return Some(directory.join(&file_name));
    }
    if let Some(prefix) = default_prefix() {
        let candidate = prefix.join("bin").join(&file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(&file_name))
        .find(|candidate| candidate.is_file())
}

/// Poll waiting for the process to exit; wait up to two minutes, continue installing on timeout (better to overwrite a failure than to stay stuck forever).
fn wait_for_process_to_exit(process_id: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::time::Instant::now() < deadline {
        if !process_is_alive(process_id) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Whether the process is still alive. `kill -0` (Unix) and `tasklist` (Windows) neither change the target process state, only check existence.
fn process_is_alive(process_id: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &process_id.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {process_id}"), "/NH"])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).contains(&process_id.to_string()))
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = process_id;
        false
    }
}

/// Give the target file the execute bit (Windows has no such concept; skip directly).
fn mark_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        // PermissionsExt provides both the read and write permission bit methods
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| format!("failed to read permissions: {error}"))?
            .permissions()
            .mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o755))
            .map_err(|error| format!("failed to set the executable bit: {error}"))?;
    }
    let _ = path;
    Ok(())
}

/// Copy files one by one from the source directory where they don't exist in the target; return the copy count.
/// Compare one by one instead of overwriting the whole directory, to preserve the user's existing preferences.json and appearance theme changes.
fn copy_missing_files_recursively(source: &Path, target: &Path) -> Result<usize, String> {
    let mut copied = 0usize;
    let entries = std::fs::read_dir(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
    for entry in entries.flatten() {
        let source_path = entry.path();
        let Some(file_name) = source_path.file_name() else {
            continue;
        };
        // Skip system junk files like .DS_Store; do not include them in the release directory
        if file_name.to_string_lossy().starts_with('.') {
            continue;
        }
        let target_path = target.join(file_name);
        if source_path.is_dir() {
            copied += copy_missing_files_recursively(&source_path, &target_path)?;
        } else if !target_path.exists() {
            if let Some(parent) = target_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::copy(&source_path, &target_path).is_ok() {
                copied += 1;
            }
        }
    }
    Ok(copied)
}

/// 把随程序发布的语言文件里"用户那份还没有的条目"补进用户那份，返回补过的文件数。
///
/// 语言文件是程序自带的文案表：旧版本安装出去的那一份会一直留在用户配置目录里
/// （`copy_missing_files_recursively` 只补不存在的文件），新版本加进来的键在那一份里根本没有，
/// 界面上就会把键名当文案显示出来。这里做的只是**补缺**：
/// 用户自己改过的条目、自己加的语言文件都不动，
/// preferences.json（用户的设置与登录会话）更是照旧碰都不碰。
fn merge_missing_language_entries(
    source_config: &Path,
    target_config: &Path,
) -> Result<usize, String> {
    let source_languages = source_config.join("languages");
    let Ok(entries) = std::fs::read_dir(&source_languages) else {
        return Ok(0);
    };
    let mut merged_file_count = 0usize;
    for entry in entries.flatten() {
        let source_path = entry.path();
        if source_path
            .extension()
            .map(|extension| extension != "json")
            .unwrap_or(true)
        {
            continue;
        }
        let target_path = target_config.join("languages").join(entry.file_name());
        // 目标里没有这份语言文件：那是"补齐缺失文件"那份逻辑的活，这里只处理"两份都有"的情况
        if !target_path.is_file() {
            continue;
        }
        let (Ok(source_content), Ok(target_content)) = (
            std::fs::read_to_string(&source_path),
            std::fs::read_to_string(&target_path),
        ) else {
            continue;
        };
        let (
            Ok(serde_json::Value::Object(source_texts)),
            Ok(serde_json::Value::Object(mut target_texts)),
        ) = (
            serde_json::from_str::<serde_json::Value>(&source_content),
            serde_json::from_str::<serde_json::Value>(&target_content),
        )
        else {
            continue;
        };
        let mut added_entry_count = 0usize;
        for (key, text) in source_texts {
            if target_texts.contains_key(&key) {
                continue;
            }
            target_texts.insert(key, text);
            added_entry_count += 1;
        }
        if added_entry_count == 0 {
            continue;
        }
        let Ok(pretty) = serde_json::to_string_pretty(&serde_json::Value::Object(target_texts))
        else {
            continue;
        };
        std::fs::write(&target_path, pretty)
            .map_err(|error| format!("failed to write {}: {error}", target_path.display()))?;
        merged_file_count += 1;
    }
    Ok(merged_file_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staging_area(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("baihua-installer-{label}"));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(directory.join("payload/config/themes")).expect("源目录应可创建");
        std::fs::create_dir_all(directory.join("target")).expect("目标目录应可创建");
        std::fs::write(directory.join("payload/baihua"), b"fake-binary").expect("写入源文件应成功");
        std::fs::write(directory.join("payload/config/themes/dark.json"), b"{}")
            .expect("写入主题应成功");
        std::fs::write(
            directory.join("payload/config/preferences.json"),
            b"{\"show_uid\":true}",
        )
        .expect("写入偏好应成功");
        directory
    }

    #[cfg(unix)]
    #[test]
    fn install_places_executable_and_config_under_prefix() {
        let staging = staging_area("basic");
        let report = install(&InstallRequest {
            source_directory: staging.join("payload"),
            prefix: staging.join("target"),
            wait_for_process: None,
        })
        .expect("安装应成功");
        assert_eq!(
            report.executable_paths.len(),
            1,
            "源目录里只有一个可执行文件时，只装这一端"
        );
        assert!(report.executable_paths[0].is_file());
        assert!(report.config_directory.join("themes/dark.json").is_file());
        use std::os::unix::fs::PermissionsExt;
        assert!(
            std::fs::metadata(&report.executable_paths[0])
                .unwrap()
                .permissions()
                .mode()
                & 0o111
                != 0,
            "安装后的可执行文件应带执行位"
        );
        let _ = std::fs::remove_dir_all(&staging);
    }

    /// 一次安装要把源目录里带了的每一端都装进 `<前缀>/bin`：发布包按端分包，
    /// 而源码树里三端产物同目录，这条测试盯的就是"三端同目录时一次装齐"。
    #[cfg(unix)]
    #[test]
    fn install_copies_every_end_found_in_the_source_directory() {
        let staging = staging_area("three-ends");
        for executable_name in installed_executable_names() {
            std::fs::write(
                staging.join("payload").join(&executable_name),
                b"fake-binary",
            )
            .expect("写入三端产物应成功");
        }
        let report = install(&InstallRequest {
            source_directory: staging.join("payload"),
            prefix: staging.join("target"),
            wait_for_process: None,
        })
        .expect("安装应成功");
        assert_eq!(
            report.executable_paths.len(),
            3,
            "源目录里的三端都要装上，实际: {:?}",
            report.executable_paths
        );
        for executable_name in installed_executable_names() {
            assert!(
                report.executable_paths.iter().any(|path| path
                    .file_name()
                    .map(|name| name == executable_name.as_str())
                    == Some(true)),
                "{executable_name} 应该装进 bin 目录"
            );
        }
        let _ = std::fs::remove_dir_all(&staging);
    }

    /// 从安装目录里再跑一次 `install`（源与目标其实是同一个文件）必须只记一条说明、不拷贝。
    ///
    /// 这条测试盯的是"只比路径字符串"那种写法：macOS 上 `/tmp` 指向 `/private/tmp`，
    /// 同一个文件有两种写法，字符串比较会判成"两个文件"，接着 `fs::copy` 先截断目标再读源，
    /// 装好的可执行文件就变成了 0 字节的空文件（本次验证安装程序时就是这样把三端全清空的）。
    #[cfg(unix)]
    #[test]
    fn install_skips_copying_the_executable_onto_itself_through_a_symlink_alias() {
        let staging = staging_area("self-copy");
        // real/bin 里放好三端产物，alias 是指向 real 的符号链接：
        // 源目录走 alias 这一条路径，安装前缀走 real 这一条路径，两者其实是同一个目录
        let real_root = staging.join("real");
        std::fs::create_dir_all(real_root.join("bin")).expect("真实安装目录应可创建");
        for executable_name in installed_executable_names() {
            std::fs::write(real_root.join("bin").join(&executable_name), b"fake-binary")
                .expect("写入三端产物应成功");
        }
        let alias_root = staging.join("alias");
        std::os::unix::fs::symlink(&real_root, &alias_root).expect("符号链接应可创建");

        let report = install(&InstallRequest {
            source_directory: alias_root.join("bin"),
            prefix: real_root.clone(),
            wait_for_process: None,
        })
        .expect("同一个文件的安装应成功");
        assert_eq!(
            report.notes.len(),
            installed_executable_names().len(),
            "每一端都该带一条“已经在安装目录里运行”的说明，实际 {:?}",
            report.notes
        );
        for executable_name in installed_executable_names() {
            let installed = real_root.join("bin").join(&executable_name);
            assert_eq!(
                std::fs::read(&installed).expect("装好的可执行文件应能读回"),
                b"fake-binary",
                "{executable_name} 被拷到了自己头上（先截断再读会得到空文件）"
            );
        }
        let _ = std::fs::remove_dir_all(&staging);
    }

    /// 源目录里一端可执行文件都没有时必须报错：否则用户会以为装好了，实际 bin 目录是空的。
    #[test]
    fn install_reports_when_the_source_directory_has_no_executable() {
        let staging = staging_area("no-executable");
        // staging_area 会预置 `payload/baihua`，这里换成只放配置的空目录
        let empty_source = staging.join("payload-without-executable");
        std::fs::create_dir_all(empty_source.join("config")).expect("空源目录应可创建");
        let error = install(&InstallRequest {
            source_directory: empty_source,
            prefix: staging.join("target"),
            wait_for_process: None,
        })
        .expect_err("没有可执行文件时不应报告成功");
        assert!(
            error.contains("no installable executable"),
            "实际错误: {error}"
        );
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[cfg(unix)]
    #[test]
    fn install_keeps_existing_user_preferences() {
        let staging = staging_area("keep-preferences");
        let target_config = staging.join("target/config");
        std::fs::create_dir_all(&target_config).expect("目标配置目录应可创建");
        std::fs::write(
            target_config.join("preferences.json"),
            b"{\"show_uid\":false}",
        )
        .expect("预置用户偏好应成功");
        install(&InstallRequest {
            source_directory: staging.join("payload"),
            prefix: staging.join("target"),
            wait_for_process: None,
        })
        .expect("安装应成功");
        assert_eq!(
            std::fs::read_to_string(target_config.join("preferences.json")).unwrap(),
            "{\"show_uid\":false}",
            "已存在的用户偏好不能被安装程序覆盖"
        );
        let _ = std::fs::remove_dir_all(&staging);
    }

    /// 本轮修复"大量文本无法读取语言文件，显示占位符"的安装侧一半：
    /// 用户配置目录里那份语言文件是旧版本留下的，缺新版本的条目；
    /// 安装（更新走的也是这条路）要把新条目补进去，同时不能动用户自己改过的条目。
    #[test]
    fn install_adds_the_language_entries_the_user_copy_is_missing() {
        let staging = staging_area("merge-language");
        let source_languages = staging.join("payload/config/languages");
        let target_languages = staging.join("target/config/languages");
        std::fs::create_dir_all(&source_languages).expect("源语言目录应可创建");
        std::fs::create_dir_all(&target_languages).expect("目标语言目录应可创建");
        std::fs::write(
            source_languages.join("zh-CN.json"),
            "{\"page_login\":\"登录\",\"message_input_placeholder\":\"输入消息\"}",
        )
        .expect("写入随程序发布的语言文件应成功");
        std::fs::write(
            target_languages.join("zh-CN.json"),
            "{\"page_login\":\"我改过的登录\"}",
        )
        .expect("写入用户那份语言文件应成功");

        install(&InstallRequest {
            source_directory: staging.join("payload"),
            prefix: staging.join("target"),
            wait_for_process: None,
        })
        .expect("安装应成功");

        let merged: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(target_languages.join("zh-CN.json"))
                .expect("应能读回合并结果"),
        )
        .expect("合并结果应是合法 JSON");
        assert_eq!(
            merged.get("page_login").and_then(serde_json::Value::as_str),
            Some("我改过的登录"),
            "用户改过的条目不能被安装程序覆盖"
        );
        assert_eq!(
            merged
                .get("message_input_placeholder")
                .and_then(serde_json::Value::as_str),
            Some("输入消息"),
            "新版本多出来的条目要补进用户那份，否则界面上显示成键名占位符"
        );
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[cfg(not(windows))]
    #[test]
    fn path_block_is_added_once_and_removed_without_touching_user_lines() {
        let directory =
            std::env::temp_dir().join(format!("baihua-path-block-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("临时目录应可创建");
        let profile = directory.join("zshrc");
        // 用户自己已有的配置必须原样保留
        std::fs::write(&profile, "export EDITOR=vim\n").expect("预置用户配置应成功");

        assert!(
            append_path_block(&profile, &directory).expect("首次写入应成功"),
            "第一次安装应写入 PATH 段落"
        );
        assert!(
            !append_path_block(&profile, &directory).expect("重复写入不应失败"),
            "重复安装不该再叠一段"
        );
        let written = std::fs::read_to_string(&profile).expect("应能读回启动文件");
        assert_eq!(
            written.matches("export PATH=").count(),
            1,
            "实际内容: {written}"
        );
        assert!(
            written.contains("export EDITOR=vim"),
            "用户自己的行不该被动过"
        );

        assert!(remove_path_block(&profile).expect("撤除应成功"));
        let after = std::fs::read_to_string(&profile).expect("应能读回启动文件");
        assert_eq!(after, "export EDITOR=vim\n", "撤除后应只剩用户自己的内容");
        assert!(
            !remove_path_block(&profile).expect("没有段落时不该报错"),
            "没写过就不该说撤除了什么"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn default_prefix_ends_with_client_directory() {
        let Some(prefix) = default_prefix() else {
            return;
        };
        assert_eq!(
            prefix
                .file_name()
                .map(|name| name.to_string_lossy().to_string()),
            Some("client".to_string())
        );
    }

    #[test]
    fn archive_with_unknown_extension_is_rejected() {
        let staging = staging_area("archive-format");
        let archive = staging.join("payload/baihua");
        let error = extract_archive(&archive, &staging.join("target")).unwrap_err();
        assert!(
            error.contains("unsupported archive format"),
            "actual error: {error}"
        );
        let _ = std::fs::remove_dir_all(&staging);
    }
}
