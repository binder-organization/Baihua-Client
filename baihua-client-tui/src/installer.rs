//! 安装程序：把客户端文件放入指定目录，供初次安装与自动更新共用。
//!
//! 设计约束：
//! - 全程不与用户交互。调用方给什么参数就做什么，结束后把安装路径打印出来即可。
//! - 只用标准库与系统自带工具，因此同一份代码在 macOS / Windows / Linux 上都能跑，
//!   后续把本文件翻译成 `.sh` 与 `.bat` 时，逐函数对照即可，不需要额外依赖知识。
//! - 更新场景下旧进程还在运行，直接覆盖自身在 Windows 上必然失败，
//!   因此支持 `wait_for_process`：由新程序自己作为独立进程等待旧进程退出后再落盘。

use baihua_core::paths;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 一次安装（或更新）的输入。
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// 待安装内容所在目录：里面应有可执行文件，可选地带一个 `config` 子目录
    pub source_directory: PathBuf,
    /// 安装前缀；最终布局为 `<前缀>/bin/<可执行文件名>` 与 `<前缀>/config`
    pub prefix: PathBuf,
    /// 需要等待退出的旧进程号（自动更新时传入自身进程号），None 表示立即安装
    pub wait_for_process: Option<u32>,
}

/// 安装结果，用于向用户汇报文件落在哪里，以及 PATH 这类附加动作的说明。
#[derive(Debug, Clone)]
pub struct InstallReport {
    pub executable_path: PathBuf,
    pub config_directory: PathBuf,
    pub copied_file_count: usize,
    /// 需要转述给用户的附加说明（写没写 PATH、待装包来源等）
    pub notes: Vec<String>,
}

/// 待安装记录：/update 或 `update` 把包装好后写在这里，
/// 随后被分离出去的安装进程用无参数的 `install` 读走。
/// 之所以用文件而不是命令行参数，是因为安装命令对外不提供 --from 之类的参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingInstall {
    /// 解包后的目录（里面有可执行文件，可能还有 config）
    pub staged_directory: String,
    /// 装到哪个前缀。必须由发起方写进来：在 target/debug 里自更新时替换的是构建目录，
    /// 而 `install` 单独运行时用的是默认前缀，两者不能混
    pub prefix: String,
    /// 需要等它退出的旧进程号，None 表示立即安装
    pub wait_for_process: Option<u32>,
}

/// 默认安装前缀：`<$BAIHUA_DIR|~/.baihua>/client`，装在用户可写位置，不需要管理员权限。
pub fn default_prefix() -> Option<PathBuf> {
    paths::install_directory().map(|directory| {
        directory
            .parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or(directory)
    })
}

/// 当前运行实例所属的安装前缀：可执行文件位于 `<前缀>/bin/<名字>` 时取上两级，
/// 否则（例如直接在 target/debug 里跑）就取其所在目录作为前缀，保证"更新自己"总能落在正确位置。
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

/// 把已校验的更新包解包并安装。命令行 `update` 直接调用它（进程没在跑界面，可以立刻替换）；
/// 界面里的 /update 改用 spawn_detached_installer，让新进程等本进程退出后再替换。
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

/// 可执行文件名（Windows 需要 .exe 后缀）。命令行入口与安装后的名字都取自这里。
fn executable_file_name() -> String {
    if cfg!(target_os = "windows") {
        "baihua.exe".to_string()
    } else {
        "baihua".to_string()
    }
}

/// 执行安装：先按需等待旧进程退出，再复制可执行文件与配置。
pub fn install(request: &InstallRequest) -> Result<InstallReport, String> {
    if let Some(process_id) = request.wait_for_process {
        wait_for_process_to_exit(process_id);
    }
    let binary_directory = request.prefix.join("bin");
    let target_config_directory = request.prefix.join("config");
    std::fs::create_dir_all(&binary_directory)
        .map_err(|error| format!("failed to create {}: {error}", binary_directory.display()))?;

    let source_executable = request.source_directory.join(executable_file_name());
    let source_executable = if source_executable.is_file() {
        source_executable
    } else {
        // 源目录里可能放了带平台后缀的产物，按前缀找第一个可执行文件
        find_executable_in(&request.source_directory)?
    };
    let target_executable = binary_directory.join(executable_file_name());
    std::fs::copy(&source_executable, &target_executable).map_err(|error| {
        format!(
            "failed to copy {} to {}: {error}",
            source_executable.display(),
            target_executable.display()
        )
    })?;
    mark_executable(&target_executable)?;
    let mut copied_file_count = 1usize;

    // 配置目录：补齐缺失文件即可，绝不覆盖已有的 preferences.json（那是用户的设置与登录会话）。
    // 来源目录里没有 config 时退回当前进程实际用到的配置目录：从 target/debug 直接跑
    // install 也能装出一份自带语言与主题的完整布局，而不是只有一个跑不起来的可执行文件
    let source_config = {
        let beside_binary = request.source_directory.join("config");
        if beside_binary.is_dir() {
            beside_binary
        } else {
            paths::config_directory()
        }
    };
    if source_config.is_dir() && source_config != target_config_directory {
        copied_file_count +=
            copy_missing_files_recursively(&source_config, &target_config_directory)?;
    }
    Ok(InstallReport {
        executable_path: target_executable,
        config_directory: target_config_directory,
        copied_file_count,
        notes: Vec::new(),
    })
}

/// 命令行 `install`（按需求不接受任何参数）：
/// 有待安装记录就照记录装（自动更新那条路径，由分离进程走，不问任何东西）；
/// 否则把当前正在运行的可执行文件与它的配置目录装进默认前缀，并按 Y/n 询问是否写入 PATH。
pub fn install_from_command_line() -> Result<InstallReport, String> {
    let fallback_prefix =
        default_prefix().ok_or_else(|| "cannot determine the installation prefix".to_string())?;
    if let Some(pending) = read_pending_install() {
        let report = install(&InstallRequest {
            source_directory: PathBuf::from(&pending.staged_directory),
            prefix: PathBuf::from(&pending.prefix),
            wait_for_process: pending.wait_for_process,
        });
        // 记录只在装成功后作废；失败时留着，用户重跑 install 还能装上
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
        source_directory,
        prefix: prefix.clone(),
        wait_for_process: None,
    })?;
    let binary_directory = report
        .executable_path
        .parent()
        .map(|parent| parent.to_path_buf())
        .unwrap_or(prefix.join("bin"));
    if !interactive() {
        // 没人能回答问题的场合擅自改 shell 配置是不合适的：只报告该加哪一行
        report.notes.push(format!(
            "(non-interactive run, PATH untouched) add it yourself when needed: export PATH=\"{}:$PATH\"",
            binary_directory.display()
        ));
    } else if ask_yes_no(&format!("Add {}/bin to PATH?", prefix.display()), true) {
        report.notes.push(add_directory_to_path(&binary_directory));
    } else {
        report.notes.push(format!(
            "PATH left unchanged; add {} to PATH to run {} directly.",
            binary_directory.display(),
            executable_file_name()
        ));
    }
    Ok(report)
}

/// 命令行 `uninstall`：删掉安装的可执行文件，并按 Y/n 询问是否一并移除配置文件。
pub fn uninstall_from_command_line() -> Result<Vec<String>, String> {
    let prefix =
        default_prefix().ok_or_else(|| "cannot determine the installation prefix".to_string())?;
    let binary_directory = prefix.join("bin");
    let executable_path = binary_directory.join(executable_file_name());
    let mut notes: Vec<String> = Vec::new();
    if executable_path.is_file() {
        std::fs::remove_file(&executable_path)
            .map_err(|error| format!("failed to remove {}: {error}", executable_path.display()))?;
        notes.push(format!("removed {}", executable_path.display()));
    } else {
        notes.push(format!(
            "no installed executable found at {}",
            executable_path.display()
        ));
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
    if let Some(cache_directory) = baihua_core::paths::cache_directory()
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

/// 我们自己写进 shell 启动文件的段落标记，卸载时照标记整段撤掉，
/// 绝不去改用户自己写的 PATH 行。
#[cfg(not(windows))]
fn path_block_marker() -> String {
    "baihua PATH (managed by baihua install/uninstall)".to_string()
}

/// 该往哪个 shell 启动文件里写：按 `$SHELL` 认 zsh / bash / 其它（POSIX 兜底 ~/.profile）。
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

/// 用户主目录（与 baihua-core 的判定一致，额外认 BAIHUA_DIR 之外的标准变量）。
#[cfg(not(windows))]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// 把装有可执行文件的目录写进 PATH。macOS/Linux 写 shell 启动文件，
/// Windows 写当前用户的用户级 PATH（不动系统级）。返回给用户看的说明。
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

/// 往 shell 启动文件尾部追加一段带标记的 PATH 设置；已有该标记时原样返回假，
/// 因此反复 install 不会把同样的 export 叠一串。
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

/// 撤掉我们自己写的那一段；文件里没有该标记时什么都不动。
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
    // 段落前后的空行是我们追加时留下的，一并收掉，用户原有内容按原样衔接
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

/// 往文件尾部追加文本（文件不存在时创建）。
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

/// 卸载时撤掉我们自己写的那一段，返回 None 表示根本没写过、不去动用户的文件。
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

/// 卸载时撤掉我们自己写的那一段（Windows 撤用户 PATH 里的那一项）。
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

/// 有没有人可以回答问题：分离进程、管道输入、重定向这些场合都没有。
/// 没人的时候绝不擅自改用户的 shell 配置，也绝不阻塞在读输入上。
fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Y/n 询问：直接回车取默认值。调用前先用 `interactive()` 确认确实有人在。
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

/// 把下载并校验过的压缩包解包后安装，供 `baihua-client update` 与界面里的 /update 共用。
/// 返回解包目录，调用方（界面）在退出前用它起一个等待自身退出的安装进程。
pub fn extract_archive(archive_path: &Path, destination: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create the unpack directory: {error}"))?;
    let name = archive_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let command_result = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        // tar 随 macOS/Linux 自带，Windows 10 起也内置了 bsdtar
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
            // 非 Windows 上的 zip 交给 bsdtar（macOS 的 tar 即 bsdtar），失败再退回 unzip
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

/// 待安装记录文件路径。
fn pending_install_path() -> Option<PathBuf> {
    paths::update_directory().map(|directory| directory.join("pending-install.json"))
}

/// 写入待安装记录（供 /update 在退出前调用）。
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

/// 读出待安装记录；文件不存在或损坏时返回 None（损坏的记录按"没有待装包"处理并被清掉）。
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

/// 安装日志路径：等待旧进程退出的安装进程是脱离终端启动的，
/// 打印内容必须落到文件里，用户与开发者才看得到结果。
fn install_log_path() -> Option<PathBuf> {
    paths::update_directory().map(|directory| directory.join("install.log"))
}

/// 以脱离终端的方式启动安装程序：待装内容先写进待安装记录，
/// 再拉起 `baihua-client install`（不带任何参数）让它等旧进程退出后落盘。
pub fn spawn_detached_installer(request: &InstallRequest) -> Result<(), String> {
    let current_executable = paths::current_executable().ok_or_else(|| {
        "cannot locate the running executable; the installer was not started".to_string()
    })?;
    write_pending_install(&PendingInstall {
        staged_directory: request.source_directory.to_string_lossy().to_string(),
        prefix: request.prefix.to_string_lossy().to_string(),
        wait_for_process: request.wait_for_process,
    })?;
    let mut command = Command::new(&current_executable);
    command.arg("install");
    // 分离进程没有终端可写，结果只落到安装日志里
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

/// 轮询等待进程退出；最多等两分钟，超时也继续安装（宁可覆盖失败也不要永远卡住）。
fn wait_for_process_to_exit(process_id: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::time::Instant::now() < deadline {
        if !process_is_alive(process_id) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// 进程是否还在。`kill -0`（Unix）与 `tasklist`（Windows）都不改变目标进程状态，只查存在性。
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

/// 在目录里找可执行文件：Unix 看执行位，Windows 看 .exe 后缀。
fn find_executable_in(directory: &Path) -> Result<PathBuf, String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("failed to read {}: {error}", directory.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if entry
                .metadata()
                .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
            {
                return Ok(path);
            }
        }
        #[cfg(windows)]
        {
            if path
                .extension()
                .map(|extension| extension == "exe")
                .unwrap_or(false)
            {
                return Ok(path);
            }
        }
    }
    Err(format!("no executable found in {}", directory.display()))
}

/// 给目标文件加执行位（Windows 无此概念，直接跳过）。
fn mark_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        // PermissionsExt 同时提供读取与写入权限位的两个方法
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

/// 把源目录里目标处不存在的文件逐个复制过去，返回复制数量。
/// 逐个比对而不是整目录覆盖，是为了保住用户已有的 preferences.json 与外观主题改动。
fn copy_missing_files_recursively(source: &Path, target: &Path) -> Result<usize, String> {
    let mut copied = 0usize;
    let entries = std::fs::read_dir(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
    for entry in entries.flatten() {
        let source_path = entry.path();
        let Some(file_name) = source_path.file_name() else {
            continue;
        };
        // 跳过 .DS_Store 一类的系统垃圾文件，别把它一起装进发布目录
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
        assert!(report.executable_path.is_file());
        assert!(report.config_directory.join("themes/dark.json").is_file());
        use std::os::unix::fs::PermissionsExt;
        assert!(
            std::fs::metadata(&report.executable_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o111
                != 0,
            "安装后的可执行文件应带执行位"
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
