mod app;
mod avatar;
mod installer;

use crate::app::{App, ensure_avatar_source_directory};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use std::io::{self, Write, stdout};
use std::sync::mpsc;
use std::time::Duration;

/// 客户端产品名，也是可执行文件名：命令行入口就是 `baihua`。
fn product_name() -> String {
    "baihua".to_string()
}

/// 客户端版本：界面顶栏、`--version` 与更新比对都用它。
fn client_version() -> String {
    App::client_version()
}

fn main() -> io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run_command_line(&arguments) {
        CommandLine::RunInterface => run_terminal_interface(),
        CommandLine::Handled(exit_code) => std::process::exit(exit_code),
    }
}

/// 命令行入口的分派结果：要么进入图形界面，要么已经把事做完并给出退出码。
enum CommandLine {
    RunInterface,
    Handled(i32),
}

/// 解析并执行命令行子命令。无参数（或 `client`）即直接启动 TUI，其余参数走 CLI 功能。
fn run_command_line(arguments: &[String]) -> CommandLine {
    let Some(first) = arguments.first() else {
        return CommandLine::RunInterface;
    };
    match first.as_str() {
        "client" => CommandLine::RunInterface,
        "help" | "--help" | "-h" => {
            print_help();
            CommandLine::Handled(0)
        }
        "version" | "--version" | "-V" => {
            println!("{} {}", product_name(), client_version());
            println!("baihua-core {}", baihua_core_version());
            CommandLine::Handled(0)
        }
        "update" => CommandLine::Handled(run_update_command(&arguments[1..])),
        "install" => CommandLine::Handled(run_install_command()),
        "uninstall" => CommandLine::Handled(run_uninstall_command()),
        other => {
            eprintln!("Unknown argument: {other}");
            print_help();
            CommandLine::Handled(2)
        }
    }
}

/// baihua-core 的版本与客户端版本各自独立演进，排查问题时两个都要看，所以一起报出来。
fn baihua_core_version() -> String {
    App::core_version()
}

/// 打印全部可用指令及说明：先列命令行子命令，再列聊天框内的斜杠指令。
fn print_help() {
    // 指令说明走语言文件，和帮助之外的界面文案保持同一来源
    let mut app = App::default();
    app.load_language(&App::current_language());
    println!("{} {}", product_name(), client_version());
    println!();
    println!("Usage: {} [subcommand]", product_name());
    println!();
    println!("Running without a subcommand opens the chat interface. Subcommands:");
    let command_lines: Vec<(&str, &str)> = vec![
        (
            "client",
            "Open the chat interface (same as passing nothing)",
        ),
        ("help", "Print this help"),
        ("version", "Print the client and core library versions"),
        (
            "update",
            "Check a new release, then download, verify and install; --check only queries",
        ),
        (
            "install",
            "Install into the default prefix (~/.baihua/client), asking about PATH",
        ),
        (
            "uninstall",
            "Remove the installed executable, asking about the configuration files",
        ),
    ];
    for (name, description) in command_lines {
        println!("  {name:<24} {description}");
    }
}

/// 执行 `install`：不带参数。存在待装包（由 /update 或 `update` 准备好的）时装那个包，
/// 否则把当前正在运行的可执行文件与它的配置目录装进默认前缀。
fn run_install_command() -> i32 {
    match installer::install_from_command_line() {
        Ok(report) => {
            println!("Installed executable: {}", report.executable_path.display());
            println!(
                "Configuration directory: {} ({} file(s) added)",
                report.config_directory.display(),
                report.copied_file_count
            );
            for note in &report.notes {
                println!("{note}");
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

/// 执行 `uninstall`：删掉安装的可执行文件，并询问是否一并移除配置文件。
fn run_uninstall_command() -> i32 {
    match installer::uninstall_from_command_line() {
        Ok(report) => {
            for note in &report {
                println!("{note}");
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

/// 执行 `update`：查询发布页 → 下载并校验 → 安装。带 `--check` 时只查询不安装。
fn run_update_command(arguments: &[String]) -> i32 {
    let check_only = arguments.iter().any(|argument| argument == "--check");
    print!("Checking for a new release... ");
    io::stdout().flush().ok();
    match baihua_core::update::check_for_update(&client_version()) {
        baihua_core::update::UpdateCheck::UpToDate {
            newest_tag,
            newest_assets,
        } => {
            println!("Already up to date (current {})", client_version());
            println!("Latest release tag: {newest_tag}");
            if newest_assets.is_empty() {
                println!("That tag has no uploaded packages");
            } else {
                println!("Assets on that tag: {}", newest_assets.join(", "));
            }
            0
        }
        baihua_core::update::UpdateCheck::Unavailable(reason) => {
            println!("Failed: {reason}");
            1
        }
        baihua_core::update::UpdateCheck::Available(package) => {
            println!("Found a newer release: {}", package.version);
            if check_only {
                println!("Tag: {} / package: {}", package.tag, package.file_name);
                return 0;
            }
            println!("Downloading and verifying {} ...", package.file_name);
            match baihua_core::update::download_package(&package) {
                Ok(archive_path) => {
                    println!("Verified, saved to {}", archive_path.display());
                    apply_downloaded_archive(&archive_path, &package.version)
                }
                Err(error) => {
                    println!("{error}");
                    1
                }
            }
        }
    }
}

/// 把已下载的压缩包解包并安装（命令行路径：进程没有界面，可以立刻替换文件）。
fn apply_downloaded_archive(archive_path: &std::path::Path, new_version: &str) -> i32 {
    match installer::apply_downloaded_archive(archive_path, new_version) {
        Ok(report) => {
            println!("Update finished: {}", report.executable_path.display());
            println!(
                "Configuration directory: {}",
                report.config_directory.display()
            );
            0
        }
        Err(error) => {
            println!("{error}");
            1
        }
    }
}

/// 启动终端聊天界面。
fn run_terminal_interface() -> io::Result<()> {
    let mut app = App::default();

    let lang = App::current_language();
    app.load_language(&lang);
    app.load_display_preferences();
    // 头像目录先建出来：设置里的"修改头像"直接列这里的图片文件
    ensure_avatar_source_directory();

    // 创建通道用于后台线程与主线程通信
    let (sender, receiver) = mpsc::channel();
    app.set_polling_sender(Some(sender));

    // 先确认服务端可达并取回版本，界面顶栏与自动登录都用这份结果
    app.probe_server_at_startup();
    // 之后连接状态交给常驻探测线程按事实维护：它与登录态无关，
    // 退出登录后照样探，不会把"没有会话"误报成"连不上服务端"
    app.start_reachability_watch();

    // 尝试用上次 /quit 保存的会话自动登录；失败则停留在登录页
    app.try_auto_login();
    // 未登录（无有效会话）时弹一次提示引导 /login 或 /register，聊天窗口照常显示不遮盖
    if !app.is_logged_in() {
        app.notify_signed_out();
    }
    // 后台检查客户端新版本：只在真的下到并校验通过包之后才弹通知，不打断启动
    app.start_update_check_thread(client_version());

    // 启用鼠标捕获：滚轮以真实鼠标事件上报，用于滚动消息显示区；
    // 否则终端会把滚轮转义为方向键导致误触群聊切换。跨终端通用，单独启用。
    execute!(stdout(), EnableMouseCapture)?;

    // 启用括号粘贴模式：粘贴内容作为单个 Event::Paste 整段送达，而不是被拆成逐字符按键事件。
    // 不启用时粘贴文本里的换行会被当成按 Enter，多行粘贴因此会连着发出多条消息。
    // 终端不支持时非致命跳过（行为退回原样）。
    let bracketed_paste_enabled = execute!(stdout(), EnableBracketedPaste).is_ok();

    // 键盘增强标志：仅 kitty/SGR 等新型协议终端支持，用于上报 Shift/Ctrl+Enter 等组合键修饰符。
    // 传统 Windows 控制台（conhost）不支持，PushKeyboardEnhancementFlags 会返回
    // "Keyboard progressive enhancement not implemented for the legacy Windows API."。
    // 因此先探测支持度、且启用失败时非致命跳过：多行输入的 Ctrl+J/Ctrl+U 作为普通控制字符
    // 在旧终端仍能上报，不依赖此增强协议，跳过不影响功能与启动。
    let keyboard_flags = KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        | KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES;
    let keyboard_enhancement_supported =
        crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    let keyboard_enhancement_pushed = keyboard_enhancement_supported
        && execute!(stdout(), PushKeyboardEnhancementFlags(keyboard_flags)).is_ok();

    let run_result = ratatui::run(|terminal| {
        loop {
            // 应用请求整屏重绘：先 clear 让 ratatui 丢弃增量基线，下一帧全量重画，
            // 用于修复终端侧偶发自动滚动造成的屏幕与缓冲区错位
            if app.take_full_repaint_request() {
                terminal.clear()?;
            }
            terminal.draw(|frame| app.ui(frame))?;

            if event::poll(Duration::from_millis(100))? && app.handle_event(&event::read()?) {
                break Ok(());
            }

            app.handle_tick();

            // 检查后台线程发来的消息
            while let Ok(polling_event) = receiver.try_recv() {
                app.handle_polling_event(polling_event);
            }

            // /quit 的后台清理（加密会话与房间退订）完成后在此安全退出
            if app.should_quit_now() {
                break Ok(());
            }
            // /update 已把安装进程挂起，本进程直接退出让位给替换动作
            if app.should_exit_for_update() {
                break Ok(());
            }
        }
    });

    // 恢复终端：仅在成功启用时才弹出键盘增强标志（否则 Pop 在传统 Windows 会报错），
    // 鼠标捕获始终关闭。均用 is_ok/非致命处理，避免收尾阶段再次因不支持而中断。
    if keyboard_enhancement_pushed {
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
    }
    if bracketed_paste_enabled {
        let _ = execute!(stdout(), DisableBracketedPaste);
    }
    let _ = execute!(stdout(), DisableMouseCapture);
    run_result
}
