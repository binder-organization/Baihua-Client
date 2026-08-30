pub mod app;
use crate::app::App;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use std::io::{self, stdout};
use std::sync::mpsc;
use std::time::Duration;

fn main() -> io::Result<()> {
    let mut app = App::default();

    let lang = App::current_language();
    app.load_language(&lang);
    app.load_display_preferences();

    // 创建通道用于后台线程与主线程通信
    let (sender, receiver) = mpsc::channel();
    app.set_polling_sender(Some(sender));

    // 尝试用上次 /quit 保存的会话自动登录；失败则停留在登录页
    app.try_auto_login();
    // 未登录（无有效会话）时弹一次提示引导 /login 或 /register，聊天窗口照常显示不遮盖
    if !app.is_logged_in() {
        app.notify_signed_out();
    }

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
