use crate::avatar::{AvatarPixels, build_avatar_pixels, placeholder_color, placeholder_initial};
use baihua_core::{
    api::{
        ApiVersion, Connector, CreateRoomRequest, EncryptHandshakeData, EncryptedMessageInfo,
        LoginRequest, MessageInfo, PollingEvent, ProfileUpdatePayload, PublicProfile,
        RegisterRequest, RoomInfo, RoomRequestInfo, ServerSignal, UserInfo, UserSearchResult,
        WsCommand, authorization_value, outbound_ws_payload, parse_websocket_event,
        websocket_auth_sentinel,
    },
    chat_cache::ChatCache,
    crypto, paths,
    update::{UpdateCheck, check_for_update, download_package},
};
use chrono::{DateTime, Local};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use ed25519_dalek::SigningKey;
use rat_text::HasScreenCursor;
use rat_text::TextPosition;
use rat_text::core::TextStore;
use rat_text::text_area;
use rat_text::text_area::{TextArea, TextAreaState};
use rat_text::text_input;
use rat_text::text_input::{TextInput, TextInputState};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Margin, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, StatefulWidget,
    },
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};
use tungstenite::Message as WebSocketMessage;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use x25519_dalek::EphemeralSecret;

/// 安全写入文件：在 Unix 系统上创建文件时使用 0600 权限（仅所有者可读写），
/// 防止敏感配置（如 preferences.json）被其他用户读取。
/// Windows 系统没有等效的文件权限机制，直接使用标准写入。
fn secure_write(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)
    }
}

/// 调试诊断。
#[cfg(debug_assertions)]
fn debug_log(message: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("baihua_client_debug.log"))
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "[{timestamp}] {message}");
    }
}

/// 调试诊断（发布版为空操作）。
#[cfg(not(debug_assertions))]
fn debug_log(_message: &str) {}

/// 正在显示的叠加层。
#[derive(Debug, Clone, PartialEq)]
pub enum DisplayingOverlay {
    Nothing,
    CreateGroup,
    CreatePrivate,
    PendingRequests,
    SettingsMenu,
    LanguageSelect,
    ServerAddress,
    /// 命令 /login 无参打开的登录表单浮层（密码框遮蔽）
    Login,
    /// 命令 /register 无参打开的注册表单浮层（密码框遮蔽）
    Register,
    /// 设置页或 /appearance 无参打开的外观选择浮层
    AppearanceSelect,
    /// 个人资料卡片（/profile 打开）：显示用户名、UID、昵称、简介与头像
    ProfileCard,
    /// 通用表单浮层（设置个人资料、修改密码、修改头像、注销账户）：
    /// 具体字段与提交动作在 App::active_form 里，本变体只表示"当前显示的是表单"
    Form,
    /// 本地头像选择浮层：列出 `<客户端目录>/config/avatars` 里的图片文件，
    /// 回车直接用该文件上传头像；浮层里按 Ctrl+U 才转到填网络链接的修改头像表单
    AvatarSelect,
}

/// 表单浮层里的一个输入项。
#[derive(Debug, Clone)]
struct FormField {
    /// 标签文案键（表单浮层逐行显示在输入框左侧）
    label_key: String,
    state: TextInputState,
    /// 密码类输入：显示为遮蔽字符，且不会被整屏框选复制走内容
    secret: bool,
}

impl FormField {
    fn new(label_key: &str, prefilled: &str, secret: bool) -> Self {
        let mut state = TextInputState::default();
        state.set_text(prefilled);
        Self {
            label_key: label_key.to_string(),
            state,
            secret,
        }
    }

    /// 输入框当前文本（去首尾空白）
    fn text(&self) -> String {
        self.state.value.text().string().trim().to_string()
    }
}

/// 表单浮层要执行的动作。字段值按表单声明顺序从 active_form 取出。
#[derive(Debug, Clone, PartialEq)]
enum FormAction {
    /// 设置个人资料：昵称、手机号、简介
    UpdateProfile,
    /// 修改密码：旧密码、新密码、新密码确认
    ChangePassword,
    /// 修改头像：本地图片路径或服务端可访问的完整链接
    ChangeAvatar,
    /// 注销账户：再输入一次密码
    DeleteAccount,
}

/// 加密会话所处阶段
#[derive(Debug, Clone, Copy, PartialEq)]
enum EncryptionPhase {
    /// 已发起邀请，等待对端接受
    AwaitingAcceptance,
    /// 密钥已协商，等待服务器确认双方就绪
    AwaitingSessionReady,
    /// 会话激活，可收发加密消息
    Active,
}

/// 单个房间的加密会话状态；临时私钥不实现 Debug/Clone，由外层手工实现 Debug
struct EncryptionSession {
    phase: EncryptionPhase,
    ephemeral_secret: Option<EphemeralSecret>,
    /// 己方临时公钥（base64）：重发邀请必须复用同一份，否则双方密钥无法一致
    own_public_key: String,
    shared_key: Option<[u8; 32]>,
    pending_content: Option<String>,
    /// 本阶段开始时刻：等待接受超过时限将自动重新发起邀请
    initiated_at: Instant,
}

/// 客户端加密状态：用户身份密钥与各房间加密会话
struct ClientCrypto {
    identity_key: SigningKey,
    sessions: HashMap<String, EncryptionSession>,
}

impl fmt::Debug for ClientCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCrypto")
            .field("session_count", &self.sessions.len())
            .finish()
    }
}

/// 所有输入框状态集中管理
#[derive(Default, Debug, Clone)]
pub struct InputCollector {
    // 登录页面
    pub login_name_state: TextInputState,
    pub login_password_state: TextInputState,
    // 注册页面
    pub register_name_state: TextInputState,
    pub register_email_state: TextInputState,
    pub register_password_state: TextInputState,
    // 聊天页面
    pub message_input_state: TextAreaState,
    // 创建群聊弹窗
    pub create_group_name_state: TextInputState,
    pub create_group_members_state: TextInputState,
    // 创建私密聊天弹窗
    pub create_private_username_state: TextInputState,
    // 服务器地址弹窗
    pub server_address_state: TextInputState,
    // 整屏鼠标框选复制：起点在左键按下时记录，拖拽时更新终点，松开时据此从整屏行文本快照
    // 取文本复制到剪贴板并清空。起点落在消息输入框内时不使用这两个字段，
    // 那种情况仍由输入控件自身维护选区（保留控件内的选词与光标语义）。
    pub selection_start: Option<(u16, u16)>,
    pub selection_end: Option<(u16, u16)>,
}

/// 外观系统的数据载体：客户端全部可配色槽位的集中定义。
/// 每个字段对应 config/themes/{外观名}.json 里的一个同名键，用户选择的名称持久化在
/// preferences.json 的 appearance 字段；界面渲染一律从这里取色，不再散落硬编码颜色。
#[derive(Debug, Clone, PartialEq)]
struct Appearance {
    /// 应用整体背景色（覆盖终端默认底色，含弹窗区域）
    app_background: Color,
    /// 消息显示区边框颜色
    message_border: Color,
    /// 群聊列表边框颜色
    room_border: Color,
    /// 所有叠加层窗口的边框颜色（浮层风格统一靠这一个槽位，主题里可单独调）
    overlay_border: Color,
    /// 消息正文文本颜色
    message_text: Color,
    /// 被选中文本颜色（群聊项、设置菜单项、指令自动补全项）
    selected_text: Color,
    /// 他人用户名文本颜色
    other_username_text: Color,
    /// 自己用户名文本颜色
    own_username_text: Color,
    /// 消息时间文本颜色
    time_text: Color,
    /// 快捷键提示文本颜色
    hint_text: Color,
    /// 提示框处于提示状态时的边框颜色
    notice_hint_border: Color,
    /// 提示框处于报错状态时的边框颜色
    notice_error_border: Color,
    /// 消息输入框默认状态边框颜色
    input_border: Color,
    /// 消息输入框内正文文本颜色
    input_text: Color,
    /// 消息输入框指令模式边框颜色
    command_border: Color,
    /// 消息输入框搜索模式边框颜色
    search_border: Color,
    /// 鼠标框选待复制文本的背景颜色
    selection_background: Color,
    /// 搜索模式命中片段的背景颜色
    search_match_background: Color,
    /// 搜索模式中"当前定位到的那一个匹配项"的背景颜色（与其余命中区分）
    search_current_match_background: Color,
    /// 消息下方已读/未读状态文本颜色
    read_state_text: Color,
}

/// 主题文件中的颜色写法：支持十六进制 "#rrggbb"、终端基本色名、以及 [红, 绿, 蓝] 三元素数组。
/// 无法识别时返回 None，由调用方按"该槽位缺失"处理，绝不猜测近似色。
fn parse_theme_color(value: &serde_json::Value) -> Option<Color> {
    if let Some(components) = value.as_array() {
        let mut bytes = [0u8; 3];
        for (index, component) in components.iter().take(3).enumerate() {
            bytes[index] = component.as_u64()?.try_into().ok()?;
        }
        if components.len() != 3 {
            return None;
        }
        return Some(Color::Rgb(bytes[0], bytes[1], bytes[2]));
    }
    let text = value.as_str()?.trim().to_lowercase();
    if let Some(hexadecimal) = text.strip_prefix('#') {
        if hexadecimal.len() != 6 {
            return None;
        }
        let red = u8::from_str_radix(&hexadecimal[0..2], 16).ok()?;
        let green = u8::from_str_radix(&hexadecimal[2..4], 16).ok()?;
        let blue = u8::from_str_radix(&hexadecimal[4..6], 16).ok()?;
        return Some(Color::Rgb(red, green, blue));
    }
    let named = match text.as_str() {
        "default" | "reset" => Color::Reset,
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "white" => Color::White,
        "dark_gray" | "dark-gray" | "bright_black" | "bright-black" => Color::DarkGray,
        "light_red" | "light-red" | "bright_red" | "bright-red" => Color::LightRed,
        "light_green" | "light-green" | "bright_green" | "bright-green" => Color::LightGreen,
        "light_yellow" | "light-yellow" | "bright_yellow" | "bright-yellow" => Color::LightYellow,
        "light_blue" | "light-blue" | "bright_blue" | "bright-blue" => Color::LightBlue,
        "light_magenta" | "light-magenta" | "bright_magenta" | "bright-magenta" => {
            Color::LightMagenta
        }
        "light_cyan" | "light-cyan" | "bright_cyan" | "bright-cyan" => Color::LightCyan,
        "gray" | "grey" => Color::Gray,
        "bright_white" | "bright-white" => Color::White,
        _ => return None,
    };
    Some(named)
}

/// 依据背景色亮度挑选可读的前景色：暗底配亮字、亮底配暗字。
/// 主题只为框选与搜索命中提供背景色，若沿用正文前景色可能出现字色与底色同深浅而看不清，
/// 故统一由此函数推导前景色；背景为终端默认色时按暗底处理。
fn contrasting_foreground(background: Color) -> Color {
    let brightness: u32 = match background {
        Color::Rgb(red, green, blue) => {
            (red as u32 * 299 + green as u32 * 587 + blue as u32 * 114) / 1000
        }
        Color::Indexed(index) => match index {
            0..=7 => 40,
            8..=15 => 170,
            16..=231 => {
                let cube = index - 16;
                let red = (cube / 36) * 51;
                let green = ((cube / 6) % 6) * 51;
                let blue = (cube % 6) * 51;
                (red as u32 * 299 + green as u32 * 587 + blue as u32 * 114) / 1000
            }
            _ => 128,
        },
        Color::Black | Color::Blue | Color::Green | Color::Magenta | Color::Red | Color::Reset => {
            40
        }
        Color::Cyan
        | Color::DarkGray
        | Color::Gray
        | Color::LightBlue
        | Color::LightCyan
        | Color::LightGreen
        | Color::LightMagenta
        | Color::LightRed
        | Color::LightYellow
        | Color::White
        | Color::Yellow => 200,
    };
    if brightness >= 128 {
        Color::Black
    } else {
        Color::White
    }
}

impl Appearance {
    /// 内置默认外观：与引入外观系统之前的硬编码配色完全一致，
    /// 同时作为主题文件缺项时的兜底色，保证未配置主题的用户看到原有效果。
    fn built_in() -> Self {
        Self {
            app_background: Color::Reset,
            message_border: Color::Cyan,
            room_border: Color::Cyan,
            overlay_border: Color::Cyan,
            message_text: Color::White,
            selected_text: Color::Yellow,
            other_username_text: Color::Cyan,
            own_username_text: Color::Green,
            time_text: Color::DarkGray,
            hint_text: Color::DarkGray,
            notice_hint_border: Color::Blue,
            notice_error_border: Color::Red,
            input_border: Color::Cyan,
            input_text: Color::White,
            command_border: Color::Yellow,
            search_border: Color::Red,
            selection_background: Color::Yellow,
            search_match_background: Color::Red,
            search_current_match_background: Color::LightYellow,
            read_state_text: Color::Blue,
        }
    }

    /// 读取 `<配置目录>/themes/{name}.json`，一次性返回完整外观结构体。
    /// 元组第二项为"字段不完整"标记：只要存在缺失槽位即为真，按主题规范不列出具体缺哪个字段；
    /// 第三项为主题文件里多出来的未知字段名列表。
    /// 文件不可读或不是合法 JSON 时返回内置默认外观，并把字段不完整标记置为真。
    fn load(name: &str) -> (Self, bool, Vec<String>) {
        let mut appearance = Self::built_in();
        let path = paths::config_path(&format!("themes/{name}.json"));
        let Ok(content) = fs::read_to_string(&path) else {
            return (appearance, true, Vec::new());
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&content) else {
            return (appearance, true, Vec::new());
        };
        let slots: Vec<(&str, &mut Color)> = vec![
            ("app_background", &mut appearance.app_background),
            ("message_border", &mut appearance.message_border),
            ("room_border", &mut appearance.room_border),
            ("overlay_border", &mut appearance.overlay_border),
            ("message_text", &mut appearance.message_text),
            ("selected_text", &mut appearance.selected_text),
            ("other_username_text", &mut appearance.other_username_text),
            ("own_username_text", &mut appearance.own_username_text),
            ("time_text", &mut appearance.time_text),
            ("hint_text", &mut appearance.hint_text),
            ("notice_hint_border", &mut appearance.notice_hint_border),
            ("notice_error_border", &mut appearance.notice_error_border),
            ("input_border", &mut appearance.input_border),
            ("input_text", &mut appearance.input_text),
            ("command_border", &mut appearance.command_border),
            ("search_border", &mut appearance.search_border),
            ("selection_background", &mut appearance.selection_background),
            (
                "search_match_background",
                &mut appearance.search_match_background,
            ),
            (
                "search_current_match_background",
                &mut appearance.search_current_match_background,
            ),
            ("read_state_text", &mut appearance.read_state_text),
        ];
        let known_field_names: Vec<&str> = slots.iter().map(|(field, _)| *field).collect();
        let mut has_missing_field = false;
        for (field, slot) in slots {
            match document.get(field).and_then(parse_theme_color) {
                Some(color) => *slot = color,
                None => has_missing_field = true,
            }
        }
        let extra_fields = document
            .as_object()
            .map(|entries| {
                entries
                    .keys()
                    .filter(|entry| !known_field_names.contains(&entry.as_str()))
                    .cloned()
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        (appearance, has_missing_field, extra_fields)
    }

    /// 表单浮层（改密码、改头像、设置资料、删除账户）里方框输入框的边框色：
    /// 恒取未选中色，当前项靠标题加粗与箭头行的 > 标记指示，避免浮层一打开满眼选中色。
    fn form_field_border(&self) -> Color {
        self.input_border
    }

    /// 登录浮层方框输入框的边框色：聚焦项用选中色，该浮层保留原有的强指示风格。
    fn login_field_border(&self, focused: bool) -> Color {
        if focused {
            self.selected_text
        } else {
            self.input_border
        }
    }

    /// 列出 config/themes 目录下所有可用外观名称（去掉 .json 后缀），按名称字典序排列
    fn available_names() -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(paths::config_directory().join("themes"))
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|extension| extension == "json")
                    .unwrap_or(false)
            })
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|stem| stem.to_string())
            })
            .collect();
        names.sort();
        names
    }
}

#[derive(Debug)]
pub struct App {
    // ==================== 上层：用户可控配置（来自 preferences.json 或界面/指令设置）====================
    pub input_collector: InputCollector,
    pub connector: Connector,
    /// 当前加载的语言字符串映射（key → 本地化文本）
    language_strings: HashMap<String, String>,
    /// 是否在消息中同时显示发送者的 uid（true 显示 username(uid)）
    show_uid: bool,
    /// 时间显示是否带日期（true 显示日期+时间，false 仅显示时间）
    time_with_date: bool,
    /// 是否启用系统通知（新消息/私聊请求时发出提示）
    sound_enabled: bool,
    /// 开启"消息免打扰"的房间 ID 集合（以各房间唯一 id 为键），持久化到 preferences.json。
    /// 免打扰房间在别处收到新消息时：不发系统通知/提示音，未读数以点（·）显示而非具体数字。
    muted_room_ids: HashSet<String>,
    /// 当前生效的外观配色（由 preferences.json 的 appearance 字段指向的主题文件加载）
    appearance: Appearance,
    /// 当前外观名称（无主题文件时为 "built_in"），用于设置页与 /appearance 回显
    appearance_name: String,
    /// 快速搜索：搜索模式下随输入即时在已加载消息里出结果，无需按 Enter。
    /// Enter 仍保留"整房拉全历史后再搜"的完整语义（每次按键都翻页拉全量会打爆接口）。
    /// 由 preferences.json 的 quick_search 字段持久化
    quick_search: bool,

    // ==================== 下层：程序运行期维护的临时状态（不写入配置文件）====================
    /// 当前聚焦的输入框索引
    focus_index: usize,
    /// 右上角通知列表，元素为 (通知文本, 是否错误类, 过期时刻)，到期自动移除
    notifications: Vec<(String, bool, Instant)>,
    /// 聊天页面状态。
    rooms: Vec<RoomInfo>,
    rooms_state: ListState,
    messages: Vec<MessageInfo>,
    /// 房间 ID → 未读消息计数，用于在非当前选中群聊名称后以红色显示消息数量
    unread_counts: HashMap<String, u32>,
    current_user_id: Option<String>,
    displaying_overlay: DisplayingOverlay,
    /// sender_id -> username 映射
    sender_names: HashMap<String, String>,
    /// 后台轮询线程通信发送器（多个后台线程共用）
    polling_sender: Option<mpsc::Sender<PollingEvent>>,
    /// 后台 WebSocket 线程的命令通道（完整的 WS JSON 载荷）
    websocket_sender: Option<mpsc::Sender<String>>,
    /// WebSocket 线程的认证令牌副本，供检测到新房间时重建连接使用
    websocket_token: Option<String>,
    /// WebSocket 线程运行标志，置为 false 可令其退出
    websocket_running: Option<Arc<AtomicBool>>,
    /// WebSocket 最近一次成功建立连接的时刻，用于定期刷新房间订阅防止退化
    websocket_connected_at: Instant,
    /// 后台轮询线程运行标志，置为 false 可令其退出（退出登录时使用）
    polling_running: Option<Arc<AtomicBool>>,
    /// 命令补全列表当前的选中项
    command_list_state: ListState,
    /// 客户端加密状态（身份密钥与各房间加密会话）
    crypto: ClientCrypto,
    /// 待处理聊天请求列表
    pending_requests: Vec<RoomRequestInfo>,
    /// 待处理请求列表当前的选中项
    request_list_state: ListState,
    /// 设置菜单当前的选中项
    menu_list_state: ListState,
    /// 消息显示区距底部的滚动距离（0 表示贴底跟随最新消息），单位为渲染行
    messages_scroll_from_bottom: u16,
    /// 当前选中房间"更早消息"分页游标（上一次消息拉取响应里的 next_cursor，
    /// 即已加载列表中最旧一条消息的服务端 ID）。Some 表示服务器告知仍有更早消息
    /// 可拉取、None 表示已无更多或拉取失败已停止；由 load_messages_for_selected_room
    /// 在每次整房加载后赋值，render_messages 检测到用户滚到顶部时经 load_older_messages 消费并前移
    messages_older_cursor: Option<String>,
    /// 最近一次整房消息加载完成的时刻。切房加载同步阻塞主线程数百毫秒，期间用户
    /// 滚轮事件在系统队列积压，加载完成后会被逐条补处理，把新房间视图"自动"顶上去
    /// 并可能误触顶拉取；该时刻起一小段窗口内丢弃滚轮事件即可消除这些迟到输入
    messages_reloaded_at: Instant,
    /// 已在本地关闭的加密私聊房间 ID：仅从界面隐藏，不通知服务器以避免产生单人房间
    closed_room_ids: HashSet<String>,
    /// 本客户端主动退出（/quit、/quit_group、/kick）的群聊房间 ID，
    /// 用于区分“主动退出”与“被移出群聊”，避免误报被踢提示
    left_room_ids: HashSet<String>,
    /// /quit 退出清理已在后台完成，主循环检测到后应立即退出
    quit_ready: bool,
    /// 语言选择列表当前的选中项
    language_list_state: ListState,
    /// 外观选择列表当前的选中项
    appearance_list_state: ListState,
    /// 本地头像选择列表当前的选中项
    avatar_list_state: ListState,
    /// 搜索模式结果：(已执行搜索的关键词, 命中消息的 ID 列表, 当前匹配项序号)。
    /// None 表示本轮搜索模式尚未执行过搜索（输入框标题仅显示"搜索模式"）。
    search_result: Option<(String, Vec<String>, usize)>,
    /// 搜索模式下待定位的消息 ID：切换匹配项时写入，render_messages 把它滚入视口后清空
    pending_scroll_message_id: Option<String>,
    /// 正在输入的成员：元素为 (房间 ID, 用户名, 最近一次 typing 帧时刻)。
    /// 服务端只有 typing:true、没有"停止输入"信号，故按 TODO 约定的 2 秒窗口在本地衰减，
    /// 超过窗口的条目既不显示也在 handle_tick 里清理
    typing_members: Vec<(String, String, Instant)>,
    /// 最近一次向上游发出 typing 帧的时刻，用于按接缝给出的间隔节流
    /// （服务端入站限流 30 条/30 秒，逐字符上报会立刻打满配额）
    last_typing_frame_sent_at: Option<Instant>,
    /// 成员在线状态表：用户 ID → 是否在线。完全由服务端 user_online / user_offline
    /// 跳变广播累积（服务端建立连接时不下发在线名单基线），
    /// 表中不存在即"未知"，界面不显示状态标记，避免把未知误显示为离线。
    presence_by_user: HashMap<String, bool>,
    /// 上一帧整屏的行文本快照（已按双宽字符跨格还原），框选松开时按行列区间从中取文本。
    /// 必须在浮层与通知都画完之后采集，才能复制到任意位置的文本而不只是消息区。
    screen_text_rows: Vec<String>,
    /// 请求主循环执行一次整屏重绘（terminal.clear 后下一帧全量重画）的标记。
    /// 由 Ctrl+L 置位：终端侧偶发的自动滚动会让屏幕内容与 ratatui 的增量缓冲区错位，
    /// 增量渲染只重写"有变化"的格子因而无法自愈，全量重画是唯一可靠修法。
    full_repaint_requested: bool,
    /// 消息输入框在屏幕上的矩形，由 render_message_input 每帧写入。
    /// 该区域内的拖拽仍交给输入控件自己处理（保留控件内的选区与光标语义），
    /// 区域外的拖拽才启动整屏框选，两种框选不会同时生效。
    message_input_area: Rect,
    /// 服务端实时连接状态：None 表示还没探测过（顶栏不显示标记，避免启动瞬间误报离线），
    /// Some(true/false) 才会画出在线或离线标记。顶栏标记与"连不上服务器只提示一次"共用它。
    connection_ready: Option<bool>,
    /// 当前登录用户名（顶栏"当前用户"显示；未登录时为空串）
    current_username: String,
    /// /profile 浮层当前展示的用户资料
    profile_view: Option<PublicProfile>,
    /// 通用表单浮层的动作与字段（仅 displaying_overlay == Form 时有值）
    active_form: Option<(FormAction, Vec<FormField>)>,
    /// 自己的邮箱与手机号。服务端只在注册、登录、资料与头像接口的完整响应里给这两项，
    /// 公开资料接口刻意不含它们，因此看别人时卡片上这两行显示"无"。
    own_contact: Option<(String, String)>,
    /// 自己发出的聊天请求列表（私聊管理浮层与收到的请求一起展示）
    sent_requests: Vec<RoomRequestInfo>,
    /// 注册用户目录缓存（服务端全量用户列表）。None 表示还没拉过，Some 即使为空也算拉过，
    /// 不再重复请求。/profile 的自动补全每帧都读它，所以拉取只能由按键触发、在后台线程完成，
    /// 绝不能出现在渲染路径里
    registered_users: Option<Vec<UserSearchResult>>,
    /// 消息本地缓存（只缓存未加密房间）。按当前登录用户 ID 建立目录，未登录时为 None
    chat_cache: Option<ChatCache>,
    /// 头像原始字节：用户 ID → 图片字节，None 表示"已确认没有头像或取回失败"。
    /// 条目存在即不再重复请求，避免每帧为同一个用户反复联网；字节由后台线程取回后经
    /// PollingEvent::AvatarLoaded 交回主线程，渲染期只做一次解码（见 avatar_pixels）。
    avatar_images: HashMap<String, Option<Vec<u8>>>,
    /// 按显示尺寸解码好的头像像素块：键为 (用户 ID, 列数, 行数)。
    /// 同一尺寸只解码一次（消息列表用小块，个人资料卡片用大块），之后每帧直接查表。
    avatar_pixels: HashMap<(String, usize, usize), AvatarPixels>,
    /// 已下载并通过校验的新版本：(新版本号, 本地包路径)。/update 与设置项"更新客户端"消费它
    pending_update: Option<(String, PathBuf)>,
    /// /update 已安排后台安装进程等待本进程退出，主循环检测到该标记后立即退出
    update_handoff_requested: bool,
    /// 后台版本检查与下载是否正在进行，避免重复派生下载线程
    update_check_running: Option<Arc<AtomicBool>>,
    /// 常驻可达性探测线程的运行标志（换服务器地址时停旧起新）
    reachability_running: Option<Arc<AtomicBool>>,
    /// 消息缓存待落盘的起始时刻：Some 表示"当前房间消息列表比磁盘新"。
    /// 消息逐条到达时只置位不写盘，handle_tick 攒够批量窗口后一次性整房写入，
    /// 避免活跃群里每条消息都触发一次整文件重写
    cache_pending_flush_since: Option<Instant>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            input_collector: InputCollector::default(),
            connector: Connector::default(),
            language_strings: HashMap::new(),
            show_uid: false,
            time_with_date: false,
            sound_enabled: true,
            muted_room_ids: HashSet::new(),
            appearance: Appearance::built_in(),
            appearance_name: "built_in".to_string(),
            quick_search: false,
            focus_index: 0,
            notifications: Vec::new(),
            rooms: Vec::new(),
            rooms_state: ListState::default(),
            messages: Vec::new(),
            unread_counts: HashMap::new(),
            current_user_id: None,
            displaying_overlay: DisplayingOverlay::Nothing,
            sender_names: HashMap::new(),
            polling_sender: None,
            websocket_sender: None,
            websocket_token: None,
            websocket_running: None,
            websocket_connected_at: Instant::now(),
            polling_running: None,
            command_list_state: ListState::default(),
            crypto: ClientCrypto {
                identity_key: crypto::generate_identity_key(),
                sessions: HashMap::new(),
            },
            pending_requests: Vec::new(),
            request_list_state: ListState::default(),
            menu_list_state: ListState::default(),
            messages_scroll_from_bottom: 0,
            messages_older_cursor: None,
            messages_reloaded_at: Instant::now(),
            closed_room_ids: HashSet::new(),
            left_room_ids: HashSet::new(),
            quit_ready: false,
            language_list_state: ListState::default(),
            appearance_list_state: ListState::default(),
            avatar_list_state: ListState::default(),
            search_result: None,
            pending_scroll_message_id: None,
            typing_members: Vec::new(),
            last_typing_frame_sent_at: None,
            presence_by_user: HashMap::new(),
            screen_text_rows: Vec::new(),
            message_input_area: Rect::default(),
            full_repaint_requested: false,
            connection_ready: None,
            current_username: String::new(),
            profile_view: None,
            active_form: None,
            own_contact: None,
            sent_requests: Vec::new(),
            registered_users: None,
            chat_cache: None,
            avatar_images: HashMap::new(),
            avatar_pixels: HashMap::new(),
            pending_update: None,
            update_handoff_requested: false,
            update_check_running: None,
            reachability_running: None,
            cache_pending_flush_since: None,
        }
    }
}

/// 计算本帧允许绘制的区域：整屏高度减一，把最底行留空。
/// 原因：向屏幕最后一行（尤其右下角那一格）写入时，部分终端会触发自动换行并把已有内容上滚一行，
/// 而 ratatui 的增量缓冲区并不知道这次滚动，之后每帧只重绘"有变化"的格子，
/// 错位就再也修不回来——表现为用中文输入法连续输入大段文本后整块界面被顶掉一截，
/// 只有切群这种引起全量重绘的操作才能恢复。留空最后一行即可从根上避免滚动。
fn drawable_area(area: Rect) -> Rect {
    if area.height <= 1 {
        return area;
    }
    Rect {
        height: area.height - 1,
        ..area
    }
}

/// 用指定背景色铺满给定区域（各组件只补自己写过的样式，因此先铺底即可被统一继承）。
fn paint_background(frame: &mut Frame, area: Rect, background: Color) {
    frame
        .buffer_mut()
        .set_style(area, Style::default().bg(background));
}

/// 把整屏缓冲区逐行还原为文本快照（双宽字符跨格推进，不插入多余空格）。
/// 在每帧所有元素绘制完成后采集，框选复制才能覆盖消息区、房间列表、浮层与通知等任意位置。
fn collect_screen_text_rows(buffer: &ratatui::buffer::Buffer, area: Rect) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    for row in area.top()..area.bottom() {
        let mut text = String::new();
        let mut column = area.left();
        while column < area.right() {
            let Some(cell) = buffer.cell((column, row)) else {
                break;
            };
            let symbol = cell.symbol();
            text.push_str(symbol);
            column += display_width(symbol).max(1);
        }
        rows.push(text);
    }
    rows
}

/// 从整屏行文本快照里取出框选矩形覆盖的文本：按行拼接、每行按显示宽度切列、
/// 去掉行尾空格与首尾整行为空的行。端点先后顺序无关，终点那一列本身计入选区。
fn extract_selected_screen_text(
    screen_text_rows: &[String],
    selection_start: (u16, u16),
    selection_end: (u16, u16),
) -> String {
    let first_row = selection_start.1.min(selection_end.1);
    let last_row = selection_start.1.max(selection_end.1);
    let first_column = selection_start.0.min(selection_end.0);
    // 终点列含格本身，故取右边界时右移一列
    let last_column = selection_start.0.max(selection_end.0) + 1;
    let mut selected_rows: Vec<String> = Vec::new();
    for row in first_row..=last_row {
        let Some(row_text) = screen_text_rows.get(row as usize) else {
            continue;
        };
        selected_rows.push(
            strip_decoration_characters(&slice_columns_by_display_width(
                row_text,
                first_column,
                last_column,
            ))
            .trim()
            .to_string(),
        );
    }
    while selected_rows.last().is_some_and(|row| row.is_empty()) {
        selected_rows.pop();
    }
    while selected_rows.first().is_some_and(|row| row.is_empty()) {
        selected_rows.remove(0);
    }
    selected_rows.join("\n")
}

/// 剔除框选结果里的界面装饰：制表框线符号、项目符号与圆点，以及作为背景填充的空白。
/// 这些格子属于外框与背景而不是内容文字，框选跨越面板边缘时不应被一起复制走。
fn strip_decoration_characters(row_text: &str) -> String {
    row_text
        .chars()
        .filter(|character| {
            !matches!(
                character,
                '─' | '│'
                    | '┌'
                    | '┐'
                    | '└'
                    | '┘'
                    | '├'
                    | '┤'
                    | '┬'
                    | '┴'
                    | '┼'
                    | '━'
                    | '┃'
                    | '┏'
                    | '┓'
                    | '┗'
                    | '┛'
                    | '═'
                    | '║'
                    | '╔'
                    | '╗'
                    | '╚'
                    | '╝'
                    | '╠'
                    | '╣'
                    | '╦'
                    | '╩'
                    | '╬'
                    | '►'
                    | '▶'
                    | '●'
                    | '○'
                    | '·'
            )
        })
        .collect()
}

/// 粘贴内容归一化：统一换行符并剔除除换行与制表以外的控制字符。
/// macOS Terminal.app 粘贴多行文本时送来的行尾是 \r\n，
/// 只按 \n 拆行会把每行结尾的 \r 一起插进文本缓冲区，
/// 表现为行间多出一个乱码格、需要用退格键删掉才能恢复正常文本。
fn normalize_pasted_text(pasted_text: &str) -> String {
    pasted_text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect()
}

/// 判断某个格子里是不是"内容文字"：空白填充与界面装饰（框线、箭头、圆点等）都不算。
/// 框选只应落在内容文字上，空白与外框既不该高亮，也不该被复制。
fn is_content_character(character: char) -> bool {
    !character.is_whitespace() && !is_decoration_character(character)
}

/// 界面装饰字符集合：制表框线、选中箭头、在线状态圆点、项目点、头像半块等。
/// 框选复制与高亮都按这份名单剔除，避免把界面图形当成聊天内容复制走。
fn is_decoration_character(character: char) -> bool {
    matches!(
        character,
        '─' | '│'
            | '┌'
            | '┐'
            | '└'
            | '┘'
            | '├'
            | '┤'
            | '┬'
            | '┴'
            | '┼'
            | '━'
            | '┃'
            | '┏'
            | '┓'
            | '┗'
            | '┛'
            | '═'
            | '║'
            | '╔'
            | '╗'
            | '╚'
            | '╝'
            | '╠'
            | '╣'
            | '╦'
            | '╩'
            | '╬'
            | '►'
            | '▶'
            | '●'
            | '○'
            | '·'
            | '▀'
            | '▄'
    )
}

/// 用外观的框选背景色高亮整屏框选矩形（两个端点的先后顺序无关），并夹取到屏幕范围内。
fn paint_screen_selection(
    frame: &mut Frame,
    area: Rect,
    selection_start: (u16, u16),
    selection_end: (u16, u16),
    appearance: &Appearance,
) {
    let first_row = selection_start.1.min(selection_end.1);
    let last_row = selection_start.1.max(selection_end.1);
    let first_column = selection_start.0.min(selection_end.0);
    let last_column = selection_start.0.max(selection_end.0);
    if area.width == 0 || area.height == 0 {
        return;
    }
    let selection_style = Style::default()
        .fg(contrasting_foreground(appearance.selection_background))
        .bg(appearance.selection_background);
    let buffer = frame.buffer_mut();
    for row in first_row..=last_row.min(area.bottom().saturating_sub(1)) {
        for column in first_column..=last_column.min(area.right().saturating_sub(1)) {
            let Some(cell) = buffer.cell_mut((column, row)) else {
                continue;
            };
            // 只高亮内容文字格：外框、装饰符与背景空白不参与框选显示
            if cell
                .symbol()
                .chars()
                .next()
                .is_some_and(is_content_character)
            {
                cell.set_style(selection_style);
            }
        }
    }
}

impl App {
    /// 设置后台轮询线程通信发送器
    pub fn set_polling_sender(&mut self, sender: Option<mpsc::Sender<PollingEvent>>) {
        self.polling_sender = sender;
    }

    /// 启动后台轮询线程，定期从服务器获取房间列表、待处理与已发送的聊天请求。
    /// 取数失败时按错误类别分流：连不上服务端只报可达性跳变（界面据此提示一次并标记顶栏），
    /// 服务端明确返回的业务错误仍按 Error 弹出。
    pub fn start_polling_thread(&mut self) {
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };

        let connector = self.connector.clone();
        let lang_map = self.language_strings.clone();

        // 通知旧轮询线程停止，避免退出登录等场景出现多个轮询线程并存
        if let Some(running_flag) = self.polling_running.take() {
            running_flag.store(false, Ordering::Relaxed);
        }
        let running_flag = Arc::new(AtomicBool::new(true));
        self.polling_running = Some(running_flag.clone());

        thread::spawn(move || {
            let tr = |key: &str| {
                lang_map
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| key.to_string())
            };
            let report_failure = |error: baihua_core::api::ConnectorError, label_key: &str| {
                if error.is_connection_failure() {
                    let _ = sender.send(PollingEvent::ReachabilityChanged(false));
                } else {
                    let _ = sender.send(PollingEvent::Error(format!("{}: {error}", tr(label_key))));
                }
            };
            let mut last_rooms: Vec<RoomInfo> = Vec::new();
            let mut last_requests: Vec<RoomRequestInfo> = Vec::new();
            let mut last_sent_requests: Vec<RoomRequestInfo> = Vec::new();
            let mut room_poll_counter: u32 = 0;
            let mut request_poll_counter: u32 = 0;

            while running_flag.load(Ordering::Relaxed) {
                // 每 2 秒轮询房间列表。连不上服务端由常驻探测线程统一报告，
                // 这里不把传输层失败当业务错误抛出，否则一次网络抖动就是一串报错框
                if room_poll_counter.is_multiple_of(20) {
                    match connector.list_rooms() {
                        Ok(rooms) => {
                            if rooms != last_rooms {
                                last_rooms = rooms.clone();
                                let _ = sender.send(PollingEvent::RoomsUpdated(rooms));
                            }
                        }
                        Err(error) if error.is_connection_failure() => {
                            debug_log(&format!("轮询房间列表时连不上服务端: {error}"));
                        }
                        Err(error) => {
                            let _ = sender.send(PollingEvent::Error(format!(
                                "{}: {error}",
                                tr("error_poll_rooms")
                            )));
                        }
                    }
                }

                // 每 3 秒轮询收到的与已发出的聊天请求；请求接口失败不改变可达性结论，
                // 房间列表已经承担同样的连通性判断，这里只把业务错误报出去
                if request_poll_counter.is_multiple_of(30) {
                    match connector.list_pending_requests() {
                        Ok(requests) => {
                            if requests != last_requests {
                                last_requests = requests.clone();
                                let _ = sender.send(PollingEvent::PendingRequestsUpdated(requests));
                            }
                        }
                        Err(error) => report_failure(error, "error_poll_requests"),
                    }
                    match connector.list_sent_requests() {
                        Ok(requests) => {
                            if requests != last_sent_requests {
                                last_sent_requests = requests.clone();
                                let _ = sender.send(PollingEvent::SentRequestsUpdated(requests));
                            }
                        }
                        Err(error) => report_failure(error, "error_poll_requests"),
                    }
                }

                room_poll_counter = room_poll_counter.wrapping_add(1);
                request_poll_counter = request_poll_counter.wrapping_add(1);

                thread::sleep(Duration::from_millis(100));
            }
        });
    }

    /// 启动 WebSocket 线程，负责实时消息的发送与接收
    /// 启动 WebSocket 线程：断线自动重连，直至被 restart_websocket_thread 替换或应用退出
    /// 可选的 connected_sender：收到服务端 connected 回执时发送信号，用于自动登录等待连接就绪
    pub fn start_websocket_thread(
        &mut self,
        token: &str,
        mut connected_sender: Option<Sender<()>>,
    ) {
        // 通知旧线程停止，并等待其完全退出：确保旧 socket 关闭后再建立新连接，
        // 避免服务端短时间内看到同一用户两个连接并存导致状态混乱
        if let Some(running_flag) = self.websocket_running.take() {
            running_flag.store(false, Ordering::Relaxed);
            // 等待旧线程退出（其内层循环 sleep 50ms 后检查标志并 return）
            thread::sleep(Duration::from_millis(150));
        }
        let Some(event_sender) = self.polling_sender.clone() else {
            return;
        };
        let (command_sender, command_receiver) = mpsc::channel::<String>();
        self.websocket_sender = Some(command_sender);
        self.websocket_token = Some(token.to_string());
        self.websocket_connected_at = Instant::now();

        let running_flag = Arc::new(AtomicBool::new(true));
        self.websocket_running = Some(running_flag.clone());
        let thread_running = running_flag.clone();

        // WebSocket 连接地址由接缝按当前版本推导（scheme 映射 + 固定路径 /websocket）
        let version = self.connector.version();
        let websocket_url = version.websocket_url(self.connector.base_url());
        let token = token.to_string();
        let lang_map = self.language_strings.clone();
        // 应用层双向心跳帧与间隔（按版本），供后台线程周期发送以维持客户端→服务端方向流量
        let heartbeat_frame = version.heartbeat_frame();
        let heartbeat_interval = version.application_heartbeat_interval();

        thread::spawn(move || {
            let tr = |key: &str| {
                lang_map
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| key.to_string())
            };
            // 外层循环支持断线自动重连；重连后服务器会按最新房间列表完成订阅
            while thread_running.load(Ordering::Relaxed) {
                // 由库自动生成符合 RFC 6455 的完整握手请求（含 Sec-WebSocket-Key 等必需头）
                let mut request = match websocket_url.as_str().into_client_request() {
                    Ok(request) => request,
                    Err(e) => {
                        debug_log(&format!("WS 请求构造失败: {e}"));
                        let _ = event_sender.send(PollingEvent::Error(format!(
                            "{}: {e}",
                            tr("error_ws_handshake")
                        )));
                        // 请求构造失败等待后重试
                        for _ in 0..20 {
                            if !thread_running.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                };
                match HeaderValue::from_str(&authorization_value(&token)) {
                    Ok(value) => {
                        request.headers_mut().insert("Authorization", value);
                    }
                    Err(e) => {
                        debug_log(&format!("WS 认证头构造失败: {e}"));
                        let _ = event_sender.send(PollingEvent::Error(format!(
                            "{}: {e}",
                            tr("error_construct_auth_failed")
                        )));
                        // 认证头构造失败等待后重试
                        for _ in 0..20 {
                            if !thread_running.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                }

                let mut socket = match tungstenite::connect(request) {
                    Ok((socket, _)) => {
                        debug_log("WS 已连接");
                        socket
                    }
                    Err(e) => {
                        debug_log(&format!("WS 连接失败: {e}"));
                        let err_msg = e.to_string();
                        let _ = event_sender.send(PollingEvent::WebSocketState(
                            "error_ws_connect_failed".to_string(),
                        ));
                        // 服务端握手鉴权失败（401/403/令牌过期等，判定标记由接缝按版本给出）：
                        // 清除会话并通知主线程，直接退出不再重试
                        if version.is_auth_failure(&err_msg) {
                            let _ = event_sender
                                .send(PollingEvent::Error(websocket_auth_sentinel().to_string()));
                            return;
                        }
                        // 连接失败等待后重试
                        for _ in 0..20 {
                            if !thread_running.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                };
                // 将底层 TCP 流设为非阻塞模式，使无数据时读取操作立即返回
                if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_ref() {
                    let _ = stream.set_nonblocking(true);
                }

                let mut connected_signaled = false;
                // 应用层双向心跳：服务端仅发送协议级 Ping 帧（30 秒），客户端方向完全静默
                // 会被中间网络设备（NAT/代理/防火墙）判定单向无流量并丢弃连接映射。
                // {"type":"pong"} 是服务端唯一确认静默忽略的报文（无回复），用于产生
                // 客户端→服务端方向的 TCP 流量以保持 NAT 映射活跃。
                let mut keepalive = Instant::now();

                loop {
                    if !thread_running.load(Ordering::Relaxed) {
                        return;
                    }
                    match socket.read() {
                        Ok(WebSocketMessage::Text(text)) => {
                            if let Some(event) = parse_websocket_event(text.as_ref(), &tr) {
                                debug_log(&format!(
                                    "WS 收到类型: {}",
                                    text.chars().take(80).collect::<String>()
                                ));
                                // 如果是 connected 事件且有 connected_sender，发送信号通知连接就绪
                                if !connected_signaled
                                    && let PollingEvent::WebSocketConnected = &event
                                {
                                    debug_log("WS connected 回执已收到，发送同步信号");
                                    if let Some(sender) = connected_sender.take() {
                                        let _ = sender.send(());
                                        connected_signaled = true;
                                    }
                                }
                                let _ = event_sender.send(event);
                            }
                        }
                        Ok(_) => {}
                        Err(tungstenite::Error::Io(ref error))
                            if error.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => {
                            debug_log(&format!("WS 断开: {e}"));
                            let _ = event_sender.send(PollingEvent::WebSocketState(
                                "error_ws_disconnected_reconnect".to_string(),
                            ));
                            break;
                        }
                    }

                    while let Ok(payload) = command_receiver.try_recv() {
                        debug_log(&format!("WS 发出: {payload}"));
                        if socket.write(WebSocketMessage::text(payload)).is_err() {
                            let _ = event_sender.send(PollingEvent::WebSocketState(
                                "error_ws_send_failed".to_string(),
                            ));
                        }
                    }

                    // 周期性发送应用层心跳帧（帧内容与间隔均由接缝按版本给出），
                    // 维持客户端→服务端方向 TCP 流量，避免中间设备丢弃连接映射
                    if keepalive.elapsed() >= heartbeat_interval {
                        let _ = socket.write(WebSocketMessage::text(heartbeat_frame.clone()));
                        keepalive = Instant::now();
                    }

                    // 无条件 flush： tungstenite 自动排队的 Pong（响应服务端 Ping）
                    // 和心跳报文均通过此 flush 写入 TCP 流
                    let _ = socket.flush();

                    thread::sleep(Duration::from_millis(50));
                }

                // 断开后稍候重连
                for _ in 0..10 {
                    if !thread_running.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    /// 重建 WebSocket 连接：服务器仅在连接建立时快照房间订阅，
    /// 出现新房间（如聊天请求刚被接受）时必须重连才能收到该房间的推送
    fn restart_websocket_thread(&mut self) {
        if let Some(token) = self.websocket_token.clone() {
            self.start_websocket_thread(&token, None);
            self.websocket_connected_at = Instant::now();
        }
    }

    /// 处理后台线程发送的事件
    pub fn handle_polling_event(&mut self, event: PollingEvent) {
        match event {
            PollingEvent::RoomsUpdated(rooms) => {
                self.apply_room_snapshot(rooms);
            }
            PollingEvent::SentRequestsUpdated(requests) => {
                self.announce_declined_invitations(&requests);
                self.sent_requests = requests;
            }
            PollingEvent::ReachabilityChanged(online) => {
                self.update_connection_state(online);
            }
            PollingEvent::AvatarLoaded((user_id, image_bytes)) => {
                self.avatar_images.insert(user_id, image_bytes);
            }
            PollingEvent::RegisteredUsersUpdated(users) => {
                self.registered_users = Some(users);
            }
            PollingEvent::UpdateReady((version, archive_path)) => {
                self.pending_update = Some((version.clone(), archive_path));
                self.push_notification(
                    self.t("update_ready")
                        .replace("{version}", &version)
                        .to_string(),
                );
            }
            PollingEvent::WebSocketConnected => {
                self.update_connection_state(true);
                // 连接（或重连）就绪：对所有未激活握手按既有密钥材料原样重发。
                // 旧邀请可能在无人订阅期间广播丢失；无未激活会话时为空操作
                let stale_room_ids: Vec<String> = self
                    .crypto
                    .sessions
                    .iter()
                    .filter(|(_, session)| session.phase != EncryptionPhase::Active)
                    .map(|(room_id, _)| room_id.clone())
                    .collect();
                for room_id in stale_room_ids {
                    self.resend_handshake_if_needed(&room_id);
                }
            }
            PollingEvent::MessageSent(message) => {
                // 服务器会同时回发确认与新消息广播，按 id 去重避免自己消息显示两次
                if !self
                    .messages
                    .iter()
                    .any(|existing| existing.id == message.id)
                {
                    self.messages.push(message);
                    self.mark_messages_dirty();
                }
            }
            PollingEvent::IncomingMessage(message) => {
                debug_log(&format!(
                    "IncomingMessage: id={} room_id={} sender_id={} selected_room={:?}",
                    message.id,
                    message.room_id,
                    message.sender_id,
                    self.rooms_state
                        .selected()
                        .and_then(|i| self.rooms.get(i))
                        .map(|r| &r.id)
                ));
                // 检查是否是自己的消息
                let is_own_message = self
                    .current_user_id
                    .as_ref()
                    .map(|uid| uid == &message.sender_id)
                    .unwrap_or(false);
                // 只要是他人的消息就触发系统通知（含提示音），无论是否在当前查看的房间；
                // 该房间开启免打扰时抑制通知（未读数仍累加）
                if !is_own_message && !self.muted_room_ids.contains(&message.room_id) {
                    let sender_name = self.sender_display_name(&message.sender_id);
                    self.send_system_notification(
                        &self.t("notification_new_message"),
                        &format!("{}: {}", sender_name, message.content),
                    );
                }
                // 如果消息属于当前选中的房间且未重复，则追加到消息列表
                let selected_room_id = self
                    .rooms_state
                    .selected()
                    .and_then(|index| self.rooms.get(index))
                    .map(|room| room.id.clone());
                let is_duplicate = self
                    .messages
                    .iter()
                    .any(|existing| existing.id == message.id);
                if selected_room_id.as_deref() == Some(message.room_id.as_str()) && !is_duplicate {
                    debug_log(&format!(
                        "append_incoming_msg room={} id={}",
                        message.room_id, message.id
                    ));
                    // 实时收到某人消息，说明他此刻确有连接：以此修正在线状态，
                    // 避免因错过 user_online 跳变而长期误显示为离线
                    if !is_own_message && !message.sender_id.is_empty() {
                        self.presence_by_user
                            .insert(message.sender_id.clone(), true);
                    }
                    let is_match = !message.content.is_empty()
                        && self.search_result.as_ref().is_some_and(|(keyword, _, _)| {
                            !find_keyword_positions(&message.content, keyword).is_empty()
                        });
                    self.messages.push(message);
                    self.mark_messages_dirty();
                    if is_match {
                        // 搜索进行中来了新的命中消息：重扫命中列表让"第 i/n"随之更新，
                        // 但不抢占视图位置（用户可能正在读当前匹配项附近的内容）
                        self.refresh_search_matches();
                    }
                } else {
                    // 消息属于非当前选中房间：累加未读数，渲染时以红色 (N) 显示
                    if selected_room_id.as_deref() != Some(message.room_id.as_str())
                        && self.rooms.iter().any(|r| r.id == message.room_id)
                    {
                        *self
                            .unread_counts
                            .entry(message.room_id.clone())
                            .or_insert(0) += 1;
                    }
                    debug_log(&format!(
                        "skip_incoming_msg: selected_room_id={:?} msg_room_id={} match={}",
                        selected_room_id.as_deref(),
                        message.room_id,
                        selected_room_id.as_deref() == Some(message.room_id.as_str())
                    ));
                }
            }
            PollingEvent::PendingRequestsUpdated(requests) => {
                // 检测新到达的请求并提示，随后更新列表与选中项
                for request in &requests {
                    let is_new = !self
                        .pending_requests
                        .iter()
                        .any(|existing| existing.id == request.id);
                    if is_new {
                        let sender_name = request
                            .sender
                            .as_ref()
                            .map(|sender| sender.username.clone())
                            .unwrap_or_else(|| self.t("unknown_user"));
                        self.push_notification(
                            self.t("notification_request_received")
                                .replace("{sender}", &sender_name)
                                .to_string(),
                        );
                        // 发送系统通知
                        self.send_system_notification(
                            &self.t("notification_new_request"),
                            &self
                                .t("notification_request_received")
                                .replace("{sender}", &sender_name),
                        );
                    }
                }
                self.apply_received_requests(requests);
                if self.request_list_state.selected().is_none() && !self.pending_requests.is_empty()
                {
                    self.request_list_state.select(Some(0));
                }
            }
            PollingEvent::EncryptInvitation(handshake) => {
                debug_log(&format!(
                    "事件 EncryptInvitation room={} peer={}",
                    handshake.room_id, handshake.peer_id
                ));
                self.handle_encrypt_invitation(handshake);
            }
            PollingEvent::EncryptAccepted(handshake) => {
                debug_log(&format!(
                    "事件 EncryptAccepted room={} peer={}",
                    handshake.room_id, handshake.peer_id
                ));
                self.handle_encrypt_accepted(handshake);
            }
            PollingEvent::EncryptSessionReady(room_id) => {
                debug_log(&format!("事件 EncryptSessionReady room={room_id}"));
                if let Some(session) = self.crypto.sessions.get_mut(&room_id) {
                    session.phase = EncryptionPhase::Active;
                }
                self.push_notification(self.t("notification_session_active"));
                // 依次冲刷握手期间排队的全部消息
                while self.flush_pending_encrypted_message(&room_id) {}
            }
            PollingEvent::EncryptedMessage(info) => {
                debug_log(&format!(
                    "事件 EncryptedMessage room={} sender={}",
                    info.room_id, info.sender_id
                ));
                self.handle_encrypted_message(info);
            }
            PollingEvent::EncryptedMessageSent(_) => {}
            PollingEvent::EncryptSessionEnded((room_id, reason)) => {
                self.crypto.sessions.remove(&room_id);
                // reason→文案键名的映射由接缝按版本集中给出
                let reason_text = self.connector.version().session_end_reason_key(&reason);
                let reason_text = self.t(reason_text);
                // 服务器重置会话时只清空消息不删房间；本地软关闭该聊天避免产生单人房间
                self.close_local_room(&room_id);
                self.push_notification(
                    self.t("notification_room_removed")
                        .replace("{reason}", &reason_text)
                        .to_string(),
                );
            }
            PollingEvent::WebSocketState(message_key) => {
                // 本端 WebSocket 抖动会自愈（自动重连 + 定期刷新订阅），默认不打扰用户；
                // 只有确实发不出去的报文才提示，避免"突然报错又自己好了"的噪声
                debug_log(&format!("WebSocket 状态事件: {message_key}"));
                match message_key.as_str() {
                    "error_ws_send_failed" => self.push_error(self.t(&message_key)),
                    // 连不上服务端：交给顶栏标记，同一故障持续期间只在这一帧弹一次错误
                    "error_ws_connect_failed" => {
                        // 版本串清空即可；连接标记交给常驻探测线程，它比单条链路的抖动可靠
                        self.connector.clear_server_version();
                    }
                    _ => {}
                }
            }
            PollingEvent::MemberTyping((room_id, user_id, username)) => {
                // 自己发出的 typing 帧服务端已过滤回声，此处再兜一层防多连接场景自我显示
                if Some(&user_id) == self.current_user_id.as_ref() || username.is_empty() {
                    return;
                }
                // 同一成员只保留最新一条：先摘掉旧记录再插入，避免重复名字堆进标题
                self.typing_members
                    .retain(|(_, kept_user_id, _)| kept_user_id != &user_id);
                self.typing_members
                    .push((room_id, username, Instant::now()));
            }
            PollingEvent::PresenceChanged((user_id, username, is_online)) => {
                self.presence_by_user.insert(user_id.clone(), is_online);
                if !is_online {
                    // 只更新在线状态与输入指示，绝不在这里清理加密会话：
                    // 服务端在本端 WebSocket 重连（新房间刷新订阅、60 秒定期重建）期间会瞬时
                    // 判定该用户完全离线并广播 user_offline，据此拆会话正是"切群再切回就把
                    // 私聊打断"的成因。会话生命周期只由服务端的权威事件驱动
                    // （encrypt_partner_disconnected 起 30 秒宽限、encrypt_session_ended /
                    // encrypt_session_expired 结束），对端在宽限期内恢复连接则会话继续可用。
                    self.typing_members
                        .retain(|(_, kept_user_id, _)| kept_user_id != &user_id);
                }
                // 在线广播自带用户名，顺带补全名称映射（新成员首次发言前也能正确显示）
                if !username.is_empty() {
                    self.sender_names.insert(user_id, username);
                }
            }
            PollingEvent::QuitCleanupFinished => {
                self.quit_ready = true;
            }
            PollingEvent::Error(error) => {
                // 客户端自造的鉴权失败哨兵（token 过期/无效）：清除会话回到未登录聊天页。
                // 置于其它分类之前，避免被当作可展示错误误报。
                if error == websocket_auth_sentinel() {
                    debug_log("WebSocket 认证失败，清除保存的会话并回到未登录聊天页");
                    Self::clear_saved_session();
                    self.current_user_id = None;
                    self.focus_index = 0;
                    self.rooms.clear();
                    self.rooms_state = ListState::default();
                    self.messages.clear();
                    self.sender_names.clear();
                    self.crypto.sessions.clear();
                    self.closed_room_ids.clear();
                    self.left_room_ids.clear();
                    self.notifications.clear();
                    self.displaying_overlay = DisplayingOverlay::Nothing;
                    self.input_collector.login_name_state = TextInputState::default();
                    self.input_collector.login_password_state = TextInputState::default();
                    self.input_collector.register_name_state = TextInputState::default();
                    self.input_collector.register_email_state = TextInputState::default();
                    self.input_collector.register_password_state = TextInputState::default();
                    if let Some(running_flag) = self.websocket_running.take() {
                        running_flag.store(false, Ordering::Relaxed);
                    }
                    if let Some(running_flag) = self.polling_running.take() {
                        running_flag.store(false, Ordering::Relaxed);
                    }
                    self.websocket_sender = None;
                    self.websocket_token = None;
                    return;
                }
                // 其余服务端错误文本按版本归类为领域信号，行为集中判定，散落字面量已收进接缝
                match self.connector.version().classify_server_error(&error) {
                    // 撞上服务器残留活跃加密会话：发 encrypt_leave 清场，同时把错误展示给用户
                    ServerSignal::StuckEncryptedSession => {
                        self.recover_stuck_encryption_sessions();
                        self.push_error(error);
                    }
                    // 对端离线导致握手被拒：清理本地等待接受的僵死会话，并把排队的明文退回输入框
                    ServerSignal::PartnerOfflineHandshakeRejected => {
                        self.discard_rejected_handshakes();
                    }
                    // /quit 批量清理对无会话房间发 leave：预期内，静默忽略
                    ServerSignal::NoActiveEncryptedSession => {}
                    // 私聊退房后服务器报"非成员"：预期内，静默忽略
                    ServerSignal::NotRoomMember => {}
                    // 其它真实错误：展示给用户
                    ServerSignal::Displayable => {
                        self.push_error(error);
                    }
                }
            }
        }
    }

    /// 对本端所有未激活的加密会话发送离开报文，促使服务器清理残留状态
    fn recover_stuck_encryption_sessions(&mut self) {
        let stuck_room_ids: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_, session)| session.phase != EncryptionPhase::Active)
            .map(|(room_id, _)| room_id.clone())
            .collect();
        for room_id in stuck_room_ids {
            self.send_ws_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptLeave { room_id: &room_id },
            ));
        }
    }

    /// 对端离线导致握手被拒时的善后：摘掉所有处于"等待对端接受"的会话（它们不可能再成功），
    /// 并把其中排队未发的明文退回消息输入框。
    /// 不退回的后果就是"消息发完立刻消失"：会话被删、排队内容随会话一起丢弃、输入框又已清空，
    /// 用户既没发出去也看不到任何痕迹。只退回当前选中房间的那条，其余房间保持丢弃。
    fn discard_rejected_handshakes(&mut self) {
        let selected_room_id = self.selected_room_id();
        let stuck_room_ids: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_, session)| session.phase == EncryptionPhase::AwaitingAcceptance)
            .map(|(room_id, _)| room_id.clone())
            .collect();
        let mut returned_content: Option<String> = None;
        for room_id in stuck_room_ids {
            if let Some(session) = self.crypto.sessions.remove(&room_id)
                && Some(room_id) == selected_room_id
            {
                returned_content = session.pending_content;
            }
        }
        self.push_notification(self.t("notification_partner_offline"));
        let Some(content) = returned_content else {
            return;
        };
        let typed = self.input_collector.message_input_state.text();
        // 输入框已被再次编辑时不覆盖用户的新内容，改为把未发内容接在最前面，两条都保住
        let merged = if typed.is_empty() {
            content
        } else {
            format!("{content}\n{typed}")
        };
        self.input_collector.message_input_state.set_text(merged);
        self.push_notification(self.t("notification_message_returned"));
    }

    /// 处理对端发起的加密会话邀请：校验签名、协商密钥、回复接受与就绪
    fn handle_encrypt_invitation(&mut self, handshake: EncryptHandshakeData) {
        // 服务器把邀请广播给房间全体成员，inviter_id 等于自己即为自身请求的回声
        if Some(&handshake.peer_id) == self.current_user_id.as_ref() {
            debug_log("invitation 早退：自身回声");
            return;
        }
        // 对端有效邀请到达时，本端处于等待接受的旧会话说明双方同时发起（角色反转），
        // 丢弃旧会话改走接受方流程；已激活或正在协商则忽略重复邀请
        if let Some(existing) = self.crypto.sessions.get(&handshake.room_id) {
            if existing.phase != EncryptionPhase::AwaitingAcceptance {
                debug_log("invitation 早退：已有非等待接受会话");
                return;
            }
            debug_log("invitation 角色反转：丢弃旧会话改走接受方");
            self.crypto.sessions.remove(&handshake.room_id);
        }
        if !crypto::verify_handshake_signature(
            &handshake.identity_key,
            &handshake.public_key,
            &handshake.signature,
        ) {
            debug_log("invitation 早退：签名校验失败");
            self.push_error(self.t("error_invitation_signature_invalid"));
            return;
        }
        // 协商共享密钥：己方新临时私钥 × 对端临时公钥
        let ephemeral_secret = crypto::generate_ephemeral_secret();
        let own_public_key = crypto::encode_x25519_public(&ephemeral_secret);
        let shared_key = match crypto::derive_shared_key(ephemeral_secret, &handshake.public_key) {
            Ok(key) => key,
            Err(e) => {
                self.push_error(format!(
                    "{}: {e}",
                    self.t("notification_encryption_failed_key")
                ));
                return;
            }
        };
        // 签名对象为己方临时公钥（服务端文档约定）
        let signature = match crypto::sign_public_key(&self.crypto.identity_key, &own_public_key) {
            Ok(signature) => signature,
            Err(e) => {
                self.push_error(format!(
                    "{}: {e}",
                    self.t("notification_encryption_failed_signature")
                ));
                return;
            }
        };
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptAccept {
                room_id: &handshake.room_id,
                public_key: &own_public_key,
                identity_key: &identity_key,
                signature: &signature,
            },
        ));
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptReady {
                room_id: &handshake.room_id,
            },
        ));
        self.crypto.sessions.insert(
            handshake.room_id.clone(),
            EncryptionSession {
                phase: EncryptionPhase::AwaitingSessionReady,
                ephemeral_secret: None,
                own_public_key,
                shared_key: Some(shared_key),
                pending_content: None,
                initiated_at: Instant::now(),
            },
        );
        self.push_notification(self.t("notification_session_accepted"));
    }

    /// 处理对端接受回应：校验签名、完成密钥协商并发送就绪
    fn handle_encrypt_accepted(&mut self, handshake: EncryptHandshakeData) {
        // acceptor_id 等于自己即为自身 accept 的广播回声
        if Some(&handshake.peer_id) == self.current_user_id.as_ref() {
            return;
        }
        let session_exists = self
            .crypto
            .sessions
            .get(&handshake.room_id)
            .is_some_and(|session| session.phase == EncryptionPhase::AwaitingAcceptance);
        if !session_exists {
            return;
        }
        if !crypto::verify_handshake_signature(
            &handshake.identity_key,
            &handshake.public_key,
            &handshake.signature,
        ) {
            self.crypto.sessions.remove(&handshake.room_id);
            self.push_error(self.t("notification_accept_failed_signature"));
            return;
        }
        let shared_key = {
            let session = self
                .crypto
                .sessions
                .get_mut(&handshake.room_id)
                .expect("会话存在性已在上方校验");
            let ephemeral_secret = session
                .ephemeral_secret
                .take()
                .expect("等待接受阶段的会话必然持有临时私钥");
            match crypto::derive_shared_key(ephemeral_secret, &handshake.public_key) {
                Ok(key) => key,
                Err(e) => {
                    self.push_error(format!(
                        "{}: {e}",
                        self.t("notification_encryption_failed_key")
                    ));
                    return;
                }
            }
        };
        let session = self
            .crypto
            .sessions
            .get_mut(&handshake.room_id)
            .expect("会话存在性已在上方校验");
        session.shared_key = Some(shared_key);
        session.phase = EncryptionPhase::AwaitingSessionReady;
        session.initiated_at = Instant::now();
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptReady {
                room_id: &handshake.room_id,
            },
        ));
    }

    /// 处理收到的加密消息：解密后按当前选中房间与消息 id 去重显示
    fn handle_encrypted_message(&mut self, info: EncryptedMessageInfo) {
        let selected_room_id = self.selected_room_id();
        let is_selected = selected_room_id.as_deref() == Some(info.room_id.as_str());
        let is_own = self
            .current_user_id
            .as_ref()
            .map(|uid| *uid == info.sender_id)
            .unwrap_or(false);
        let shared_key = self
            .crypto
            .sessions
            .get(&info.room_id)
            .and_then(|session| session.shared_key);
        // 能解密则取明文用于通知预览，不能解密也不影响未读统计
        let plaintext =
            shared_key.and_then(|key| crypto::decrypt_message(&key, &info.ciphertext).ok());

        if !is_selected {
            // 私聊在别的房间也会漏通知的修复：非当前查看房间同样累加未读并发系统通知，
            // 该房间开启免打扰（或自己发出的回声）时抑制通知
            *self.unread_counts.entry(info.room_id.clone()).or_insert(0) += 1;
            if !is_own && !self.muted_room_ids.contains(&info.room_id) {
                let sender_name = self.sender_display_name(&info.sender_id);
                let preview = plaintext.unwrap_or_else(|| self.t("encrypted_mark"));
                self.send_system_notification(
                    &self.t("notification_new_message"),
                    &format!("{}: {}", sender_name, preview),
                );
            }
            return;
        }

        // 当前查看房间：解密后追加显示
        match plaintext {
            Some(plaintext) => {
                if !self.messages.iter().any(|existing| existing.id == info.id) {
                    // 加密房间不落盘，这里只标脏也无害：落盘前还会按房间加密标志再挡一次
                    self.mark_messages_dirty();
                    self.messages.push(MessageInfo {
                        id: info.id,
                        room_id: info.room_id,
                        sender_id: info.sender_id,
                        content: self
                            .t("notification_encrypted_prefix")
                            .replace("{text}", &plaintext)
                            .to_string(),
                        created_at: info.created_at,
                    });
                }
            }
            None => {
                if shared_key.is_none() {
                    self.push_error(self.t("notification_decrypt_failed_no_key"));
                } else {
                    self.push_error(self.t("notification_decrypt_failed"));
                }
            }
        }
    }

    /// 会话激活后发送一条排队中的明文消息（加密后发出）；返回是否确有消息被发送
    fn flush_pending_encrypted_message(&mut self, room_id: &str) -> bool {
        let payload = {
            let session = match self.crypto.sessions.get_mut(room_id) {
                Some(session) if session.phase == EncryptionPhase::Active => session,
                _ => return false,
            };
            let content = match session.pending_content.take() {
                Some(content) => content,
                None => return false,
            };
            let shared_key = match session.shared_key {
                Some(key) => key,
                None => return false,
            };
            match crypto::encrypt_message(&shared_key, &content) {
                Ok(ciphertext) => outbound_ws_payload(
                    self.connector.version(),
                    WsCommand::EncryptMessage {
                        room_id,
                        ciphertext: &ciphertext,
                    },
                ),
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_encrypt_message_failed")));
                    return false;
                }
            }
        };
        self.send_ws_payload(payload);
        true
    }

    /// 发起加密会话握手；带待发内容时会话就绪后自动发送
    fn initiate_encryption(&mut self, room_id: &str, pending_content: Option<String>) {
        let ephemeral_secret = crypto::generate_ephemeral_secret();
        let public_key = crypto::encode_x25519_public(&ephemeral_secret);
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        let signature = match crypto::sign_public_key(&self.crypto.identity_key, &public_key) {
            Ok(signature) => signature,
            Err(e) => {
                self.push_error(format!(
                    "{}: {e}",
                    self.t("notification_encryption_failed_signature")
                ));
                return;
            }
        };
        debug_log(&format!(
            "initiate room={room_id} public_key前8={}",
            &public_key[..8.min(public_key.len())]
        ));
        self.send_encrypt_request(room_id, &public_key, &identity_key, &signature);
        self.crypto.sessions.insert(
            room_id.to_string(),
            EncryptionSession {
                phase: EncryptionPhase::AwaitingAcceptance,
                ephemeral_secret: Some(ephemeral_secret),
                own_public_key: public_key,
                shared_key: None,
                pending_content,
                initiated_at: Instant::now(),
            },
        );
    }

    /// 发送加密握手邀请报文
    fn send_encrypt_request(
        &mut self,
        room_id: &str,
        public_key: &str,
        identity_key: &str,
        signature: &str,
    ) {
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptRequest {
                room_id,
                public_key,
                identity_key,
                signature,
            },
        ));
    }

    /// 以会话中既有的密钥材料原样重发握手报文：
    /// 等待接受则重发邀请（同一公钥），等待就绪则重发 ready（服务器幂等）
    fn resend_handshake_if_needed(&mut self, room_id: &str) {
        let payload = {
            let session = match self.crypto.sessions.get_mut(room_id) {
                Some(session) if session.phase != EncryptionPhase::Active => session,
                _ => return,
            };
            match session.phase {
                EncryptionPhase::AwaitingAcceptance => {
                    let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
                    // 签名对象仍是同一份临时公钥，保证对端无论响应哪一次邀请都能协商一致
                    let signature = match crypto::sign_public_key(
                        &self.crypto.identity_key,
                        &session.own_public_key,
                    ) {
                        Ok(signature) => signature,
                        Err(_) => return,
                    };
                    session.initiated_at = Instant::now();
                    outbound_ws_payload(
                        self.connector.version(),
                        WsCommand::EncryptRequest {
                            room_id,
                            public_key: &session.own_public_key,
                            identity_key: &identity_key,
                            signature: &signature,
                        },
                    )
                }
                EncryptionPhase::AwaitingSessionReady => {
                    session.initiated_at = Instant::now();
                    outbound_ws_payload(
                        self.connector.version(),
                        WsCommand::EncryptReady { room_id },
                    )
                }
                EncryptionPhase::Active => return,
            }
        };
        self.send_ws_payload(payload);
    }

    /// 主循环周期调用：1) WebSocket 连接超过 60 秒时定期重建刷新房间订阅；
    /// 2) 未激活握手超时重发；3) 清理超出衰减窗口的输入状态记录
    pub fn handle_tick(&mut self) {
        // 服务端订阅快照机制：subscribe_to_room 仅在连接建立时执行一次，
        // 此后新加入的房间无法动态添加。定期重连确保订阅始终最新。
        // 定期重建 WebSocket 以刷新房间订阅的间隔，由接缝按当前服务端版本给出
        let version = self.connector.version();
        if self.websocket_token.is_some()
            && self.websocket_connected_at.elapsed() >= version.subscription_refresh_interval()
        {
            debug_log("tick 触发定期 WebSocket 重连刷新房间订阅");
            self.restart_websocket_thread();
            self.websocket_connected_at = Instant::now();
        }

        let resend_interval = version.handshake_resend_interval();
        let stale_room_ids: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.phase != EncryptionPhase::Active
                    && session.initiated_at.elapsed() >= resend_interval
            })
            .map(|(room_id, _)| room_id.clone())
            .collect();
        for room_id in stale_room_ids {
            debug_log(&format!("tick 触发重发 room={room_id}"));
            self.resend_handshake_if_needed(&room_id);
        }

        // 攒够批量窗口的消息变更一次性落盘（消息逐条到达时只置脏标记）
        self.flush_pending_message_cache();

        // 服务端不广播"停止输入"，超时即视为已停止：定期摘掉过期记录，防止列表无限增长
        let display_window = version.typing_display_window();
        self.typing_members
            .retain(|(_, _, seen_at)| seen_at.elapsed() < display_window);
    }

    /// 消息输入框内容发生变化的统一入口（普通按键、Ctrl+J、Ctrl+U、粘贴四处都经这里）：
    /// 上报输入状态，并让与当前输入不符的旧搜索结果立即失效。
    /// 快速搜索模式下随输入就地重扫已加载消息；普通搜索模式下关键词一改（含用退格删掉一段、
    /// 或删掉井号前缀退出搜索模式），上次结果就不再成立，匹配列表、当前序号与定位一起清掉，
    /// 标题随即回到"未执行搜索"，上下键也不再跳转旧结果。
    fn handle_message_input_changed(&mut self) {
        self.notify_typing_if_needed();
        // 打出 "/profile " 这一刻把服务端全部用户捞回来，补全面板随后几帧就有内容
        if self
            .input_collector
            .message_input_state
            .text()
            .starts_with("/profile ")
        {
            self.ensure_registered_users_loaded();
        }
        if !self.in_search_mode() {
            self.search_result = None;
            self.pending_scroll_message_id = None;
            return;
        }
        if self.quick_search {
            self.apply_quick_search();
        } else if self.active_search_keyword().is_none() {
            self.search_result = None;
            self.pending_scroll_message_id = None;
        }
    }

    /// 输入框文本变化后上报输入状态（增删均算，符合"2 秒内视作处于打字状态"的判定）。
    /// 只在已登录、WebSocket 就绪、选中了房间、输入的是普通文本（非指令/搜索模式）时发送，
    /// 并按接缝给出的间隔节流——服务端入站限流为 30 条/30 秒，逐字符上报会立即打满配额。
    fn notify_typing_if_needed(&mut self) {
        if !self.is_logged_in() || self.websocket_sender.is_none() {
            return;
        }
        let Some(room_id) = self.selected_room_id() else {
            return;
        };
        let typed = self.input_collector.message_input_state.text();
        if typed.is_empty() || typed.starts_with('/') || typed.starts_with('#') {
            return;
        }
        if let Some(sent_at) = self.last_typing_frame_sent_at
            && sent_at.elapsed() < self.connector.version().typing_send_interval()
        {
            return;
        }
        let version = self.connector.version();
        self.last_typing_frame_sent_at = Some(Instant::now());
        self.send_ws_payload(outbound_ws_payload(
            version,
            WsCommand::SendTyping {
                room_id: room_id.as_str(),
            },
        ));
    }

    /// 通过 WebSocket 命令通道发送一条完整的 WS JSON 载荷
    fn send_ws_payload(&self, payload: serde_json::Value) {
        if let Some(sender) = &self.websocket_sender {
            let _ = sender.send(payload.to_string());
        }
    }

    /// 追加一条信息类通知（标题"提示"、蓝色边框），存活时长按文本长度计算（基础 3 秒，每 20 个字符加 1 秒）
    fn push_notification(&mut self, message: String) {
        let lifetime = Duration::from_secs(3 + (message.chars().count() / 20) as u64);
        // 新通知排在已有通知下方，把整列向下挤压
        self.notifications
            .push((message, false, Instant::now() + lifetime));
    }

    /// 追加一条错误类通知（客户端校验或接口报错，标题"错误"、红色边框）
    fn push_error(&mut self, message: String) {
        let lifetime = Duration::from_secs(3 + (message.chars().count() / 20) as u64);
        self.notifications
            .push((message, true, Instant::now() + lifetime));
    }

    /// 移除已超过过期时刻的通知
    fn remove_expired_notifications(&mut self) {
        let now = Instant::now();
        self.notifications
            .retain(|(_, _, deadline)| *deadline > now);
    }
}

impl App {
    /// 从 config/languages/{lang}.json 加载语言字符串到 language_strings
    pub fn load_language(&mut self, lang: &str) {
        let path = paths::config_path(&format!("languages/{lang}.json"));
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<HashMap<String, String>>(&content) {
                Ok(map) => {
                    self.language_strings = map;
                }
                Err(_) => {
                    self.push_error(format!(
                        "{path}: {message}",
                        path = path.display(),
                        message = self.t("error_lang_file_format"),
                    ));
                }
            },
            Err(_) => {
                self.push_error(format!(
                    "{path}: {message}",
                    path = path.display(),
                    message = self.t("error_lang_file_read"),
                ));
            }
        }
    }

    /// 根据语言键名从 language_strings 中查找对应的本地化文本，未找到时返回键名本身
    pub fn t(&self, key: &str) -> String {
        self.language_strings
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }
    /// 返回 config/languages/ 下所有可用的语言代码（去 .json 后缀）
    fn get_available_languages() -> Vec<String> {
        let dir = paths::config_directory().join("languages");
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|s| s.to_string())
            })
            .collect()
    }

    /// 获取当前语言代码（从 preferences.json 读取）
    pub fn current_language() -> String {
        let prefs_path = paths::readable_config_path("preferences.json");
        fs::read_to_string(&prefs_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|v| v.get("language")?.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "zh-CN".to_string())
    }

    /// 保存语言设置到 preferences.json
    fn save_language_preference(lang: &str) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let content = fs::read_to_string(&prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["language"] = serde_json::json!(lang);
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// 从 preferences.json 读取显示偏好（show_uid / time_with_date / server_address / sound_enabled /
    /// appearance / read_state_manual），读不到时保持默认
    pub fn load_display_preferences(&mut self) {
        let prefs_path = paths::readable_config_path("preferences.json");
        if let Some(v) = fs::read_to_string(&prefs_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        {
            self.show_uid = v
                .get("show_uid")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            self.time_with_date = v
                .get("time_with_date")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            self.sound_enabled = v
                .get("sound_enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            self.quick_search = v
                .get("quick_search")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if let Some(addr) = v.get("server_address").and_then(serde_json::Value::as_str)
                && !addr.is_empty()
            {
                self.connector.set_base_url(addr);
            }
            // 读取开启免打扰的房间 ID 列表
            self.muted_room_ids = v
                .get("muted_rooms")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            // 读取外观名称并加载主题（未配置时沿用内置配色，不打扰用户）
            if let Some(name) = v.get("appearance").and_then(serde_json::Value::as_str)
                && !name.is_empty()
            {
                self.apply_appearance(name);
            }
        }
    }

    /// 应用名为 name 的外观主题：加载 config/themes/{name}.json 并把结果写入 self.appearance。
    /// 主题缺字段或多字段时按 TODO 约定明确标记（缺字段只报"不完整"、不列举具体项，多字段列出名称），
    /// 缺项槽位由内置默认色兜底，保证界面永不出现无配色可用的情况。
    fn apply_appearance(&mut self, name: &str) {
        let (appearance, has_missing_field, extra_fields) = Appearance::load(name);
        self.appearance = appearance;
        self.appearance_name = name.to_string();
        if has_missing_field {
            self.push_error(
                self.t("appearance_missing_fields")
                    .replace("{name}", name)
                    .to_string(),
            );
        }
        if !extra_fields.is_empty() {
            self.push_error(
                self.t("appearance_extra_fields")
                    .replace("{name}", name)
                    .replace("{fields}", &extra_fields.join(", "))
                    .to_string(),
            );
        }
    }

    /// 用户主动切换外观的统一入口：应用主题、写回 preferences.json、给出结果提示。
    /// 设置页浮层与 /appearance 命令共用，保证两条路径行为一致。
    fn switch_appearance(&mut self, name: &str) {
        self.apply_appearance(name);
        self.save_appearance_preference();
        self.push_notification(
            self.t("appearance_switched")
                .replace("{name}", name)
                .to_string(),
        );
    }

    /// 将外观名称写入 preferences.json（配置项，与显示偏好同一文件同一写法）
    fn save_appearance_preference(&self) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["appearance"] = serde_json::json!(self.appearance_name);
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// 将全部界面显示偏好写入 preferences.json（新增显示类开关只改这一处即可）
    fn save_display_preferences(&self) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["show_uid"] = serde_json::json!(self.show_uid);
        prefs["time_with_date"] = serde_json::json!(self.time_with_date);
        prefs["sound_enabled"] = serde_json::json!(self.sound_enabled);
        prefs["quick_search"] = serde_json::json!(self.quick_search);
        prefs["muted_rooms"] =
            serde_json::json!(self.muted_room_ids.iter().cloned().collect::<Vec<String>>());
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// 将自定义服务器地址写入 preferences.json
    fn save_server_address(&self) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["server_address"] = serde_json::json!(self.connector.base_url());
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// 发送系统通知（如果已启用）
    fn send_system_notification(&self, title: &str, body: &str) {
        if !self.sound_enabled {
            debug_log("系统通知已禁用 (sound_enabled=false)");
            return;
        }
        debug_log(&format!("发送系统通知: title={}, body={}", title, body));

        // 在后台线程播放提示音，避免阻塞主线程
        let sound_enabled = self.sound_enabled;
        std::thread::spawn(move || {
            if !sound_enabled {
                return;
            }
            // 在 macOS 上使用 afplay 播放系统声音
            #[cfg(target_os = "macos")]
            {
                // 使用最可靠的系统提示音文件
                const SOUND_FILE: &str = "/System/Library/Sounds/Ping.aiff";
                match std::process::Command::new("afplay")
                    .arg(SOUND_FILE)
                    .status()
                {
                    Ok(status) => {
                        if status.success() {
                            debug_log(&format!("afplay 播放成功: {}", SOUND_FILE));
                        } else {
                            debug_log(&format!("afplay 退出码非零: {:?}", status));
                            // 回退到 terminal bell
                            let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\x07");
                            let _ = std::io::Write::flush(&mut std::io::stderr());
                        }
                    }
                    Err(e) => {
                        debug_log(&format!("afplay 启动失败: {:?}，回退到 terminal bell", e));
                        let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\x07");
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                    }
                }
            }
            // 在其他系统上尝试使用 terminal bell
            #[cfg(not(target_os = "macos"))]
            {
                if let Err(e) = std::io::Write::write_all(&mut std::io::stderr(), b"\x07") {
                    debug_log(&format!("terminal bell 写入失败: {e}"));
                }
                if let Err(e) = std::io::Write::flush(&mut std::io::stderr()) {
                    debug_log(&format!("terminal bell 刷新失败: {e}"));
                }
            }
        });

        // 异步发送桌面通知：macOS 用 osascript（notify-rust 在终端 TUI 下常不可用），
        // 其余平台仍用 notify-rust。
        let title = title.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            #[cfg(target_os = "macos")]
            {
                let escape = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
                let script = format!(
                    "display notification \"{}\" with title \"{}\"",
                    escape(&body),
                    escape(&title)
                );
                match std::process::Command::new("osascript")
                    .arg("-e")
                    .arg(&script)
                    .status()
                {
                    Ok(status) if status.success() => debug_log("osascript 桌面通知已发送"),
                    Ok(status) => debug_log(&format!("osascript 通知失败，退出码 {:?}", status)),
                    Err(e) => debug_log(&format!("osascript 启动失败: {e}")),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                if let Err(e) = notify_rust::Notification::new()
                    .summary(&title)
                    .body(&body)
                    .appname("Baihua Client")
                    .show()
                {
                    debug_log(&format!("桌面通知发送失败: {e}"));
                }
            }
        });
    }

    /// 将登录会话（JWT 与企业用户 ID）写入 preferences.json，供下次启动自动登录。
    /// 令牌经静态加密后落盘，不保存明文密码或用户名。
    fn save_session_preferences(token: &str, user_id: &str, contact: Option<&(String, String)>) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["token"] = serde_json::json!(crypto::encrypt_at_rest(token));
        prefs["user_id"] = serde_json::json!(user_id);
        match contact {
            Some((email, phone_number)) => {
                prefs["email"] = serde_json::json!(crypto::encrypt_at_rest(email));
                prefs["phone_number"] = serde_json::json!(crypto::encrypt_at_rest(phone_number));
            }
            None => {
                if let Some(map) = prefs.as_object_mut() {
                    map.remove("email");
                    map.remove("phone_number");
                }
            }
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// 读取上次退出时存下的邮箱与手机号（服务端没有"查自己的联系方式"接口，
    /// 自动登录路径拿不到登录响应，只能靠本地会话记录还原资料卡这两行）。
    fn load_saved_contact() -> Option<(String, String)> {
        let content = fs::read_to_string(paths::config_path("preferences.json")).ok()?;
        let prefs: serde_json::Value = serde_json::from_str(&content).ok()?;
        let email = crypto::decrypt_at_rest(prefs.get("email")?.as_str()?)?;
        let phone_number = crypto::decrypt_at_rest(prefs.get("phone_number")?.as_str()?)?;
        Some((email, phone_number))
    }

    /// 读取已保存的登录会话；令牌先解密，凭证缺失或解密失败时返回 None
    fn load_saved_session() -> Option<(String, String)> {
        let prefs_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&prefs_path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&content).ok()?;
        let token = crypto::decrypt_at_rest(v.get("token")?.as_str()?)?;
        let user_id = v.get("user_id")?.as_str()?;
        Some((token, user_id.to_string()))
    }

    /// 清除已保存的登录会话（token 失效或不再需要自动登录时调用）
    fn clear_saved_session() {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        if let Some(map) = prefs.as_object_mut() {
            map.remove("token");
            map.remove("user_id");
            map.remove("email");
            map.remove("phone_number");
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// 尝试用保存的会话自动登录：token 有效则进入聊天页并后台线程就绪，
    /// 失效则清除会话并停留在登录页。返回是否成功自动登录。
    pub fn try_auto_login(&mut self) -> bool {
        let Some((token, user_id)) = Self::load_saved_session() else {
            // 无有效会话（可能遗留明文/损坏令牌）：清理陈旧会话字段
            Self::clear_saved_session();
            return false;
        };
        debug_log(&format!(
            "=== JWT AUTO-LOGIN START: token前8={} ===",
            &token[..8.min(token.len())]
        ));
        self.connector.set_token(&token);
        if self.connector.list_rooms().is_err() {
            debug_log("JWT AUTO-LOGIN: list_rooms 失败，清除会话");
            Self::clear_saved_session();
            return false;
        }
        self.update_connection_state(true);
        debug_log("JWT AUTO-LOGIN: list_rooms 成功，设置用户状态");
        // 自动登录同样立即探测服务端版本（token 已 set），令后续线上决策匹配真实版本
        self.detect_and_apply_api_version();
        self.current_user_id = Some(user_id.clone());
        // 自动登录没有登录响应，联系方式用上次退出时存下的那份
        self.own_contact = Self::load_saved_contact();
        // 服务端不会给自己广播 user_online，本端在线状态需自行登记
        self.presence_by_user.insert(user_id, true);
        self.focus_index = 0;
        // 与普通登录保持完全一致的流程：先加载房间列表，再启动后台线程
        self.load_rooms();
        self.start_polling_thread();
        self.start_websocket_thread(&token, None);
        self.prepare_session_state(None);
        self.push_notification(self.t("auto_login_notification"));
        debug_log("=== JWT AUTO-LOGIN COMPLETE ===");
        true
    }
}

/// 内置聊天命令表，元素为 (命令名, 描述的语言键名)。
/// 扩展新命令时在此追加条目，并在 App::execute_chat_command 中增加对应执行分支即可。
pub(crate) fn chat_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("quit", "command_quit"),
        ("exit", "command_quit"),
        ("quit_group", "command_quit_group"),
        ("kick", "command_kick"),
        ("info", "command_info"),
        ("list_users", "command_list_users"),
        ("search_users", "command_search_users"),
        ("profile", "command_profile"),
        ("language", "command_language"),
        ("appearance", "command_appearance"),
        ("update", "command_update"),
        ("logout", "command_logout"),
        ("server_address", "command_server_address"),
        ("add_member", "command_add_member"),
        ("mute", "command_mute"),
        ("login", "command_login"),
        ("register", "command_register"),
    ]
}

/// 按已输入的命令前缀过滤出可补全的命令表条目
fn command_completions(prefix: &str) -> Vec<(&'static str, &'static str)> {
    chat_commands()
        .into_iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .collect()
}

/// 判断群成员角色是否为群管理员或群主（服务端角色字符串不区分大小写）
fn is_admin_role(role: &str) -> bool {
    let lowered = role.to_lowercase();
    lowered == "owner" || lowered == "admin"
}

/// 过滤不可见的房间：本地已关闭的加密私聊，以及成员不足两人的残留私聊空壳
fn filter_visible_rooms(rooms: Vec<RoomInfo>, closed_room_ids: &HashSet<String>) -> Vec<RoomInfo> {
    rooms
        .into_iter()
        .filter(|room| {
            !closed_room_ids.contains(&room.id) && (room.is_group || room.members.len() >= 2)
        })
        .collect()
}

/// 估算字符串在终端中的显示宽度，CJK 与全角字符按两列计
fn display_width(text: &str) -> u16 {
    text.chars()
        .map(|character| {
            let code = character as u32;
            if (0x1100..=0x115F).contains(&code)
                || (0x2E80..=0xA4CF).contains(&code)
                || (0xAC00..=0xD7A3).contains(&code)
                || (0xF900..=0xFAFF).contains(&code)
                || (0xFE10..=0xFE19).contains(&code)
                || (0xFE30..=0xFE6F).contains(&code)
                || (0xFF00..=0xFF60).contains(&code)
                || (0xFFE0..=0xFFE6).contains(&code)
            {
                2
            } else {
                1
            }
        })
        .sum()
}

/// 两批消息按 ID 合并成一批：先到的（本地已有，可能是解密后的明文）优先保留，
/// 后到的只补新条目，最后按创建时间与服务端 ID 升序排列。
fn merge_messages_by_id(
    existing: Vec<MessageInfo>,
    incoming: Vec<MessageInfo>,
) -> Vec<MessageInfo> {
    let mut merged = existing;
    let mut seen: HashSet<String> = merged.iter().map(|message| message.id.clone()).collect();
    for message in incoming {
        if seen.insert(message.id.clone()) {
            merged.push(message);
        }
    }
    merged.sort_by(|left, right| (&left.created_at, &left.id).cmp(&(&right.created_at, &right.id)));
    merged
}

/// 叠加层统一窗口边框：四边框加左上角标题，边框色一律取外观的 overlay_border。
/// 所有浮层（表单、列表、卡片、输入框组）都从这里取窗口外观，
/// 换主题或调风格只动这一处，不会再出现某个浮层跟着消息区边框色走的情况。
fn overlay_frame_block(appearance: &Appearance, title: &str) -> Block<'static> {
    Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(appearance.overlay_border))
}

/// 无边框输入项：箭头行形态的表单用它，正文、光标、框选配色与方框输入框同源。
fn render_plain_field(
    appearance: &Appearance,
    frame: &mut Frame,
    area: Rect,
    secret: bool,
    state: &mut TextInputState,
) {
    let mut input = TextInput::new()
        .style(Style::default().fg(appearance.input_text))
        .block(Block::default())
        .cursor_style(Style::default().fg(appearance.own_username_text))
        .select_style(
            Style::default()
                .fg(contrasting_foreground(appearance.selection_background))
                .bg(appearance.selection_background),
        );
    if secret {
        input = input.passwd();
    }
    input.render(area, frame.buffer_mut(), state);
}

/// 统一"方框输入框"：标签写在边框标题上，正文、光标、框选配色全部取自外观。
/// 少于三个输入条目的浮层用它；三个及以上改用箭头行（见 render_form）。
/// 取自由函数形式是为了让调用方同时持有外观的不可变借用与输入状态的可变借用。
/// 边框色与标题样式都由调用方给出：登录/注册用聚焦态切换的选中色边框，表单浮层一律用
/// 未选中色边框（见 Appearance::form_field_border），当前项改由标题加粗指示，
/// 与箭头行形态的同类指示保持一致。
fn render_box_field(
    appearance: &Appearance,
    frame: &mut Frame,
    area: Rect,
    title: Line<'static>,
    border_color: Color,
    secret: bool,
    state: &mut TextInputState,
) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let mut input = TextInput::new()
        .style(Style::default().fg(appearance.input_text))
        .block(block)
        .cursor_style(Style::default().fg(appearance.own_username_text))
        .select_style(
            Style::default()
                .fg(contrasting_foreground(appearance.selection_background))
                .bg(appearance.selection_background),
        );
    if secret {
        input = input.passwd();
    }
    input.render(area, frame.buffer_mut(), state);
}

/// 提示类文本的统一样式（快捷键说明、顶栏标签、表单提示行都用它）
fn hint_style(color: Color) -> Style {
    Style::default().fg(color)
}

/// 把资料卡片里的 "标签: 值" 行按可用宽度折行，续行缩进到值的起始列。
/// 窄终端上 UID、邮箱、头像链接这类长单行因此是换行显示，而不是被面板右边界切掉。
fn wrap_profile_fields(body: Text<'static>, available_width: u16) -> Text<'static> {
    if available_width == 0 {
        return body;
    }
    let mut lines: Vec<Line<'static>> = Vec::new();
    for line in body.lines {
        let plain = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        if (line.width() as u16) <= available_width {
            lines.push(line);
            continue;
        }
        let style = line
            .spans
            .last()
            .map(|span| span.style)
            .unwrap_or_else(Style::default);
        let separator = match plain.find(": ") {
            Some(position) => position,
            // 没有"标签: "结构的行（如关闭提示）整行按宽度折，不做缩进对齐
            None => {
                for piece in wrap_by_display_width(&plain, available_width) {
                    lines.push(Line::from(Span::styled(piece, style)));
                }
                continue;
            }
        };
        // 按字节切片：": " 是两个 ASCII 字符，切点必然落在字符边界上；
        // 标签本身可能是多字节中文，所以不能用字符数去算切点
        let prefix = plain[..separator + 2].to_string();
        let value = plain[separator + 2..].to_string();
        let indent_columns = usize::from(display_width(&prefix));
        let value_width = available_width.saturating_sub(indent_columns as u16).max(1);
        for (index, piece) in wrap_by_display_width(&value, value_width)
            .into_iter()
            .enumerate()
        {
            let text = if index == 0 {
                format!("{prefix}{piece}")
            } else {
                format!("{}{piece}", " ".repeat(indent_columns))
            };
            lines.push(Line::from(Span::styled(text, style)));
        }
    }
    Text::from(lines)
}

/// 头像还没取回、或该用户根本没设头像时的占位：在头像块左上角画一个按用户 ID 稳定取色的首字符。
/// 占位与真图共用同一块区域，头像到位后只是把这块画满，文字位置不会跳动。
fn paint_avatar_placeholder(
    frame: &mut Frame,
    area: Rect,
    username: &str,
    appearance: &Appearance,
    user_id: &str,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            placeholder_initial(username),
            Style::default()
                .fg(placeholder_color(user_id))
                .add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(appearance.app_background)),
        Rect::new(area.x, area.y, 1, 1),
    );
}

/// 多行文本里最宽一行的显示宽度（整段文本的总宽度不能用来定面板宽，会把多行提示算虚高）
fn longest_line_width(text: &str) -> u16 {
    text.lines().map(display_width).max().unwrap_or(0)
}

/// 估算文本在给定内宽下会占多少渲染行：显式换行各算一行，每行再按显示宽度向上取整折行
fn estimated_wrapped_line_count(text: &str, inner_width: u16) -> u16 {
    if inner_width == 0 {
        return 1;
    }
    text.lines()
        .map(|line| display_width(line).div_ceil(inner_width).max(1))
        .sum::<u16>()
        .max(1)
}

/// 在给定区域内算出居中的面板矩形（各浮层共用，避免每处重复写偏移）
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

/// 收到的那条请求是否仍在等自己处理。服务端 `GET /requests/pending` 只回仍是 pending 的行
/// 且不返回状态字段，所以状态缺省即"仍在等"；本端处理过的条目会被就地写上结果状态。
/// 自己发出的那侧服务端总给状态，按字面 `== "pending"` 判即可，不共用这个函数。
fn received_request_is_pending(request: &RoomRequestInfo) -> bool {
    request
        .status
        .as_deref()
        .is_none_or(|status| status == "pending")
}

/// 列表类浮层（设置菜单、语言、外观、本地头像）的统一排版：
/// 面板宽度按"最宽一条 + 边框 + 高亮符号"定，但不超出可绘制区；
/// 返回 (面板矩形, 条目可用宽度)，条目宽度由调用方交给 `wrapped_list_item` 折行。
fn overlay_list_panel(labels: &[String], area: Rect) -> (Rect, u16) {
    let longest = labels
        .iter()
        .map(|label| display_width(label))
        .max()
        .unwrap_or(0);
    // 边框 2 列 + 高亮符号 2 列 + 左右各 1 列余量；面板本身按内容定宽，
    // 但既不留成一条窄缝也不铺满整屏，最后再让位给屏幕宽度
    let wanted_width = (longest + 6).clamp(30, 60);
    let width_ceiling = area.width.saturating_sub(2).max(12);
    let panel_width = if wanted_width > width_ceiling {
        width_ceiling
    } else {
        wanted_width
    };
    // 条目比"面板宽 − 边框 − 高亮符号"还长就折行，宁可多占一行也不在右边界切掉
    let body_width = panel_width.saturating_sub(6).max(1);
    let line_count: u16 = labels
        .iter()
        .map(|label| display_width(label).div_ceil(body_width).max(1))
        .sum();
    let wanted_height = line_count + 4;
    let height_ceiling = area.height.saturating_sub(2).max(5);
    let panel_height = if wanted_height > height_ceiling {
        height_ceiling
    } else {
        wanted_height
    };
    (centered_rect(panel_width, panel_height, area), body_width)
}

/// 补全面板一条候选的行集合：说明与命令名同排放得下就同排，放不下时说明另起一行，
/// 两截都按面板内宽折行。返回行数供调用方算面板高度。
fn completion_lines(
    label: &str,
    description: &str,
    label_style: Style,
    description_style: Style,
    body_width: u16,
) -> Vec<Line<'static>> {
    let same_row_fits = display_width(label) + display_width(description) + 2 <= body_width;
    let mut lines: Vec<Line> = wrap_preserving_words(label, body_width)
        .into_iter()
        .map(|piece| Line::from(Span::styled(piece, label_style)))
        .collect();
    if description.is_empty() {
        return lines;
    }
    if same_row_fits {
        if let Some(first) = lines.first_mut() {
            first.push_span(Span::styled(format!("  {description}"), description_style));
        }
        return lines;
    }
    lines.extend(
        wrap_preserving_words(description, body_width.saturating_sub(2).max(1))
            .into_iter()
            .map(|piece| Line::from(Span::styled(format!("  {piece}"), description_style))),
    );
    lines
}

/// 把一段提示文本按可用宽度折成带样式的 Text。折点由本函数定死、渲染时不再让
/// Paragraph 自己折，"预留几行"与"实际占几行"才必然一致（交给 Paragraph 按词边界折行时，
/// 中英混排会比估算值多占一行，面板正好把尾行裁掉）。
/// 行内优先在空格处断开，英文句子不会被从单词中间切开；纯中文按字折。
fn wrapped_hint_text(hint: &str, style: Style, available_width: u16) -> Text<'static> {
    Text::from(
        wrap_preserving_words(hint, available_width)
            .into_iter()
            .map(|piece| Line::from(Span::styled(piece, style)))
            .collect::<Vec<Line>>(),
    )
}

/// 按显示宽度折行，尽量在空格处断行：先按字塞满一行，再回退到本行最后一个空格。
/// 找不到空格（中文整句、或单个超长词）就照字面宽度硬断，保证永不死循环。
fn wrap_preserving_words(text: &str, limit: u16) -> Vec<String> {
    let limit = limit.max(1) as usize;
    let mut lines: Vec<String> = Vec::new();
    for paragraph in text.lines() {
        let characters: Vec<char> = paragraph.chars().collect();
        let mut start = 0usize;
        while start < characters.len() {
            let mut end = start;
            let mut width = 0usize;
            let mut last_space: Option<usize> = None;
            while end < characters.len() {
                let character_width =
                    usize::from(display_width(&characters[end].to_string()).max(1));
                if width + character_width > limit && end > start {
                    break;
                }
                if characters[end] == ' ' {
                    last_space = Some(end);
                }
                width += character_width;
                end += 1;
            }
            let break_at = if end < characters.len() {
                last_space.unwrap_or(end)
            } else {
                end
            };
            let piece: String = characters[start..break_at].iter().collect();
            lines.push(piece.trim_end().to_string());
            start = if break_at > start { break_at } else { end };
            // 断在空格上时把空格本身跳掉，下一行不会以空格开头
            while start < characters.len() && characters[start] == ' ' {
                start += 1;
            }
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// 一条列表文案折成 ListItem：续行补两个空格，与高亮符号 "> " 的宽度对齐，
/// 选中与未选中的正文因此都在同一列上开始。
fn wrapped_list_item(label: &str, style: Style, body_width: u16) -> ListItem<'static> {
    ListItem::new(
        wrap_preserving_words(label, body_width)
            .into_iter()
            .enumerate()
            .map(|(index, piece)| {
                let text = if index == 0 {
                    piece
                } else {
                    format!("  {piece}")
                };
                Line::from(Span::styled(text, style))
            })
            .collect::<Vec<Line>>(),
    )
}

/// 表单浮层底部提示所用文案键（写明服务端对该表单的限制，避免用户提交后才吃一个 400）
fn form_hint_key(action: &FormAction) -> String {
    match action {
        FormAction::UpdateProfile => "form_profile_hint".to_string(),
        FormAction::ChangePassword => "form_password_hint".to_string(),
        FormAction::ChangeAvatar => "form_avatar_hint".to_string(),
        FormAction::DeleteAccount => "form_delete_hint".to_string(),
    }
}

/// 设置菜单每一项回车后的动作。渲染与按键分派共用同一张条目表，
/// 菜单增删项时不必再去别处同步"第几项"的数字。
#[derive(Debug, Clone, PartialEq)]
enum SettingsAction {
    /// 打开既有浮层（创建群聊、创建私聊、私聊管理、语言、外观、服务器地址、登录、注册）
    OpenOverlay(DisplayingOverlay),
    /// 打开表单浮层（设置个人资料、修改密码、修改头像、注销账户）
    OpenForm(FormAction),
    /// 拨动"显示用户UID"
    ToggleShowUid,
    /// 拨动"时间显示含日期"
    ToggleTimeWithDate,
    /// 拨动"快速搜索"
    ToggleQuickSearch,
    /// 拨动"声音通知"
    ToggleSound,
    /// 立即用已下载并校验的更新包开始更新
    UpdateClient,
    /// 退出登录
    Logout,
}

impl SettingsAction {
    /// 该条目是否必须有登录态才有意义：改自己账号的四项表单、要带令牌的服务端操作
    /// （建房、发邀请、私聊请求管理）与退出登录都算。
    /// 未登录时选中它们只提示"未登录"，不切换浮层，避免进去之后才发现做不了。
    fn requires_login(&self) -> bool {
        match self {
            SettingsAction::OpenForm(_) | SettingsAction::Logout => true,
            SettingsAction::OpenOverlay(overlay) => matches!(
                overlay,
                DisplayingOverlay::CreateGroup
                    | DisplayingOverlay::CreatePrivate
                    | DisplayingOverlay::PendingRequests
                    | DisplayingOverlay::AvatarSelect
            ),
            SettingsAction::ToggleShowUid
            | SettingsAction::ToggleTimeWithDate
            | SettingsAction::ToggleQuickSearch
            | SettingsAction::ToggleSound
            | SettingsAction::UpdateClient => false,
        }
    }
}

/// 表单浮层标题与输入项定义：把四类表单的文案键集中一处，
/// 打开表单与渲染表单都从这里取，避免两处字典漂移。
fn form_definition(action: &FormAction) -> (String, Vec<(String, bool)>) {
    let (title_key, fields) = match action {
        FormAction::UpdateProfile => (
            "option_edit_profile",
            vec![
                ("profile_nickname_label".to_string(), false),
                ("profile_phone_label".to_string(), false),
                ("profile_bio_label".to_string(), false),
            ],
        ),
        FormAction::ChangePassword => (
            "option_change_password",
            vec![
                ("password_old_label".to_string(), true),
                ("password_new_label".to_string(), true),
                ("password_confirm_label".to_string(), true),
            ],
        ),
        FormAction::ChangeAvatar => (
            "option_change_avatar",
            vec![("avatar_input_label".to_string(), false)],
        ),
        FormAction::DeleteAccount => (
            "option_delete_account",
            vec![("delete_account_password_label".to_string(), true)],
        ),
    };
    (title_key.to_string(), fields)
}

/// 按显示宽度折行；至少推进一个字符避免超宽单字符导致死循环
fn wrap_by_display_width(text: &str, limit: u16) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0u16;
    for character in text.chars() {
        let character_width = display_width(&character.to_string()).max(1);
        if current_width + character_width > limit && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(character);
        current_width += character_width;
    }
    lines.push(current);
    lines
}

/// 在文本中查找关键词出现的所有位置（不区分大小写），返回以字符为单位的 [起始, 结束) 区间列表。
/// 命中后跳过整段，不统计重叠匹配。逐字符小写化对齐原串下标，
/// 因此区间可直接用于切分含中日韩宽字符的原文，不会错位。
fn find_keyword_positions(text: &str, keyword: &str) -> Vec<(usize, usize)> {
    let haystack: Vec<char> = text
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect();
    let needle: Vec<char> = keyword
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect();
    let mut positions: Vec<(usize, usize)> = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return positions;
    }
    let mut start = 0usize;
    while start + needle.len() <= haystack.len() {
        if haystack[start..start + needle.len()] == needle[..] {
            positions.push((start, start + needle.len()));
            start += needle.len();
        } else {
            start += 1;
        }
    }
    positions
}

/// 把一行文本按关键词命中位置切成 (文本片段, 片段样式) 序列：
/// 命中片段套用搜索命中样式，其余套用正文样式；无命中时整行一个片段。
fn split_line_by_keyword(
    line: &str,
    keyword: &str,
    body_style: Style,
    match_style: Style,
) -> Vec<(String, Style)> {
    let characters: Vec<char> = line.chars().collect();
    let mut segments: Vec<(String, Style)> = Vec::new();
    let mut cursor = 0usize;
    for (start, end) in find_keyword_positions(line, keyword) {
        if start > cursor {
            let plain: String = characters[cursor..start].iter().collect();
            segments.push((plain, body_style));
        }
        let matched: String = characters[start..end].iter().collect();
        segments.push((matched, match_style));
        cursor = end;
    }
    if cursor < characters.len() {
        let tail: String = characters[cursor..].iter().collect();
        segments.push((tail, body_style));
    }
    if segments.is_empty() {
        segments.push((String::new(), body_style));
    }
    segments
}

/// 按显示宽度折行一组带样式片段，返回可直接渲染的行序列。
/// 实现方式：把片段摊平成 (字符, 样式) 流后逐字累积，同一行内连续同样式字符合成一个 Span；
/// 折行落在高亮区间内部时该区间会被自然切断并在新行续接，高亮不会丢失。
fn wrap_styled_segments(segments: &[(String, Style)], limit: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let mut spans: Vec<Span> = Vec::new();
    let mut run = String::new();
    let mut run_style: Option<Style> = None;
    let mut width = 0u16;
    for (character, style) in segments
        .iter()
        .flat_map(|(text, style)| text.chars().map(move |character| (character, *style)))
    {
        let character_width = display_width(&character.to_string()).max(1);
        let need_new_line = width + character_width > limit && width > 0;
        // 样式切换或本行宽度不足时先收尾：把攒下的同样式文本落成 Span，必要时结束当前行
        if run_style != Some(style) || need_new_line {
            if let Some(closed_style) = run_style.take() {
                spans.push(Span::styled(std::mem::take(&mut run), closed_style));
            }
            if need_new_line {
                lines.push(Line::from(std::mem::take(&mut spans)));
                width = 0;
            }
        }
        if run_style.is_none() {
            run_style = Some(style);
        }
        run.push(character);
        width += character_width;
    }
    if let Some(closed_style) = run_style.take() {
        spans.push(Span::styled(std::mem::take(&mut run), closed_style));
    }
    if !spans.is_empty() {
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines
}

/// 按显示宽度从行文本里切出 [起始列, 结束列) 区间：与区间有任何重叠的双宽字符都整块纳入，
/// 因此框选永远不会只复制到一个汉字的半个格子上，也不会因为起点落在字中间而丢字。
fn slice_columns_by_display_width(row_text: &str, start_column: u16, end_column: u16) -> String {
    let mut text = String::new();
    let mut column = 0u16;
    for character in row_text.chars() {
        let character_width = display_width(&character.to_string()).max(1);
        if column >= end_column {
            break;
        }
        if column + character_width > start_column {
            text.push(character);
        }
        column += character_width;
    }
    text
}

/// 将服务器下发的 RFC3339 UTC 时间戳格式化为本地时间显示字符串。
/// with_date 为 true 时带日期（MM-DD HH:MM），否则仅显示时间（HH:MM）。
/// 解析失败时返回 None（不渲染时间头）。
fn format_message_time(created_at: &str, with_date: bool) -> Option<String> {
    let local = DateTime::parse_from_rfc3339(created_at)
        .ok()?
        .with_timezone(&Local);
    let text = if with_date {
        local.format("%m-%d %H:%M").to_string()
    } else {
        local.format("%H:%M").to_string()
    };
    Some(text)
}

impl App {
    fn max_focus_index(&self) -> usize {
        if matches!(self.displaying_overlay, DisplayingOverlay::Form) {
            // 表单浮层的可聚焦项数由字段数量决定
            self.active_form
                .as_ref()
                .map(|(_, fields)| fields.len().saturating_sub(1))
                .unwrap_or(0)
        } else if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup)
            || matches!(self.displaying_overlay, DisplayingOverlay::Login)
        {
            1
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Register) {
            2
        } else {
            0
        }
    }

    fn get_focused_state(&mut self) -> Option<&mut TextInputState> {
        if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.create_group_name_state),
                1 => Some(&mut self.input_collector.create_group_members_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::CreatePrivate) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.create_private_username_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Login) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.login_name_state),
                1 => Some(&mut self.input_collector.login_password_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Register) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.register_name_state),
                1 => Some(&mut self.input_collector.register_email_state),
                2 => Some(&mut self.input_collector.register_password_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::ServerAddress) {
            Some(&mut self.input_collector.server_address_state)
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Form) {
            // 通用表单浮层：字段数量随表单种类而变，聚焦位置直接落在对应输入项上
            match &mut self.active_form {
                Some((_, fields)) => fields
                    .get_mut(self.focus_index)
                    .map(|field| &mut field.state),
                None => None,
            }
        } else if matches!(
            self.displaying_overlay,
            DisplayingOverlay::PendingRequests
                | DisplayingOverlay::SettingsMenu
                | DisplayingOverlay::ProfileCard
        ) {
            // 列表、菜单与只读卡片类弹窗不聚焦任何输入框
            None
        } else {
            // 聊天页无弹窗时聚焦多行消息输入框，经 dispatch_focused_input_event 单独处理
            None
        }
    }

    /// 将键盘/鼠标事件分发到当前聚焦的输入框：
    /// 聊天页无弹窗时转发到多行消息输入框，其余页面/弹窗转发到单行输入框
    fn dispatch_focused_input_event(&mut self, focus: bool, event: &Event) {
        if self.displaying_overlay == DisplayingOverlay::Nothing {
            let _ = text_area::handle_events(
                &mut self.input_collector.message_input_state,
                focus,
                event,
            );
        } else if let Some(state) = self.get_focused_state() {
            let _ = text_input::handle_events(state, focus, event);
        }
    }

    fn get_field_areas(&self, layout: &[Rect]) -> Vec<Rect> {
        if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup) {
            vec![]
        } else {
            vec![layout[8]]
        }
    }

    /// 探测并应用服务端 API 版本：登录成功、启动自动登录、切换服务器地址后调用。
    /// 探测失败不致命（沿用当前/默认版本）；版本未识别时提示用户核对兼容性。
    /// 探测结果决定 api 接缝内所有按版本 match 的线上行为（成功码、报文、事件名等）。
    fn detect_and_apply_api_version(&mut self) {
        match self.connector.probe_version() {
            Ok((version, raw)) => {
                debug_log(&format!("探测服务端版本: raw={raw} parsed={version:?}"));
                if version == ApiVersion::Unknown {
                    self.push_notification(format!("{}: {raw}", self.t("api_version_unknown")));
                }
            }
            Err(e) => {
                debug_log(&format!("版本探测失败(保留当前版本): {e}"));
            }
        }
    }

    /// 浮层登录提交：读取登录表单两个字段后执行登录。
    fn do_login(&mut self) {
        let username = self.input_collector.login_name_state.value.text().string();
        let password = self
            .input_collector
            .login_password_state
            .value
            .text()
            .string();
        self.perform_login(username, password);
    }

    /// 执行登录核心流程，供登录浮层与 `/login <用户名> <密码>` 命令共用。
    /// 密码经客户端确定性加密后传输；成功后启动轮询与 WebSocket 线程并关闭登录浮层。
    fn perform_login(&mut self, username: String, password: String) {
        if username.is_empty() || password.is_empty() {
            self.push_error(self.t("error_empty_credentials"));
            return;
        }
        let encrypted_password = crypto::encrypt_login_password(&password);
        let req = LoginRequest {
            username,
            password: encrypted_password,
        };
        match self.connector.login(req) {
            Ok(data) => {
                debug_log(&format!(
                    "=== LOGIN START: user={} token前8={} ===",
                    data.user.id,
                    &data.token[..8.min(data.token.len())]
                ));
                self.current_user_id = Some(data.user.id.clone());
                // 服务端不会给自己广播 user_online，本端在线状态需自行登记
                self.presence_by_user.insert(data.user.id.clone(), true);
                self.connector.set_token(&data.token);
                let logged_username = data.user.username.clone();
                // 登录后立即探测服务端版本，使后续所有线上决策匹配真实版本
                self.detect_and_apply_api_version();
                self.focus_index = 0;
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.load_rooms();
                self.start_polling_thread();
                self.start_websocket_thread(&data.token, None);
                self.prepare_session_state(Some(logged_username));
                // 登录响应里的完整用户对象是唯一能看到自己邮箱与手机号的地方，资料卡要用
                self.remember_own_profile(&data.user);
                // 清空表单，避免凭据残留在输入框
                self.input_collector.login_name_state = TextInputState::default();
                self.input_collector.login_password_state = TextInputState::default();
                self.push_notification(self.t("login_success"));
            }
            Err(e) => {
                self.push_error(format!("{e}"));
            }
        }
    }

    /// 浮层注册提交：读取注册表单三个字段后执行注册。
    fn do_register(&mut self) {
        let username = self
            .input_collector
            .register_name_state
            .value
            .text()
            .string();
        let email = self
            .input_collector
            .register_email_state
            .value
            .text()
            .string();
        let password = self
            .input_collector
            .register_password_state
            .value
            .text()
            .string();
        self.perform_register(username, email, password);
    }

    /// 执行注册核心流程，供注册浮层与 `/register <用户名> <密码> <邮箱>` 命令共用。
    /// 与登录使用同一确定性加密变换，成功后提示并（在浮层场景下）切换到登录浮层。
    fn perform_register(&mut self, username: String, email: String, password: String) {
        if username.is_empty() || email.is_empty() || password.is_empty() {
            self.push_error(self.t("error_empty_fields"));
            return;
        }
        let encrypted_password = crypto::encrypt_login_password(&password);
        let req = RegisterRequest {
            username,
            email,
            password: encrypted_password,
        };
        match self.connector.register(req) {
            Ok(_) => {
                self.input_collector.register_name_state = TextInputState::default();
                self.input_collector.register_email_state = TextInputState::default();
                self.input_collector.register_password_state = TextInputState::default();
                // 若从注册浮层发起，注册成功后引导用户进入登录浮层；命令直接注册则仅提示
                if self.displaying_overlay == DisplayingOverlay::Register {
                    self.displaying_overlay = DisplayingOverlay::Login;
                    self.focus_index = 0;
                }
                self.push_notification(self.t("register_success"));
            }
            Err(e) => {
                self.push_error(format!("{e}"));
            }
        }
    }

    /// 直接刷新房间列表（UI 操作或接受请求等绕过轮询的路径调用），与轮询事件共用快照逻辑。
    fn load_rooms(&mut self) {
        match self.connector.list_rooms() {
            Ok(rooms) => self.apply_room_snapshot(rooms),
            Err(e) => {
                self.push_error(format!("{e}"));
            }
        }
    }

    /// 应用一份最新房间快照：检测被踢出群聊、按可见性过滤、恢复/回退选中房间并重载
    /// 消息、对新出现房间触发 WebSocket 重连与成员名刷新。load_rooms 与轮询事件
    /// RoomsUpdated 共用此唯一入口，确保两条路径行为完全一致。
    fn apply_room_snapshot(&mut self, rooms: Vec<RoomInfo>) {
        // 检测相对当前列表新出现的房间：本连接未订阅它，必须重连才能收到推送。
        // 僵尸单人间不算新房间，避免触发无谓重连
        let known_room_ids: HashSet<&str> =
            self.rooms.iter().map(|room| room.id.as_str()).collect();
        let has_new_room = rooms.iter().any(|room| {
            !known_room_ids.contains(room.id.as_str()) && (room.is_group || room.members.len() >= 2)
        });
        // 记录相对旧列表新出现的房间 ID（持有所有权，供重赋值后判断"自动切换到新私聊"使用）
        let new_room_ids: HashSet<String> = rooms
            .iter()
            .filter(|room| !known_room_ids.contains(room.id.as_str()))
            .map(|room| room.id.clone())
            .collect();
        let previous_selected_id = self.selected_room_id();
        // 记录当前可见的群聊：若群聊消失且非本客户端主动退出，则判定为被移出群聊
        let previous_groups: HashMap<String, String> = self
            .rooms
            .iter()
            .filter(|room| room.is_group)
            .map(|room| (room.id.clone(), room.name.clone().unwrap_or_default()))
            .collect();
        let new_group_ids: HashSet<String> = rooms
            .iter()
            .filter(|room| room.is_group)
            .map(|room| room.id.clone())
            .collect();
        let kicked_groups: Vec<(String, String)> = previous_groups
            .iter()
            .filter(|(id, _)| {
                !new_group_ids.contains(*id)
                    && !self.left_room_ids.contains(*id)
                    && !self.closed_room_ids.contains(*id)
            })
            .map(|(id, name)| (id.clone(), name.clone()))
            .collect();
        self.rooms = filter_visible_rooms(rooms, &self.closed_room_ids);
        if self.rooms.is_empty() {
            self.rooms_state.select(None);
            self.messages.clear();
        } else {
            let restored_index = previous_selected_id
                .and_then(|id| self.rooms.iter().position(|room| room.id == id));
            // 只要新出现了私聊房间（接受请求建房、或对端接受后本端轮询发现），自动切换到它
            let new_private_index = self
                .rooms
                .iter()
                .position(|room| !room.is_group && new_room_ids.contains(&room.id));
            let selected_index = new_private_index.or(restored_index).unwrap_or(0);
            self.rooms_state.select(Some(selected_index));
            // 既非沿用原选中房、也非切到新私聊，说明原选中房已消失并回退到 0，需清旧消息防残留
            if new_private_index.is_none() && restored_index.is_none() {
                self.messages.clear();
            }
            self.load_messages_for_selected_room();
        }
        if has_new_room {
            // 新房间本连接未订阅，需重连让服务器重新快照订阅；握手补发统一在 WebSocketConnected 进行
            self.restart_websocket_thread();
            self.refresh_all_sender_names();
        }
        for (group_id, name) in kicked_groups {
            self.announce_kicked_from_group(&group_id, &name);
        }
    }

    /// 拉取所有可见房间的成员名单并入发送者名称映射，确保拉入群聊等场景下成员名称正确显示
    fn refresh_all_sender_names(&mut self) {
        let room_ids: Vec<String> = self.rooms.iter().map(|room| room.id.clone()).collect();
        for room_id in room_ids {
            if let Ok(room_detail) = self.connector.get_room(&room_id) {
                for member in &room_detail.members {
                    self.sender_names
                        .insert(member.user_id.clone(), member.username.clone());
                }
            }
        }
    }

    /// 提示用户被移出某群聊：优先使用轮询捕获到的群聊名称，缺失时回退为群聊 ID
    fn announce_kicked_from_group(&mut self, group_id: &str, known_name: &str) {
        let name = if known_name.is_empty() {
            group_id.to_string()
        } else {
            known_name.to_string()
        };
        self.push_notification(self.t("kicked_from_group").replace("{name}", &name));
    }

    fn load_messages_for_selected_room(&mut self) {
        // 先取房间快照再往下走：本方法后半段要多次可变借用 self（合并消息、写缓存），
        // 一路持有 self.rooms 的引用会让这些写操作无法进行
        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };
        {
            // 整房（重新）加载一律把滚动位置拉回最底部并配合下方重写消息列表：
            // 本方法任何路径都会用最新消息整表替换 self.messages，旧的"距底部偏移"对新列表
            // 已无意义——若残留较大偏移，会被夹取到顶部而误触发自动拉取、停在高位置。
            // 因此切换群聊与同房刷新统一归零贴底，用户主动上滚后才会再次累积偏移
            self.messages_scroll_from_bottom = 0;
            debug_log(&format!("整房加载 room={} 滚动偏移归零", room.id));
            // 用户正在查看该房间，清零其未读消息计数
            self.unread_counts.remove(&room.id);
            // 先把本地缓存里该房间已看过的历史铺上屏幕：服务端第一页只有 50 条，
            // 缓存里可能有几百条，先显示缓存再合并，切房时不会看到"历史突然变短"。
            // 端到端加密房间不缓存，取不到缓存就是空
            let cached_messages = if room.is_encrypted {
                None
            } else {
                self.chat_cache
                    .as_ref()
                    .and_then(|cache| cache.load_room(&room.id))
            };
            if let Some(cached) = cached_messages.clone() {
                self.messages = cached.messages;
                self.messages_older_cursor = cached.older_cursor;
            }
            // 获取房间细节
            match self.connector.get_room(&room.id) {
                Ok(room_detail) => {
                    for member in &room_detail.members {
                        self.sender_names
                            .insert(member.user_id.clone(), member.username.clone());
                    }
                    // 添加当前用户
                    if let Some(ref user_id) = self.current_user_id {
                        self.sender_names
                            .insert(user_id.clone(), self.t("self_name"));
                    }
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_room_failed")));
                    self.messages_reloaded_at = Instant::now();
                    return;
                }
            };
            match self.connector.get_messages(&room.id, 50, None) {
                Ok(data) => {
                    // 接口按最新在前返回，反转为旧消息在上、新消息在下，与实时追加方向一致
                    let mut loaded = data.messages;
                    loaded.reverse();
                    // 与服务端这一页按消息 ID 合并而不是整表替换：本地缓存里可能有这一页没有的
                    // 更早消息，替换会把它们丢掉；合并时保留本地已有条目，也顺带避免加密私聊里
                    // 已解密的明文被服务端返回的密文占位覆盖
                    self.messages = match cached_messages.clone() {
                        Some(cached) => merge_messages_by_id(cached.messages, loaded),
                        None => loaded,
                    };
                    // 记录更早消息分页游标（服务器无更多时返回 None），供滚到顶部时自动翻页；
                    // 缓存里已握有更早消息时沿用缓存的游标，翻页从本地已知位置接着往回走
                    self.messages_older_cursor = cached_messages
                        .as_ref()
                        .and_then(|cached| cached.older_cursor.clone())
                        .or(data.next_cursor);
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                    // 拉取失败时保留已有内容（缓存或内存里的），这正是本地缓存的意义：
                    // 服务端暂时连不上也还能翻看历史
                    if cached_messages.is_none() && self.messages.is_empty() {
                        self.messages_older_cursor = None;
                    }
                }
            }
            self.messages_reloaded_at = Instant::now();
            // 整表替换后旧的命中消息 ID 可能已不在列表里，重扫保证搜索跳转有效
            self.refresh_search_matches();
            let loaded_room_id = room.id.clone();
            self.cache_loaded_messages(&loaded_room_id);
        }
    }

    /// 用户滚到消息显示区顶部时自动向上翻页：按 messages_older_cursor 拉取一批（50 条）
    /// 更早消息并前插到消息列表头部。游标为空表示已无更早消息或上次拉取失败，直接返回；
    /// 成功后游标更新为响应的 next_cursor（无更多时为 None，翻页自然停止）；
    /// 失败时清空游标并弹错，避免每帧重试打爆服务端
    fn load_older_messages(&mut self) {
        let Some(cursor) = self.messages_older_cursor.clone() else {
            return;
        };
        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };
        match self.connector.get_messages(&room.id, 50, Some(&cursor)) {
            Ok(data) => {
                // 接口按最新在前返回，反转后整批前插；"距底部偏移"滚动模型下
                // 偏移不变而总行数增大，视口停留在原内容上，用户可继续上滑进入新拉取的历史
                let mut older = data.messages;
                older.reverse();
                debug_log(&format!(
                    "更早消息前插 room={} 数量={} 新游标={:?}",
                    room.id,
                    older.len(),
                    data.next_cursor
                ));
                self.messages.splice(0..0, older);
                self.messages_older_cursor = data.next_cursor;
                let room_id = room.id.clone();
                self.cache_loaded_messages(&room_id);
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                self.messages_older_cursor = None;
            }
        }
    }

    /// 当前是否已登录（持有用户身份）。登录/注册改为命令式后，以此取代独立登录页的存在判断。
    pub fn is_logged_in(&self) -> bool {
        self.current_user_id.is_some()
    }

    /// 受登录保护的操作统一入口：未登录时弹出提示并返回 false，调用方据此中止。
    fn require_login(&mut self) -> bool {
        if self.is_logged_in() {
            return true;
        }
        self.push_notification(self.t("error_not_logged_in"));
        false
    }

    /// 启动时若未登录（无有效会话），弹一次提示引导用 /login 登录或 /register 注册；
    /// 聊天窗口正常显示，不遮盖。
    pub fn notify_signed_out(&mut self) {
        self.push_notification(self.t("logged_out_hint"));
    }

    fn send_message(&mut self) {
        if !self.require_login() {
            return;
        }
        let content = self.input_collector.message_input_state.text();
        if content.is_empty() {
            return;
        }

        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };

        // 私聊一律走端到端加密途径（创建请求时已强制约定加密）
        if !room.is_group {
            self.send_encrypted_message(&room.id, content);
            return;
        }

        if self.websocket_sender.is_none() {
            self.push_error(self.t("error_ws_not_ready"));
            return;
        }
        // 消息通过 WebSocket 线程发送，服务器确认后由回显事件去重显示
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::SendMessage {
                room_id: &room.id,
                content: &content,
            },
        ));
        self.input_collector.message_input_state.set_text("");
    }

    /// 加密途径发送消息：会话激活则加密发出，握手中则排队等待就绪后自动发送
    fn send_encrypted_message(&mut self, room_id: &str, content: String) {
        let session_phase = self
            .crypto
            .sessions
            .get(room_id)
            .map(|session| session.phase);
        match session_phase {
            Some(EncryptionPhase::Active) => {
                let shared_key = self
                    .crypto
                    .sessions
                    .get(room_id)
                    .and_then(|session| session.shared_key);
                let Some(shared_key) = shared_key else {
                    self.push_error(self.t("error_session_key_missing"));
                    return;
                };
                match crypto::encrypt_message(&shared_key, &content) {
                    Ok(ciphertext) => {
                        self.send_ws_payload(outbound_ws_payload(
                            self.connector.version(),
                            WsCommand::EncryptMessage {
                                room_id,
                                ciphertext: &ciphertext,
                            },
                        ));
                    }
                    Err(e) => {
                        self.push_error(format!("{}: {e}", self.t("error_encrypt_message_failed")));
                        return;
                    }
                }
            }
            Some(EncryptionPhase::AwaitingAcceptance)
            | Some(EncryptionPhase::AwaitingSessionReady) => {
                // 握手进行中新消息一律排队，就绪后按序自动发出；
                // 此处不做任何握手重置，避免覆盖正在进行的密钥协商
                let session = self
                    .crypto
                    .sessions
                    .get_mut(room_id)
                    .expect("会话存在性已在上方确认");
                session.pending_content = Some(content);
                self.push_notification(self.t("error_session_establishing"));
            }
            None => {
                self.initiate_encryption(room_id, Some(content));
                self.push_notification(self.t("error_session_initiating"));
            }
        }
        self.input_collector.message_input_state.set_text("");
    }

    fn create_group(&mut self) {
        if !self.require_login() {
            return;
        }
        let name = self
            .input_collector
            .create_group_name_state
            .value
            .text()
            .string();
        let members_str = self
            .input_collector
            .create_group_members_state
            .value
            .text()
            .string();

        if name.is_empty() {
            self.push_error(self.t("error_group_name_empty"));
            return;
        }

        let usernames: Vec<String> = members_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let req = CreateRoomRequest::group(name, usernames);
        match self.connector.create_room(req) {
            Ok(_) => {
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.input_collector.create_group_name_state.set_text("");
                self.input_collector.create_group_members_state.set_text("");
                self.load_rooms();
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_create_group_failed")));
            }
        }
    }

    /// 发起私密聊天：搜索对方用户取得 ID 后发送聊天请求，等待对方接受后房间自动出现
    fn create_private_chat(&mut self) {
        if !self.require_login() {
            return;
        }
        let username = self
            .input_collector
            .create_private_username_state
            .value
            .text()
            .string();

        if username.is_empty() {
            self.push_error(self.t("error_username_empty"));
            return;
        }

        let search_result = match self.connector.search_users(&username) {
            Ok(users) => users,
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_search_user_failed")));
                return;
            }
        };
        // 优先精确匹配用户名，其次取第一条搜索结果
        let target = search_result
            .iter()
            .find(|user| user.username == username)
            .or_else(|| search_result.first());
        let Some(target) = target else {
            self.push_error(self.t("error_user_not_found"));
            return;
        };
        if Some(&target.id) == self.current_user_id.as_ref() {
            self.push_error(self.t("error_cannot_send_to_self"));
            return;
        }

        // 私聊一律以加密房间建立，无需运行时开关
        let request_message = self.t("private_request_message");
        match self
            .connector
            .create_room_request(&target.id, &request_message, true)
        {
            Ok(_) => {
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.input_collector
                    .create_private_username_state
                    .set_text("");
                self.push_notification(self.t("notification_request_sent"));
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_send_request_failed")));
            }
        }
    }

    /// 接受选中的待处理聊天请求，成功后刷新房间列表与请求列表
    fn accept_selected_request(&mut self) {
        let Some(request_id) = self.selected_request_id() else {
            return;
        };
        match self.connector.accept_room_request(&request_id) {
            Ok(_) => {
                self.push_notification(self.t("notification_request_accepted"));
                self.load_rooms();
                self.mark_pending_request_handled(&request_id, "accepted");
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_accept_request_failed")));
            }
        }
    }

    /// 拒绝选中的待处理聊天请求
    fn decline_selected_request(&mut self) {
        let Some(request_id) = self.selected_request_id() else {
            return;
        };
        match self.connector.decline_room_request(&request_id) {
            Ok(_) => {
                self.push_notification(self.t("notification_request_declined"));
                self.mark_pending_request_handled(&request_id, "declined");
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_decline_request_failed")));
            }
        }
    }

    /// 本端处理完一条收到的请求后就在地把结果状态写上，条目继续留在"收到的"区里。
    /// 不能摘掉：服务端 `GET /requests/pending` 只回仍是 pending 的行，摘掉就等于
    /// 把这段历史永久丢了（发出侧没这问题，因为 `/requests/sent` 回全部状态）。
    /// 也不额外发一次列表请求 —— 两处来源先后写同一个列表会互相覆盖。
    fn mark_pending_request_handled(&mut self, request_id: &str, status: &str) {
        if let Some(request) = self
            .pending_requests
            .iter_mut()
            .find(|request| request.id == request_id)
        {
            request.status = Some(status.to_string());
        }
    }

    /// 轮询带回的"收到的请求"与服务端对齐：服务端列表里没有已处理的行，
    /// 因此把本端已记下结果的条目接回列表末尾，历史才不会处理一次就清空。
    fn apply_received_requests(&mut self, polled: Vec<RoomRequestInfo>) {
        let handled: Vec<RoomRequestInfo> = self
            .pending_requests
            .iter()
            .filter(|request| !received_request_is_pending(request))
            .filter(|kept| !polled.iter().any(|request| request.id == kept.id))
            .cloned()
            .collect();
        self.pending_requests = polled.into_iter().chain(handled).collect();
    }

    /// 把发出的请求就地标成已撤回，同样等轮询确认
    fn mark_sent_request_cancelled(&mut self, request_id: &str) {
        if let Some(request) = self
            .sent_requests
            .iter_mut()
            .find(|request| request.id == request_id)
        {
            request.status = Some("cancelled".to_string());
        }
    }

    fn selected_request_id(&self) -> Option<String> {
        self.request_list_state
            .selected()
            .and_then(|index| self.pending_requests.get(index))
            .map(|request| request.id.clone())
    }

    /// 处理终端事件；返回 true 表示应用请求退出（由聊天命令或退出快捷键触发）
    pub fn handle_event(&mut self, event: &Event) -> bool {
        // 括号粘贴最先处理：浮层分支会对任何事件提前返回，放在后面就收不到粘贴内容。
        // 未启用括号粘贴时，粘贴被拆成逐字符按键事件，其中的换行等同于按 Enter，
        // 于是"复制多行文本再粘贴"会连着发出多条单行消息。
        if let Event::Paste(pasted_text) = event {
            self.handle_pasted_text(pasted_text);
            return false;
        }

        // 整屏框选排在浮层分派之前：浮层、通知、顶栏之上的文字同样要能被选中复制。
        // 拖拽与松手由框选独占（返回真值表示本事件已处理完），按下只登记起点并继续
        // 走原有的点击聚焦分发，不抢输入框自己的选区逻辑
        if let Event::Mouse(mouse) = event
            && self.handle_screen_selection_mouse(*mouse)
        {
            return false;
        }

        match self.displaying_overlay {
            DisplayingOverlay::CreateGroup => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            // 先逐级上移焦点，位于第一个输入框时退回设置菜单
                            if self.focus_index == 1 {
                                self.focus_index = 0;
                            } else {
                                self.dismiss_overlay_back();
                                self.input_collector.create_group_name_state.set_text("");
                                self.input_collector.create_group_members_state.set_text("");
                            }
                            return false;
                        }
                        KeyCode::Enter => {
                            if self.focus_index == 1 {
                                self.focus_index = 0;
                                self.create_group();
                                return false;
                            } else {
                                self.focus_index = 1;
                            }
                        }
                        KeyCode::Tab => {
                            self.focus_index = (self.focus_index + 1) % 2;
                            return false;
                        }
                        _ => {}
                    }
                    if let Some(state) = self.get_create_group_focused_state() {
                        let _ = text_input::handle_events(state, true, event);
                    }
                }
                return false;
            }

            DisplayingOverlay::CreatePrivate => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            self.input_collector
                                .create_private_username_state
                                .set_text("");
                            self.focus_index = 0;
                            return false;
                        }
                        KeyCode::Enter => {
                            self.create_private_chat();
                            return false;
                        }
                        _ => {}
                    }
                    if let Some(state) = self.get_create_private_focused_state() {
                        let _ = text_input::handle_events(state, true, event);
                    }
                }
                return false;
            }

            DisplayingOverlay::PendingRequests => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // 收到的与已发出的请求拼成一条扁平序列，上下键跨区连续移动，
                    // 因此环绕按条目总数而不是单一列表长度计算
                    let entries = self.request_entries();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            if !entries.is_empty() {
                                let count = entries.len();
                                let current = self.request_list_state.selected().unwrap_or(0);
                                let next = if key.code == KeyCode::Up {
                                    (current + count - 1) % count
                                } else {
                                    (current + 1) % count
                                };
                                self.request_list_state.select(Some(next));
                            }
                            return false;
                        }
                        KeyCode::Enter => {
                            // 接受只对仍在等的收到请求有意义：发出项与已处理过的历史都什么都不做
                            if matches!(
                                self.request_list_state
                                    .selected()
                                    .and_then(|index| entries.get(index)),
                                Some((false, request))
                                if received_request_is_pending(request)
                            ) {
                                self.accept_selected_request();
                            }
                            if self.pending_requests.is_empty() && self.sent_requests.is_empty() {
                                self.dismiss_overlay_back();
                            }
                            return false;
                        }
                        KeyCode::Char('d') => {
                            // 同一枚按键在两个区里的语义分别是"拒绝"与"撤回"
                            match self
                                .request_list_state
                                .selected()
                                .and_then(|index| entries.get(index))
                            {
                                Some((false, request)) if received_request_is_pending(request) => {
                                    self.decline_selected_request();
                                }
                                // 已结束的邀请撤不回，这里什么都不做（不再弹"能不能撤"的提示）
                                Some((true, request))
                                    if request.status.as_deref() == Some("pending") =>
                                {
                                    self.cancel_sent_request(&request.id);
                                }
                                _ => {}
                            }
                            if self.pending_requests.is_empty() && self.sent_requests.is_empty() {
                                self.dismiss_overlay_back();
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::AvatarSelect => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // 列表只在本地目录有图片时才会打开，条目数在这里重读一次磁盘
                    let count = local_avatar_files().len();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down if count > 0 => {
                            let current = self.avatar_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + count - 1) % count
                            } else {
                                (current + 1) % count
                            };
                            self.avatar_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter if count > 0 => {
                            self.apply_local_avatar();
                            return false;
                        }
                        // 只有在这个浮层里 Ctrl+U 才改作"填网络链接"，消息输入框里仍是删整行
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            self.open_declared_form(&FormAction::ChangeAvatar);
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::Form => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // 上下键与 Tab 一样切换当前输入项：长表单里逐个 Tab 太绕
                    if matches!(key.code, KeyCode::Up | KeyCode::Down) {
                        self.cycle_form_focus(key.code == KeyCode::Up);
                        return false;
                    }
                    match key.code {
                        KeyCode::Esc => {
                            self.active_form = None;
                            self.focus_index = 0;
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Tab => {
                            let field_count = self
                                .active_form
                                .as_ref()
                                .map(|(_, fields)| fields.len())
                                .unwrap_or(1);
                            self.focus_index = (self.focus_index + 1) % field_count.max(1);
                            return false;
                        }
                        KeyCode::Enter => {
                            self.submit_active_form();
                            return false;
                        }
                        _ => {}
                    }
                    if let Some(state) = self.get_focused_state() {
                        let _ = text_input::handle_events(state, true, event);
                    }
                }
                return false;
            }

            DisplayingOverlay::ProfileCard => {
                // 只读卡片：Esc 关掉回到聊天页（它由 /profile 指令打开，不属于设置菜单链路）
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                    && key.code == KeyCode::Esc
                {
                    self.profile_view = None;
                    self.displaying_overlay = DisplayingOverlay::Nothing;
                    self.restore_chat_focus();
                }
                return false;
            }

            DisplayingOverlay::SettingsMenu => {
                // 菜单项与动作由 settings_menu_entries 一处定义，渲染与分派读同一张表，
                // 增删菜单项不需要再手工同步"第几项"的数字
                let entries = self.settings_menu_entries();
                let menu_count = entries.len().max(1);
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            let current = self.menu_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + menu_count - 1) % menu_count
                            } else {
                                (current + 1) % menu_count
                            };
                            self.menu_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter => {
                            let selected = self.menu_list_state.selected().unwrap_or(0);
                            let Some((_, _, action)) = entries.get(selected) else {
                                return false;
                            };
                            let action = action.clone();
                            // 未登录要改账号或做服务端操作：给一条提示，浮层保持停在设置菜单
                            if action.requires_login() && !self.require_login() {
                                return false;
                            }
                            match action {
                                SettingsAction::ToggleShowUid => {
                                    self.show_uid = !self.show_uid;
                                    self.save_display_preferences();
                                }
                                SettingsAction::ToggleTimeWithDate => {
                                    self.time_with_date = !self.time_with_date;
                                    self.save_display_preferences();
                                }
                                SettingsAction::ToggleQuickSearch => {
                                    self.quick_search = !self.quick_search;
                                    self.save_display_preferences();
                                }
                                SettingsAction::ToggleSound => {
                                    self.sound_enabled = !self.sound_enabled;
                                    self.save_display_preferences();
                                }
                                SettingsAction::Logout => {
                                    self.logout();
                                    self.displaying_overlay = DisplayingOverlay::Nothing;
                                    self.restore_chat_focus();
                                }
                                SettingsAction::UpdateClient => {
                                    // 更新成功会挂起安装进程并由主循环退出；失败则留在设置菜单里看提示
                                    self.start_downloaded_update();
                                }
                                SettingsAction::OpenForm(form_action) => {
                                    self.open_declared_form(&form_action);
                                }
                                SettingsAction::OpenOverlay(overlay) => {
                                    self.open_overlay(overlay);
                                }
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::AppearanceSelect => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    let names = Appearance::available_names();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            let count = names.len();
                            if count == 0 {
                                return false;
                            }
                            let current = self.appearance_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + count - 1) % count
                            } else {
                                (current + 1) % count
                            };
                            self.appearance_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter => {
                            if let Some(index) = self.appearance_list_state.selected()
                                && let Some(name) = names.get(index)
                            {
                                self.switch_appearance(name);
                            }
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::LanguageSelect => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    let languages = Self::get_available_languages();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            let count = languages.len();
                            if count == 0 {
                                return false;
                            }
                            let current = self.language_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + count - 1) % count
                            } else {
                                (current + 1) % count
                            };
                            self.language_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter => {
                            if let Some(idx) = self.language_list_state.selected()
                                && let Some(lang) = languages.get(idx)
                            {
                                Self::save_language_preference(lang);
                                self.load_language(lang);
                                self.push_notification(
                                    self.t("language_switched")
                                        .replace("{lang}", lang)
                                        .to_string(),
                                );
                            }
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::ServerAddress => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Enter => {
                            let new_addr = self
                                .input_collector
                                .server_address_state
                                .text()
                                .trim()
                                .to_string();
                            if new_addr.is_empty() {
                                self.push_notification(self.t("error_server_address_empty"));
                                return false;
                            }
                            // 测试连通性
                            let test_connector = Connector::new(&new_addr);
                            match test_connector.greet() {
                                Ok(_) => {
                                    self.connector.set_base_url(&new_addr);
                                    self.save_server_address();
                                    // 切换服务器后重新探测版本，使线上决策匹配新服务端
                                    self.detect_and_apply_api_version();
                                    // 可达性探测也要改探新地址
                                    self.start_reachability_watch();
                                    self.push_notification(self.t("server_address_saved"));
                                    self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                                }
                                Err(_) => {
                                    self.push_notification(self.t("error_server_connect_failed"));
                                }
                            }
                            return false;
                        }
                        _ => {
                            let _ = text_input::handle_events(
                                &mut self.input_collector.server_address_state,
                                true,
                                event,
                            );
                            return false;
                        }
                    }
                }
                return false;
            }

            DisplayingOverlay::Login | DisplayingOverlay::Register => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    let max_index = self.max_focus_index();
                    match key.code {
                        KeyCode::Esc => {
                            // 与创建群聊一致：先逐级上移焦点，位于第一个输入框时再关闭浮层
                            if self.focus_index > 0 {
                                self.focus_index -= 1;
                            } else {
                                self.dismiss_overlay_back();
                            }
                            return false;
                        }
                        KeyCode::Tab => {
                            if max_index > 0 {
                                self.focus_index = (self.focus_index + 1) % (max_index + 1);
                            }
                        }
                        KeyCode::BackTab => {
                            if self.focus_index > 0 {
                                self.focus_index -= 1;
                            }
                        }
                        KeyCode::Enter => {
                            if self.focus_index == max_index {
                                if matches!(self.displaying_overlay, DisplayingOverlay::Login) {
                                    self.do_login();
                                } else {
                                    self.do_register();
                                }
                            } else if max_index > 0 {
                                self.focus_index += 1;
                            }
                        }
                        _ => {
                            self.dispatch_focused_input_event(true, event);
                        }
                    }
                }
                return false;
            }
            DisplayingOverlay::Nothing => {}
        }

        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // 搜索模式下的上下键语义被整体接管：不再移动输入框光标、也不再切房间，
                // 一律切换匹配项。放在修饰键分支之前并用"任意修饰键"匹配，
                // 是因为不同终端对 Ctrl/Ctrl+Shift+方向键的上报差异极大（Terminal.app 甚至不区分），
                // 只认某一种组合键会表现为按了完全没反应、只剩输入框光标在动。
                if matches!(key.code, KeyCode::Up | KeyCode::Down) && self.in_search_mode() {
                    debug_log(&format!("搜索切换匹配项: {key:?}"));
                    self.navigate_search_result(key.code == KeyCode::Up);
                    return false;
                }
                // Ctrl+L 请求整屏重绘（由主循环执行 terminal.clear，用于修回终端侧滚动造成的错位）
                if matches!(key.code, KeyCode::Char('l') | KeyCode::Char('L'))
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    self.full_repaint_requested = true;
                    debug_log("Ctrl+L 请求整屏重绘");
                    return false;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    // 聊天页 Ctrl+P 打开设置菜单（创建群聊/私聊与待处理请求入口）
                    if let KeyCode::Char('p') = key.code {
                        self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                        self.menu_list_state.select(Some(0));
                        return false;
                    }
                }

                match key.code {
                    KeyCode::Up | KeyCode::Down => {
                        let input_text = self.input_collector.message_input_state.text();
                        if let Some(command_prefix) = input_text.strip_prefix('/') {
                            // 补全列表开启时上下键选择命令，禁用群聊切换
                            let candidate_count = self.completion_candidates(command_prefix).len();
                            if candidate_count > 0 {
                                let current = self.command_list_state.selected().unwrap_or(0);
                                let next = if key.code == KeyCode::Up {
                                    (current + candidate_count - 1) % candidate_count
                                } else {
                                    (current + 1) % candidate_count
                                };
                                self.command_list_state.select(Some(next));
                            }
                        } else {
                            // 多行文本时上下键移动光标，到达首/末行才切换群聊
                            let state = &mut self.input_collector.message_input_state;
                            let before = state.cursor();
                            if key.code == KeyCode::Up {
                                state.move_up(1, false);
                            } else {
                                state.move_down(1, false);
                            }
                            let after = state.cursor();
                            // 光标未移动说明已在边界，执行群聊切换；
                            // 带 Ctrl 的组合键不用于切房，避免与搜索等组合键语义混淆
                            if before == after
                                && !self.rooms.is_empty()
                                && !key.modifiers.contains(KeyModifiers::CONTROL)
                            {
                                let selected = self.rooms_state.selected().unwrap_or(0);
                                if key.code == KeyCode::Up {
                                    if selected > 0 {
                                        self.rooms_state.select(Some(selected - 1));
                                        self.load_messages_for_selected_room();
                                    }
                                } else if selected + 1 < self.rooms.len() {
                                    self.rooms_state.select(Some(selected + 1));
                                    self.load_messages_for_selected_room();
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        let input_text = self.input_collector.message_input_state.text();
                        if input_text.starts_with('/') {
                            // 清空前缀即退出 command 模式
                            self.input_collector.message_input_state.set_text("");
                            return false;
                        }
                        if input_text.starts_with('#') {
                            // 搜索模式同样以前缀清空作为退出条件，并连带清掉高亮与定位
                            self.exit_search_mode();
                            return false;
                        }
                        self.dispatch_focused_input_event(true, event);
                    }
                    KeyCode::Enter => {
                        // Enter 发送消息
                        return self.handle_chat_submit();
                    }
                    KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+J 插入换行
                        self.input_collector.message_input_state.insert_newline();
                        self.handle_message_input_changed();
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+U 删除光标所在整行
                        self.input_collector.message_input_state.delete_line();
                        self.handle_message_input_changed();
                    }
                    _ => {
                        self.dispatch_focused_input_event(true, event);
                        // 输入变化后命令选择回到第一项；由组件自身完成插入以保持光标位置
                        let input_text = self.input_collector.message_input_state.text();
                        if input_text.starts_with('/') {
                            self.command_list_state.select(Some(0));
                        }
                        // 文本增删即视为处于打字状态，按需上报输入状态（内部已节流）；
                        // 同时让与当前输入不符的旧搜索结果失效（快速搜索则就地重扫）
                        self.handle_message_input_changed();
                    }
                }
            }
            Event::Mouse(mouse) => {
                // 聊天页无弹窗时滚轮控制消息显示区滚动，其余界面忽略滚轮
                if matches!(
                    mouse.kind,
                    MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                ) {
                    if self.displaying_overlay == DisplayingOverlay::Nothing {
                        // 整房加载（切群/同房刷新）同步阻塞主线程期间产生的滚轮事件会在
                        // 系统队列积压、加载完成后迟到补处理，把新房间视图"自动"顶上去并
                        // 可能误触顶拉取；加载完成后的静默窗口内一律丢弃滚轮事件消除这些迟到输入
                        if self.messages_reloaded_at.elapsed() < Duration::from_millis(500) {
                            debug_log("整房加载后静默窗口内丢弃迟到的滚轮事件");
                            return false;
                        }
                        let scroll_step = 3u16;
                        if mouse.kind == MouseEventKind::ScrollUp {
                            self.messages_scroll_from_bottom =
                                self.messages_scroll_from_bottom.saturating_add(scroll_step);
                        } else {
                            self.messages_scroll_from_bottom =
                                self.messages_scroll_from_bottom.saturating_sub(scroll_step);
                        }
                        debug_log(&format!(
                            "滚轮 {:?} 后 offset={}",
                            mouse.kind, self.messages_scroll_from_bottom
                        ));
                    }
                    return false;
                }
                // 整屏框选本身已提到 handle_event 开头（浮层之上也要能框选）；
                // 这里只保留输入框内由控件自己维护的选区
                // 输入框内的框选仍由控件自身维护，松开时复制控件选区文本
                if self.displaying_overlay == DisplayingOverlay::Nothing
                    && mouse.kind == MouseEventKind::Up(crossterm::event::MouseButton::Left)
                {
                    self.copy_message_selection();
                }
                if mouse.kind == MouseEventKind::Down(crossterm::event::MouseButton::Left) {
                    let areas = self.get_field_areas(&[
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                    ]);
                    for (i, area) in areas.iter().enumerate() {
                        if area.contains(ratatui::layout::Position::new(mouse.column, mouse.row)) {
                            self.focus_index = i;
                            break;
                        }
                    }
                    self.dispatch_focused_input_event(true, event);
                } else {
                    self.dispatch_focused_input_event(true, event);
                }
            }
            _ => {
                self.dispatch_focused_input_event(true, event);
            }
        }
        false
    }

    /// 计算命令输入的补全候选列表，返回 (补全后写入输入框的文本, 列表展示文本, 描述文本)。
    /// /kick 后带空格时列出当前群聊成员（仅群聊且当前用户为管理员/群主才提示），
    /// /language 后带空格时列出可用语言；其余情况为命令名补全。
    fn completion_candidates(
        &self,
        raw_command_after_slash: &str,
    ) -> Vec<(String, String, String)> {
        if raw_command_after_slash.starts_with("kick ") {
            let room_id = self.selected_room_id();
            let room_is_group = room_id
                .as_ref()
                .and_then(|id| self.rooms.iter().find(|room| room.id == *id))
                .map(|room| room.is_group)
                .unwrap_or(false);
            if !room_is_group {
                return Vec::new();
            }
            let Ok(detail) = self
                .connector
                .get_room(room_id.as_deref().unwrap_or_default())
            else {
                return Vec::new();
            };
            let is_admin = self.current_user_id.as_deref().is_some_and(|uid| {
                detail
                    .members
                    .iter()
                    .any(|member| member.user_id == uid && is_admin_role(&member.role))
            });
            if !is_admin {
                return Vec::new();
            }
            // 提取空格后的输入用于过滤
            let filter_text = raw_command_after_slash.strip_prefix("kick ").unwrap_or("");
            return detail
                .members
                .iter()
                .filter(|member| member.username.starts_with(filter_text))
                .map(|member| {
                    (
                        format!("/kick {}", member.username),
                        member.username.clone(),
                        String::new(),
                    )
                })
                .collect();
        }
        if raw_command_after_slash.starts_with("language ") {
            // 提取空格后的输入用于过滤
            let filter_text = raw_command_after_slash
                .strip_prefix("language ")
                .unwrap_or("");
            return Self::get_available_languages()
                .into_iter()
                .filter(|lang| lang.starts_with(filter_text))
                .map(|lang| (format!("/language {lang}"), lang.clone(), String::new()))
                .collect();
        }
        if raw_command_after_slash.starts_with("appearance ") {
            // /appearance 后打出空格即列出 config/themes 下全部可用外观，可继续输入前缀过滤
            let filter_text = raw_command_after_slash
                .strip_prefix("appearance ")
                .unwrap_or("");
            return Appearance::available_names()
                .into_iter()
                .filter(|name| name.starts_with(filter_text))
                .map(|name| (format!("/appearance {name}"), name.clone(), String::new()))
                .collect();
        }
        if raw_command_after_slash.starts_with("profile ") {
            // /profile 后打出空格即列出全部注册用户；条目文本按 "<用户名> - <UID>" 呈现，
            // 回车补全进输入框的是用户名（服务端资料接口用户名与 UID 都认）
            let filter_text = raw_command_after_slash
                .strip_prefix("profile ")
                .unwrap_or("");
            return self
                .registered_users
                .iter()
                .flatten()
                .filter(|user| {
                    user.username.starts_with(filter_text) || user.id.starts_with(filter_text)
                })
                .map(|user| {
                    (
                        format!("/profile {}", user.username),
                        format!("{} - {}", user.username, user.id),
                        user.nickname.clone().unwrap_or_default(),
                    )
                })
                .collect();
        }
        if raw_command_after_slash.starts_with("server_address ") {
            let current = self.connector.base_url();
            return vec![(
                format!("/server_address {current}"),
                current.to_string(),
                self.t("server_address_current"),
            )];
        }
        if raw_command_after_slash.starts_with("add_member ") {
            // add_member 命令只需要提示输入用户名，不提供具体补全
            return vec![(
                "/add_member <username>".to_string(),
                "<username>".to_string(),
                self.t("add_member_hint"),
            )];
        }
        if raw_command_after_slash.starts_with("mute ") {
            // /mute <bool> 补全 true/false
            let filter_text = raw_command_after_slash.strip_prefix("mute ").unwrap_or("");
            return ["true", "false"]
                .into_iter()
                .filter(|value| value.starts_with(filter_text))
                .map(|value| (format!("/mute {value}"), value.to_string(), String::new()))
                .collect();
        }
        command_completions(raw_command_after_slash.trim())
            .into_iter()
            .map(|(name, description)| {
                (format!("/{name}"), format!("/{name}"), self.t(description))
            })
            .collect()
    }

    /// 处理聊天页回车提交；返回 true 表示应用请求退出
    fn handle_chat_submit(&mut self) -> bool {
        let input_text = self.input_collector.message_input_state.text();
        // 搜索模式：Enter 执行/重执行搜索，绝不把 "#关键词" 当消息发出去
        if input_text.starts_with('#') {
            self.execute_message_search();
            return false;
        }
        if !input_text.starts_with('/') {
            self.send_message();
            return false;
        }
        let trimmed = input_text.trim();
        let name = trimmed
            .strip_prefix('/')
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("");
        // /kick all 是内置批量操作（非成员名），不参与成员补全，直接走命令执行
        let kick_argument = trimmed.split_whitespace().nth(1).unwrap_or("");
        let is_kick_all = name == "kick" && kick_argument.eq_ignore_ascii_case("all");
        // 命令后带空格即进入参数补全：列群成员、语言、外观、服务器地址、注册用户，
        // 按 Enter 把选中项补进输入框，再次 Enter（此时已是完整命令）才执行
        let argument_completion_commands = [
            "kick",
            "language",
            "mute",
            "appearance",
            "server_address",
            "profile",
        ];
        if argument_completion_commands.contains(&name) && input_text.contains(' ') && !is_kick_all
        {
            let raw_prefix = input_text.strip_prefix('/').unwrap_or("");
            let candidates = self.completion_candidates(raw_prefix);
            // 检查当前输入是否已经精确匹配某个补全候选，如果是则直接执行
            let exact_match = candidates
                .iter()
                .any(|(insert_text, _, _)| insert_text == &input_text);
            if !exact_match {
                // 当前输入不是完整命令，尝试插入选中的补全项
                if let Some(selected_index) = self.command_list_state.selected()
                    && let Some((insert_text, _, _)) =
                        candidates.get(selected_index.min(candidates.len().saturating_sub(1)))
                {
                    self.input_collector
                        .message_input_state
                        .set_text(insert_text);
                    self.input_collector.message_input_state.set_cursor(
                        TextPosition::new(insert_text.chars().count().try_into().unwrap(), 0),
                        false,
                    );
                    self.command_list_state.select(Some(0));
                }
                return false;
            }
            // 如果是精确匹配，继续往下执行命令
        }
        // 登录与注册不接受任何形式的参数：口令不该留在命令行与屏幕回滚历史里。
        // 这里既不执行也不清空输入框，让用户自己把参数删掉或改用浮层
        if matches!(name, "login" | "register")
            && !trimmed
                .strip_prefix(&format!("/{name}"))
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return false;
        }
        // 命令名已是完整已知命令时直接执行（含带参数的 /kick name、/language code）
        let is_known = chat_commands().iter().any(|(known, _)| *known == name);
        if is_known {
            let should_exit = self.execute_chat_command(trimmed);
            if !should_exit {
                self.input_collector.message_input_state.set_text("");
            }
            return should_exit;
        }
        // 命令名尚未补全为完整命令时，按 Enter 将选中命令补全到输入框，再次 Enter 才执行
        let candidates = self.completion_candidates(name);
        if !candidates.is_empty() {
            let selected = self.command_list_state.selected().unwrap_or(0);
            let index = selected.min(candidates.len() - 1);
            if let Some((insert_text, _, _)) = candidates.get(index) {
                let full = insert_text.clone();
                self.input_collector.message_input_state.set_text(&full);
                // 将光标移动到补全文本末尾，便于用户直接补充参数或回车执行
                self.input_collector.message_input_state.set_cursor(
                    TextPosition::new(full.chars().count().try_into().unwrap(), 0),
                    false,
                );
                self.command_list_state.select(Some(0));
            }
        }
        false
    }

    /// 执行以 / 开头的聊天命令；返回 true 表示应用请求退出。
    /// 扩展新命令：在 chat_commands 表追加条目，并在此处的 match 中增加分派分支。
    fn execute_chat_command(&mut self, command_line: &str) -> bool {
        let Some(name) = command_line
            .strip_prefix('/')
            .and_then(|rest| rest.split_whitespace().next())
        else {
            let usage = chat_commands()
                .iter()
                .map(|(name, _)| format!("/{name}"))
                .collect::<Vec<_>>()
                .join(" ");
            self.push_error(format!("{}: {usage}", self.t("error_available_commands")));
            return false;
        };
        if !chat_commands().iter().any(|(known, _)| *known == name) {
            self.push_error(
                self.t("error_unknown_command")
                    .replace("{name}", name)
                    .to_string(),
            );
            return false;
        }
        // 未登录时仅放行登录/注册/退出/quit/语言/外观/服务器地址，其余聊天操作先弹提示拒绝
        let allowed_signed_out = matches!(
            name,
            "login"
                | "register"
                | "logout"
                | "quit"
                | "exit"
                | "update"
                | "language"
                | "appearance"
                | "server_address"
        );
        if !allowed_signed_out && !self.is_logged_in() {
            self.push_notification(self.t("error_not_logged_in"));
            return false;
        }
        match name {
            "quit" | "exit" => {
                self.begin_quit_cleanup();
                false
            }
            "quit_group" => {
                self.quit_current_group();
                false
            }
            "mute" => {
                // /mute <bool>：对当前选中房间开/关消息免打扰并持久化到 preferences.json
                let argument = command_line
                    .strip_prefix("/mute")
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();
                let enable_mute = match argument.as_str() {
                    "true" | "on" | "1" => true,
                    "false" | "off" | "0" => false,
                    _ => {
                        self.push_notification(self.t("error_mute_usage"));
                        return false;
                    }
                };
                let Some(selected_room) = self
                    .rooms_state
                    .selected()
                    .and_then(|index| self.rooms.get(index))
                    .cloned()
                else {
                    self.push_error(self.t("error_no_room_selected"));
                    return false;
                };
                if enable_mute {
                    self.muted_room_ids.insert(selected_room.id.clone());
                } else {
                    self.muted_room_ids.remove(&selected_room.id);
                }
                self.save_display_preferences();
                let state_text = if enable_mute {
                    self.t("mute_dnd_on")
                } else {
                    self.t("mute_dnd_off")
                };
                let room_name = selected_room
                    .name
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                self.push_notification(format!("{}: {}", room_name, state_text));
                false
            }
            "kick" => {
                let argument = command_line.strip_prefix("/kick").unwrap_or("!").trim();
                self.execute_kick(argument);
                false
            }
            "info" => {
                self.show_room_info();
                false
            }
            "language" => {
                // /language 无参 → 打开语言选择浮层；/language <语言码> → 直接切换
                let argument = command_line
                    .strip_prefix("/language")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    self.displaying_overlay = DisplayingOverlay::LanguageSelect;
                    self.language_list_state.select(Some(0));
                    return false;
                }
                let languages = Self::get_available_languages();
                if !languages.iter().any(|language| language == &argument) {
                    self.push_error(self.t("error_no_languages"));
                    return false;
                }
                Self::save_language_preference(&argument);
                self.load_language(&argument);
                self.push_notification(
                    self.t("language_switched")
                        .replace("{lang}", &argument)
                        .to_string(),
                );
                false
            }
            "logout" => {
                self.logout();
                false
            }
            "server_address" => {
                let argument = command_line
                    .strip_prefix("/server_address")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    // 无参数 → 打开服务器地址设置浮层，预填当前地址供编辑
                    self.input_collector
                        .server_address_state
                        .set_text(self.connector.base_url());
                    self.focus_index = 0;
                    self.displaying_overlay = DisplayingOverlay::ServerAddress;
                    return false;
                }
                // 有参数时直接测试并保存
                let test_connector = Connector::new(&argument);
                match test_connector.greet() {
                    Ok(_) => {
                        self.connector.set_base_url(&argument);
                        self.save_server_address();
                        // 切换服务器后重新探测版本，使线上决策匹配新服务端
                        self.detect_and_apply_api_version();
                        self.push_notification(self.t("server_address_saved"));
                    }
                    Err(_) => {
                        self.push_notification(self.t("error_server_connect_failed"));
                    }
                }
                false
            }
            "add_member" => {
                let argument = command_line
                    .strip_prefix("/add_member")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    self.push_notification(self.t("error_add_member_usage"));
                    return false;
                }
                // 获取当前选中的房间
                let Some(room_id) = self.selected_room_id() else {
                    self.push_error(self.t("error_no_room_selected"));
                    return false;
                };
                // 检查是否是群聊
                let room_is_group = self
                    .rooms
                    .iter()
                    .find(|room| room.id == room_id)
                    .map(|room| room.is_group)
                    .unwrap_or(false);
                if !room_is_group {
                    self.push_error(self.t("error_not_group"));
                    return false;
                }
                // 调用 API 添加成员
                let usernames = vec![argument];
                match self.connector.add_members(&room_id, &usernames) {
                    Ok(_) => {
                        self.push_notification(self.t("add_member_success"));
                    }
                    Err(e) => {
                        self.push_error(format!("{}: {e}", self.t("error_add_member_failed")));
                    }
                }
                false
            }
            "appearance" => {
                // /appearance 无参 → 打开外观选择浮层；/appearance <外观名> → 直接应用
                let argument = command_line
                    .strip_prefix("/appearance")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    self.displaying_overlay = DisplayingOverlay::AppearanceSelect;
                    let names = Appearance::available_names();
                    if names.is_empty() {
                        self.push_error(self.t("error_no_appearances"));
                        self.displaying_overlay = DisplayingOverlay::Nothing;
                        return false;
                    }
                    let idx = names.iter().position(|name| name == &self.appearance_name);
                    self.appearance_list_state.select(idx.or(Some(0)));
                    return false;
                }
                if !Appearance::available_names()
                    .iter()
                    .any(|name| name == &argument)
                {
                    self.push_error(
                        self.t("error_appearance_not_found")
                            .replace("{name}", &argument)
                            .to_string(),
                    );
                    return false;
                }
                self.switch_appearance(&argument);
                false
            }
            "login" | "register" => {
                // 带参数的情况已在提交入口拦掉（见 handle_chat_submit），这里只会收到无参调用：
                // 直接打开对应浮层填写
                self.displaying_overlay = if name == "login" {
                    DisplayingOverlay::Login
                } else {
                    DisplayingOverlay::Register
                };
                self.focus_index = 0;
                false
            }
            "list_users" => {
                self.show_registered_users();
                false
            }
            "search_users" => {
                let argument = command_line
                    .strip_prefix("/search_users")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                self.search_registered_users(&argument);
                false
            }
            "profile" => {
                // 无参看自己，带参看指定用户；参数可以是用户名或 UID
                let argument = command_line
                    .strip_prefix("/profile")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                self.show_profile_card(if argument.is_empty() {
                    None
                } else {
                    Some(&argument)
                });
                false
            }
            "update" => {
                self.start_downloaded_update();
                false
            }
            _ => false,
        }
    }

    /// 退出登录：停止后台线程、清除持久化会话与聊天状态，回到登录页以便重新登录
    fn logout(&mut self) {
        if let Some(running_flag) = self.websocket_running.take() {
            running_flag.store(false, Ordering::Relaxed);
        }
        if let Some(running_flag) = self.polling_running.take() {
            running_flag.store(false, Ordering::Relaxed);
        }
        self.websocket_sender = None;
        self.websocket_token = None;
        // 攒着未落盘的消息先写出去，缓存按用户 ID 分目录，退出登录后仍可被下次自动登录复用
        if let Some(room_id) = self.selected_room_id() {
            let room_id = room_id.clone();
            self.cache_loaded_messages(&room_id);
        }
        self.cache_pending_flush_since = None;
        Self::clear_saved_session();
        self.current_user_id = None;
        self.current_username.clear();
        self.own_contact = None;
        self.sent_requests.clear();
        self.registered_users = None;
        self.profile_view = None;
        self.active_form = None;
        self.avatar_images.clear();
        self.avatar_pixels.clear();
        self.avatar_list_state = ListState::default();
        self.chat_cache = None;
        self.rooms.clear();
        self.rooms_state = ListState::default();
        self.messages.clear();
        self.sender_names.clear();
        self.crypto.sessions.clear();
        self.closed_room_ids.clear();
        self.left_room_ids.clear();
        self.typing_members.clear();
        self.last_typing_frame_sent_at = None;
        self.presence_by_user.clear();
        self.search_result = None;
        self.pending_scroll_message_id = None;
        self.notifications.clear();
        self.displaying_overlay = DisplayingOverlay::Nothing;
        self.focus_index = 0;
        // 清空登录/注册表单，回到未登录聊天页（显示登录提示）
        self.input_collector.login_name_state = TextInputState::default();
        self.input_collector.login_password_state = TextInputState::default();
        self.input_collector.register_name_state = TextInputState::default();
        self.input_collector.register_email_state = TextInputState::default();
        self.input_collector.register_password_state = TextInputState::default();
    }

    /// /quit 退出清理：对所有私聊先发 encrypt_leave 促使服务器清理加密会话
    /// 并让在线对端同步隐藏界面，等待 5 秒后逐一退出房间，完成后经事件通道通知退出。
    /// 客户端无法探测对端是否在线，故统一等待；对端离线时仅表现为退出延迟。
    fn begin_quit_cleanup(&mut self) {
        if self.quit_ready {
            return;
        }
        // 退出前把攒着未落盘的消息写进本地缓存，避免最后几秒收到的内容丢在内存里
        if let Some(room_id) = self.selected_room_id() {
            let room_id = room_id.clone();
            self.cache_loaded_messages(&room_id);
        }
        // 退出前持久化登录会话（JWT 与企业用户 ID、自己才可见的联系方式），供下次自动登录
        if let (Some(token), Some(user_id)) =
            (self.websocket_token.clone(), self.current_user_id.clone())
        {
            Self::save_session_preferences(&token, &user_id, self.own_contact.as_ref());
        }
        let private_room_ids: Vec<String> = self
            .rooms
            .iter()
            .filter(|room| !room.is_group)
            .map(|room| room.id.clone())
            .collect();

        if private_room_ids.is_empty() {
            self.quit_ready = true;
            return;
        }

        // 先经 WebSocket 请求服务器清理各房间的加密会话（失败不影响后续退房）
        for room_id in &private_room_ids {
            self.send_ws_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptLeave {
                    room_id: room_id.as_str(),
                },
            ));
        }
        self.push_notification(self.t("notification_cleanup_started"));

        let Some(event_sender) = self.polling_sender.clone() else {
            self.quit_ready = true;
            return;
        };
        let connector = self.connector.clone();
        let Some(user_id) = self.current_user_id.clone() else {
            self.quit_ready = true;
            return;
        };

        thread::spawn(move || {
            // 等待在线对端完成结束事件的处理与界面更新
            thread::sleep(Duration::from_secs(5));
            for room_id in &private_room_ids {
                let _ = connector.remove_member(room_id, &user_id);
            }
            let _ = event_sender.send(PollingEvent::QuitCleanupFinished);
        });
    }

    /// 主循环查询退出清理是否已完成
    /// 取出并复位"整屏重绘"请求：主循环每帧调用一次，为真时执行 terminal.clear()。
    pub fn take_full_repaint_request(&mut self) -> bool {
        std::mem::take(&mut self.full_repaint_requested)
    }

    pub fn should_quit_now(&self) -> bool {
        self.quit_ready
    }

    /// 离开当前选中的聊天（群聊或私聊均可）：移除自己、发送加密告别并清理本地会话
    fn quit_current_group(&mut self) {
        let Some(room_id) = self.selected_room_id() else {
            self.push_error(self.t("error_no_room_selected"));
            return;
        };
        let is_group = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .map(|room| room.is_group)
            .unwrap_or(false);
        if !is_group {
            // 退出私聊前先经 WebSocket 请求服务器清理加密会话，
            // 让在线对端同步收到结束事件关闭界面，再移除自己退房
            self.send_ws_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptLeave {
                    room_id: room_id.as_str(),
                },
            ));
            self.crypto.sessions.remove(&room_id);
            self.closed_room_ids.insert(room_id.clone());
        }
        self.leave_room(&room_id);
    }

    /// 以当前用户身份退出指定房间并刷新房间列表；身份缺失或请求失败给出通知
    fn leave_room(&mut self, room_id: &str) {
        let Some(user_id) = self.current_user_id.clone() else {
            self.push_error(self.t("error_no_user_id"));
            return;
        };
        match self.connector.remove_member(room_id, &user_id) {
            Ok(_) => {
                // 记录主动退出的房间，避免后续轮询判为“被移出群聊”而误报被踢提示
                self.left_room_ids.insert(room_id.to_string());
                if self.selected_room_id().as_deref() == Some(room_id) {
                    self.messages.clear();
                }
                self.load_rooms();
                self.push_notification(self.t("left_chat"));
            }
            Err(e) => {
                // 房间已被服务器或对端先行删除/主动离开已生效时无需提示，静默完成本地刷新；
                // 私聊退房先发 encrypt_leave 已促使服务器移除成员，随后 remove_member 会报"非成员"
                let error_text = format!("{e}");
                self.left_room_ids.insert(room_id.to_string());
                // "房间不存在/非成员"类预期错误的判定表由接缝按版本集中给出
                let is_expected_gone = self
                    .connector
                    .version()
                    .is_ignorable_room_removal_error(&error_text);
                if !is_expected_gone {
                    self.push_error(format!("{}: {e}", self.t("exit_chat_failed")));
                }
                if self.selected_room_id().as_deref() == Some(room_id) {
                    self.messages.clear();
                }
                self.load_rooms();
            }
        }
    }

    /// 获取当前选中房间的 ID
    fn selected_room_id(&self) -> Option<String> {
        self.rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .map(|room| room.id.clone())
    }

    /// 取私聊房间里"对方"的用户 ID（成员中不是自己的那一个）。
    /// 群聊没有单一对端、或房间内除自己外没有其它成员时返回 None，调用方据此不显示对端状态。
    fn chat_peer_id_of(&self, room: &RoomInfo) -> Option<String> {
        if room.is_group {
            return None;
        }
        room.members
            .iter()
            .find(|member| Some(*member) != self.current_user_id.as_ref())
            .cloned()
    }

    /// 浮层 Esc / 操作完成后的统一退路：所有浮层都从设置菜单进入，
    /// 因此一律退回设置菜单，只有设置菜单自身才退回无浮层状态，
    /// 保证 Esc 是层层回退而不是直接把整层界面关掉。
    fn dismiss_overlay_back(&mut self) {
        self.displaying_overlay =
            if matches!(self.displaying_overlay, DisplayingOverlay::SettingsMenu) {
                DisplayingOverlay::Nothing
            } else {
                DisplayingOverlay::SettingsMenu
            };
        self.restore_chat_focus();
    }

    /// 退回聊天页时把焦点交还消息输入框。
    /// 浮层期间 focus_index 指的是浮层里的输入项或列表位置，
    /// 关浮层后不重置的话，键盘输入会落到一个谁都不持有的 0 号上，表现为"打字没反应"。
    fn restore_chat_focus(&mut self) {
        if self.displaying_overlay == DisplayingOverlay::Nothing {
            self.focus_index = 8;
        }
    }

    /// 本地软关闭一个加密私聊：仅从界面隐藏并清理会话，
    /// 不通知服务器退房，避免对端重连后看到只有一人的残留房间
    fn close_local_room(&mut self, room_id: &str) {
        self.closed_room_ids.insert(room_id.to_string());
        self.crypto.sessions.remove(room_id);
        if let Some(cache) = &self.chat_cache {
            cache.forget_room(room_id);
        }
        let was_selected = self.selected_room_id().as_deref() == Some(room_id);
        self.rooms.retain(|room| room.id != room_id);
        if was_selected {
            self.messages.clear();
            if !self.rooms.is_empty() {
                self.rooms_state.select(Some(0));
                self.load_messages_for_selected_room();
            } else {
                self.rooms_state.select(None);
            }
        }
    }

    fn get_create_group_focused_state(&mut self) -> Option<&mut TextInputState> {
        match self.focus_index {
            0 => Some(&mut self.input_collector.create_group_name_state),
            1 => Some(&mut self.input_collector.create_group_members_state),
            _ => None,
        }
    }

    fn get_create_private_focused_state(&mut self) -> Option<&mut TextInputState> {
        match self.focus_index {
            0 => Some(&mut self.input_collector.create_private_username_state),
            _ => None,
        }
    }

    pub fn ui(&mut self, frame: &mut Frame) {
        // 最底行留给终端，避免任何写入触发滚动（见 drawable_area）
        let area = drawable_area(frame.area());

        // 先整屏铺一层外观背景色：ratatui 的各组件只会"打补丁"式覆盖自身样式
        // （Cell::set_style 仅写入 Some 的字段），因此先铺底即可让所有未显式指定背景的
        // 文本与空白区域统一继承外观里的应用背景色。
        paint_background(frame, area, self.appearance.app_background);

        // 顶栏固定占一行，聊天页、浮层与通知都在它下方绘制；
        // 行文本快照仍按整屏采集，顶栏上的文字同样可以被框选复制
        let [bar_area, body_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        self.render_status_bar(frame, bar_area);

        // 应用恒为单一聊天页：登录/注册改为命令打开的浮层；未登录时聊天页居中显示登录提示。
        self.render_chat_page(frame, body_area);

        match self.displaying_overlay {
            DisplayingOverlay::CreateGroup => self.render_create_group_modal(frame, body_area),
            DisplayingOverlay::CreatePrivate => self.render_create_private_modal(frame, body_area),
            DisplayingOverlay::PendingRequests => self.render_pending_requests(frame, body_area),
            DisplayingOverlay::SettingsMenu => self.render_settings_menu(frame, body_area),
            DisplayingOverlay::LanguageSelect => self.render_language_select(frame, body_area),
            DisplayingOverlay::ServerAddress => self.render_server_address(frame, body_area),
            DisplayingOverlay::Login => self.render_login_modal(frame, body_area),
            DisplayingOverlay::Register => self.render_register_modal(frame, body_area),
            DisplayingOverlay::AppearanceSelect => self.render_appearance_select(frame, body_area),
            DisplayingOverlay::ProfileCard => self.render_profile_card(frame, body_area),
            DisplayingOverlay::Form => self.render_form(frame, body_area),
            DisplayingOverlay::AvatarSelect => self.render_avatar_select(frame, body_area),
            DisplayingOverlay::Nothing => {}
        }

        // 渲染前先移除已到期的通知，再在右上角显示剩余通知
        self.remove_expired_notifications();
        if !self.notifications.is_empty() {
            self.render_notifications(frame, body_area);
        }

        // 在全部元素绘制完成后采集整屏行文本快照，框选松开时才能复制到任意位置的文本
        self.screen_text_rows = collect_screen_text_rows(&*frame.buffer_mut(), area);

        // 框选高亮最后绘制，保证它盖在浮层与通知之上依然可见
        if let Some(selection_start) = self.input_collector.selection_start {
            let selection_end = self
                .input_collector
                .selection_end
                .unwrap_or(selection_start);
            paint_screen_selection(
                frame,
                area,
                selection_start,
                selection_end,
                &self.appearance,
            );
        }

        // 将硬件光标定位到当前聚焦输入框处
        self.place_cursor(frame);
    }

    /// 将终端硬件光标定位到当前聚焦的输入框光标处；
    /// rat-text 仅在输入框标记为聚焦时返回可见光标位置，故先置位聚焦标志
    fn place_cursor(&mut self, frame: &mut Frame) {
        let screen_area = drawable_area(frame.area());
        // 钳制到屏幕内：光标位置一旦落到缓冲区之外（长文本把 caret 顶过最后一行等），
        // 终端会因越界写自动上滚一行，而渲染缓冲区并不跟着滚动，整块界面就此错位且不再恢复
        let clamp_position = |position: Position| {
            Position::new(
                position.x.min(screen_area.width.saturating_sub(1)),
                position.y.min(screen_area.height.saturating_sub(1)),
            )
        };
        // 聊天页无弹窗时聚焦多行消息输入框，单独经 TextAreaState 处理
        if self.displaying_overlay == DisplayingOverlay::Nothing {
            self.input_collector.message_input_state.focus.set(true);
            if let Some((x, y)) = self.input_collector.message_input_state.screen_cursor() {
                frame.set_cursor_position(clamp_position(Position::new(x, y)));
            }
            return;
        }
        if let Some(state) = self.get_focused_state() {
            state.focus.set(true);
            if let Some((x, y)) = state.screen_cursor() {
                frame.set_cursor_position(clamp_position(Position::new(x, y)));
            }
        }
    }

    fn copy_message_selection(&mut self) {
        let cursor = self.input_collector.message_input_state.cursor();
        let selected = self.input_collector.message_input_state.selected_text();
        // 仅在实际框选了非空文本时尝试写入系统剪贴板并提示
        if !selected.is_empty()
            && let Ok(mut clipboard) = arboard::Clipboard::new()
            && clipboard.set_text(selected).is_ok()
        {
            self.push_notification(self.t("copied_to_clipboard"));
        }
        // 复制后取消框选：将锚点移回光标处，使选中高亮消失
        self.input_collector
            .message_input_state
            .set_cursor(cursor, false);
    }

    /// 处理一次括号粘贴：把整段文本原样插入当前聚焦的输入框，
    /// 消息输入框按行插入（换行保持为框内多行，绝不触发发送），
    /// 其余单行输入框只取首行内容。
    fn handle_pasted_text(&mut self, pasted_text: &str) {
        if pasted_text.is_empty() {
            return;
        }
        let pasted_text = normalize_pasted_text(pasted_text);
        if pasted_text.is_empty() {
            return;
        }
        let focus_on_message_box = self.displaying_overlay == DisplayingOverlay::Nothing;
        if focus_on_message_box {
            let mut lines = pasted_text.split('\n').peekable();
            while let Some(line) = lines.next() {
                self.input_collector.message_input_state.insert_str(line);
                if lines.peek().is_some() {
                    self.input_collector.message_input_state.insert_newline();
                }
            }
            self.handle_message_input_changed();
            return;
        }
        // 单行输入框（登录、注册、建群等）不保留换行，只取粘贴内容的首行插到光标处
        let first_line = pasted_text.lines().next().unwrap_or_default();
        if let Some(state) = self.get_focused_state() {
            let insert_position = state.value.cursor();
            let _ = state.value.insert_str(insert_position, first_line);
        }
    }

    /// 复制整屏框选矩形内的文本到系统剪贴板并清除框选高亮。
    /// 文本取自上一帧采集的整屏行文本快照，因此浮层、通知、房间列表等任意位置都可复制；
    /// 按显示宽度切列，双宽字符整块保留，行尾空格与整行为空的首尾行会被去掉。
    /// 整屏框选的鼠标处理：起点在消息输入框之外时开始记录，拖拽更新终点，松开即复制。
    /// 因为本方法在浮层分派之前被调用，所以房间列表、消息区、顶栏、任何浮层与通知
    /// 之上的文字都能框选复制；显示区的边框不算文字（见 `is_content_character`），
    /// 既不会被高亮也不会进剪贴板。返回真值表示事件已被框选消费（拖拽与松手）。
    fn handle_screen_selection_mouse(&mut self, mouse: crossterm::event::MouseEvent) -> bool {
        let pointer = (mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left)
                if !self
                    .message_input_area
                    .contains(ratatui::layout::Position::new(mouse.column, mouse.row)) =>
            {
                // 只记下起点，事件继续走原有的点击聚焦分发；
                // 起点与终点重合时尚不构成框选，松手也不会触发复制
                self.input_collector.selection_start = Some(pointer);
                self.input_collector.selection_end = Some(pointer);
                false
            }
            MouseEventKind::Drag(crossterm::event::MouseButton::Left)
                if self.input_collector.selection_start.is_some() =>
            {
                self.input_collector.selection_end = Some(pointer);
                true
            }
            MouseEventKind::Up(crossterm::event::MouseButton::Left)
                if self.input_collector.selection_start.is_some() =>
            {
                let dragged = self
                    .input_collector
                    .selection_start
                    .is_some_and(|start| start != pointer);
                self.input_collector.selection_end = Some(pointer);
                if dragged {
                    self.copy_screen_selection();
                } else {
                    // 原地按下没拖动：只清掉框选起点，不复制、不提示
                    self.input_collector.selection_start = None;
                    self.input_collector.selection_end = None;
                }
                true
            }
            _ => false,
        }
    }

    fn copy_screen_selection(&mut self) {
        let (selection_start, selection_end) = match (
            self.input_collector.selection_start,
            self.input_collector.selection_end,
        ) {
            (Some(start), Some(end)) => (start, end),
            _ => {
                self.input_collector.selection_start = None;
                self.input_collector.selection_end = None;
                return;
            }
        };
        let selected_text =
            extract_selected_screen_text(&self.screen_text_rows, selection_start, selection_end);

        self.input_collector.selection_start = None;
        self.input_collector.selection_end = None;
        if selected_text.is_empty() {
            return;
        }
        if let Ok(mut clipboard) = arboard::Clipboard::new()
            && clipboard.set_text(selected_text).is_ok()
        {
            self.push_notification(self.t("copied_to_clipboard"));
        }
    }

    /// 清空浮层区域并立刻在该区域重铺应用背景色。
    /// Clear 会把区域内单元格样式复位，不补这一层时浮层内部会露出终端默认底色，与主题不一致。
    fn clear_overlay_area(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        paint_background(frame, area, self.appearance.app_background);
    }

    /// 渲染顶栏：左侧连接状态与当前用户，右侧服务端版本与客户端版本。
    /// 连接标记同时承担"连不上服务器"的持续提示（报错只在状态跳变时弹一次），
    /// 未登录不显示当前用户，未连上服务端不显示服务端版本。
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let online = self.connection_ready.unwrap_or(false);
        let (connection_label, mark, user_text, right_text) = self.status_bar_texts();
        // 左侧整段的纯文本先拼出来，量宽度用（下面的分栏要按两段的实际宽度决定谁让位）
        let left_plain_text = format!("{connection_label} {mark}{user_text}");
        // 标记紧跟"连接"二字并单独着色：用户名一长就把圆点推到行尾的话，
        // 它就再也表示不了连接状态，所以这里固定按"标签 标记 用户段"的顺序拼
        let left_line = Line::from(vec![
            Span::styled(
                format!("{connection_label} "),
                hint_style(self.appearance.hint_text),
            ),
            Span::styled(
                mark,
                Style::default()
                    .fg(if online {
                        self.appearance.own_username_text
                    } else {
                        self.appearance.notice_error_border
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(user_text, hint_style(self.appearance.hint_text)),
        ]);
        let right_line = Line::from(Span::styled(
            right_text.clone(),
            hint_style(self.appearance.hint_text),
        ));
        // 一行放不下两段时优先保左侧：连接标记与"当前用户"表示的是现在能不能用、
        // 以什么身份在用，版本信息只是参考。原先按右侧定尺会让窄终端把用户名整段挤掉。
        let left_width = display_width(&left_plain_text);
        let right_width = display_width(&right_text) + 1;
        let left_reserve = if left_width + right_width <= area.width {
            area.width.saturating_sub(right_width)
        } else {
            left_width.min(area.width)
        };
        let [left_area, right_area] =
            Layout::horizontal([Constraint::Length(left_reserve), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(left_line).style(Style::default().bg(self.appearance.app_background)),
            left_area,
        );
        frame.render_widget(
            Paragraph::new(right_line)
                .alignment(Alignment::Right)
                .style(Style::default().bg(self.appearance.app_background)),
            right_area,
        );
    }

    /// 顶栏四段文本：(连接标签, 连接标记, 当前用户段, 右侧版本信息)。
    /// 拆成四段是为了把标记夹在"连接"与用户名之间并单独着色，
    /// 也便于在没有真实服务端的情况下断言显示规则：
    /// 未登录不显示用户名，未连上服务端不显示服务端版本，客户端版本始终显示。
    fn status_bar_texts(&self) -> (String, String, String, String) {
        let online = self.connection_ready.unwrap_or(false);
        let mark = if online { "●" } else { "○" };
        let mut user_text = String::new();
        if self.is_logged_in() && !self.current_username.is_empty() {
            user_text = format!(
                "  |  {} {}",
                self.t("bar_current_user"),
                self.current_username
            );
        }
        let server_version = self.connector.server_version_text();
        let mut right_parts: Vec<String> = Vec::new();
        if online && !server_version.is_empty() {
            right_parts.push(format!(
                "{}: {server_version}",
                self.t("bar_server_version")
            ));
        }
        right_parts.push(format!(
            "{}: {}",
            self.t("bar_client_version"),
            Self::client_version()
        ));
        (
            self.t("bar_connection"),
            mark.to_string(),
            user_text,
            right_parts.join("  |  "),
        )
    }

    /// 渲染通用表单浮层：标题一行一个字段，左侧标签、右侧输入框，最后一项回车提交。
    /// 四类表单（个人资料、修改密码、修改头像、注销账户）字段数量不同，
    /// 面板高度按字段数算，标签列宽按当前语言里最宽的标签算，避免出现横向滚动或截断。
    /// 渲染通用表单浮层。窗口风格与其它浮层一致（同一 overlay_border）。
    /// 输入条目不少于三个时用 `> 标签 内容` 的箭头行（昵称/手机号/简介、旧密码/新密码/确认）；
    /// 一两个条目的（修改头像、删除账户）沿用原来的方框输入框。
    fn render_form(&mut self, frame: &mut Frame, area: Rect) {
        // 先把需要读 self 的内容取成自有值，渲染期要可变借用表单字段状态
        let Some((action, fields)) = &self.active_form else {
            return;
        };
        let field_count = fields.len();
        let secret_flags: Vec<bool> = fields.iter().map(|field| field.secret).collect();
        let labels: Vec<String> = fields
            .iter()
            .map(|field| self.t(&field.label_key))
            .collect();
        let title = self.t(&form_definition(action).0);
        let hint = self.t(&form_hint_key(action));
        let appearance = self.appearance.clone();
        let focused = self.focus_index;
        // 三个及以上条目走箭头行：一行一项，比三个方框叠起来省一半高度
        let arrow_rows = field_count >= 3;
        // 先把面板宽度定死（含夹到屏幕内），提示的折行与面板高度都按这个宽度算
        let panel_width = 60u16
            .min(area.width.saturating_sub(2))
            .max(30)
            .min(area.width.max(1));
        let hint_text = wrapped_hint_text(
            &hint,
            hint_style(appearance.hint_text),
            panel_width.saturating_sub(4),
        );
        let hint_lines = hint_text.lines.len().max(1) as u16;
        let needed_height = if arrow_rows {
            field_count as u16 + 3 + hint_lines
        } else {
            field_count as u16 * 4 + 3 + hint_lines
        };
        let panel_height = needed_height
            .min(area.height.saturating_sub(2))
            .max(if arrow_rows { 6 } else { 8 });
        let panel_rect = centered_rect(panel_width, panel_height, area);
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(overlay_frame_block(&appearance, &title), panel_rect);

        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 2,
        });
        if arrow_rows {
            self.render_arrow_form_rows(frame, &labels, &secret_flags, inner, hint_text);
            return;
        }
        // 方框形态：每个输入框占三行，框间留一行，最后一行给提示
        let rows = Layout::vertical(
            (0..field_count)
                .map(|_| Constraint::Length(3))
                .chain(std::iter::once(Constraint::Length(hint_lines)))
                .chain(std::iter::once(Constraint::Min(0)))
                .collect::<Vec<Constraint>>(),
        )
        .split(inner);
        for index in 0..field_count {
            // 与箭头行形态同一口径：当前项用正文色加粗，其余用提示色，都不碰选中色
            let field_style = if index == focused {
                Style::default()
                    .fg(appearance.input_text)
                    .add_modifier(Modifier::BOLD)
            } else {
                hint_style(appearance.hint_text)
            };
            render_box_field(
                &appearance,
                frame,
                rows[index],
                Line::from(Span::styled(format!(" {} ", labels[index]), field_style)),
                appearance.form_field_border(),
                secret_flags[index],
                &mut self
                    .active_form
                    .as_mut()
                    .expect("表单浮层显示期间表单必定存在")
                    .1[index]
                    .state,
            );
        }
        if let Some(hint_row) = rows.get(field_count) {
            frame.render_widget(
                Paragraph::new(hint_text).style(Style::default().bg(appearance.app_background)),
                *hint_row,
            );
        }
    }

    /// 箭头行形态的表单主体：左侧 `> 标签`（当前项选中色加粗，其余用提示色），
    /// 右侧同一行是无边框输入区。上下方向键与 Tab 都用来切换当前项。
    fn render_arrow_form_rows(
        &mut self,
        frame: &mut Frame,
        labels: &[String],
        secret_flags: &[bool],
        inner: Rect,
        hint: Text<'static>,
    ) {
        let appearance = self.appearance.clone();
        let field_count = labels.len();
        let hint_lines = hint.lines.len().max(1) as u16;
        let rows = Layout::vertical(
            (0..field_count)
                .map(|_| Constraint::Length(1))
                .chain(std::iter::once(Constraint::Length(hint_lines)))
                .chain(std::iter::once(Constraint::Min(0)))
                .collect::<Vec<Constraint>>(),
        )
        .split(inner);
        let label_width = labels
            .iter()
            .map(|label| display_width(label))
            .max()
            .unwrap_or(0)
            .saturating_add(4)
            .min(inner.width.saturating_sub(6))
            .max(6);
        for index in 0..field_count {
            let [label_area, input_area] =
                Layout::horizontal([Constraint::Length(label_width), Constraint::Fill(1)])
                    .areas(rows[index]);
            let is_focused = self.focus_index == index;
            let marker = if is_focused { ">" } else { " " };
            // 当前项用输入正文色加粗，其余用提示色；都不使用"选中文本色"
            let label_style = if is_focused {
                Style::default()
                    .fg(appearance.input_text)
                    .add_modifier(Modifier::BOLD)
            } else {
                hint_style(appearance.hint_text)
            };
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("{marker} {}", labels[index]),
                    label_style,
                )))
                .style(Style::default().bg(appearance.app_background)),
                label_area,
            );
            render_plain_field(
                &appearance,
                frame,
                input_area,
                secret_flags[index],
                &mut self
                    .active_form
                    .as_mut()
                    .expect("表单浮层显示期间表单必定存在")
                    .1[index]
                    .state,
            );
        }
        if let Some(hint_row) = rows.get(field_count) {
            frame.render_widget(
                Paragraph::new(hint).style(Style::default().bg(appearance.app_background)),
                *hint_row,
            );
        }
    }

    /// 渲染个人资料卡片：左侧头像块（半块字符真色绘制），右侧依次是
    /// 真名、昵称（没有就整行不显示）、UID、在线状态、邮箱、手机号、简介、头像；
    /// 后四项没有值时显示"无"。头像若是服务端上传得到的相对路径，按规范显示成"本地"。
    /// 邮箱与手机号只有查自己且登录响应给过时才有值 —— 别人的资料接口不返回这两项。
    fn render_profile_card(&mut self, frame: &mut Frame, area: Rect) {
        let Some(profile) = self.profile_view.clone() else {
            return;
        };
        let max_avatar_columns = profile_avatar_cells().0;
        let title = self.t("profile_title");
        let none_text = self.t("profile_none");
        let is_self = Some(profile.id.as_str()) == self.current_user_id.as_deref();
        let online_label = match self.presence_by_user.get(&profile.id).copied() {
            Some(true) => self.t("presence_online"),
            Some(false) => self.t("presence_offline"),
            None => self.t("presence_unknown"),
        };
        // 邮箱与手机号只在"看自己且登录响应给过"时可得，其余一律按"无"处理
        let (email, phone_number) = match (&self.own_contact, is_self) {
            (Some(contact), true) => (contact.0.clone(), contact.1.clone()),
            _ => (String::new(), String::new()),
        };
        let value_or_none = |value: String| {
            if value.is_empty() {
                none_text.clone()
            } else {
                value
            }
        };
        let avatar_text = match profile.avatar.clone() {
            None => none_text.clone(),
            Some(path) if path.is_empty() => none_text.clone(),
            // 服务端把上传的头像存成 /static/avatars/xxx.png 这类相对路径
            Some(path) if path.starts_with('/') => self.t("profile_avatar_local"),
            Some(path) => path,
        };
        let mut body_lines = vec![Line::from(Span::styled(
            profile.username.clone(),
            Style::default()
                .fg(self.appearance.own_username_text)
                .add_modifier(Modifier::BOLD),
        ))];
        if let Some(nickname) = profile.nickname.clone().filter(|value| !value.is_empty()) {
            body_lines.push(Line::from(format!(
                "{}: {nickname}",
                self.t("profile_nickname_label")
            )));
        }
        for (label, value) in [
            (self.t("profile_uid"), profile.id.clone()),
            (self.t("presence_state"), online_label),
            (self.t("profile_email_label"), value_or_none(email)),
            (self.t("profile_phone_label"), value_or_none(phone_number)),
            (
                self.t("profile_bio_label"),
                value_or_none(profile.bio.clone().unwrap_or_default()),
            ),
            (self.t("profile_avatar_url"), avatar_text),
        ] {
            body_lines.push(Line::from(format!("{label}: {value}")));
        }
        body_lines.push(Line::from(""));
        body_lines.push(Line::from(Span::styled(
            self.t("profile_close_hint"),
            hint_style(self.appearance.hint_text),
        )));
        let body = Text::from(body_lines);

        // 面板宽度只能压到屏幕以内，正文再按可用宽度折行：
        // 原先固定 40 列下限且不折行，窄终端上 UID、邮箱、头像链接这类长单行会被右边界切掉
        let appearance = self.appearance.clone();
        let screen_width = area.width.saturating_sub(2);
        // 面板宽度下限要能容下"满格头像 + 一栏正文"：否则昵称/简介一短，
        // 面板就跟着变窄，头像被降档到很小的一块（正文长时不受影响）
        let text_minimum = 24u16;
        let width_floor = (max_avatar_columns as u16 + 5 + text_minimum + 4)
            .min(screen_width.max(1))
            .max(24u16.min(screen_width.max(1)));
        let panel_width = (body.width() as u16 + 4).clamp(width_floor, screen_width.max(1));
        // 头像列最多占面板一半，且必须"列 = 2×行"：窄面板上整体降档，不把圆脸压成竖条
        let (avatar_columns, avatar_rows) = avatar_grid_within(
            (panel_width / 2).max(2),
            area.height.saturating_sub(4).max(1),
        );
        let avatar_columns = avatar_columns as usize;
        let pixels = self.avatar_pixels_at(&profile.id, avatar_columns, avatar_rows as usize);
        let body_text_width = panel_width.saturating_sub(avatar_columns as u16 + 5).max(8);
        let body = wrap_profile_fields(body, body_text_width);
        let body_height: u16 = body
            .lines
            .iter()
            .map(|line| (line.width() as u16).div_ceil(body_text_width).max(1))
            .sum();
        let panel_height = (body_height.max(avatar_rows) + 4)
            .min(area.height.saturating_sub(2))
            .max(8);
        let panel_rect = centered_rect(panel_width, panel_height, area);
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(overlay_frame_block(&appearance, &title), panel_rect);
        let inner = panel_rect.inner(Margin {
            horizontal: 2,
            vertical: 1,
        });
        let [picture_area, text_area] = Layout::horizontal([
            Constraint::Length(avatar_columns as u16 + 1),
            Constraint::Fill(1),
        ])
        .areas(inner);
        // 图片按网格自身的行数画，多余的高度留给下面（画满 inner 会把比例再拉歪一次）
        let picture_area = Rect::new(
            picture_area.x,
            picture_area.y,
            avatar_columns as u16,
            avatar_rows,
        );
        // 头像占位与真图共用同一块区域：图片到位后只是把这块画满，右侧文字位置不动
        match pixels {
            Some(pixels) => pixels.paint(frame, picture_area, appearance.app_background),
            None => paint_avatar_placeholder(
                frame,
                picture_area,
                &profile.username,
                &appearance,
                &profile.id,
            ),
        }
        frame.render_widget(
            Paragraph::new(body).style(Style::default().bg(appearance.app_background)),
            text_area,
        );
    }

    /// 居中渲染登录浮层：用户名与密码（星号遮蔽）两个输入框。
    /// 浮层只保留输入框与提交，Tab/Enter/Esc 属通用键，按快捷键提示规范不再单独占一行提示。
    fn render_login_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_rect = centered_rect(
            50u16.min(area.width.saturating_sub(4)).max(30),
            11u16.min(area.height.saturating_sub(4)).max(9),
            area,
        );
        self.clear_overlay_area(frame, panel_rect);
        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 2,
        });
        let name_rect = Rect::new(inner.x, inner.y, inner.width, 3);
        let password_rect = Rect::new(inner.x, inner.y + 4, inner.width, 3);
        let appearance = self.appearance.clone();
        render_box_field(
            &appearance,
            frame,
            name_rect,
            Line::from(Span::raw(self.t("label_username"))),
            appearance.login_field_border(self.focus_index == 0),
            false,
            &mut self.input_collector.login_name_state,
        );
        render_box_field(
            &appearance,
            frame,
            password_rect,
            Line::from(Span::raw(self.t("label_password"))),
            appearance.login_field_border(self.focus_index == 1),
            true,
            &mut self.input_collector.login_password_state,
        );
        let title = self.t("page_login");
        frame.render_widget(overlay_frame_block(&appearance, &title), panel_rect);
    }

    /// 居中渲染注册浮层：用户名、邮箱、密码（星号遮蔽）三个输入框。
    /// 同登录浮层，Tab/Enter/Esc 属通用键不再提示，故去掉底部提示行并收窄面板。
    fn render_register_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_rect = centered_rect(50, 14, area);
        self.clear_overlay_area(frame, panel_rect);

        // 输入框正文文本颜色由外观给出
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("page_register")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));
        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let focus_style = Style::default()
            .fg(self.appearance.selected_text)
            .add_modifier(Modifier::BOLD);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);

        let name_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_username")))
            .border_style(if self.focus_index == 0 {
                focus_style
            } else {
                Style::default().fg(self.appearance.input_border)
            });
        let email_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_email")))
            .border_style(if self.focus_index == 1 {
                focus_style
            } else {
                Style::default().fg(self.appearance.input_border)
            });
        let pwd_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_password")))
            .border_style(if self.focus_index == 2 {
                focus_style
            } else {
                Style::default().fg(self.appearance.input_border)
            });

        TextInput::new()
            .style(input_text_style)
            .block(name_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .render(
                Rect::new(inner.x, inner.y, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_name_state,
            );
        TextInput::new()
            .style(input_text_style)
            .block(email_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .render(
                Rect::new(inner.x, inner.y + 4, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_email_state,
            );
        TextInput::new()
            .style(input_text_style)
            .block(pwd_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .passwd()
            .render(
                Rect::new(inner.x, inner.y + 8, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_password_state,
            );

        frame.render_widget(block, panel_rect);
    }

    fn render_chat_page(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        // 未登录时聊天窗口照常显示（不遮盖），仅通过一次性弹窗提示登录/注册，
        // 并在各受保护操作入口拒绝未登录调用。
        self.render_room_list(frame, chunks[0]);
        self.render_chat_area(frame, chunks[1]);
    }

    fn render_room_list(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(format!(" {} ", self.t("rooms")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.room_border));

        let items: Vec<ListItem> = self
            .rooms
            .iter()
            .enumerate()
            .map(|(i, room)| {
                let name = room
                    .name
                    .clone()
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                let style = if self.rooms_state.selected() == Some(i) {
                    Style::default()
                        .fg(self.appearance.selected_text)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(self.appearance.message_text)
                };
                // 非选中房间若有未读消息，在名称后追加红色 (数量)
                let unread = if self.rooms_state.selected() == Some(i) {
                    0
                } else {
                    self.unread_counts.get(&room.id).copied().unwrap_or(0)
                };
                let mut spans = vec![Span::styled(name, style)];
                // 私聊在名称后标注对端在线状态：实心点在线、空心点离线，
                // 服务端从未广播过该成员（无在线名单基线）时不标注，避免把未知显示成离线
                if let Some(peer_id) = self.chat_peer_id_of(room) {
                    let presence_mark = match self.presence_by_user.get(&peer_id) {
                        Some(true) => {
                            Some(("●", Style::default().fg(self.appearance.own_username_text)))
                        }
                        Some(false) => Some(("○", Style::default().fg(self.appearance.hint_text))),
                        None => None,
                    };
                    if let Some((mark, mark_style)) = presence_mark {
                        spans.push(Span::styled(format!(" {mark}"), mark_style));
                    }
                }
                if unread > 0 {
                    // 免打扰房间未读数一律显示为点（·），其余显示具体数量（超过 99 显示 99+）
                    let suffix = if self.muted_room_ids.contains(&room.id) {
                        "(·)".to_string()
                    } else if unread > 99 {
                        "(99+)".to_string()
                    } else {
                        format!("({})", unread)
                    };
                    spans.push(Span::styled(
                        suffix,
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("► ");

        frame.render_stateful_widget(list, area, &mut self.rooms_state);
    }

    fn render_chat_area(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(5),
            Constraint::Length(3),
        ])
        .split(area);

        self.render_messages(frame, chunks[0]);
        self.render_message_input(frame, chunks[1]);

        // 输入以 / 开头时在输入框上方显示命令自动补全面板
        let input_text = self.input_collector.message_input_state.text();
        if let Some(command_prefix) = input_text.strip_prefix('/') {
            self.render_command_completions(frame, chunks[1], command_prefix);
        }

        // 快捷键提示随输入模式切换：组合键必须提示，Tab/Enter/Esc 这类通用键不再提示
        let hint_key = if input_text.starts_with('#') {
            "search_hint"
        } else if input_text.starts_with('/') {
            "command_hint"
        } else {
            "message_hint"
        };
        let hint = Paragraph::new(Text::raw(self.t(hint_key)))
            .alignment(Alignment::Center)
            .style(Style::default().fg(self.appearance.hint_text));
        frame.render_widget(hint, chunks[2]);
    }

    /// 在输入框上方渲染命令补全列表，上下键选择、回车插入选中项
    fn render_command_completions(
        &mut self,
        frame: &mut Frame,
        input_area: Rect,
        raw_prefix: &str,
    ) {
        let candidates = self.completion_candidates(raw_prefix);
        if candidates.is_empty() {
            return;
        }
        if self
            .command_list_state
            .selected()
            .is_none_or(|index| index >= candidates.len())
        {
            self.command_list_state.select(Some(0));
        }
        // 成员/语言/外观等参数补全列表可能较长，允许更高面板；命令名补全保持紧凑
        let max_height = if raw_prefix.starts_with("kick ")
            || raw_prefix.starts_with("language ")
            || raw_prefix.starts_with("appearance ")
            || raw_prefix.starts_with("profile ")
        {
            12
        } else {
            7
        };
        let popup_width = input_area.width.saturating_sub(2);
        // 边框 2 列 + 高亮符号 2 列
        let body_width = popup_width.saturating_sub(6).max(1);
        let candidate_lines: Vec<Vec<Line<'static>>> = candidates
            .iter()
            .map(|(_, label, description)| {
                completion_lines(
                    label,
                    description,
                    Style::default().fg(self.appearance.selected_text),
                    Style::default().fg(self.appearance.hint_text),
                    body_width,
                )
            })
            .collect();
        let total_lines: u16 = candidate_lines.iter().map(|lines| lines.len() as u16).sum();
        let popup_height = (total_lines + 2).min(max_height);
        let popup_y = input_area.y.saturating_sub(popup_height);
        let popup_rect = Rect::new(input_area.x + 1, popup_y, popup_width, popup_height);

        let items: Vec<ListItem> = candidate_lines.into_iter().map(ListItem::new).collect();

        let title_key = if raw_prefix.starts_with("kick ") {
            "member_select_title"
        } else if raw_prefix.starts_with("language ") {
            "select_language_title"
        } else if raw_prefix.starts_with("appearance ") {
            "appearance_select_title"
        } else if raw_prefix.starts_with("profile ") || raw_prefix.starts_with("search_users ") {
            "user_select_title"
        } else {
            "command_list"
        };
        let popup_block = Block::default()
            .title(format!(" {} ", self.t(title_key)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.command_border));
        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("► ");
        // 缓冲区为叠加式渲染，先清空面板区域防止下层文字透出
        self.clear_overlay_area(frame, popup_rect);
        frame.render_widget(popup_block, popup_rect);
        frame.render_stateful_widget(
            list,
            popup_rect.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.command_list_state,
        );
    }

    /// 渲染消息显示区：按显示宽度预折行，右侧滚动条，滚轮与贴底跟随由反向滚动偏移驱动
    fn render_messages(&mut self, frame: &mut Frame, area: Rect) {
        let mut title_spans: Vec<Span> = match self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
        {
            Some(room) => {
                let name = room
                    .name
                    .clone()
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                vec![Span::raw(format!(" {} ({}) ", name, room.members.len()))]
            }
            None => vec![Span::raw(format!(" {} ", self.t("chat_history")))],
        };
        // 输入状态指示：把本房间 2 秒衰减窗口内的成员名追加到消息区标题栏，
        // 不占用消息行也不打断阅读（客户端只在标题栏这一处显示输入状态）
        let selected_room_id = self.selected_room_id();
        let mut typing_names: Vec<String> = Vec::new();
        for (room_id, username, _) in &self.typing_members {
            if Some(room_id) != selected_room_id.as_ref() {
                continue;
            }
            // 同名成员（多账号或重连产生的重复记录）只显示一次，
            // 否则标题会先出现两个相同名字、过期一条后再变回一个
            if !typing_names.contains(username) {
                typing_names.push(username.clone());
            }
        }
        if !typing_names.is_empty() {
            let typing_text = if typing_names.len() == 1 {
                self.t("typing_one").replace("{username}", &typing_names[0])
            } else {
                self.t("typing_multiple")
                    .replace("{names}", &typing_names.join(", "))
            };
            title_spans.push(Span::styled(
                typing_text,
                Style::default().fg(self.appearance.hint_text),
            ));
        }

        let block = Block::default()
            .title(Line::from(title_spans))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.message_border));

        let inner = area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 1,
        });
        // 右侧留一列绘制滚动条
        let text_width = inner.width.saturating_sub(1).max(1);
        let scroll_area = Rect {
            x: inner.x + inner.width.saturating_sub(1),
            y: inner.y,
            width: 1,
            height: inner.height,
        };

        let (lines, message_first_lines) = self.build_message_lines(text_width);
        let total_lines = lines.len() as u16;
        let visible_height = inner.height.max(1);
        let max_scroll_y = total_lines.saturating_sub(visible_height);

        // 搜索模式切换匹配项后把命中消息滚入视口：顶部对齐并留一行余量，再按可滚范围夹取。
        // 消息在列表中的下标可能因"更早消息"前插而变化，故按消息 ID 定位而非缓存下标。
        let mut scrolled_to_match = false;
        if let Some(target_id) = self.pending_scroll_message_id.take() {
            let target_index = self
                .messages
                .iter()
                .position(|message| message.id == target_id);
            if let Some(Some(first_line)) =
                target_index.map(|index| message_first_lines.get(index).copied())
            {
                let desired_scroll_y =
                    (first_line.saturating_sub(1)).min(usize::from(max_scroll_y));
                self.messages_scroll_from_bottom = max_scroll_y - desired_scroll_y as u16;
                scrolled_to_match = true;
            }
        }
        // 反向偏移夹取到可滚动范围并回写，0 表示贴底跟随最新消息
        self.messages_scroll_from_bottom = self.messages_scroll_from_bottom.min(max_scroll_y);
        let scroll_y = max_scroll_y - self.messages_scroll_from_bottom;

        // 用户滚到消息显示区顶部（偏移离开底部且已抵到最大可滚位置）且服务器仍有更早消息时，
        // 自动拉取一批；前插后总行数增大使 scroll_y 离开顶部，天然避免逐帧重复拉取。
        // 守卫：消息列表必须确实属于当前选中房间（切房加载未完成/失败时列表与选中可能错位），
        // 防止拿旧房间的残留偏移与游标误拉他房更早历史；本帧刚定位过匹配项时不拉取，
        // 否则前插会使行号整体位移，定位结果被冲掉
        let selected_room_id = self.selected_room_id();
        let list_matches_room = self
            .messages
            .last()
            .is_some_and(|message| Some(&message.room_id) == selected_room_id.as_ref());
        if self.messages_scroll_from_bottom > 0
            && scroll_y == 0
            && list_matches_room
            && !scrolled_to_match
        {
            debug_log(&format!(
                "触顶自动拉取 room={selected_room_id:?} offset={}",
                self.messages_scroll_from_bottom
            ));
            self.load_older_messages();
        }

        let paragraph = Paragraph::new(Text::from(lines)).scroll((scroll_y, 0));
        let paragraph_area = Rect {
            width: inner.width.saturating_sub(1),
            ..inner
        };
        frame.render_widget(paragraph, paragraph_area);

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(None);
        let mut scrollbar_state =
            ScrollbarState::new(max_scroll_y as usize).position(scroll_y as usize);
        frame.render_stateful_widget(scrollbar, scroll_area, &mut scrollbar_state);

        frame.render_widget(block, area);
    }

    /// 构建消息显示区的渲染行。
    /// 返回 (渲染行列表, 每条消息首行在列表中的行号)，两个向量的消息顺序一一对应；
    /// 行号供搜索模式把命中消息滚入视口使用（只有这里能算出折行后的真实行号）。
    /// 处于搜索模式且关键词生效时，命中片段套用外观里的搜索命中背景色。
    fn build_message_lines(&self, text_width: u16) -> (Vec<Line<'static>>, Vec<usize>) {
        let current_user_id = self.current_user_id.as_deref().unwrap_or("");
        let keyword = self.active_search_keyword();
        // 当前定位到的那一条匹配项：命中的那条消息用另一个背景色，与其余命中区分开
        let current_match_message_id: Option<String> = keyword.as_ref().and_then(|_| {
            self.search_result
                .as_ref()
                .and_then(|(_, matched, selected)| matched.get(*selected).cloned())
        });
        let body_style = Style::default().fg(self.appearance.message_text);
        let match_style = Style::default()
            .fg(contrasting_foreground(
                self.appearance.search_match_background,
            ))
            .bg(self.appearance.search_match_background);
        let current_match_style = Style::default()
            .fg(contrasting_foreground(
                self.appearance.search_current_match_background,
            ))
            .bg(self.appearance.search_current_match_background);
        let mut lines: Vec<Line> = Vec::new();
        let mut message_first_lines: Vec<usize> = Vec::new();
        let mut last_time_key: Option<String> = None;
        for message in &self.messages {
            // 时间头：与上一条消息同分钟则隐藏，跨分钟才插入居中时间条
            if let Some(time_text) = format_message_time(&message.created_at, self.time_with_date)
                && last_time_key.as_deref() != Some(time_text.as_str())
            {
                lines.push(
                    Line::from(Span::styled(
                        time_text.clone(),
                        Style::default().fg(self.appearance.time_text),
                    ))
                    .alignment(Alignment::Center),
                );
                last_time_key = Some(time_text);
            }
            let is_own = message.sender_id == current_user_id;
            let sender_name = if is_own {
                self.t("self_name").to_string()
            } else {
                self.sender_display_name(&message.sender_id)
            };
            // 注销过的发言人没有 ID 可展示，只留"未知用户"
            let display_sender = if self.show_uid && !sender_name.is_empty() {
                format!("{} ({})", sender_name, message.sender_id)
            } else {
                sender_name
            };
            let name_style = if is_own {
                Style::default()
                    .fg(self.appearance.own_username_text)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.appearance.other_username_text)
            };
            let alignment = if is_own {
                Alignment::Right
            } else {
                Alignment::Left
            };
            // 行号向量记录的是首行正文：复制选区与搜索定位都按"正文块"划分，
            // 把用户名行算进去会改变它们的边界
            for piece in wrap_by_display_width(&display_sender, text_width) {
                lines.push(Line::from(Span::styled(piece, name_style)).alignment(alignment));
            }
            message_first_lines.push(lines.len());
            let message_match_style = if Some(&message.id) == current_match_message_id.as_ref() {
                current_match_style
            } else {
                match_style
            };
            for source_line in message.content.split('\n') {
                let segments = match keyword.as_deref() {
                    Some(keyword) => {
                        split_line_by_keyword(source_line, keyword, body_style, message_match_style)
                    }
                    None => vec![(source_line.to_string(), body_style)],
                };
                for line in wrap_styled_segments(&segments, text_width) {
                    lines.push(line.alignment(alignment));
                }
            }
        }
        (lines, message_first_lines)
    }

    /// 当前生效的搜索关键词：仅当输入框处于搜索模式（以 # 开头）、已执行过搜索，
    /// 且输入框里的关键词与已执行的那次一致时才返回。用户改动关键词后旧结果立刻停止高亮，
    /// 避免出现与当前输入不符的残留高亮。
    fn active_search_keyword(&self) -> Option<String> {
        let typed = self.input_collector.message_input_state.text();
        let typed_keyword = typed.strip_prefix('#')?;
        let (executed_keyword, _, _) = self.search_result.as_ref()?;
        if executed_keyword != typed_keyword {
            return None;
        }
        Some(executed_keyword.clone())
    }

    /// 当前是否处于搜索模式：判定方式与指令模式一致，输入框内容以 # 开头。
    fn in_search_mode(&self) -> bool {
        self.input_collector
            .message_input_state
            .text()
            .starts_with('#')
    }

    /// 退出搜索模式：清空输入框与全部搜索结果状态（高亮、命中列表、定位一并复位）
    fn exit_search_mode(&mut self) {
        self.input_collector.message_input_state.set_text("");
        self.search_result = None;
        self.pending_scroll_message_id = None;
    }

    /// 按关键词扫描当前已加载消息，返回命中消息的 ID 列表（保持消息显示顺序，不区分大小写）
    fn messages_matching_keyword(&self, keyword: &str) -> Vec<String> {
        self.messages
            .iter()
            .filter(|message| {
                !keyword.is_empty() && !find_keyword_positions(&message.content, keyword).is_empty()
            })
            .map(|message| message.id.clone())
            .collect()
    }

    /// 执行消息搜索（搜索模式下按 Enter 触发）。
    /// 服务端消息接口只有 limit/before 游标、没有关键词检索参数，故先把当前房间的历史消息
    /// 整房拉到本地（load_full_room_history），再在完整列表里扫描关键词。
    /// 命中后默认定位到最后一个匹配项（即最近一条命中），未命中时结果列表为空、标题显示未找到。
    fn execute_message_search(&mut self) {
        let Some(typed) = self
            .input_collector
            .message_input_state
            .text()
            .strip_prefix('#')
            .map(|rest| rest.to_string())
        else {
            return;
        };
        let keyword = typed.trim().to_string();
        if keyword.is_empty() {
            self.exit_search_mode();
            return;
        }
        // 只在服务端仍报告有更早消息时才整房拉取，重复按 Enter 不会反复翻页
        if self.messages_older_cursor.is_some() {
            self.push_notification(self.t("search_loading_history"));
            self.load_full_room_history();
        }
        self.apply_search_keyword(&keyword);
    }

    /// 快速搜索：搜索模式下输入文本每次变化都即时扫描已加载消息，无需按 Enter。
    /// 刻意不做整房翻页拉取——逐字符翻页会打爆消息接口，完整历史仍由 Enter 触发。
    /// 关键词清空时直接清掉结果，标题回到未搜索态。
    fn apply_quick_search(&mut self) {
        let Some(typed) = self
            .input_collector
            .message_input_state
            .text()
            .strip_prefix('#')
            .map(|rest| rest.to_string())
        else {
            return;
        };
        let keyword = typed.trim().to_string();
        if keyword.is_empty() {
            self.search_result = None;
            self.pending_scroll_message_id = None;
            return;
        }
        self.apply_search_keyword(&keyword);
    }

    /// 按关键词在已加载消息里扫描命中项并写入搜索结果状态：
    /// 默认定位到最后一个匹配项（最近一条命中），无命中时命中列表为空、标题显示未找到。
    /// 正式搜索与快速搜索共用，差别只在于调用前是否先拉全历史。
    fn apply_search_keyword(&mut self, keyword: &str) {
        let matched = self.messages_matching_keyword(keyword);
        let selected = matched.len().saturating_sub(1);
        let target_id = matched.get(selected).cloned();
        self.search_result = Some((keyword.to_string(), matched, selected));
        self.pending_scroll_message_id = target_id;
    }

    /// 把当前选中房间的历史消息按游标翻页全部拉到本地，供全量关键词搜索使用。
    /// 单次请求 100 条（服务端 limit 的硬上限），服务端返回 has_more 且游标推进时才继续，
    /// 游标不前进立即停止，杜绝死循环。已在本地的消息按 ID 去重保留：
    /// 加密私聊里本端已解密的明文条目不能被服务端返回的占位密文覆盖掉。
    fn load_full_room_history(&mut self) {
        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };
        let mut fetched: Vec<MessageInfo> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let before = cursor.clone();
            match self
                .connector
                .get_messages(&room.id, 100, before.as_deref())
            {
                Ok(page) => {
                    let has_more = page.has_more;
                    let next_cursor = page.next_cursor;
                    fetched.extend(page.messages);
                    // 游标缺失或没有前进都视为已到尽头，立即停止，避免服务端异常时循环打爆接口
                    if !has_more
                        || next_cursor.is_none()
                        || next_cursor == cursor
                        || fetched.len() >= 5000
                    {
                        break;
                    }
                    cursor = next_cursor;
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                    break;
                }
            }
        }
        if fetched.is_empty() {
            return;
        }
        // 接口按最新在前返回，反转成旧在上、新在下后再合并
        fetched.reverse();
        let existing_ids: HashSet<String> = self
            .messages
            .iter()
            .map(|message| message.id.clone())
            .collect();
        let fresh: Vec<MessageInfo> = fetched
            .into_iter()
            .filter(|message| !existing_ids.contains(&message.id))
            .collect();
        if fresh.is_empty() {
            return;
        }
        debug_log(&format!(
            "全量历史合并 room={} 新增={} 总计={}",
            room.id,
            fresh.len(),
            self.messages.len() + fresh.len()
        ));
        self.messages.extend(fresh);
        let merged_room_id = room.id.clone();
        self.cache_loaded_messages(&merged_room_id);
        // RFC3339 时间戳的字典序即时间序，稳定排序保持同一时刻消息的原有相对顺序
        self.messages
            .sort_by(|left, right| left.created_at.cmp(&right.created_at));
        // 已无更早消息可翻，关闭触顶自动翻页，避免搜索后再去拉一遍重复历史
        self.messages_older_cursor = None;
    }

    /// 消息列表整体变化（切房重载、全量拉取、更早消息前插）后重新校验搜索结果：
    /// 按已执行的关键词在当前列表里重扫命中项，并把当前匹配项序号夹回有效范围。
    /// 不重扫的话命中 ID 会指向已不存在的消息，切换匹配项时表现为"跳不动"。
    fn refresh_search_matches(&mut self) {
        let Some((keyword, _, selected)) = self.search_result.clone() else {
            return;
        };
        let refreshed = self.messages_matching_keyword(&keyword);
        let bounded = if refreshed.is_empty() {
            0
        } else {
            selected.min(refreshed.len() - 1)
        };
        self.search_result = Some((keyword, refreshed, bounded));
    }

    /// 在搜索结果中切换匹配项：to_previous 为真取上一个（已在第一个时回绕到最后一个），
    /// 否则取下一个（已在最后一个时回绕到第一个），并把目标消息登记为待定位。
    /// 匹配项为 0 个或 1 个时不动作，避免无意义抖动滚动位置。
    fn navigate_search_result(&mut self, to_previous: bool) {
        let Some((keyword, matched, selected)) = self.search_result.clone() else {
            return;
        };
        if matched.is_empty() {
            return;
        }
        let next_index = if to_previous {
            if selected == 0 {
                matched.len() - 1
            } else {
                selected - 1
            }
        } else if selected + 1 >= matched.len() {
            0
        } else {
            selected + 1
        };
        self.pending_scroll_message_id = matched.get(next_index).cloned();
        self.search_result = Some((keyword, matched, next_index));
    }

    /// 消息输入框的标题文本与边框颜色：按指令模式 / 搜索模式 / 普通模式三态给出。
    /// 搜索模式标题要体现"未搜索""第 i/n 个匹配项""未找到"三种进度，未找到时标题标红。
    fn message_input_title(&self) -> (Line<'static>, Color) {
        let input_text = self.input_collector.message_input_state.text();
        if self.in_search_mode() {
            // 输入框里的关键词与上次执行的不一致（含用退格删改），上次结果就已经不成立了：
            // 标题回到"未执行搜索"，不再显示旧的匹配进度，避免看着有结果其实早已失效
            let title = match (self.active_search_keyword(), self.search_result.as_ref()) {
                (None, _) | (_, None) => {
                    Line::from(Span::raw(format!(" {} ", self.t("search_mode"))))
                }
                (_, Some((_, matched, _))) if matched.is_empty() => Line::from(Span::styled(
                    format!(" {} ", self.t("search_not_found")),
                    Style::default()
                        .fg(self.appearance.notice_error_border)
                        .add_modifier(Modifier::BOLD),
                )),
                (_, Some((_, matched, selected))) => Line::from(Span::raw(format!(
                    " {} ",
                    self.t("search_progress")
                        .replace("{current}", &(selected + 1).to_string())
                        .replace("{total}", &matched.len().to_string())
                ))),
            };
            return (title, self.appearance.search_border);
        }
        if input_text.starts_with('/') {
            return (
                Line::from(Span::raw(format!(" {} ", self.t("command_mode")))),
                self.appearance.command_border,
            );
        }
        (
            Line::from(Span::raw(format!(" {} ", self.t("message_input")))),
            self.appearance.input_border,
        )
    }

    fn render_message_input(&mut self, frame: &mut Frame, area: Rect) {
        // 记下本帧输入框位置：落在其内的拖拽交给控件自己选词，其外的拖拽才启动整屏框选
        self.message_input_area = area;
        let cursor_style = Style::default().fg(self.appearance.own_username_text);
        let (title, border_color) = self.message_input_title();

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            );

        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);
        TextArea::new()
            .block(block)
            .style(Style::default().fg(self.appearance.input_text))
            .cursor_style(cursor_style)
            .select_style(selection_style)
            .render(
                area,
                frame.buffer_mut(),
                &mut self.input_collector.message_input_state,
            );
    }

    fn render_create_group_modal(&mut self, frame: &mut Frame, area: Rect) {
        // 面板尺寸先按内容要，再夹到可绘制区以内：窄终端上超出的部分过去会被终端整列切掉
        let panel_rect = centered_rect(60, 18, area);

        // 仅清空并覆盖弹窗自身区域，避免破坏底层群聊列表与聊天记录的边框
        self.clear_overlay_area(frame, panel_rect);

        let focus_style = Style::default()
            .fg(self.appearance.selected_text)
            .add_modifier(Modifier::BOLD);
        let cursor_style = Style::default().fg(self.appearance.own_username_text);
        let unfocused_style = Style::default().fg(self.appearance.input_border);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);

        // 输入框正文文本颜色由外观给出
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("create_group_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(inner);

        let name_focused = self.focus_index == 0;
        let members_focused = self.focus_index == 1;

        let name_block = Block::default()
            .title(format!(" {} ", self.t("group_name_label")))
            .borders(Borders::ALL)
            .border_style(if name_focused {
                focus_style
            } else {
                unfocused_style
            });
        let members_block = Block::default()
            .title(format!(" {} ", self.t("members_hint_label")))
            .borders(Borders::ALL)
            .border_style(if members_focused {
                focus_style
            } else {
                unfocused_style
            });

        frame.render_widget(block.clone(), panel_rect);
        frame.render_widget(name_block.clone(), layout[2]);
        frame.render_widget(members_block.clone(), layout[4]);

        TextInput::new()
            .style(input_text_style)
            .block(name_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .cursor_style(cursor_style)
            .render(
                layout[2],
                frame.buffer_mut(),
                &mut self.input_collector.create_group_name_state,
            );

        TextInput::new()
            .style(input_text_style)
            .block(members_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .cursor_style(cursor_style)
            .render(
                layout[4],
                frame.buffer_mut(),
                &mut self.input_collector.create_group_members_state,
            );
    }

    fn render_create_private_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_rect = centered_rect(50, 14, area);

        // 仅清空并覆盖弹窗自身区域，避免破坏底层群聊列表与聊天记录的边框
        self.clear_overlay_area(frame, panel_rect);

        let focus_style = Style::default()
            .fg(self.appearance.selected_text)
            .add_modifier(Modifier::BOLD);
        let cursor_style = Style::default().fg(self.appearance.own_username_text);
        let unfocused_style = Style::default().fg(self.appearance.input_border);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);

        // 输入框正文文本颜色由外观给出
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("create_private_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(inner);

        let name_focused = self.focus_index == 0;

        let name_block = Block::default()
            .title(format!(" {} ", self.t("peer_username_label")))
            .borders(Borders::ALL)
            .border_style(if name_focused {
                focus_style
            } else {
                unfocused_style
            });
        frame.render_widget(block.clone(), panel_rect);

        frame.render_widget(name_block.clone(), layout[2]);

        TextInput::new()
            .style(input_text_style)
            .block(name_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .cursor_style(cursor_style)
            .render(
                layout[2],
                frame.buffer_mut(),
                &mut self.input_collector.create_private_username_state,
            );
    }

    fn execute_kick(&mut self, target: &str) {
        let selected_room_id = self.selected_room_id();
        let Some(room) =
            selected_room_id.and_then(|id| self.rooms.iter().find(|room| room.id == id))
        else {
            self.push_error(self.t("error_no_room_selected"));
            return;
        };
        if !room.is_group {
            self.push_error(self.t("error_not_group"));
            return;
        }
        let room_id = room.id.clone();
        // /kick 仅限群管理员/群主；非管理员即使目标是自己也不允许用其移除成员
        let detail = match self.connector.get_room(&room_id) {
            Ok(detail) => detail,
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_get_members_failed")));
                return;
            }
        };
        let is_admin = self.current_user_id.as_deref().is_some_and(|uid| {
            detail
                .members
                .iter()
                .any(|member| member.user_id == uid && is_admin_role(&member.role))
        });
        if !is_admin {
            self.push_error(self.t("error_kick_requires_admin"));
            return;
        }
        if target.to_uppercase() == "ALL" {
            self.kick_all_members(&room_id);
            return;
        }
        let Some(target_member) = detail
            .members
            .iter()
            .find(|member| member.username == target)
        else {
            self.push_error(
                self.t("error_user_not_found_in_group")
                    .replace("{target}", target)
                    .to_string(),
            );
            return;
        };
        match self
            .connector
            .remove_member(&room_id, &target_member.user_id)
        {
            Ok(_) => {
                // 若移除的是自己则记入主动退出集合，避免被误判为"被移出群聊"
                if self.current_user_id.as_deref() == Some(target_member.user_id.as_str()) {
                    self.left_room_ids.insert(room_id.clone());
                }
                self.push_notification(
                    self.t("removed_member")
                        .replace("{target}", target)
                        .to_string(),
                );
                self.load_rooms();
            }
            Err(error) => {
                self.push_error(format!(
                    "{}: {error}",
                    self.t("remove_member_failed").replace("{target}", target)
                ));
            }
        }
    }

    fn kick_all_members(&mut self, room_id: &str) {
        let Some(room) = self.rooms.iter().find(|room| room.id == room_id) else {
            return;
        };
        let member_ids: Vec<String> = room.members.clone();
        let own_id = self.current_user_id.clone().unwrap_or_default();
        let mut other_ids: Vec<String> = member_ids
            .iter()
            .filter(|id| *id != &own_id)
            .cloned()
            .collect();
        other_ids.reverse();
        for member_id in &other_ids {
            let _ = self.connector.remove_member(room_id, member_id);
        }
        // 移除自己时记入主动退出集合，避免被误判为"被移出群聊"
        self.left_room_ids.insert(room_id.to_string());
        let _ = self.connector.remove_member(room_id, &own_id);
        self.load_rooms();
        self.push_notification(self.t("removed_all_members"));
    }

    fn show_room_info(&mut self) {
        let Some(room) = self
            .selected_room_id()
            .and_then(|id| self.rooms.iter().find(|room| room.id == id))
        else {
            self.push_error(self.t("error_no_group_selected"));
            return;
        };
        if !room.is_group {
            self.push_error(self.t("error_info_not_group"));
            return;
        }
        let room_id = room.id.clone();
        let detail = match self.connector.get_room(&room_id) {
            Ok(detail) => detail,
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_get_room_info_failed")));
                return;
            }
        };
        // 成员名册改走专用的成员接口：房间详情里的成员数组是附带字段，
        // 成员接口才是服务端给出的权威名册（带 count 与完整 role/joined_at），
        // 两者都取到才拼出完整信息；成员接口失败时退回详情里那份，不至于什么都显示不出
        let roster = self.connector.list_members(&room_id).ok();
        let room_name = detail
            .name
            .clone()
            .unwrap_or_else(|| self.t("private_chat_fallback"));
        let encrypted_label = if detail.is_encrypted {
            self.t("room_info_yes")
        } else {
            self.t("room_info_no")
        };
        let members_text: Vec<String> = roster
            .as_ref()
            .map(|fetched| &fetched.members[..])
            .unwrap_or(&detail.members)
            .iter()
            .map(|member| {
                // 成员后跟在线标记（与服务端广播一致的 ●/○），未知状态不显示标记
                let presence_mark = match self.presence_by_user.get(&member.user_id) {
                    Some(true) => "●",
                    Some(false) => "○",
                    None => "",
                };
                let joined_at = format_message_time(&member.joined_at, true)
                    .map(|moment| format!(" ({moment})"))
                    .unwrap_or_default();
                format!(
                    "{} [{}]{}{}",
                    member.username, member.role, presence_mark, joined_at
                )
            })
            .collect();
        let member_total = roster
            .as_ref()
            .map(|fetched| fetched.count)
            .unwrap_or(detail.member_count as usize);
        let online_count = detail
            .members
            .iter()
            .filter(|member| self.presence_by_user.get(&member.user_id) == Some(&true))
            .count();
        let info = format!(
            "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}/{}\n{}: {}",
            self.t("room_info_name"),
            room_name,
            self.t("room_info_id"),
            detail.id,
            self.t("room_info_creator"),
            if detail.created_by.is_empty() {
                self.t("unknown_user")
            } else {
                detail.created_by.clone()
            },
            self.t("room_info_created"),
            detail.created_at,
            self.t("room_info_encrypted"),
            encrypted_label,
            self.t("room_info_member_count"),
            member_total,
            self.t("room_info_online_count"),
            online_count,
            member_total,
            self.t("room_info_members"),
            members_text.join(", ")
        );
        self.push_notification(info);
    }

    /// 发送者的显示名：先查用户名映射，查不到退回用户 ID。
    /// 账号注销后服务端会把 `messages.sender_id` 置为 null（`ON DELETE SET NULL`），
    /// 接缝把 null 收敛成空串，此时既没有名字也没有 ID，统一显示"未知用户"。
    fn sender_display_name(&self, sender_id: &str) -> String {
        if sender_id.is_empty() {
            return self.t("unknown_user");
        }
        self.sender_names
            .get(sender_id)
            .cloned()
            .unwrap_or_else(|| sender_id.to_string())
    }

    /// 设置菜单条目表：(标签, 文字颜色, 回车动作)。
    /// 浮层渲染与按键分派都读这一张表，菜单增删项只改这里一处。
    /// 注销账户按 TODO 要求用红字标出，退出登录同样是破坏性操作故也用红字。
    fn settings_menu_entries(&self) -> Vec<(String, Color, SettingsAction)> {
        let on_off = |enabled: bool| if enabled { "ON" } else { "OFF" };
        let plain_text = self.appearance.message_text;
        let danger_text = self.appearance.notice_error_border;
        // 数字只提示"待处理"条数：收到的都是待处理（接口只返回 pending），
        // 自己发出的只有还是 pending 的才算，已接受/已拒绝/已过期的旧邀请不计
        let request_count = self
            .pending_requests
            .iter()
            .filter(|request| received_request_is_pending(request))
            .count()
            + self
                .sent_requests
                .iter()
                .filter(|request| request.status.as_deref() == Some("pending"))
                .count();
        let update_suffix = match self.pending_update.as_ref() {
            Some((version, _)) => format!(" ({version})"),
            None => String::new(),
        };
        vec![
            (
                format!(" {}", self.t("option_create_group")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::CreateGroup),
            ),
            (
                format!(" {}", self.t("option_create_private")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::CreatePrivate),
            ),
            (
                format!(" {} ({})", self.t("option_pending_requests"), request_count),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::PendingRequests),
            ),
            (
                format!(
                    " {} ({})",
                    self.t("option_language"),
                    Self::current_language()
                ),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::LanguageSelect),
            ),
            (
                format!(
                    " {} ({})",
                    self.t("option_appearance"),
                    self.appearance_name
                ),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::AppearanceSelect),
            ),
            (
                format!(" {} [{}]", self.t("option_show_uid"), on_off(self.show_uid)),
                plain_text,
                SettingsAction::ToggleShowUid,
            ),
            (
                format!(
                    " {} [{}]",
                    self.t("option_time_format"),
                    on_off(self.time_with_date)
                ),
                plain_text,
                SettingsAction::ToggleTimeWithDate,
            ),
            (
                format!(
                    " {} [{}]",
                    self.t("option_quick_search"),
                    on_off(self.quick_search)
                ),
                plain_text,
                SettingsAction::ToggleQuickSearch,
            ),
            (
                format!(
                    " {} [{}]",
                    self.t("option_sound_enabled"),
                    on_off(self.sound_enabled)
                ),
                plain_text,
                SettingsAction::ToggleSound,
            ),
            (
                format!(" {}", self.t("option_edit_profile")),
                plain_text,
                SettingsAction::OpenForm(FormAction::UpdateProfile),
            ),
            (
                format!(" {}", self.t("option_change_password")),
                plain_text,
                SettingsAction::OpenForm(FormAction::ChangePassword),
            ),
            (
                format!(" {}", self.t("option_change_avatar")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::AvatarSelect),
            ),
            (
                format!(" {}", self.t("option_server_address")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::ServerAddress),
            ),
            (
                format!(" {}{update_suffix}", self.t("option_update_client")),
                plain_text,
                SettingsAction::UpdateClient,
            ),
            (
                format!(" {}", self.t("option_delete_account")),
                danger_text,
                SettingsAction::OpenForm(FormAction::DeleteAccount),
            ),
            (
                format!(" {}", self.t("option_logout")),
                danger_text,
                SettingsAction::Logout,
            ),
            (
                format!(" {}", self.t("option_login")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::Login),
            ),
            (
                format!(" {}", self.t("option_register")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::Register),
            ),
        ]
    }

    /// 打开一个既有浮层，顺带完成各自需要的初始化：列表类浮层把选中项摆到当前生效条目，
    /// 服务器地址浮层预填现有地址，表单与输入类浮层把焦点回到第一项。
    fn open_overlay(&mut self, overlay: DisplayingOverlay) {
        self.focus_index = 0;
        match overlay {
            DisplayingOverlay::PendingRequests => {
                self.request_list_state
                    .select(if self.request_entries().is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            DisplayingOverlay::LanguageSelect => {
                let languages = Self::get_available_languages();
                let current = Self::current_language();
                self.language_list_state
                    .select(languages.iter().position(|language| language == &current));
            }
            DisplayingOverlay::AppearanceSelect => {
                let names = Appearance::available_names();
                self.appearance_list_state
                    .select(names.iter().position(|name| name == &self.appearance_name));
            }
            DisplayingOverlay::ServerAddress => {
                self.input_collector
                    .server_address_state
                    .set_text(self.connector.base_url());
            }
            DisplayingOverlay::AvatarSelect => {
                ensure_avatar_source_directory();
                if local_avatar_files().is_empty() {
                    // 目录里还没图片：不摆空面板，直接给原来的链接输入表单
                    self.open_declared_form(&FormAction::ChangeAvatar);
                    return;
                }
                self.avatar_list_state.select(Some(0));
            }
            _ => {}
        }
        self.displaying_overlay = overlay;
    }

    /// 按表单声明打开表单浮层。个人资料表单额外按服务端当前值预填昵称与简介；
    /// 手机号没有任何只读接口能取回（登录响应之外不给），故留空表示"不改这一项"。
    fn open_declared_form(&mut self, action: &FormAction) {
        let (_, declared) = form_definition(action);
        let mut prefilled: Vec<String> = Vec::new();
        if *action == FormAction::UpdateProfile {
            let loaded = self
                .current_user_id
                .as_ref()
                .and_then(|user_id| self.connector.get_user_profile(user_id).ok());
            prefilled = vec![
                loaded
                    .as_ref()
                    .and_then(|profile| profile.nickname.clone())
                    .unwrap_or_default(),
                String::new(),
                loaded
                    .as_ref()
                    .and_then(|profile| profile.bio.clone())
                    .unwrap_or_default(),
            ];
        }
        let fields: Vec<FormField> = declared
            .iter()
            .enumerate()
            .map(|(index, (label_key, secret))| {
                FormField::new(
                    label_key,
                    prefilled.get(index).map(String::as_str).unwrap_or_default(),
                    *secret,
                )
            })
            .collect();
        self.open_form(action.clone(), fields);
    }

    /// 渲染设置菜单浮层：条目、颜色与动作全部来自 settings_menu_entries，
    /// 面板高度按条目数算，超出屏幕时由列表自身随选中项滚动。
    fn render_settings_menu(&mut self, frame: &mut Frame, area: Rect) {
        let entries = self.settings_menu_entries();
        let labels: Vec<String> = entries.iter().map(|(label, _, _)| label.clone()).collect();
        let colors: Vec<Color> = entries.iter().map(|(_, color, _)| *color).collect();
        let (panel_rect, body_width) = overlay_list_panel(&labels, area);
        self.clear_overlay_area(frame, panel_rect);
        let block = Block::default()
            .title(format!(" {} ", self.t("settings_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let menu_items: Vec<ListItem> = labels
            .iter()
            .zip(colors.iter())
            .map(|(label, color)| wrapped_list_item(label, Style::default().fg(*color), body_width))
            .collect();

        let list = List::new(menu_items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.menu_list_state);
    }

    /// 渲染语言选择浮层：列出 config/languages 下的全部语言文件，回车切换并写回 preferences.json
    fn render_language_select(&mut self, frame: &mut Frame, area: Rect) {
        let languages = Self::get_available_languages();
        let current = Self::current_language();
        let labels: Vec<String> = languages
            .iter()
            .map(|name| {
                if name == &current {
                    format!(" {name} ✓")
                } else {
                    format!(" {name}")
                }
            })
            .collect();
        let (panel_rect, body_width) = overlay_list_panel(&labels, area);
        self.clear_overlay_area(frame, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("select_language_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let items: Vec<ListItem> = labels
            .iter()
            .map(|label| {
                wrapped_list_item(
                    label,
                    Style::default().fg(self.appearance.message_text),
                    body_width,
                )
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.language_list_state);
    }

    /// 渲染外观选择浮层：列出 config/themes 下的全部主题文件名（去 .json 后缀），
    /// 回车即应用并写回 preferences.json 的 appearance 字段。
    fn render_appearance_select(&mut self, frame: &mut Frame, area: Rect) {
        let names = Appearance::available_names();
        let labels: Vec<String> = names
            .iter()
            .map(|name| {
                if name == &self.appearance_name {
                    format!(" {name} ✓")
                } else {
                    format!(" {name}")
                }
            })
            .collect();
        let (panel_rect, body_width) = overlay_list_panel(&labels, area);
        self.clear_overlay_area(frame, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("appearance_select_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let items: Vec<ListItem> = labels
            .iter()
            .map(|label| {
                wrapped_list_item(
                    label,
                    Style::default().fg(self.appearance.message_text),
                    body_width,
                )
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.appearance_list_state);
    }

    /// 本地头像选择浮层：窗口、列表、高亮符号与语言/外观选择完全一致，
    /// 条目是 `<客户端目录>/config/avatars` 里的图片文件名。
    fn render_avatar_select(&mut self, frame: &mut Frame, area: Rect) {
        let files = local_avatar_files();
        let labels: Vec<String> = files.iter().map(|(name, _)| name.clone()).collect();
        let hint = self.t("hint_avatar_select");
        let (base_rect, body_width) = overlay_list_panel(&labels, area);
        // 提示按条目同一内宽折行，行数超出面板自带的两行余量时才把面板加高
        let hint_block =
            wrapped_hint_text(&hint, hint_style(self.appearance.hint_text), body_width);
        let hint_rows = hint_block.lines.len().max(1) as u16;
        let panel_rect = centered_rect(
            base_rect.width,
            base_rect.height + hint_rows.saturating_sub(2),
            area,
        );
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(
            overlay_frame_block(&self.appearance, &self.t("option_change_avatar")),
            panel_rect,
        );
        let items: Vec<ListItem> = labels
            .iter()
            .map(|label| {
                wrapped_list_item(
                    label,
                    Style::default().fg(self.appearance.message_text),
                    body_width,
                )
            })
            .collect();
        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let [list_area, hint_area] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(hint_rows)]).areas(inner);
        frame.render_stateful_widget(list, list_area, &mut self.avatar_list_state);
        frame.render_widget(
            Paragraph::new(hint_block).alignment(Alignment::Center),
            hint_area,
        );
    }

    /// 用选中的本地图片换头像：文件名来自头像目录。
    fn apply_local_avatar(&mut self) {
        let index = self.avatar_list_state.selected().unwrap_or(0);
        let files = local_avatar_files();
        let Some((_, path)) = files.get(index) else {
            return;
        };
        self.upload_local_avatar(path);
    }

    /// 把一张本地图片交给服务端的 multipart 上传接口（列表选择与表单填路径两条入口共用）。
    /// 服务端存不下文件时按它给的报错原样显示：存放目录由服务端自己在启动时建，
    /// 客户端不去碰服务端的数据目录；要传链接版头像请用浮层里的 Ctrl+U。
    fn upload_local_avatar(&mut self, path: &std::path::Path) {
        let Some((file_name, content_type, bytes)) = read_local_image(path) else {
            self.push_error(self.t("error_avatar_local_file_unusable"));
            return;
        };
        match self
            .connector
            .upload_avatar(&file_name, &content_type, bytes)
        {
            Ok(user) => self.finish_avatar_change(&user),
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_avatar_update_failed")))
            }
        }
    }

    /// 渲染服务器地址浮层：单输入框，回车测试连通性并保存。
    fn render_server_address(&mut self, frame: &mut Frame, area: Rect) {
        // 提示与输入框都要放得下：面板宽度先夹到屏幕内，提示按最终内宽折行后再定高度
        let panel_width = 50u16.min(area.width.max(1));
        let label = wrapped_hint_text(
            &self.t("server_address_label"),
            Style::default().fg(self.appearance.message_text),
            panel_width.saturating_sub(6),
        );
        let label_lines = label.lines.len().max(1) as u16;
        let panel_rect = centered_rect(panel_width, 5 + label_lines, area);

        self.clear_overlay_area(frame, panel_rect);

        // 输入框正文文本颜色由外观给出
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("server_address_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(self.appearance.message_text)),
            Rect::new(inner.x, inner.y, inner.width, label_lines),
        );

        let input_rect = Rect::new(inner.x, inner.y + label_lines, inner.width, 3);
        let input_state = &mut self.input_collector.server_address_state;
        input_state.focus.set(true);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);
        let input = TextInput::new()
            .style(input_text_style)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(self.appearance.input_border)),
            )
            .select_style(selection_style)
            .cursor_style(Style::default().fg(self.appearance.own_username_text));
        frame.render_stateful_widget(input, input_rect, input_state);

        frame.render_widget(block, panel_rect);
    }

    /// 渲染私聊管理浮层：上半区是别人发给自己的请求（可接受/拒绝），
    /// 下半区是自己发出的请求（可撤回，并显示服务端回报的当前状态）。
    /// 两个区拼成一条扁平序列用同一个选中下标导航，因此这里手工画每行、
    /// 只给可选项计数，标题行不参与选中。
    /// 渲染私聊管理浮层：上半区是别人发给自己的请求（可接受/拒绝），
    /// 下半区是自己发出的请求（可撤回，并显示服务端回报的当前状态）。
    /// 两个区拼成一条扁平序列用同一个选中下标导航，标题行不参与选中，
    /// 因此这里手工逐行绘制并自己算滚动偏移。邀请正文按面板宽度折行完整显示，
    /// 长度超出面板时随选中项滚动，不会像之前那样只显示一行。
    fn render_pending_requests(&mut self, frame: &mut Frame, area: Rect) {
        let entries = self.request_entries();
        let received_count = self.pending_requests.len();
        let selected = self.request_list_state.selected().unwrap_or(0);
        let panel_width = area.width.saturating_sub(4).clamp(40, 88);
        // 正文可用宽度：减去边框、选中标记与缩进
        let body_width = panel_width.saturating_sub(8).max(20) as usize;
        let appearance = self.appearance.clone();
        let empty_text = self.t("no_pending_requests");
        let unknown_text = self.t("unknown_user");
        let encrypted_mark = self.t("encrypted_mark");
        let received_title = self.t("request_section_received");
        let sent_title = self.t("request_section_sent");
        let panel_title = self.t("pending_requests_title");
        let hint_text = self.t("hint_pending_requests");

        // 第一遍只算行：每个条目可能占多行（正文折行），面板高度与滚动都要用它
        let mut rows: Vec<(Option<usize>, Line)> = Vec::new();
        if entries.is_empty() {
            rows.push((
                None,
                Line::from(Span::styled(
                    empty_text.clone(),
                    hint_style(appearance.hint_text),
                ))
                .alignment(Alignment::Center),
            ));
        }
        for (index, (is_sent, request)) in entries.iter().enumerate() {
            let starts_section = *is_sent || (received_count > 0 && index == received_count);
            if starts_section {
                if index > 0 {
                    rows.push((None, Line::from("")));
                }

                rows.push((
                    None,
                    Line::from(Span::styled(
                        format!(
                            " {}",
                            if *is_sent {
                                &sent_title
                            } else {
                                &received_title
                            }
                        ),
                        Style::default()
                            .fg(appearance.time_text)
                            .add_modifier(Modifier::BOLD),
                    )),
                ));
            }
            let peer_name = if *is_sent {
                request.receiver.as_ref()
            } else {
                request.sender.as_ref()
            }
            .map(|peer| peer.username.clone())
            .unwrap_or_else(|| unknown_text.clone());
            // 发出侧服务端总给状态；收到侧只有本端处理过的那几条有状态（历史条目），
            // 仍在等的收到条目状态缺省，不跟后缀
            let status_suffix = match request.status.as_deref() {
                Some(status) if *is_sent || status != "pending" => {
                    format!(" [{}]", self.request_status_label(status))
                }
                _ => String::new(),
            };
            let encryption_mark = if request.is_encrypted {
                encrypted_mark.clone()
            } else {
                String::new()
            };
            let is_current = index == selected;
            let entry_color = if is_current {
                appearance.selected_text
            } else {
                appearance.other_username_text
            };
            let body_color = if is_current {
                appearance.selected_text
            } else {
                appearance.message_text
            };
            let message_lines = wrap_by_display_width(
                &format!("{}{encryption_mark}", request.message),
                body_width as u16,
            );
            // 人名与状态本身可能宽过正文区：放不下就让它先独占若干行，正文顺延到下一行，
            // 否则整条邀请会被裁得看不见
            let label_text = format!("{peer_name}{status_suffix}：");
            let label_width = usize::from(display_width(&label_text));
            let label_pieces: Vec<String> = if label_width > body_width {
                wrap_by_display_width(&label_text, body_width as u16)
            } else {
                Vec::new()
            };
            for (line_index, piece) in label_pieces.iter().enumerate() {
                rows.push((
                    (is_current && line_index == 0).then_some(index),
                    Line::from(vec![
                        Span::raw(if is_current && line_index == 0 {
                            "> "
                        } else {
                            "  "
                        }),
                        Span::styled(piece.clone(), Style::default().fg(entry_color)),
                    ]),
                ));
            }
            // 与人名同排时正文按人名宽度缩进；人名另起一行时正文顶格
            let same_row_label = label_pieces.is_empty();
            let indentation = if same_row_label { label_width } else { 0 };
            for (line_index, message_line) in message_lines.iter().enumerate() {
                rows.push((
                    (is_current && same_row_label && line_index == 0).then_some(index),
                    Line::from(vec![
                        Span::raw(if is_current && same_row_label && line_index == 0 {
                            "> "
                        } else {
                            "  "
                        }),
                        Span::styled(
                            if line_index == 0 && same_row_label {
                                label_text.clone()
                            } else {
                                " ".repeat(indentation)
                            },
                            Style::default().fg(entry_color),
                        ),
                        Span::styled(message_line.clone(), Style::default().fg(body_color)),
                    ]),
                ));
            }
        }

        // 底部提示同样按面板内宽折行，并把占用的真实行数算进面板高度（英文文案比面板还宽时会被裁）
        let hint_block = wrapped_hint_text(
            &hint_text,
            hint_style(appearance.hint_text),
            panel_width.saturating_sub(4).max(1),
        );
        let hint_rows = hint_block.lines.len().max(1) as u16;
        let panel_height = (rows.len() as u16 + 3 + hint_rows)
            .min(area.height.saturating_sub(2))
            .max(7);
        let panel_rect = centered_rect(panel_width, panel_height, area);
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(overlay_frame_block(&appearance, &panel_title), panel_rect);
        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let [list_area, hint_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(hint_rows)]).areas(inner);
        let visible_rows = usize::from(list_area.height.max(1));
        // 选中条目不在可视范围时把它滚到最后一行；标题行不算条目，所以按行的条目归属查找
        let selected_row = rows
            .iter()
            .position(|(entry_index, _)| *entry_index == Some(selected));
        let scroll_offset = match selected_row {
            Some(row) if row >= visible_rows.saturating_sub(1) => {
                row - visible_rows.saturating_sub(1) + 1
            }
            _ => 0,
        };
        let list = Paragraph::new(Text::from(
            rows.into_iter()
                .map(|(_, line)| line)
                .collect::<Vec<Line>>(),
        ))
        .scroll((scroll_offset as u16, 0))
        .style(Style::default().bg(appearance.app_background));
        frame.render_widget(list, list_area);

        // 只提示 d 这个非通用键位（Enter/Esc 属通用键，按快捷键提示规范不再列出）
        frame.render_widget(
            Paragraph::new(hint_block).alignment(Alignment::Center),
            hint_area,
        );
    }

    /// 请求状态的本地化文案：服务端给的是小写英文状态串，未知状态原样显示。
    fn request_status_label(&self, status: &str) -> String {
        let key = match status {
            "pending" => "request_status_pending",
            "accepted" => "request_status_accepted",
            "declined" => "request_status_declined",
            "expired" => "request_status_expired",
            "cancelled" => "request_status_cancelled",
            other => return other.to_string(),
        };
        self.t(key)
    }

    /// 在右上角渲染通知弹窗列，每条一个带边框小面板，依次向下堆叠
    fn render_notifications(&self, frame: &mut Frame, area: Rect) {
        let margin_between = 1u16;
        // 列宽按"所有提示里最宽的那一行"折算：此前用的是整段文本的总宽度
        // （多行提示会把宽度算得虚高），且上限只有半屏，结果单行长文本既撑不开面板、
        // 又因为高度算错被整条丢弃，小屏幕上就看不到内容。
        let longest_line = self
            .notifications
            .iter()
            .map(|(text, _, _)| longest_line_width(text))
            .max()
            .unwrap_or(0);
        // 允许用到屏宽三分之二（至少 28 列），窄终端上也至少给一行的容身之处
        let preferred_width = area.width.saturating_sub(2).clamp(28, 60);
        let column_width = (longest_line + 4).clamp(28u16.min(preferred_width), preferred_width);
        let inner_width = column_width.saturating_sub(2).max(1);
        let mut next_top = area.y + 1;

        for (text, is_error, _) in &self.notifications {
            // 逐行按显示宽度估行：显式换行与折行都要计入，否则多行提示会被裁切
            let line_count = estimated_wrapped_line_count(text, inner_width);
            // 额外留一行：按词边界折行可能早于列宽上限换行
            let needed_height = line_count + 3;
            let available_height = (area.y + area.height).saturating_sub(next_top);
            if available_height < 3 {
                // 连最小的带框面板都放不下，剩下的旧提示本轮就不显示（到期会自动清除）
                break;
            }
            let panel_height = needed_height.min(available_height);
            let panel_x = area.x + area.width.saturating_sub(column_width + 1);
            let panel_rect = Rect::new(panel_x, next_top, column_width, panel_height);

            // 错误类边框用外观的报错边框色，信息类用提示边框色；标题同步取色
            let (title_text, border_color) = if *is_error {
                (
                    format!(" {} ", self.t("error_title")),
                    self.appearance.notice_error_border,
                )
            } else {
                (
                    format!(" {} ", self.t("info_title")),
                    self.appearance.notice_hint_border,
                )
            };
            let panel_block = Block::default()
                .title(title_text)
                .title_style(
                    Style::default()
                        .fg(border_color)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color));

            let message = Paragraph::new(Text::raw(text.as_str()))
                .style(Style::default().fg(self.appearance.message_text))
                .wrap(ratatui::widgets::Wrap { trim: true });
            // 缓冲区为叠加式渲染，必须先清空面板区域（并重铺主题背景），否则下层文字会透出造成混乱
            self.clear_overlay_area(frame, panel_rect);
            frame.render_widget(panel_block, panel_rect);
            // 文字必须限制在上下边框之内，避免段落样式把边框染成白色
            frame.render_widget(
                message,
                panel_rect.inner(ratatui::layout::Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
            );

            next_top += panel_height + margin_between;
        }
    }
}

// ==================== 顶栏连接状态、消息缓存、头像、账户资料与更新 ====================

/// 头像原始文件的本地缓存路径。图片本身可再生（服务端那份才是正本），
/// 存在 `<客户端目录>/cache/avatar/<用户 ID>.img`，卸载时可一并清掉。
fn avatar_cache_path(user_id: &str) -> Option<PathBuf> {
    let safe_name: String = user_id
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => character,
            _ => '_',
        })
        .collect();
    Some(paths::avatar_directory()?.join(format!("{safe_name}.img")))
}

/// 读已缓存的头像字节
fn load_cached_avatar(user_id: &str) -> Option<Vec<u8>> {
    fs::read(avatar_cache_path(user_id)?).ok()
}

/// 删掉某个用户的头像字节：换头像之后旧字节就是错的，只能重新拉
fn drop_cached_avatar(user_id: &str) {
    if let Some(path) = avatar_cache_path(user_id) {
        let _ = fs::remove_file(path);
    }
}

/// 写头像缓存（目录建不出来或磁盘写失败都只影响下次要多下载一次，不报错给用户）
fn store_cached_avatar(user_id: &str, bytes: &[u8]) {
    let Some(path) = avatar_cache_path(user_id) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, bytes);
}

/// 头像网格的最大尺寸（单元格列数、行数）。一格用半块字符 `▀` 承载上下两个像素，
/// 而终端单元格本身约是 1:2 的宽高比，所以列数取行数两倍时画出来才是正方形：
/// 32 列 × 16 行即 32×32 像素。卡片是专门看人的地方，尺寸要给到能辨认脸型与配色；
/// 消息区不再画头像，因此这个尺寸只影响卡片一处。
fn profile_avatar_cells() -> (usize, usize) {
    (32, 16)
}

/// 在给定可用区里定头像网格：始终保证"列数 = 行数的两倍"，只整体降档不改比例。
/// 源图先被裁成正方形再按"列 × 行×2"像素重采样，所以列数不等于行数两倍时
/// （老做法：面板一变窄就只裁列数、行数仍按 16 走）圆脸就会被压成竖长方形。
fn avatar_grid_within(columns_available: u16, rows_available: u16) -> (u16, u16) {
    let (wanted_columns, wanted_rows) = profile_avatar_cells();
    let wanted_columns = wanted_columns as u16;
    let wanted_rows = wanted_rows as u16;
    // 一行单元格装上下两个像素，所以"列 = 行 × 2"才对应正方形像素块：
    // 先用可用宽度与可用高度夹出行数，列数再由行数推出，比例恒定
    let rows = wanted_rows
        .min(wanted_columns.min(columns_available.max(2)) / 2)
        .min(rows_available.max(1))
        .max(1);
    (rows * 2, rows)
}

impl App {
    /// 客户端版本：编译期取自本包的 Cargo.toml，顶栏与 `--version` 共用同一来源。
    pub fn client_version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// 核心库版本：与客户端版本各自独立演进，顶栏与 `--version` 一并报出便于定位问题。
    pub fn core_version() -> String {
        baihua_core::core_version().to_string()
    }

    /// 顶栏连接标记与"连不上服务器只提示一次"共用这一处状态更新：
    /// 跳变为断开时弹一条错误、由断到通时弹一条恢复提示，持续态只反映在顶栏上，不再重复弹框。
    fn update_connection_state(&mut self, online: bool) {
        let previous = self.connection_ready;
        if previous == Some(online) {
            return;
        }
        self.connection_ready = Some(online);
        if online {
            // 只有"此前明确断开过"才报恢复；首次探测到连通不打扰用户（登录另有提示）
            if previous == Some(false) {
                self.push_notification(self.t("connection_restored"));
            }
        } else {
            self.push_error(self.t("error_server_unreachable"));
        }
    }

    /// 启动时探测一次服务端：既为顶栏取到服务端版本串（未登录也要能显示），
    /// 也为"能不能连上"给出初始标记。
    pub fn probe_server_at_startup(&mut self) {
        match self.connector.probe_version() {
            Ok((version, raw_version)) => {
                if version == ApiVersion::Unknown {
                    self.push_notification(
                        self.t("api_version_unknown")
                            .replace("{version}", &raw_version),
                    );
                }
                self.update_connection_state(true);
            }
            Err(error) => {
                debug_log(&format!("启动探测失败: {error}"));
                self.connector.clear_server_version();
                self.update_connection_state(false);
            }
        }
    }

    /// 启动常驻的服务端可达性探测线程：与登录态无关，退出登录后照样工作，
    /// 所以"登出就提示断开"这类误报不会再出现。
    /// 连续两次探测失败才判离线（登录瞬间一串请求挤在一起、服务端刚重启都可能让
    /// 单次探测超时），一次成功即恢复。
    pub fn start_reachability_watch(&mut self) {
        // 换服务器地址后要重新起一轮：旧线程探的是旧地址，留着就会把两条结论混着报
        if let Some(previous) = self.reachability_running.take() {
            previous.store(false, Ordering::Relaxed);
        }
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        let connector = self.connector.clone();
        let running_flag = Arc::new(AtomicBool::new(true));
        self.reachability_running = Some(running_flag.clone());
        thread::spawn(move || {
            let mut failed_in_a_row = 0usize;
            while running_flag.load(Ordering::Relaxed) {
                let reachable = connector.probe_reachable();
                if reachable {
                    failed_in_a_row = 0;
                } else {
                    failed_in_a_row += 1;
                }
                // 首次成功、以及连续第二次失败才上报，中间的单次抖动不惊动界面
                if reachable || failed_in_a_row == 2 {
                    debug_log(&format!("服务端可达性探测: {reachable}"));
                    if sender
                        .send(PollingEvent::ReachabilityChanged(reachable))
                        .is_err()
                    {
                        return;
                    }
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }

    /// 后台检查新版本：发现新版本就下载并校验，只有包真的取回本地才弹通知——
    /// 通知一出现就意味着"现在 /update 可以立刻完成"，不会出现提示了却还要等下载。
    /// 检查失败（无网络、发布页改版、本平台没有包）只记调试日志，不打扰用户。
    pub fn start_update_check_thread(&mut self, current_version: String) {
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        // 正在查就不再起第二个：/update 可以再按一次，两条线程同时下载同一个包没有意义
        if self
            .update_check_running
            .as_ref()
            .is_some_and(|running| running.load(Ordering::Relaxed))
        {
            return;
        }
        let running_flag = Arc::new(AtomicBool::new(true));
        self.update_check_running = Some(running_flag.clone());
        thread::spawn(move || {
            match check_for_update(&current_version) {
                UpdateCheck::Available(package) => {
                    debug_log(&format!("发现新版本 {}，开始下载", package.version));
                    match download_package(&package) {
                        Ok(archive_path) => {
                            let _ = sender
                                .send(PollingEvent::UpdateReady((package.version, archive_path)));
                        }
                        Err(error) => debug_log(&format!("新版本下载或校验失败: {error}")),
                    }
                }
                UpdateCheck::UpToDate {
                    newest_tag,
                    newest_assets,
                } => debug_log(&format!(
                    "客户端已是最新版本（发布页最新标签 {newest_tag}，附件 {newest_assets:?}）"
                )),
                UpdateCheck::Unavailable(reason) => debug_log(&format!("版本检查未完成: {reason}")),
            }
            // 检查与下载都结束了才落标志，其间重复按 /update 不会派出第二个下载线程
            running_flag.store(false, Ordering::Relaxed);
        });
    }

    /// 会话建立后要做的公共准备（正常登录、自动登录两条入口都走这里）：
    /// 顶栏用户名、本地消息缓存目录、自己的头像。用户目录不在这里拉，
    /// 它只在用户真的打出 "/profile " 时才取，登录瞬间不该为它翻页。
    /// 用户名以登录响应为准；只有令牌没有响应的自动登录再按 UID 查一次资料。
    fn prepare_session_state(&mut self, known_username: Option<String>) {
        let user_id = match self.current_user_id.clone() {
            Some(user_id) => user_id,
            None => return,
        };
        self.current_username = known_username.unwrap_or_default();
        if self.current_username.is_empty() {
            self.current_username = self
                .connector
                .get_user_profile(&user_id)
                .map(|profile| profile.username)
                .unwrap_or_default();
        }
        self.ensure_chat_cache();
        self.request_missing_avatars(std::slice::from_ref(&user_id));
        // 预取注册用户目录：/profile 的参数补全要用它，等用户打出来再拉就总是慢一帧
        self.ensure_registered_users_loaded();
    }

    /// 为当前登录用户建立消息缓存目录（登录成功、自动登录后调用；未登录时保持无缓存）。
    fn ensure_chat_cache(&mut self) {
        if self.chat_cache.is_some() {
            return;
        }
        let Some(user_id) = self.current_user_id.clone() else {
            return;
        };
        self.chat_cache = ChatCache::open(&user_id);
    }

    /// 取指定房间的加密标志：加密房间的消息一律不进本地缓存。
    fn room_is_encrypted(&self, room_id: &str) -> bool {
        self.rooms
            .iter()
            .any(|room| room.id == room_id && room.is_encrypted)
    }

    /// 整房写入缓存（切房加载、触顶翻页、全量搜索之后）。加密房间直接跳过。
    fn cache_loaded_messages(&self, room_id: &str) {
        if room_id.is_empty() || self.room_is_encrypted(room_id) {
            return;
        }
        let Some(cache) = &self.chat_cache else {
            return;
        };
        // 内存里的列表必须确实是这个房间的才落盘：切换房间的瞬间 messages 可能还是
        // 上一个房间的内容，写错房间会把别人的历史混进这个文件
        let belongs_to_room = self
            .messages
            .last()
            .is_some_and(|message| message.room_id == room_id);
        if !belongs_to_room {
            return;
        }
        cache.store_room(
            room_id,
            &self.messages,
            self.messages_older_cursor.as_deref(),
            self.messages_older_cursor.is_some(),
        );
    }

    /// 标记"当前房间消息列表比磁盘新"，交给 handle_tick 批量落盘。
    /// 逐条到达就写一次文件会在活跃群里造成无谓的整文件重写。
    fn mark_messages_dirty(&mut self) {
        if self.cache_pending_flush_since.is_none() {
            self.cache_pending_flush_since = Some(Instant::now());
        }
    }

    /// 脏标记超过一个批量窗口后落盘（主循环每轮调用，本身不产生网络请求）。
    fn flush_pending_message_cache(&mut self) {
        let Some(dirty_since) = self.cache_pending_flush_since else {
            return;
        };
        if dirty_since.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.cache_pending_flush_since = None;
        if let Some(room_id) = self.selected_room_id() {
            let room_id = room_id.clone();
            self.cache_loaded_messages(&room_id);
        }
    }

    /// 为这批用户补齐头像：本地已有结论（包括"确实没有头像"）的跳过，
    /// 其余交给后台线程按资料接口取回图片字节，取回后经 AvatarLoaded 交回主线程。
    /// 渲染期绝不做网络请求，这里只登记待取与派生活。
    fn request_missing_avatars(&mut self, user_ids: &[String]) {
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        let mut missing: Vec<String> = Vec::new();
        for user_id in user_ids {
            if user_id.is_empty() || self.avatar_images.contains_key(user_id) {
                continue;
            }
            // 先占位登记，避免同一批用户在下一帧又被判定为缺失而重复发请求
            self.avatar_images.insert(user_id.clone(), None);
            missing.push(user_id.clone());
        }
        if missing.is_empty() {
            return;
        }
        let connector = self.connector.clone();
        thread::spawn(move || {
            for user_id in missing {
                let image_bytes = load_cached_avatar(&user_id).or_else(|| {
                    let bytes = connector
                        .get_user_profile(&user_id)
                        .ok()
                        .and_then(|profile| profile.avatar)
                        .map(|avatar_path| avatar_path.trim().to_string())
                        .filter(|avatar_path| !avatar_path.is_empty())
                        .and_then(|avatar_path| {
                            connector.fetch_static_resource(&avatar_path).ok()
                        })?;
                    store_cached_avatar(&user_id, &bytes);
                    Some(bytes)
                });
                let _ = sender.send(PollingEvent::AvatarLoaded((user_id, image_bytes)));
            }
        });
    }

    /// 取某用户在指定尺寸下的头像像素块（首次用到该尺寸时按已取回的字节解码一次）。
    /// 没有头像、或字节不是可解码的图片时返回 None，由调用方退回占位显示。
    fn avatar_pixels_at(
        &mut self,
        user_id: &str,
        columns: usize,
        rows: usize,
    ) -> Option<AvatarPixels> {
        let key = (user_id.to_string(), columns, rows);
        if let Some(cached) = self.avatar_pixels.get(&key) {
            return Some(cached.clone());
        }
        let image_bytes = self.avatar_images.get(user_id).cloned().flatten()?;
        let pixels = build_avatar_pixels(&image_bytes, columns, rows)?;
        self.avatar_pixels.insert(key, pixels.clone());
        Some(pixels)
    }

    /// 打开通用表单浮层（设置个人资料、修改密码、修改头像、注销账户共用渲染与按键处理）。
    fn open_form(&mut self, action: FormAction, fields: Vec<FormField>) {
        self.active_form = Some((action, fields));
        self.displaying_overlay = DisplayingOverlay::Form;
        self.focus_index = 0;
    }

    /// 提交当前表单：按表单动作分派到对应的服务端接口，成功后关闭浮层。
    fn submit_active_form(&mut self) {
        let Some((action, fields)) = self.active_form.clone() else {
            return;
        };
        match action {
            FormAction::UpdateProfile => self.submit_profile_update(&fields),
            FormAction::ChangePassword => self.submit_password_change(&fields),
            FormAction::ChangeAvatar => self.submit_avatar_change(&fields),
            FormAction::DeleteAccount => self.submit_account_deletion(&fields),
        }
    }

    /// 在当前表单的输入项之间循环移动焦点
    fn cycle_form_focus(&mut self, to_previous: bool) {
        let field_count = self
            .active_form
            .as_ref()
            .map(|(_, fields)| fields.len())
            .unwrap_or(0);
        if field_count == 0 {
            return;
        }
        self.focus_index = if to_previous {
            (self.focus_index + field_count - 1) % field_count
        } else {
            (self.focus_index + 1) % field_count
        };
    }

    /// 关闭表单浮层并退回设置菜单
    fn close_form(&mut self) {
        self.active_form = None;
        self.dismiss_overlay_back();
    }

    /// 设置个人资料：昵称、手机号、简介。输入框留空表示清空该项（服务端按显式 null 处理），
    /// 未改动时提交原值即可，界面不引入"是否改动过"的额外状态。
    fn submit_profile_update(&mut self, fields: &[FormField]) {
        let text_of = |index: usize| fields.get(index).map(FormField::text).unwrap_or_default();
        let payload = ProfileUpdatePayload {
            nickname: profile_field_value(&text_of(0)),
            phone_number: profile_field_value(&text_of(1)),
            bio: profile_field_value(&text_of(2)),
            avatar: None,
        };
        if payload.nickname.is_none() && payload.phone_number.is_none() && payload.bio.is_none() {
            self.push_notification(self.t("profile_nothing_to_update"));
            return;
        }
        match self.connector.update_profile(&payload) {
            Ok(user) => {
                self.remember_own_profile(&user);
                self.close_form();
                self.push_notification(self.t("profile_updated"));
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_profile_update_failed")
            )),
        }
    }

    /// 修改密码：旧密码、新密码、新密码确认。
    /// 服务端改密会同步作废此前签发的全部令牌，因此成功后必须清掉本地会话重新登录。
    fn submit_password_change(&mut self, fields: &[FormField]) {
        let text_of = |index: usize| fields.get(index).map(FormField::text).unwrap_or_default();
        let old_password = text_of(0);
        let new_password = text_of(1);
        if new_password != text_of(2) {
            self.push_error(self.t("error_password_mismatch"));
            return;
        }
        if old_password.is_empty() || new_password.is_empty() {
            self.push_error(self.t("error_empty_credentials"));
            return;
        }
        match self.connector.change_password(
            &crypto::encrypt_login_password(&old_password),
            &crypto::encrypt_login_password(&new_password),
        ) {
            Ok(_) => {
                self.active_form = None;
                self.logout();
                self.displaying_overlay = DisplayingOverlay::Login;
                self.focus_index = 0;
                self.push_notification(self.t("password_changed_relogin"));
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_password_change_failed")
            )),
        }
    }

    /// 修改头像：填完整链接走资料接口，填本地图片路径走头像上传接口（服务端只收
    /// JPEG/PNG/GIF/WebP，大小受服务端配置限制）。
    fn submit_avatar_change(&mut self, fields: &[FormField]) {
        let Some(input) = fields.first().map(FormField::text) else {
            return;
        };
        let input = input.trim().to_string();
        if input.is_empty() {
            self.push_error(self.t("error_avatar_input_empty"));
            return;
        }
        // 填完整链接走资料接口，其余按本地图片文件走头像上传接口
        if input.starts_with("http://") || input.starts_with("https://") {
            let payload = ProfileUpdatePayload {
                avatar: Some(Some(input)),
                ..ProfileUpdatePayload::default()
            };
            match self.connector.update_profile(&payload) {
                Ok(user) => self.finish_avatar_change(&user),
                Err(error) => {
                    self.push_error(format!("{}: {error}", self.t("error_avatar_update_failed")))
                }
            }
            return;
        }
        // 填的是本地路径：与列表选择走同一条上传路（读不到的文案也共用）
        self.upload_local_avatar(&PathBuf::from(&input));
    }

    /// 头像换好了：先废掉自己的旧头像字节（内存与磁盘），再记下服务端返回的完整资料。
    /// 磁盘那份必须删：`request_missing_avatars` 的后台线程先读盘再请求，
    /// 留着就会永远显示第一次缓存下来的那张 —— 换成 URL 头像也一样。
    fn finish_avatar_change(&mut self, user: &UserInfo) {
        drop_cached_avatar(&user.id);
        self.remember_own_profile(user);
        self.close_form();
        self.push_notification(self.t("avatar_updated"));
    }

    /// 注销账户：再输入一次密码。成功后清空本地一切残留（会话、缓存、头像）。
    fn submit_account_deletion(&mut self, fields: &[FormField]) {
        let Some(password) = fields.first().map(FormField::text) else {
            return;
        };
        if password.is_empty() {
            self.push_error(self.t("error_empty_credentials"));
            return;
        }
        match self
            .connector
            .delete_account(&crypto::encrypt_login_password(&password))
        {
            Ok(_) => {
                if let Some(cache) = &self.chat_cache {
                    cache.clear_all();
                }
                self.chat_cache = None;
                self.avatar_images.clear();
                self.avatar_pixels.clear();
                self.active_form = None;
                self.logout();
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.push_notification(self.t("account_deleted"));
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_account_delete_failed")
            )),
        }
    }

    /// 服务端返回的完整用户对象落到本地：顶栏用户名与自己头像的显示都取自它。
    /// 头像可能刚被改掉，因此丢掉自己的旧头像结果重新按资料接口取一次，
    /// 否则界面上还会继续显示上一张。
    fn remember_own_profile(&mut self, user: &UserInfo) {
        self.current_username = user.username.clone();
        self.own_contact = Some((
            user.email.clone(),
            user.phone_number.clone().unwrap_or_default(),
        ));
        self.avatar_images.remove(&user.id);
        self.avatar_pixels
            .retain(|(cached_user_id, _, _), _| cached_user_id != &user.id);
        let own_user_id = user.id.clone();
        self.request_missing_avatars(std::slice::from_ref(&own_user_id));
    }

    /// /profile [用户名或 UID]：无参看自己，有参看指定用户，以卡片浮层展示（含头像）。
    fn show_profile_card(&mut self, user_key: Option<&str>) {
        let lookup_key = match user_key {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => match self.current_user_id.clone() {
                Some(user_id) => user_id,
                None => {
                    self.push_notification(self.t("error_not_logged_in"));
                    return;
                }
            },
        };
        match self.connector.get_user_profile(&lookup_key) {
            Ok(profile) => {
                // 卡片上的头像是大图，尺寸与消息区不同，需要单独取一次字节并按大尺寸解码
                self.avatar_images.remove(&profile.id);
                self.request_missing_avatars(std::slice::from_ref(&profile.id));
                self.profile_view = Some(profile);
                self.displaying_overlay = DisplayingOverlay::ProfileCard;
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_profile_not_found")))
            }
        }
    }

    /// 确保用户目录已在后台发起拉取：只在从没拉过时派生活，之后无论成功失败都不再重复请求。
    /// 由"打出 /profile 加空格"这次按键触发，补全面板首帧可能还是空的，取回后自动填上。
    fn ensure_registered_users_loaded(&mut self) {
        if self.registered_users.is_some() {
            return;
        }
        // 先占位再拉取，避免同一帧之后再次进入本方法重复派线程
        self.registered_users = Some(Vec::new());
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        let connector = self.connector.clone();
        thread::spawn(move || match connector.list_all_users() {
            Ok(users) => {
                let _ = sender.send(PollingEvent::RegisteredUsersUpdated(users));
            }
            Err(error) => debug_log(&format!("拉取用户目录失败: {error}")),
        });
    }

    /// /list_users：列出服务端全部注册用户（用户名与 UID 同行显示）。
    fn show_registered_users(&mut self) {
        match self.connector.list_all_users() {
            Ok(users) => {
                self.registered_users = Some(users.clone());
                if users.is_empty() {
                    self.push_notification(self.t("list_users_empty"));
                    return;
                }
                let lines: Vec<String> = users
                    .iter()
                    .map(|user| format!("{} - {}", user.username, user.id))
                    .collect();
                let title = self
                    .t("list_users_title")
                    .replace("{count}", &lines.len().to_string());
                self.push_notification(format!("{title}\n{}", lines.join("\n")));
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_list_users_failed")))
            }
        }
    }

    /// /search_users <关键字>：按用户名子串或 UID 精确查用户。
    fn search_registered_users(&mut self, keyword: &str) {
        if keyword.is_empty() {
            self.push_notification(self.t("search_users_usage"));
            return;
        }
        match self.connector.search_users(keyword) {
            Ok(users) => {
                if users.is_empty() {
                    self.push_notification(
                        self.t("search_users_empty")
                            .replace("{keyword}", keyword)
                            .to_string(),
                    );
                    return;
                }
                let lines: Vec<String> = users
                    .iter()
                    .map(|user| format!("{} - {}", user.username, user.id))
                    .collect();
                let title = self
                    .t("search_users_title")
                    .replace("{keyword}", keyword)
                    .replace("{count}", &lines.len().to_string());
                self.push_notification(format!("{title}\n{}", lines.join("\n")));
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_search_users_failed")))
            }
        }
    }

    /// 私聊管理浮层里的全部条目：(是否自己发出的, 请求条目)。收到的在前、发出的在后，
    /// 上下键在两个区之间连续移动，因此渲染与按键都用同一份扁平序列定位选中项。
    fn request_entries(&self) -> Vec<(bool, RoomRequestInfo)> {
        let mut entries: Vec<(bool, RoomRequestInfo)> = self
            .pending_requests
            .iter()
            .map(|request| (false, request.clone()))
            .collect();
        entries.extend(
            self.sent_requests
                .iter()
                .map(|request| (true, request.clone())),
        );
        entries
    }

    /// 服务端不为"请求被处理"广播事件，只能从"我发出的请求"的状态变化里看出来：
    /// 上一轮还是待处理、这一轮变成已拒绝的，给发出者补一条通知。
    fn announce_declined_invitations(&mut self, latest: &[RoomRequestInfo]) {
        let mut notices: Vec<String> = Vec::new();
        for previous in &self.sent_requests {
            if previous.status.as_deref() != Some("pending") {
                continue;
            }
            let Some(current) = latest.iter().find(|request| request.id == previous.id) else {
                continue;
            };
            if current.status.as_deref() != Some("declined") {
                continue;
            }
            let receiver_name = current
                .receiver
                .as_ref()
                .map(|peer| peer.username.clone())
                .unwrap_or_else(|| self.t("unknown_user"));
            notices.push(
                self.t("request_declined_notice")
                    .replace("{user}", &receiver_name),
            );
        }
        for notice in notices {
            self.push_notification(notice);
        }
    }

    /// 撤回自己发出的私聊请求：服务端把请求置为 cancelled，对方不会再看到它。
    fn cancel_sent_request(&mut self, request_id: &str) {
        match self.connector.cancel_room_request(request_id) {
            Ok(_) => {
                self.push_notification(self.t("request_cancelled"));
                self.mark_sent_request_cancelled(request_id);
                if let Some(index) = self.request_list_state.selected()
                    && index >= self.request_entries().len()
                {
                    self.request_list_state
                        .select(if self.request_entries().is_empty() {
                            None
                        } else {
                            Some(index.min(self.request_entries().len() - 1))
                        });
                }
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_cancel_request_failed")
            )),
        }
    }

    /// /update 与设置项"更新客户端"：用已下载并校验过的更新包安排替换，本进程随后退出，
    /// 让位给安装进程。安装进程会等本进程号消失再动文件，避免 Windows 上
    /// "正被占用的可执行文件无法覆盖"。
    /// 包还没回来时不能在这里同步下载——下载要占满整个界面线程，
    /// 所以改成再补派一次后台检查，取回后照常弹通知，用户稍后再执行即可。
    fn start_downloaded_update(&mut self) -> bool {
        let Some((version, archive_path)) = self.pending_update.clone() else {
            self.start_update_check_thread(Self::client_version());
            self.push_notification(self.t("update_not_ready"));
            return false;
        };
        let staged_directory = match paths::update_directory() {
            Some(directory) => directory.join(format!("staged-{version}")),
            None => {
                self.push_error(self.t("error_update_directory_unavailable"));
                return false;
            }
        };
        if let Err(error) = crate::installer::extract_archive(&archive_path, &staged_directory) {
            self.push_error(format!(
                "{}: {error}",
                self.t("error_update_extract_failed")
            ));
            return false;
        }
        let Some(prefix) = crate::installer::current_prefix() else {
            self.push_error(self.t("error_update_prefix_unavailable"));
            return false;
        };
        let request = crate::installer::InstallRequest {
            source_directory: staged_directory,
            prefix,
            wait_for_process: Some(std::process::id()),
        };
        match crate::installer::spawn_detached_installer(&request) {
            Ok(()) => {
                self.update_handoff_requested = true;
                true
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_update_start_failed")));
                false
            }
        }
    }

    /// 主循环退出判定：/update 已把安装进程挂起，本进程要立即让位
    pub fn should_exit_for_update(&self) -> bool {
        self.update_handoff_requested
    }
}

/// 资料字段取值：有内容就按新值写入，留空则这一项不进请求体（服务端语义是"缺省=保持原值"）。
/// 表单打开时已把服务端现值预填进来，所以"不改"就是"原样提交"，不需要额外的清空写法。
fn profile_field_value(text: &str) -> Option<Option<String>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Some(trimmed.to_string()))
    }
}

/// 读本地图片文件用于上传：只认服务端接受的四种格式，其余返回 None 由调用方提示用户。
/// 服务端另有自己的大小上限（默认 2 MB，可配置），这里只挡明显离谱的体积，
/// 免得用户误填一个几百兆的文件时整份读进内存；真正的限额交给服务端回答。
fn read_local_image(path: &std::path::Path) -> Option<(String, String, Vec<u8>)> {
    let content_type = image_content_type_of(path)?;
    if fs::metadata(path)
        .map(|metadata| metadata.len() > 8 * 1024 * 1024)
        .unwrap_or(true)
    {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let file_name = path.file_name()?.to_str()?.to_string();
    Some((file_name, content_type.to_string(), bytes))
}

/// 服务端接受的四类图片格式 → multipart 里的 CONTENT_TYPE。
/// 目录列表与上传共用这一处判定，列出来能选的就一定能传。
fn image_content_type_of(path: &std::path::Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

/// 用户自备头像的目录：不存在就建出来，用户照着这个路径放图片即可。
/// 启动时与每次进入头像浮层时各保证一次，渲染路径不碰磁盘创建。
pub(crate) fn ensure_avatar_source_directory() {
    if let Some(directory) = baihua_core::paths::avatar_source_directory() {
        let _ = fs::create_dir_all(directory);
    }
}

/// 头像目录里可选的图片，元素为 (展示用的文件名, 上传用的完整路径)，按文件名排序。
/// 目录读不到或没有图片时返回空表，由调用方退回填链接的表单。
fn local_avatar_files() -> Vec<(String, PathBuf)> {
    match baihua_core::paths::avatar_source_directory() {
        Some(directory) => avatar_files_in(&directory),
        None => Vec::new(),
    }
}

/// 列出指定目录里的可上传图片。格式判定与上传共用 `image_content_type_of`，
/// 列出来能被选中的文件就一定传得上去；子目录与读不到的条目直接跳过。
fn avatar_files_in(directory: &std::path::Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files: Vec<(String, PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_string();
            image_content_type_of(&path).map(|_| (name, path))
        })
        .collect();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    // 父模块的 use 不会对子模块可见，测试里的假服务端需要自己引入读写 trait
    use std::io::{Read, Write};

    /// 把带样式片段渲染成的行还原成纯文本，便于断言折行与切分结果
    fn line_text(line: &Line) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn keyword_positions_are_case_insensitive_and_char_indexed() {
        assert_eq!(
            find_keyword_positions("Baihua chat", "bai"),
            vec![(0usize, 3usize)]
        );
        assert_eq!(
            find_keyword_positions("Baihua CHAT chat", "chat"),
            vec![(7usize, 11usize), (12usize, 16usize)]
        );
        // 中文关键词按字符下标返回，不受 UTF-8 字节长度影响
        assert_eq!(
            find_keyword_positions("你好，世界。世界！", "世界"),
            vec![(3usize, 5usize), (6usize, 8usize)]
        );
        // 空关键词与超长关键词都不应当命中，避免整屏高亮
        assert!(find_keyword_positions("abc", "").is_empty());
        assert!(find_keyword_positions("ab", "abc").is_empty());
    }

    #[test]
    fn keyword_positions_skip_overlapping_matches() {
        // "aa" 在 "aaaa" 中命中两次而非三次：命中后跳过整段
        assert_eq!(
            find_keyword_positions("aaaa", "aa"),
            vec![(0usize, 2usize), (2usize, 4usize)]
        );
    }

    #[test]
    fn split_line_marks_only_matched_segments() {
        let matched_style = Style::default().bg(Color::Red);
        let body_style = Style::default().fg(Color::White);
        let segments = split_line_by_keyword("xxAAYY", "aa", body_style, matched_style);
        let texts: Vec<&str> = segments.iter().map(|(text, _)| text.as_str()).collect();
        assert_eq!(texts, vec!["xx", "AA", "YY"]);
        assert_eq!(segments[0].1, body_style);
        assert_eq!(segments[1].1, matched_style);
        assert_eq!(segments[2].1, body_style);
        // 无命中时整行作为单个正文片段返回
        let untouched = split_line_by_keyword("nothing", "zz", body_style, matched_style);
        assert_eq!(untouched.len(), 1);
        assert_eq!(untouched[0].0, "nothing");
        assert_eq!(untouched[0].1, body_style);
    }

    #[test]
    fn wrapping_keeps_highlight_across_line_breaks() {
        let body_style = Style::default().fg(Color::White);
        let matched_style = Style::default().bg(Color::Red);
        // 关键词恰好落在折行边界上，命中样式必须跟着被切断的后半段续到下一行
        let segments = split_line_by_keyword("aaaBB", "BB", body_style, matched_style);
        let lines = wrap_styled_segments(&segments, 4);
        assert_eq!(lines.len(), 2);
        assert_eq!(line_text(&lines[0]), "aaaB");
        assert_eq!(line_text(&lines[1]), "B");
        // 第二行唯一的片段就是命中样式，说明高亮没有在折行时丢失
        assert_eq!(lines[1].spans.len(), 1);
        assert_eq!(lines[1].spans[0].style, matched_style);
        assert_eq!(lines[0].spans[0].style, body_style);
    }

    #[test]
    fn wrapping_respects_display_width_for_wide_characters() {
        let segments = vec![("你好世界".to_string(), Style::default())];
        // 每个汉字两列，宽度 4 只放得下两个字
        let lines = wrap_styled_segments(&segments, 4);
        assert_eq!(lines.len(), 2);
        assert_eq!(line_text(&lines[0]), "你好");
        assert_eq!(line_text(&lines[1]), "世界");
        // 空输入也要产出一行，避免 Paragraph 少一行导致滚动位置错位
        assert_eq!(wrap_styled_segments(&[], 10).len(), 1);
    }

    #[test]
    fn theme_colors_accept_hex_names_and_rgb_array() {
        assert_eq!(
            parse_theme_color(&serde_json::json!("#efebe2")),
            Some(Color::Rgb(239, 235, 226))
        );
        assert_eq!(
            parse_theme_color(&serde_json::json!("light-blue")),
            Some(Color::LightBlue)
        );
        assert_eq!(
            parse_theme_color(&serde_json::json!("default")),
            Some(Color::Reset)
        );
        assert_eq!(
            parse_theme_color(&serde_json::json!([24, 26, 31])),
            Some(Color::Rgb(24, 26, 31))
        );
        // 非法写法一律返回 None，由调用方按缺字段标记，绝不猜测近似色
        assert_eq!(parse_theme_color(&serde_json::json!("#fff")), None);
        assert_eq!(parse_theme_color(&serde_json::json!("notacolor")), None);
        assert_eq!(parse_theme_color(&serde_json::json!(12)), None);
        assert_eq!(parse_theme_color(&serde_json::json!([1, 2])), None);
    }

    #[test]
    fn contrasting_foreground_stays_readable_on_both_light_and_dark_backgrounds() {
        assert_eq!(
            contrasting_foreground(Color::Rgb(239, 235, 226)),
            Color::Black
        );
        assert_eq!(contrasting_foreground(Color::Rgb(24, 26, 31)), Color::White);
        assert_eq!(contrasting_foreground(Color::Yellow), Color::Black);
        assert_eq!(contrasting_foreground(Color::Reset), Color::White);
    }

    #[test]
    fn every_shipped_theme_is_field_complete_and_well_formatted() {
        // 仓库自带的每个主题文件都必须字段齐全且无多余键，否则说明主题规范与代码脱节
        let names = Appearance::available_names();
        assert!(!names.is_empty(), "config/themes 下应至少有一个外观文件");
        for name in names {
            let (_appearance, has_missing_field, extra_fields) = Appearance::load(&name);
            assert!(
                !has_missing_field,
                "config/themes/{name}.json 缺少外观槽位，需补齐或同步 Appearance 字段"
            );
            assert!(
                extra_fields.is_empty(),
                "config/themes/{name}.json 含未知字段: {extra_fields:?}"
            );
        }
        // default.json 是内置配色的镜像，两者不允许漂移
        let (default_appearance, _, _) = Appearance::load("default");
        assert_eq!(default_appearance, Appearance::built_in());
    }

    #[test]
    fn missing_theme_file_falls_back_to_built_in_and_is_flagged() {
        let (appearance, has_missing_field, extra_fields) =
            Appearance::load("this-theme-does-not-exist");
        assert!(has_missing_field);
        assert!(extra_fields.is_empty());
        assert_eq!(appearance.room_border, Appearance::built_in().room_border);
    }

    /// 构造一个可直接渲染的聊天页应用：加载仓库真实的语言文件与指定外观，
    /// 写入一间群聊与两条消息，并保证渲染路径不会触发任何网络请求。
    fn chat_page_app_for_render(appearance_name: &str) -> App {
        let mut app = App::default();
        app.load_language("zh-CN");
        let (appearance, _, _) = Appearance::load(appearance_name);
        app.appearance = appearance;
        app.appearance_name = appearance_name.to_string();
        // 有 token 才算已登录，否则消息区会被"未登录"提示整体覆盖，断言不到消息样式
        app.connector.set_token("test-token");
        app.connector.set_base_url("http://localhost:1");
        app.current_user_id = Some("user-self".to_string());
        app.rooms = vec![RoomInfo {
            id: "room-one".to_string(),
            name: Some("群聊一号".to_string()),
            is_group: true,
            created_by: "user-self".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: false,
            created_at: String::new(),
        }];
        app.rooms_state.select(Some(0));
        app.sender_names
            .insert("user-other".to_string(), "bob".to_string());
        app.messages = vec![
            MessageInfo {
                id: "message-1".to_string(),
                room_id: "room-one".to_string(),
                sender_id: "user-other".to_string(),
                content: "alpha hello world".to_string(),
                created_at: "2026-08-30T08:00:00+00:00".to_string(),
            },
            MessageInfo {
                id: "message-2".to_string(),
                room_id: "room-one".to_string(),
                sender_id: "user-self".to_string(),
                content: "second message".to_string(),
                created_at: "2026-08-30T08:01:00+00:00".to_string(),
            },
        ];
        app
    }

    #[test]
    fn status_bar_shows_connection_user_and_versions_with_documented_omissions() {
        let mut app = chat_page_app_for_render("default");
        // 未探测过连接状态：按离线画空心点，且不显示服务端版本
        let (connection_label, mark, user_text, right) = app.status_bar_texts();
        assert_eq!(mark, "○");
        assert_eq!(connection_label, app.t("bar_connection"));
        assert!(user_text.is_empty(), "未登录不该显示当前用户");
        assert!(!right.contains(&app.t("bar_server_version")));
        assert!(right.contains(&app.t("bar_client_version")));
        assert!(right.contains(&App::client_version()));

        // 连上但未探测到版本串：仍然不显示服务端版本
        app.connection_ready = Some(true);
        let (_, online_mark, _, right_without_version) = app.status_bar_texts();
        assert_eq!(online_mark, "●");
        assert!(!right_without_version.contains(&app.t("bar_server_version")));

        // 登录后显示当前用户名，且标记仍夹在"连接"与用户名之间（顶栏顺序即语义顺序）
        app.current_username = "alice".to_string();
        let (label, mark, user_text, _) = app.status_bar_texts();
        assert_eq!(label, app.t("bar_connection"));
        assert_eq!(mark, "●");
        assert!(user_text.contains("alice"));
        assert!(user_text.contains(&app.t("bar_current_user")));
        let assembled = format!("{label} {mark}{user_text}");
        assert!(
            assembled.find(&app.t("bar_connection")).unwrap() < assembled.find("●").unwrap(),
            "圆点必须紧跟在连接标签之后，不能被用户名推到行尾"
        );
        assert!(
            assembled.contains("●  |  当前用户 alice"),
            "实际拼接: {assembled}"
        );
    }

    #[test]
    fn editing_search_keyword_backwards_drops_the_previous_result_set() {
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.search_result = Some(("hello".to_string(), vec!["message-1".to_string()], 0));
        // 用退格删掉一个字母：结果不再成立，命中列表与定位一起清掉
        app.input_collector.message_input_state.set_text("#hell");
        app.handle_message_input_changed();
        assert!(
            app.search_result.is_none(),
            "改动关键词后应丢弃上次搜索结果"
        );
        assert!(app.pending_scroll_message_id.is_none());
        // 标题回到"搜索模式"，既不显示旧进度也不显示"未找到"
        let (title, _) = app.message_input_title();
        let rendered = title
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(rendered.contains(&app.t("search_mode")));
        assert!(!rendered.contains(&app.t("search_progress")));
    }

    #[test]
    fn quick_search_recomputes_instead_of_dropping_results() {
        let mut app = chat_page_app_for_render("default");
        app.quick_search = true;
        app.input_collector.message_input_state.set_text("#hel");
        app.handle_message_input_changed();
        let early = app.search_result.clone().expect("快速搜索应即时给出结果");
        assert_eq!(early.1, vec!["message-1".to_string()]);
        app.input_collector.message_input_state.set_text("#hello");
        app.handle_message_input_changed();
        let refined = app
            .search_result
            .clone()
            .expect("改关键词后应重扫而不是清空");
        assert_eq!(refined.0, "hello".to_string());
    }

    #[test]
    fn notification_panel_clips_to_screen_instead_of_vanishing() {
        let mut app = chat_page_app_for_render("default");
        // 十条六十列长文本，在小屏幕上按旧算法高度会算超屏幕而整条不画
        let long_body = (0..10)
            .map(|index| format!("{index} 一六〇列宽的长文本占位。").repeat(4))
            .collect::<Vec<String>>()
            .join("\n");
        app.push_notification(long_body.clone());
        let buffer = render_snapshot(&mut app, 50, 12);
        let first_line = long_body.lines().next().unwrap_or_default();
        let visible_head: String = first_line.chars().take(6).collect();
        assert!(
            buffer_contains(&buffer, &visible_head),
            "提示框在小屏幕上被整体丢弃了，长文本没能自适应"
        );
    }

    #[test]
    fn settings_menu_covers_account_operations_and_marks_destructive_ones() {
        let app = chat_page_app_for_render("default");
        let entries = app.settings_menu_entries();
        let labels: Vec<String> = entries.iter().map(|(label, _, _)| label.clone()).collect();
        for key in [
            "option_edit_profile",
            "option_change_password",
            "option_change_avatar",
            "option_update_client",
            "option_delete_account",
        ] {
            assert!(
                labels.iter().any(|label| label.contains(&app.t(key))),
                "设置菜单缺少条目 {key}"
            );
        }
        let delete_entry = entries
            .iter()
            .find(|(label, _, _)| label.contains(&app.t("option_delete_account")))
            .expect("应有删除账户条目");
        assert_eq!(
            delete_entry.1, app.appearance.notice_error_border,
            "删除账户必须用报错色显示"
        );
        assert_eq!(
            delete_entry.2,
            SettingsAction::OpenForm(FormAction::DeleteAccount)
        );
        // 每一项都要有标签：分派直接读这张表，不再有需要对齐的索引常量
        assert!(
            entries.iter().all(|(label, _, _)| !label.trim().is_empty()),
            "菜单项标签不该为空"
        );
    }

    #[test]
    fn request_overlay_lists_sent_invitations_with_their_status() {
        let mut app = chat_page_app_for_render("default");
        app.pending_requests = vec![RoomRequestInfo {
            id: "request-in".to_string(),
            message: "加个好友".to_string(),
            is_encrypted: false,
            created_at: String::new(),
            sender: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-other".to_string(),
                username: "bob".to_string(),
                nickname: None,
            }),
            receiver: None,
            status: Some("pending".to_string()),
        }];
        app.sent_requests = vec![RoomRequestInfo {
            id: "request-out".to_string(),
            message: "你好".to_string(),
            is_encrypted: false,
            created_at: String::new(),
            sender: None,
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: Some("accepted".to_string()),
        }];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 100, 30);
        assert!(buffer_contains(&buffer, &app.t("request_section_received")));
        assert!(buffer_contains(&buffer, &app.t("request_section_sent")));
        assert!(buffer_contains(&buffer, "carol"));
        assert!(buffer_contains(&buffer, &app.t("request_status_accepted")));
        // 扁平序列把收到的排在前面，撤回与拒绝按所在区分别是不同动作
        let entries = app.request_entries();
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].0);
        assert!(entries[1].0);
    }

    /// 构造一条私聊请求条目，状态与收发方向可按用例填。
    fn invitation_with_status(id: &str, status: Option<&str>) -> RoomRequestInfo {
        RoomRequestInfo {
            id: id.to_string(),
            message: "加个好友".to_string(),
            is_encrypted: false,
            created_at: String::new(),
            sender: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-other".to_string(),
                username: "bob".to_string(),
                nickname: None,
            }),
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: status.map(str::to_string),
        }
    }

    #[test]
    fn settings_badge_counts_only_invitations_still_pending() {
        let mut app = chat_page_app_for_render("default");
        // 收到的条目接口只给待处理的，全部计数；自己发出的要按状态筛
        app.pending_requests = vec![
            invitation_with_status("received-1", Some("pending")),
            invitation_with_status("received-2", Some("pending")),
        ];
        app.sent_requests = vec![
            invitation_with_status("sent-pending", Some("pending")),
            invitation_with_status("sent-accepted", Some("accepted")),
            invitation_with_status("sent-declined", Some("declined")),
            invitation_with_status("sent-expired", Some("expired")),
            invitation_with_status("sent-cancelled", Some("cancelled")),
            invitation_with_status("sent-unknown", None),
        ];
        let label = app
            .settings_menu_entries()
            .iter()
            .find(|(label, _, _)| label.contains(&app.t("option_pending_requests")))
            .expect("设置菜单应有私聊请求管理条目")
            .0
            .clone();
        assert_eq!(
            label,
            format!(" {} (3)", app.t("option_pending_requests")),
            "数字提示只该算两条收到的加一条仍在等的"
        );
    }

    #[test]
    fn declined_sent_invitation_is_labelled_declined_and_never_cancelled() {
        let mut app = chat_page_app_for_render("default");
        app.sent_requests = vec![invitation_with_status("sent-declined", Some("declined"))];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 96, 30);
        assert!(buffer_contains(&buffer, &app.t("request_status_declined")));
        assert!(
            !buffer_contains(&buffer, &app.t("request_status_cancelled")),
            "被拒绝的邀请不能显示成已撤回"
        );
    }

    #[test]
    fn acting_on_an_invitation_keeps_it_in_the_received_history() {
        let mut app = chat_page_app_for_render("default");
        app.pending_requests = vec![
            // 服务端"收到的请求"列表不给状态字段，这里按接口原样留 None
            invitation_with_status("received-1", None),
            invitation_with_status("received-2", None),
        ];
        app.sent_requests = vec![invitation_with_status("sent-1", Some("pending"))];
        app.request_list_state.select(Some(0));
        // 处理完只做本地乐观更新（不再补发一次列表请求与轮询抢着写同一张列表），
        // 且条目必须留在"收到的"区里：服务端下一次就再也回不到它了
        app.mark_pending_request_handled("received-1", "accepted");
        assert_eq!(
            app.pending_requests.len(),
            2,
            "已处理的邀请不能从历史里消失"
        );
        assert_eq!(
            app.pending_requests[0].status.as_deref(),
            Some("accepted"),
            "结果状态要就地记上，否则看上去还是待处理"
        );
        assert_eq!(app.request_entries().len(), 3);
        app.mark_pending_request_handled("received-2", "declined");
        assert_eq!(app.pending_requests[1].status.as_deref(), Some("declined"));
        app.mark_sent_request_cancelled("sent-1");
        assert_eq!(
            app.sent_requests[0].status.as_deref(),
            Some("cancelled"),
            "撤回后本地状态就要变，否则列表里仍显示待处理"
        );
    }

    #[test]
    fn polled_received_requests_keep_locally_handled_history() {
        let mut app = chat_page_app_for_render("default");
        // 本地历史：一条仍在等、一条已接受
        app.pending_requests = vec![
            invitation_with_status("waiting", None),
            invitation_with_status("handled", Some("accepted")),
        ];
        // 轮询带回的列表只会是服务端仍是 pending 的行（已处理的那条不在其中）
        app.apply_received_requests(vec![
            invitation_with_status("waiting", None),
            invitation_with_status("newly-arrived", None),
        ]);
        let ids: Vec<&str> = app
            .pending_requests
            .iter()
            .map(|request| request.id.as_str())
            .collect();
        assert_eq!(ids, vec!["waiting", "newly-arrived", "handled"]);
        assert_eq!(
            app.pending_requests
                .iter()
                .find(|request| request.id == "handled")
                .and_then(|request| request.status.as_deref()),
            Some("accepted"),
            "合并轮询结果时不能把本端记的结果状态冲掉"
        );
        // 同一条目同时出现在两份来源里时以服务端为准，不重复列两遍
        app.apply_received_requests(vec![invitation_with_status("handled", None)]);
        assert_eq!(app.pending_requests.len(), 1);
    }

    /// 只取面板矩形内部的文本（去掉边框字符与空白）逐行拼接。
    /// 折行后的文案跨多行，只有把范围限制在面板列区间里才能整段连续比对。
    fn panel_body_text(buffer: &ratatui::buffer::Buffer, panel_rect: Rect) -> String {
        let border_characters = ['─', '│', '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼'];
        let mut text = String::new();
        for row in panel_rect.y..panel_rect.y + panel_rect.height {
            for column in panel_rect.x..panel_rect.x + panel_rect.width {
                let symbol = buffer[(column, row)].symbol();
                for character in symbol.chars() {
                    if !character.is_whitespace() && !border_characters.contains(&character) {
                        text.push(character);
                    }
                }
            }
        }
        text
    }

    #[test]
    fn narrow_settings_menu_wraps_entries_instead_of_clipping_them() {
        let mut app = chat_page_app_for_render("default");
        app.pending_requests = vec![invitation_with_status("received-1", None)];
        let labels: Vec<String> = app
            .settings_menu_entries()
            .iter()
            .map(|(label, _, _)| label.clone())
            .collect();
        app.displaying_overlay = DisplayingOverlay::SettingsMenu;
        app.menu_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 26, 64);
        // 面板矩形用生产代码同一个算法算，才能只取面板内的列区间：
        // 整行拼接会把面板两侧的聊天页文字混进来，折行的条目因此永远比对不上
        let (panel_rect, body_width) = overlay_list_panel(&labels, Rect::new(0, 1, 26, 63));
        assert!(panel_rect.width <= 26, "面板不该比屏幕还宽");
        let inside = panel_body_text(&buffer, panel_rect);
        for label in &labels {
            let compact: String = label
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            assert!(inside.contains(&compact), "设置菜单条目被裁掉: {label}");
        }
        assert!(
            labels.iter().any(|label| display_width(label) > body_width),
            "这份数据本该窄到需要折行，否则测不到折行分支"
        );
    }

    /// 取一段文案的尾巴若干字符（折行后尾行必须整段看得见，被裁掉时最先不见的就是尾巴）
    fn tail_of(text: &str, characters: usize) -> String {
        text.chars()
            .rev()
            .take(characters)
            .collect::<Vec<char>>()
            .iter()
            .rev()
            .collect::<String>()
    }

    #[test]
    fn english_requests_and_form_hints_wrap_on_a_narrow_panel() {
        let mut app = chat_page_app_for_render("default");
        // 英文文案比中文长得多，窄面板上的裁切只在英文里才暴露，所以这一发用 en-US
        app.load_language("en-US");
        app.sent_requests = vec![invitation_with_status("sent-1", Some("accepted"))];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 56, 20);
        assert!(
            buffer_contains(&buffer, &tail_of(&app.t("hint_pending_requests"), 8)),
            "私聊请求浮层的底部提示被右边界裁掉了"
        );

        app.open_form(
            FormAction::ChangePassword,
            vec![
                FormField::new("password_old_label", "", true),
                FormField::new("password_new_label", "", true),
                FormField::new("password_confirm_label", "", true),
            ],
        );
        let narrow = render_snapshot(&mut app, 40, 20);
        assert!(
            buffer_contains(&narrow, &tail_of(&app.t("form_password_hint"), 8)),
            "改密表单的底部提示在 40 列面板里被裁掉了"
        );
    }

    #[test]
    fn narrow_status_bar_keeps_the_connection_mark_and_user() {
        let mut app = chat_page_app_for_render("default");
        app.connection_ready = Some(true);
        app.current_username = "buitest13".to_string();
        // 版本信息是次要的：一行放不下时让它先被裁，连接标记与当前用户必须留下
        let buffer = render_snapshot(&mut app, 56, 20);
        assert!(buffer_contains(&buffer, "连接 ●"), "窄屏把连接标记挤掉了");
        assert!(
            buffer_contains(&buffer, &format!("当前用户 {}", app.current_username)),
            "窄屏把当前用户挤掉了"
        );
        // 宽屏上两段都放得下，版本信息照旧完整（服务端版本没探测过，本来就不显示）
        let wide = render_snapshot(&mut app, 120, 20);
        assert!(buffer_contains(&wide, &app.t("bar_client_version")));
        assert!(buffer_contains(&wide, &App::client_version()));
        assert!(buffer_contains(&wide, "当前用户 buitest13"));
    }

    #[test]
    fn wrapped_hint_text_keeps_every_character_and_stays_within_width() {
        // 表单浮层预留的高度就是这个函数的行数，所以"不丢字 + 每行不超宽"即等价于不裁切
        let app = chat_page_app_for_render("default");
        let hint = app.t("form_profile_hint");
        let wrapped = wrapped_hint_text(&hint, Style::default(), 34);
        assert!(wrapped.lines.len() >= 2, "窄面板里提示应该折行");
        let joined: String = wrapped
            .lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let original: String = hint
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert_eq!(joined, original, "折行丢了字");
        for line in &wrapped.lines {
            let plain: String = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            assert!(display_width(&plain) <= 34, "折出来的行仍超宽: {plain}");
        }
    }

    #[test]
    fn account_settings_refuse_a_signed_out_user_without_leaving_the_menu() {
        let mut app = chat_page_app_for_render("default");
        app.current_user_id = None;
        app.websocket_token = None;
        app.displaying_overlay = DisplayingOverlay::SettingsMenu;
        let profile_index = app
            .settings_menu_entries()
            .iter()
            .position(|(_, _, action)| {
                matches!(action, SettingsAction::OpenForm(FormAction::UpdateProfile))
            })
            .expect("设置菜单应有改资料条目");
        app.menu_list_state.select(Some(profile_index));
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert_eq!(
            app.displaying_overlay,
            DisplayingOverlay::SettingsMenu,
            "未登录不该切进表单浮层"
        );
        assert!(app.active_form.is_none());
        assert!(
            app.notifications
                .iter()
                .any(|(text, _, _)| text == &app.t("error_not_logged_in"))
        );
        // 本地显示开关与语言/外观不依赖登录态，仍要照常生效
        let toggle_index = app
            .settings_menu_entries()
            .iter()
            .position(|(_, _, action)| matches!(action, SettingsAction::ToggleShowUid))
            .expect("设置菜单应有显示 UID 开关");
        app.menu_list_state.select(Some(toggle_index));
        let before = app.show_uid;
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.show_uid, !before);
    }

    #[test]
    fn avatar_overlay_hands_url_input_over_to_the_form() {
        let mut app = chat_page_app_for_render("default");
        app.displaying_overlay = DisplayingOverlay::AvatarSelect;
        app.avatar_list_state.select(Some(0));
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Char('u'),
            KeyModifiers::CONTROL,
        )));
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Form);
        assert_eq!(
            app.active_form.as_ref().map(|(action, _)| action.clone()),
            Some(FormAction::ChangeAvatar),
            "Ctrl+U 应打开原来的修改头像表单"
        );
    }

    #[test]
    fn avatar_directory_offers_only_uploadable_images() {
        let directory = std::env::temp_dir().join("baihua-avatar-source-listing");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(directory.join("子目录")).expect("临时目录应可创建");
        for name in [
            "me.png",
            "other.JPG",
            "notes.txt",
            "archive.tar.gz",
            "icon.webp",
        ] {
            fs::write(directory.join(name), b"x").expect("临时文件应可写入");
        }
        let names: Vec<String> = avatar_files_in(&directory)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, vec!["icon.webp", "me.png", "other.JPG"]);
        // 每条都带回真实路径，回车上传用的就是它
        let entries = avatar_files_in(&directory);
        assert!(entries.iter().all(|(_, path)| path.starts_with(&directory)));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn completion_descriptions_move_onto_their_own_line_when_tight() {
        let label = "/profile bobbington";
        let description = "01a070d7-d079-71c0-a254-32706c393476";
        let wide = completion_lines(label, description, Style::default(), Style::default(), 80);
        assert_eq!(wide.len(), 1, "放得下时不该多占一行");
        let tight = completion_lines(label, description, Style::default(), Style::default(), 24);
        assert!(tight.len() >= 2, "挤不下时说明要另起一行");
        let flattened: String = tight
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let expected = format!("{label}{description}")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert_eq!(flattened, expected, "挤不下时说明要完整挪到下一行");
    }

    /// 造一张纯色 PNG 的字节：卡片测试不依赖仓库里的素材文件
    fn synthetic_avatar_png() -> Vec<u8> {
        let image_buffer = image::RgbaImage::from_pixel(64, 64, image::Rgba([220, 30, 30, 255]));
        let mut encoded = std::io::Cursor::new(Vec::new());
        image_buffer
            .write_to(&mut encoded, image::ImageFormat::Png)
            .expect("测试图片应能编码");
        encoded.into_inner()
    }

    /// 头像网格必须始终"列 = 2×行"（一格装上下两个像素），否则正方形源图会被压成矩形。
    #[test]
    fn avatar_grid_keeps_the_square_pixel_ratio_at_every_width() {
        for columns_available in [4u16, 7, 12, 20, 21, 32, 48] {
            let (columns, rows) = avatar_grid_within(columns_available, 30);
            assert_eq!(columns, rows * 2, "{columns_available} 列可用时比例失真");
            assert!(
                columns <= columns_available.max(2),
                "{columns_available} 列可用时超出宽度"
            );
            assert!(
                rows <= profile_avatar_cells().1 as u16,
                "行数不该超过最大网格"
            );
        }
    }

    /// 卡片上真正画出来的像素块也要保持同一比例（宽度只算半块字符所在的列）
    #[test]
    fn profile_card_paints_an_avatar_that_is_not_stretched() {
        let mut app = chat_page_app_for_render("default");
        app.profile_view = Some(PublicProfile {
            id: "user-self".to_string(),
            username: "self".to_string(),
            nickname: None,
            bio: Some("短".to_string()),
            avatar: Some("/static/avatars/me.png".to_string()),
        });
        app.avatar_images
            .insert("user-self".to_string(), Some(synthetic_avatar_png()));
        app.displaying_overlay = DisplayingOverlay::ProfileCard;
        for (width, height) in [(40u16, 22u16), (64, 24), (120, 36)] {
            let buffer = render_snapshot(&mut app, width, height);
            let mut columns: Vec<u16> = Vec::new();
            let mut rows: Vec<u16> = Vec::new();
            for row in 0..buffer.area.height {
                for column in 0..buffer.area.width {
                    if buffer[(column, row)].symbol() == "▀" {
                        if !columns.contains(&column) {
                            columns.push(column);
                        }
                        if !rows.contains(&row) {
                            rows.push(row);
                        }
                    }
                }
            }
            assert!(
                !rows.is_empty(),
                "{width}x{height} 下没画出头像素块（头像被文字挤掉了）"
            );
            assert_eq!(
                columns.len(),
                rows.len() * 2,
                "{width}x{height} 下头像被压成 {}×{} 的矩形",
                columns.len(),
                rows.len()
            );
        }
    }

    #[test]
    fn profile_card_wraps_long_fields_instead_of_clipping_them() {
        let mut app = chat_page_app_for_render("default");
        app.own_contact = Some((
            "someone.with.a.long.mail@example.com".to_string(),
            "13800000000".to_string(),
        ));
        app.profile_view = Some(PublicProfile {
            id: "user-self".to_string(),
            username: "self".to_string(),
            nickname: Some("长着中文昵称的自己".to_string()),
            bio: Some("这是一段非常长的个人简介，专门用来验证窄屏下资料卡不会裁掉尾部".to_string()),
            avatar: Some("https://avatar.example.com/users/0123456789abcdef.png".to_string()),
        });
        app.displaying_overlay = DisplayingOverlay::ProfileCard;
        let buffer = render_snapshot(&mut app, 62, 24);
        assert!(
            buffer_contains(&buffer, "裁掉尾部"),
            "窄屏下长简介尾部被右边界切掉"
        );
        assert!(
            buffer_contains(&buffer, "abcdef.png"),
            "窄屏下长头像链接尾部被右边界切掉"
        );
        assert!(
            buffer_contains(&buffer, "example.com"),
            "窄屏下长邮箱尾部被右边界切掉"
        );
    }

    #[test]
    fn form_overlay_masks_password_fields() {
        let mut app = chat_page_app_for_render("default");
        app.active_form = Some((
            FormAction::ChangePassword,
            vec![
                FormField::new("password_old_label", "hunter2", true),
                FormField::new("password_new_label", "", true),
                FormField::new("password_confirm_label", "", true),
            ],
        ));
        app.displaying_overlay = DisplayingOverlay::Form;
        let buffer = render_snapshot(&mut app, 90, 24);
        assert!(buffer_contains(&buffer, &app.t("password_old_label")));
        assert!(buffer_contains(&buffer, &app.t("password_confirm_label")));
        assert!(
            !buffer_contains(&buffer, "hunter2"),
            "密码字段必须以遮蔽字符显示，不能把明文画到屏幕上"
        );
        // 标签列宽取最宽标签，焦点标记只出现在当前项上
        assert!(buffer_contains(&buffer, &app.t("form_password_hint")));
    }

    #[test]
    fn profile_field_value_skips_empty_and_writes_the_rest() {
        // 留空 = 这一项不进请求体（服务端语义是保持原值），有内容就按新值写入。
        // 单个减号已不再有特殊含义，就是一个普通值
        assert_eq!(profile_field_value("   "), None);
        assert_eq!(profile_field_value("-"), Some(Some("-".to_string())));
        assert_eq!(
            profile_field_value("  新昵称  "),
            Some(Some("新昵称".to_string()))
        );
    }

    #[test]
    fn plain_room_history_is_cached_and_encrypted_room_is_not() {
        let root = std::env::temp_dir().join(format!("baihua-app-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut app = chat_page_app_for_render("default");
        app.current_user_id = Some("user-self".to_string());
        app.chat_cache = Some(baihua_core::chat_cache::ChatCache::open_in(
            "user-self",
            &root,
        ));

        // 未加密房间：整房写入后能按原样读回，并带回翻页游标
        app.cache_loaded_messages("room-one");
        let cache = app.chat_cache.as_ref().expect("应已建立缓存目录");
        let cached = cache.load_room("room-one").expect("明聊房间应已落盘");
        assert_eq!(cached.messages.len(), 2);
        assert_eq!(cached.messages[0].id, "message-1");

        // 加密房间：一律不落盘
        app.rooms.push(RoomInfo {
            id: "room-secret".to_string(),
            name: None,
            is_group: false,
            created_by: "user-self".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: true,
            created_at: String::new(),
        });
        app.messages.push(MessageInfo {
            id: "message-secret".to_string(),
            room_id: "room-secret".to_string(),
            sender_id: "user-other".to_string(),
            content: "只存在于内存里的明文".to_string(),
            created_at: "2026-08-30T08:02:00+00:00".to_string(),
        });
        app.cache_loaded_messages("room-secret");
        assert!(
            cache.load_room("room-secret").is_none(),
            "加密房间不得写入本地缓存"
        );
        // 消息列表混合了两个房间的内容时，也不允许按某个房间落盘
        assert!(
            cache.load_room("room-one").is_some(),
            "此前写好的明聊缓存不该被误删"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exit_alias_runs_the_same_quit_path() {
        let commands = chat_commands();
        let quit = commands
            .iter()
            .find(|(name, _)| *name == "quit")
            .expect("应有 /quit");
        let exit = commands
            .iter()
            .find(|(name, _)| *name == "exit")
            .expect("应有 /exit 别名");
        assert_eq!(quit.1, exit.1, "别名必须共用同一条说明文案");
        // 没有私聊要清理时退出流程立即就绪，正好用来验证别名走的是同一条路径
        let mut app = chat_page_app_for_render("default");
        assert!(!app.should_quit_now());
        app.execute_chat_command("/exit");
        assert!(app.should_quit_now(), "/exit 应像 /quit 一样进入退出流程");
    }

    #[test]
    fn dark_theme_is_shipped_complete_and_differs_from_default() {
        let names = Appearance::available_names();
        assert!(
            names.iter().any(|name| name == "dark"),
            "应随仓库提供暗色主题"
        );
        let (dark, has_missing_field, extra_fields) = Appearance::load("dark");
        assert!(!has_missing_field);
        assert!(extra_fields.is_empty());
        let built_in = Appearance::built_in();
        assert_ne!(dark.app_background, built_in.app_background);
        assert_ne!(dark.message_text, built_in.message_text);
        // 暗色主题下正文必须比背景亮，否则等于看不见
        assert!(
            theme_luminance(dark.message_text) > theme_luminance(dark.app_background),
            "暗色主题的正文颜色应明显亮于背景"
        );
    }

    /// 颜色的感知亮度（与 contrasting_foreground 同一套加权，用于主题自检）
    fn theme_luminance(color: Color) -> u32 {
        match color {
            Color::Rgb(red, green, blue) => {
                (u32::from(red) * 299 + u32::from(green) * 587 + u32::from(blue) * 114) / 1000
            }
            _ => 255,
        }
    }

    #[test]
    fn form_with_one_field_falls_back_to_box_input_and_still_masks_it() {
        let mut app = chat_page_app_for_render("default");
        // 一个条目的表单（删除账户）按规矩用方框输入框，而不是箭头行
        app.active_form = Some((
            FormAction::DeleteAccount,
            vec![FormField::new(
                "delete_account_password_label",
                "hunter2",
                true,
            )],
        ));
        app.displaying_overlay = DisplayingOverlay::Form;
        let buffer = render_snapshot(&mut app, 90, 24);
        let body = buffer_row_text(&buffer, 0);
        assert!(!body.contains("hunter2"), "口令不该出现在屏幕上");
        // 方框存在的证据：有一个左上角，且边框是"未选中"的输入框边框色
        // （表单刻意不用选中色，见 render_box_field）
        assert!(
            buffer
                .content
                .iter()
                .any(|cell| cell.symbol() == "┌" && cell.fg == app.appearance.input_border),
            "少于三个条目的表单应自带方框输入框，且默认不是选中色"
        );
        assert!(buffer_contains(
            &buffer,
            &app.t("delete_account_password_label")
        ));
    }

    #[test]
    fn request_overlay_shows_the_whole_invitation_message() {
        let mut app = chat_page_app_for_render("default");
        let long_message =
            "这是一条很长很长的私聊验证消息，用来检验浮层会不会把内容截成一行。".repeat(3);
        app.pending_requests = vec![RoomRequestInfo {
            id: "request-long".to_string(),
            message: long_message.clone(),
            is_encrypted: false,
            created_at: String::new(),
            sender: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-other".to_string(),
                username: "bob".to_string(),
                nickname: None,
            }),
            receiver: None,
            status: Some("pending".to_string()),
        }];
        app.sent_requests = vec![RoomRequestInfo {
            id: "request-out".to_string(),
            message: "你好，加个好友".to_string(),
            is_encrypted: true,
            created_at: String::new(),
            sender: None,
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: Some("pending".to_string()),
        }];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 96, 30);
        let tail: String = long_message.chars().rev().take(6).collect::<String>();
        let tail: String = tail.chars().rev().collect();
        assert!(
            buffer_contains(&buffer, &tail),
            "邀请正文被截断，末尾的 {tail:?} 没出现在浮层里"
        );
        // 自己发出的那条也在，并带上加密标记与状态
        assert!(buffer_contains(&buffer, "carol"));
        assert!(buffer_contains(&buffer, &app.t("request_status_pending")));
    }

    #[test]
    fn closing_an_overlay_returns_keyboard_focus_to_the_message_box() {
        let mut app = chat_page_app_for_render("default");
        // 浮层打开时 focus_index 指的是浮层里的输入项，关掉后必须交还消息输入框，
        // 否则会回到"打字没有落点"的状态（表现是键盘输入完全没反应）
        app.displaying_overlay = DisplayingOverlay::Form;
        app.active_form = Some((
            FormAction::DeleteAccount,
            vec![FormField::new("delete_account_password_label", "", true)],
        ));
        app.focus_index = 0;
        let escape = Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        ));
        app.handle_event(&escape);
        assert_eq!(app.displaying_overlay, DisplayingOverlay::SettingsMenu);
        app.handle_event(&escape);
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Nothing);
        for character in ['/', 'p', 'r'] {
            app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
                KeyCode::Char(character),
                KeyModifiers::NONE,
            )));
        }
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "/pr",
            "退出浮层后输入应落回消息输入框"
        );
    }

    #[test]
    fn login_and_register_with_arguments_are_refused_without_a_word() {
        let mut app = chat_page_app_for_render("default");
        // 带参数的登录既不该执行、也不该被清空重写，静默拒绝即可
        app.input_collector
            .message_input_state
            .set_text("/login somebody hunter2");
        app.handle_chat_submit();
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "/login somebody hunter2",
            "带参数的登录行不该被吃掉"
        );
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Nothing);
        assert!(app.notifications.is_empty(), "不该再多一句提示");
        // 无参数才打开登录浮层
        app.input_collector.message_input_state.set_text("/login");
        app.handle_chat_submit();
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Login);
    }

    #[test]
    fn declined_invitation_is_announced_once_to_the_sender() {
        fn invitation(status: &str) -> RoomRequestInfo {
            RoomRequestInfo {
                id: "request-1".to_string(),
                message: "加个好友".to_string(),
                is_encrypted: false,
                created_at: String::new(),
                sender: None,
                receiver: Some(baihua_core::api::RoomRequestPeer {
                    user_id: "user-carol".to_string(),
                    username: "carol".to_string(),
                    nickname: None,
                }),
                status: Some(status.to_string()),
            }
        }
        let mut app = chat_page_app_for_render("default");
        app.sent_requests = vec![invitation("pending")];
        // 轮询带回"已拒绝"，发出者要收到一条通知
        app.announce_declined_invitations(&[invitation("declined")]);
        let notices: Vec<String> = app
            .notifications
            .iter()
            .map(|(text, _, _)| text.clone())
            .collect();
        assert_eq!(notices.len(), 1, "实际通知: {notices:?}");
        assert!(
            notices[0].contains("carol"),
            "通知里要点明是谁拒的: {notices:?}"
        );
        // 本地列表更新后再来一轮同样状态，不该重复提示
        app.notifications.clear();
        app.sent_requests = vec![invitation("declined")];
        app.announce_declined_invitations(&[invitation("declined")]);
        assert!(app.notifications.is_empty(), "同一状态变化不该报两次");
    }

    #[test]
    fn profile_completion_reads_the_cached_directory_only() {
        let mut app = chat_page_app_for_render("default");
        // 目录还没拉到时没有候选，且渲染路径不会发请求（base_url 指向不可达端口，
        // 一旦这里真去请求就会走到执行分支而不是补全分支）
        app.registered_users = None;
        assert!(app.completion_candidates("profile ").is_empty());
        app.registered_users = Some(vec![UserSearchResult {
            id: "01a0".to_string(),
            username: "carol".to_string(),
            nickname: Some("卡尔".to_string()),
            bio: None,
            avatar: None,
        }]);
        let candidates = app.completion_candidates("profile ");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "/profile carol");
        assert_eq!(candidates[0].1, "carol - 01a0");
        assert_eq!(candidates[0].2, "卡尔");
        // 已输入前缀时继续过滤，不要求从头匹配
        assert_eq!(app.completion_candidates("profile ca").len(), 1);
        assert!(app.completion_candidates("profile zz").is_empty());
    }

    #[test]
    fn every_overlay_frame_uses_the_theme_overlay_border_color() {
        let mut app = chat_page_app_for_render("high-contrast");
        let overlay_border = app.appearance.overlay_border;
        let frames = [
            DisplayingOverlay::SettingsMenu,
            DisplayingOverlay::LanguageSelect,
            DisplayingOverlay::AppearanceSelect,
            DisplayingOverlay::Login,
            DisplayingOverlay::Register,
            DisplayingOverlay::CreateGroup,
            DisplayingOverlay::CreatePrivate,
            DisplayingOverlay::ServerAddress,
            DisplayingOverlay::PendingRequests,
            DisplayingOverlay::ProfileCard,
            DisplayingOverlay::Form,
            DisplayingOverlay::AvatarSelect,
        ];
        for frame_kind in frames {
            app.displaying_overlay = frame_kind.clone();
            if frame_kind == DisplayingOverlay::Form {
                app.active_form = Some((
                    FormAction::ChangeAvatar,
                    vec![FormField::new("avatar_input_label", "", false)],
                ));
            } else {
                app.active_form = None;
            }
            if frame_kind == DisplayingOverlay::ProfileCard {
                app.profile_view = Some(PublicProfile {
                    id: "user-other".to_string(),
                    username: "bob".to_string(),
                    nickname: None,
                    bio: None,
                    avatar: None,
                });
            } else {
                app.profile_view = None;
            }
            let buffer = render_snapshot(&mut app, 100, 30);
            assert!(
                buffer
                    .content
                    .iter()
                    .any(|cell| cell.symbol() == "└" && cell.fg == overlay_border),
                "{frame_kind:?} 的窗口边框没走外观里的 overlay_border"
            );
        }
    }

    #[test]
    fn very_long_single_line_notification_is_still_visible_on_a_small_screen() {
        let mut app = chat_page_app_for_render("default");
        let head = "很长的单行提示内容";
        app.push_notification(format!("{}结尾看得见", head.repeat(12)));
        let buffer = render_snapshot(&mut app, 60, 14);
        // 旧算法按整段文本的总宽度估高度，小屏幕上算出来超过屏高就整条不画；
        // 现在按"最宽一行"定宽、逐行估高，放不下时裁切显示而不是丢弃
        assert!(
            buffer_contains(&buffer, head),
            "长提示在小屏幕上被整条丢弃，没有自适应宽高"
        );
    }

    /// 用 ratatui 的测试后端把整个界面渲染进内存缓冲区。
    /// 没有真实终端时这是唯一能验证到"像素"（单元格符号与样式）的手段。
    fn render_snapshot(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("测试后端应能初始化");
        terminal.draw(|frame| app.ui(frame)).expect("渲染聊天页");
        terminal.backend().buffer().clone()
    }

    /// 把缓冲区某一行还原成纯文本，便于按字符串断言标题栏、提示行等文本内容。
    /// 双宽字符（中文）占两个单元格、第二格是空占位格，必须按显示宽度跨格推进，
    /// 否则还原出的中文文本会被插入空格。
    fn buffer_row_text(buffer: &ratatui::buffer::Buffer, row: u16) -> String {
        let mut text = String::new();
        let mut column = 0u16;
        while column < buffer.area.width {
            let symbol = buffer[(column, row)].symbol();
            text.push_str(symbol);
            column += display_width(symbol).max(1);
        }
        text
    }

    /// 整屏任意一行是否包含给定文本
    fn buffer_contains(buffer: &ratatui::buffer::Buffer, text: &str) -> bool {
        (0..buffer.area.height).any(|row| buffer_row_text(buffer, row).contains(text))
    }

    /// 收集整屏套用某背景色的单元格所在行（去重排序），用于验证高亮落在哪条消息上
    fn rows_with_background(buffer: &ratatui::buffer::Buffer, background: Color) -> Vec<i32> {
        let mut rows: Vec<i32> = Vec::new();
        for row in 0..buffer.area.height {
            for column in 0..buffer.area.width {
                if buffer[(column, row)].bg == background {
                    rows.push(row as i32);
                    break;
                }
            }
        }
        rows
    }

    /// 收集整屏套用某背景色的单元格文本，用于验证高亮恰好覆盖了命中片段
    fn cells_with_background(buffer: &ratatui::buffer::Buffer, background: Color) -> String {
        buffer
            .content
            .iter()
            .filter(|cell| cell.bg == background)
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    /// 假消息服务：按顺序应答两次翻页请求。第一次返回两页中的第一页（has_more 为真、
    /// 游标指向更旧一条），第二次返回最后一页（has_more 为假、游标为空）。
    /// 消息按服务端约定"最新在前"排列，用来验证客户端的停止条件、反转、去重与合并排序。
    fn spawn_two_page_message_server() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定本地测试端口");
        let address = listener.local_addr().expect("测试端口应能读回地址");
        std::thread::spawn(move || {
            for page_index in 0..2usize {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = vec![0u8; 4096];
                let _ = stream.read(&mut request);
                let body = if page_index == 0 {
                    r#"{"response_id":"page-one","code":"SUCCESS","message":"ok","data":{"messages":[{"id":"old-2","room_id":"room-one","sender_id":"user-other","content":"older hello second","created_at":"2026-08-30T07:00:02+00:00"},{"id":"old-1","room_id":"room-one","sender_id":"user-other","content":"older hello first","created_at":"2026-08-30T07:00:01+00:00"}],"has_more":true,"next_cursor":"old-2"}}"#
                } else {
                    r#"{"response_id":"page-two","code":"SUCCESS","message":"ok","data":{"messages":[{"id":"oldest-0","room_id":"room-one","sender_id":"user-other","content":"oldest message hello","created_at":"2026-08-30T06:00:00+00:00"}],"has_more":false,"next_cursor":null}}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        address
    }

    #[test]
    fn full_history_search_pages_to_end_then_merges_sorts_and_locates_last_match() {
        let mut app = chat_page_app_for_render("default");
        app.connector
            .set_base_url(&format!("http://{}", spawn_two_page_message_server()));
        app.input_collector.message_input_state.set_text("#hello");
        // 服务端首页响应里 has_more 为真时才会留下翻页游标，这里模拟"仍有更早消息"的房间
        app.messages_older_cursor = Some("message-1".to_string());

        app.execute_message_search();

        // 三页历史全部并入，整体按时间升序重排，本地原有的两条保持内容不变
        let ids: Vec<&str> = app
            .messages
            .iter()
            .map(|message| message.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["oldest-0", "old-1", "old-2", "message-1", "message-2"]
        );
        // 命中列表按显示顺序排列：四条含 hello 的消息，默认定位到最后一条匹配项
        let (keyword, matched, selected) = app.search_result.clone().expect("搜索应已执行");
        assert_eq!(keyword, "hello");
        assert_eq!(matched, vec!["oldest-0", "old-1", "old-2", "message-1"]);
        assert_eq!(selected, matched.len() - 1);
        assert_eq!(app.pending_scroll_message_id, Some("message-1".to_string()));
        // 全量已拉到底，触顶翻页游标必须关闭，否则搜索后还会重复拉一遍历史
        assert!(app.messages_older_cursor.is_none());
    }

    #[test]
    fn repeated_search_skips_history_fetch_when_room_is_already_complete() {
        // 游标为空说明本房间已无更早消息（服务端 has_more 为假），
        // 重复按 Enter 只应重扫已有消息，绝不再翻页拉取，也不会因连不上而报错
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.execute_message_search();
        let (keyword, matched, selected) = app.search_result.expect("搜索应已执行");
        assert_eq!(keyword, "hello");
        assert_eq!(matched, vec!["message-1".to_string()]);
        assert_eq!(selected, 0);
        assert!(app.notifications.is_empty());
    }

    #[test]
    fn screen_selection_extracts_rectangle_text_ignoring_wide_char_splits() {
        let rows = vec![
            "┌ 房间 ┐".to_string(),
            "│群聊一号│".to_string(),
            "│      │".to_string(),
        ];
        // 覆盖第二行的四个汉字：按显示宽度切列，双宽汉字整块保留
        assert_eq!(
            extract_selected_screen_text(&rows, (2, 1), (8, 1)),
            "群聊一号"
        );
        // 端点顺序无关（从右下往左上拖）
        assert_eq!(
            extract_selected_screen_text(&rows, (8, 1), (2, 1)),
            "群聊一号"
        );
        // 只框到一个汉字的第一列时整块取该字（终点列本身计入选区）
        assert_eq!(extract_selected_screen_text(&rows, (2, 1), (2, 1)), "群");
        // 跨行选择时首尾整行为空的行被丢掉
        assert_eq!(extract_selected_screen_text(&rows, (13, 0), (13, 2)), "");
    }

    #[test]
    fn search_navigation_relocates_view_even_with_a_single_match() {
        // 只有一条命中时旧实现直接 return（matched.len() < 2），用户按组合键毫无反应；
        // 现在仍会把视图推到那条消息上
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.search_result = Some(("hello".to_string(), vec!["message-1".to_string()], 0));
        app.pending_scroll_message_id = None;
        app.navigate_search_result(false);
        assert_eq!(app.pending_scroll_message_id, Some("message-1".to_string()));
        assert_eq!(
            app.search_result,
            Some(("hello".to_string(), vec!["message-1".to_string()], 0))
        );
    }

    #[test]
    fn selection_text_drops_frame_and_decoration_cells() {
        let rows = vec![
            "┌ 房间 ┐".to_string(),
            "│► 群聊一号●│".to_string(),
            "│          │".to_string(),
        ];
        // 跨整块面板框选：制表框线、选中箭头、在线圆点与背景空白都不该进剪贴板
        assert_eq!(
            extract_selected_screen_text(&rows, (0, 0), (12, 2)),
            "房间\n群聊一号"
        );
    }

    #[test]
    fn search_mode_up_down_keys_navigate_matches_with_any_modifiers() {
        // 直接喂合成按键事件，验证搜索模式下上下键被匹配项切换接管：
        // 无修饰、Ctrl、Ctrl+Shift 三种上报形式都要生效（不同终端给的组合键形式不一致）
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.messages.push(MessageInfo {
            id: "message-3".to_string(),
            room_id: "room-one".to_string(),
            sender_id: "user-other".to_string(),
            content: "hello again".to_string(),
            created_at: "2026-08-30T08:02:00+00:00".to_string(),
        });
        app.search_result = Some((
            "hello".to_string(),
            vec!["message-1".to_string(), "message-3".to_string()],
            0,
        ));

        for modifiers in [
            KeyModifiers::NONE,
            KeyModifiers::CONTROL,
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ] {
            let before = app
                .search_result
                .as_ref()
                .map(|(_, _, selected)| *selected)
                .unwrap();
            app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
                KeyCode::Down,
                modifiers,
            )));
            let after = app
                .search_result
                .as_ref()
                .map(|(_, _, selected)| *selected)
                .expect("搜索结果应仍在");
            assert_ne!(before, after, "修饰键 {modifiers:?} 下按 ↓ 未切换匹配项");
            assert!(
                app.pending_scroll_message_id.is_some(),
                "切换后要标记待定位的消息"
            );
        }
        // 最后一个匹配项再按下应回绕到第一个
        assert_eq!(app.search_result.as_ref().unwrap().2, 1);
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.search_result.as_ref().unwrap().2, 0);
        // 上下键不得改动房间选择（搜索模式下切房由别的操作负责）
        assert_eq!(app.rooms_state.selected(), Some(0));
    }

    #[test]
    fn pasted_text_with_carriage_returns_yields_clean_new_lines() {
        // macOS Terminal.app 粘贴的行尾是 \r\n，不能把 \r 留在文本缓冲区里
        let mut app = chat_page_app_for_render("default");
        app.handle_pasted_text("第一行\r\n第二行\r\n第三行");
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "第一行\n第二行\n第三行"
        );
        assert!(
            !app.input_collector
                .message_input_state
                .text()
                .contains('\r'),
            "粘贴结果里不应残留回车符"
        );
        // 裸 \r（旧 Mac 行尾）转成换行；其他控制字符（如响铃 \u{7}）直接丢弃
        assert_eq!(normalize_pasted_text("a\rb\u{7}c"), "a\nbc");
        // 制表符属于可输入的正文内容，保留
        assert_eq!(normalize_pasted_text("a\tb"), "a\tb");
    }

    #[test]
    fn pasted_multiline_text_goes_into_the_input_box_without_sending() {
        let mut app = chat_page_app_for_render("default");
        let message_count_before = app.messages.len();
        app.handle_pasted_text("第一行\n第二行\n第三行");
        // 三行都留在输入框内，换行不触发发送
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "第一行\n第二行\n第三行"
        );
        assert_eq!(app.messages.len(), message_count_before);
    }

    #[test]
    fn rendering_reserves_the_bottom_terminal_row() {
        // 最底行留空可避免终端因写入右下角而自动滚动，从而不再出现整屏错位
        assert_eq!(drawable_area(Rect::new(0, 0, 120, 36)).height, 35);
        assert_eq!(drawable_area(Rect::new(0, 0, 120, 1)).height, 1);
        let mut app = chat_page_app_for_render("default");
        let buffer = render_snapshot(&mut app, 120, 36);
        assert!(
            (0..120u16).all(|column| buffer[(column, 35u16)].symbol() == " "),
            "最底行应保持空白"
        );
        assert_eq!(app.screen_text_rows.len(), 35);
    }

    #[test]
    fn quick_search_scans_loaded_messages_without_enter() {
        let mut app = chat_page_app_for_render("default");
        app.quick_search = true;
        app.input_collector.message_input_state.set_text("#hello");
        app.apply_quick_search();
        let (keyword, matched, selected) = app
            .search_result
            .clone()
            .expect("快速搜索应随输入立即出结果");
        assert_eq!(keyword, "hello");
        assert_eq!(matched, vec!["message-1".to_string()]);
        assert_eq!(selected, 0);
        // 快速搜索不触发整房翻页拉取，因此不会留下任何"正在拉取历史"的提示
        assert!(app.notifications.is_empty());

        // 关键词清空后回到未搜索态：结果整体作废，标题不再显示进度
        app.input_collector.message_input_state.set_text("#");
        app.apply_quick_search();
        assert!(app.search_result.is_none());
        assert!(app.pending_scroll_message_id.is_none());
    }

    #[test]
    fn esc_from_any_overlay_returns_to_the_settings_menu() {
        let mut app = chat_page_app_for_render("default");
        for overlay in [
            DisplayingOverlay::Login,
            DisplayingOverlay::Register,
            DisplayingOverlay::CreateGroup,
            DisplayingOverlay::CreatePrivate,
            DisplayingOverlay::ServerAddress,
            DisplayingOverlay::LanguageSelect,
            DisplayingOverlay::AppearanceSelect,
            DisplayingOverlay::PendingRequests,
        ] {
            app.displaying_overlay = overlay.clone();
            app.dismiss_overlay_back();
            assert_eq!(
                app.displaying_overlay,
                DisplayingOverlay::SettingsMenu,
                "{overlay:?} 的 Esc 应退回设置菜单"
            );
        }
        // 设置菜单自身再退一层才是无浮层的聊天页
        app.dismiss_overlay_back();
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Nothing);
    }

    #[test]
    fn rendered_screen_paints_theme_background_over_the_whole_frame() {
        let mut app = chat_page_app_for_render("high-contrast");
        let buffer = render_snapshot(&mut app, 120, 36);
        // 背景铺满整屏：120x36 里绝大多数单元格都应带上主题的应用背景色
        let painted_cells = buffer
            .content
            .iter()
            .filter(|cell| cell.bg == Color::Black)
            .count();
        assert!(
            painted_cells > 120 * 36 / 2,
            "应用背景未铺满整屏，仅 {painted_cells} 个单元格着色"
        );
        // 第 0 行是顶栏，房间列表左上角边框从第 1 行起（high-contrast 下为白色）
        assert_eq!(buffer[(0u16, 1u16)].fg, Color::White);
    }

    #[test]
    fn rendered_screen_highlights_search_matches_with_theme_background() {
        let mut app = chat_page_app_for_render("high-contrast");
        // 再补一条同样命中 hello 的消息，好把"其余命中"与"当前命中"两种颜色区分开
        app.messages.push(MessageInfo {
            id: "message-3".to_string(),
            room_id: "room-one".to_string(),
            sender_id: "user-other".to_string(),
            content: "hello once more".to_string(),
            created_at: "2026-08-30T08:02:00+00:00".to_string(),
        });
        // 进入搜索模式并执行过一次搜索：两条命中，当前停在第一条
        app.input_collector.message_input_state.set_text("#hello");
        app.search_result = Some((
            "hello".to_string(),
            vec!["message-1".to_string(), "message-3".to_string()],
            0,
        ));
        let buffer = render_snapshot(&mut app, 120, 36);
        // 其余命中用 search_match_background（light_yellow），当前这条用
        // search_current_match_background（light_red），各自只盖住关键词那几个字
        assert_eq!(
            cells_with_background(&buffer, Color::LightYellow),
            "hello".to_string()
        );
        let current_rows = rows_with_background(&buffer, Color::LightRed);
        let other_rows = rows_with_background(&buffer, Color::LightYellow);
        assert_eq!(current_rows.len(), 1, "只应有一条命中被标成当前色");
        assert_eq!(other_rows.len(), 1, "只应有一条命中保持普通命中色");
        assert!(
            current_rows[0] < other_rows[0],
            "当前停在第一条命中，特殊色应出现在更靠上的行"
        );
        // 换到第二个匹配项：两种颜色的位置互换，证明"当前"标记跟着选中项走
        app.search_result = Some((
            "hello".to_string(),
            vec!["message-1".to_string(), "message-3".to_string()],
            1,
        ));
        let swapped_buffer = render_snapshot(&mut app, 120, 36);
        assert_eq!(
            rows_with_background(&swapped_buffer, Color::LightRed),
            other_rows
        );
        assert_eq!(
            rows_with_background(&swapped_buffer, Color::LightYellow),
            current_rows
        );
        // 输入框标题给出匹配进度
        assert!(buffer_contains(&buffer, "搜索模式: 第 1/2 个匹配项"));
        // 搜索模式边框取 search_border（high-contrast 下为 light_red）
        assert!(buffer.content.iter().any(|cell| cell.fg == Color::LightRed));
    }

    #[test]
    fn search_mode_without_match_reports_not_found_and_plain_mode_does_not_highlight() {
        let mut app = chat_page_app_for_render("high-contrast");
        app.input_collector
            .message_input_state
            .set_text("#nosuchword");
        app.search_result = Some(("nosuchword".to_string(), Vec::new(), 0));
        let buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&buffer, "搜索模式: 未找到"));
        // 未命中时不该有任何搜索命中高亮
        assert!(cells_with_background(&buffer, Color::LightYellow).is_empty());

        // 普通模式（输入框不以 # 开头）即使残留旧结果也不高亮
        let mut plain_app = chat_page_app_for_render("high-contrast");
        plain_app
            .input_collector
            .message_input_state
            .set_text("hello");
        plain_app.search_result = Some(("hello".to_string(), vec!["message-1".to_string()], 0));
        let plain_buffer = render_snapshot(&mut plain_app, 120, 36);
        assert!(cells_with_background(&plain_buffer, Color::LightYellow).is_empty());
        assert!(buffer_contains(&plain_buffer, "消息输入"));
    }

    #[test]
    fn message_area_title_shows_who_is_typing() {
        let mut app = chat_page_app_for_render("high-contrast");
        app.typing_members
            .push(("room-one".to_string(), "bob".to_string(), Instant::now()));
        let buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&buffer, "bob 正在输入"));
        // 其它房间的成员输入状态不该显示在当前房间标题上
        let mut other_room_app = chat_page_app_for_render("high-contrast");
        other_room_app.typing_members.push((
            "room-two".to_string(),
            "bob".to_string(),
            Instant::now(),
        ));
        let other_room_buffer = render_snapshot(&mut other_room_app, 120, 36);
        assert!(!buffer_contains(&other_room_buffer, "正在输入"));
    }

    #[test]
    fn private_room_in_list_is_marked_by_peer_presence() {
        let mut app = chat_page_app_for_render("high-contrast");
        app.rooms.push(RoomInfo {
            id: "room-private".to_string(),
            name: None,
            is_group: false,
            created_by: "user-other".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: false,
            created_at: String::new(),
        });
        // 顶栏的连接标记同样是实心点，所以这里一律按"房间名 + 标记"整体断言，
        // 免得把顶栏那个点误当成房间列表的在线标注
        // 私聊在列表里显示为本地化后的"私聊"字样，标记就贴在它后面
        let private_room_label = app.t("private_chat_fallback");
        let peer_line = |mark: &str| format!("{private_room_label} {mark}");
        let unknown_buffer = render_snapshot(&mut app, 120, 36);
        assert!(!buffer_contains(&unknown_buffer, &peer_line("●")));
        assert!(!buffer_contains(&unknown_buffer, &peer_line("○")));
        // 收到在线广播后标注实心点，离线后标注空心点
        app.presence_by_user.insert("user-other".to_string(), true);
        let online_buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&online_buffer, &peer_line("●")));
        app.presence_by_user.insert("user-other".to_string(), false);
        let offline_buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&offline_buffer, &peer_line("○")));
        assert!(!buffer_contains(&offline_buffer, &peer_line("●")));
    }

    #[test]
    fn switching_appearance_changes_every_coloured_slot() {
        // 同一份内容分别用两套外观渲染，边框取色必须随主题切换
        let mut built_in_app = chat_page_app_for_render("default");
        let built_in_buffer = render_snapshot(&mut built_in_app, 120, 36);
        assert_eq!(built_in_buffer[(0u16, 1u16)].fg, Color::Cyan);

        let mut light_app = chat_page_app_for_render("light");
        let light_buffer = render_snapshot(&mut light_app, 120, 36);
        assert_eq!(light_buffer[(0u16, 1u16)].fg, Color::Rgb(138, 127, 109));
        assert_eq!(light_buffer[(59u16, 20u16)].bg, Color::Rgb(239, 235, 226));
    }
}
