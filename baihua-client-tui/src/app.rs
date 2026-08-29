use baihua_core::{
    api::{
        ApiVersion, Connector, CreateRoomRequest, EncryptHandshakeData, EncryptedMessageInfo,
        LoginRequest, MessageInfo, PollingEvent, RegisterRequest, RoomInfo, RoomRequestInfo,
        ServerSignal, WsCommand, authorization_value, outbound_ws_payload, parse_websocket_event,
        websocket_auth_sentinel,
    },
    crypto,
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
    layout::{Alignment, Constraint, Layout, Position, Rect},
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

/// 调试诊断。
fn debug_log(message: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/baihua_client_debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "[{timestamp}] {message}");
    }
}

/// 当前页面。
#[derive(Default, Debug, Clone, PartialEq)]
pub enum CurrentPage {
    #[default]
    Login,
    Register,
    Chat,
}

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
}

#[derive(Debug)]
pub struct App {
    pub current_page: CurrentPage,
    pub input_collector: InputCollector,
    pub connector: Connector,
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
    /// 当前加载的语言字符串映射（key → 本地化文本）
    language_strings: HashMap<String, String>,
    /// 语言选择列表当前的选中项
    language_list_state: ListState,
    /// 是否在消息中同时显示发送者的 uid（true 显示 username(uid)）
    show_uid: bool,
    /// 时间显示是否带日期（true 显示日期+时间，false 仅显示时间）
    time_with_date: bool,
    /// 是否启用系统通知（新消息/私聊请求时发出提示）
    sound_enabled: bool,
    /// 开启"消息免打扰"的房间 ID 集合（以各房间唯一 id 为键），持久化到 preferences.json。
    /// 免打扰房间在别处收到新消息时：不发系统通知/提示音，未读数以点（·）显示而非具体数字。
    muted_room_ids: HashSet<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            current_page: CurrentPage::Chat,
            input_collector: InputCollector::default(),
            connector: Connector::default(),
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
            language_strings: HashMap::new(),
            language_list_state: ListState::default(),
            show_uid: false,
            time_with_date: false,
            sound_enabled: true,
            muted_room_ids: HashSet::new(),
        }
    }
}

impl App {
    /// 设置后台轮询线程通信发送器
    pub fn set_polling_sender(&mut self, sender: Option<mpsc::Sender<PollingEvent>>) {
        self.polling_sender = sender;
    }

    /// 启动后台轮询线程，定期从服务器获取房间列表与待处理聊天请求
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
            let mut last_rooms: Vec<RoomInfo> = Vec::new();
            let mut last_requests: Vec<RoomRequestInfo> = Vec::new();
            let mut room_poll_counter: u32 = 0;
            let mut request_poll_counter: u32 = 0;

            while running_flag.load(Ordering::Relaxed) {
                // 每 2 秒轮询房间列表
                if room_poll_counter.is_multiple_of(20) {
                    match connector.list_rooms() {
                        Ok(rooms) => {
                            if rooms != last_rooms {
                                last_rooms = rooms.clone();
                                let _ = sender.send(PollingEvent::RoomsUpdated(rooms));
                            }
                        }
                        Err(e) => {
                            let _ = sender.send(PollingEvent::Error(format!(
                                "{}: {e}",
                                tr("error_poll_rooms")
                            )));
                        }
                    }
                }

                // 每 3 秒轮询待处理聊天请求
                if request_poll_counter.is_multiple_of(30) {
                    match connector.list_pending_requests() {
                        Ok(requests) => {
                            if requests != last_requests {
                                last_requests = requests.clone();
                                let _ = sender.send(PollingEvent::PendingRequestsUpdated(requests));
                            }
                        }
                        Err(e) => {
                            let _ = sender.send(PollingEvent::Error(format!(
                                "{}: {e}",
                                tr("error_poll_requests")
                            )));
                        }
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
                        let _ = event_sender.send(PollingEvent::Error(format!(
                            "{}: {e}",
                            tr("error_ws_connect_failed")
                        )));
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
                            let _ = event_sender.send(PollingEvent::Error(format!(
                                "{}: {e}",
                                tr("error_ws_disconnected_reconnect")
                            )));
                            break;
                        }
                    }

                    while let Ok(payload) = command_receiver.try_recv() {
                        debug_log(&format!("WS 发出: {payload}"));
                        if socket.write(WebSocketMessage::text(payload)).is_err() {
                            let _ = event_sender
                                .send(PollingEvent::Error(tr("error_ws_send_failed").to_string()));
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
            PollingEvent::WebSocketConnected => {
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
                    let sender_name = self
                        .sender_names
                        .get(&message.sender_id)
                        .cloned()
                        .unwrap_or_else(|| message.sender_id.clone());
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
                    self.messages.push(message);
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
                self.pending_requests = requests;
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
            PollingEvent::PartnerOffline(user_id) => {
                // 对端连接断开：其参与的加密私聊的本地加密会话已失效，仅清理会话。
                // 房间本身保留可见——成员关系以房间列表为准（对端只是离线并未退房时列表仍为 2 人），
                // 对端上线后再发消息会自动重握手。绝不在此软关闭房间：本端因新房间或定期
                // 重连触发的 user_offline 抖动会把"刚创建的私聊"永久隐藏（closed_room_ids 粘性），
                // 这正是"私聊刚创建就被删除"的根因。真正的单人空壳由 filter_visible_rooms(members>=2) 隐藏。
                let affected_room_ids: Vec<String> = self
                    .rooms
                    .iter()
                    .filter(|room| {
                        !room.is_group && room.members.iter().any(|member| member == &user_id)
                    })
                    .map(|room| room.id.clone())
                    .collect();
                for room_id in affected_room_ids {
                    self.crypto.sessions.remove(&room_id);
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
                    self.current_page = CurrentPage::Chat;
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
                    // 对端离线导致握手被拒：清理本地等待接受的僵死会话，避免消息永久排队
                    ServerSignal::PartnerOfflineHandshakeRejected => {
                        let stuck_room_ids: Vec<String> = self
                            .crypto
                            .sessions
                            .iter()
                            .filter(|(_, session)| {
                                session.phase == EncryptionPhase::AwaitingAcceptance
                            })
                            .map(|(room_id, _)| room_id.clone())
                            .collect();
                        for room_id in stuck_room_ids {
                            self.crypto.sessions.remove(&room_id);
                        }
                        self.push_notification(self.t("notification_partner_offline"));
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
                let sender_name = self
                    .sender_names
                    .get(&info.sender_id)
                    .cloned()
                    .unwrap_or_else(|| info.sender_id.clone());
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
    /// 2) 未激活握手超时重发
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
        let path = format!("config/languages/{lang}.json");
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<HashMap<String, String>>(&content) {
                Ok(map) => {
                    self.language_strings = map;
                }
                Err(_) => {
                    self.push_error(format!("{}: {path}", self.t("error_lang_file_format")));
                }
            },
            Err(_) => {
                self.push_error(format!("{}: {path}", self.t("error_lang_file_read")));
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
        let dir = "config/languages";
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
        let prefs_path = "config/preferences.json";
        fs::read_to_string(prefs_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|v| v.get("language")?.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "zh-CN".to_string())
    }

    /// 保存语言设置到 preferences.json
    fn save_language_preference(lang: &str) {
        let prefs_path = "config/preferences.json";
        let content = fs::read_to_string(prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["language"] = serde_json::json!(lang);
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(prefs_path, pretty);
        }
    }

    /// 从 preferences.json 读取显示偏好（show_uid / time_with_date / server_address / sound_enabled），读不到时保持默认
    pub fn load_display_preferences(&mut self) {
        let prefs_path = "config/preferences.json";
        if let Some(v) = fs::read_to_string(prefs_path)
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
        }
    }

    /// 将 show_uid 与 time_with_date 显示偏好写入 preferences.json
    fn save_display_preferences(&self) {
        let prefs_path = "config/preferences.json";
        let content = fs::read_to_string(prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["show_uid"] = serde_json::json!(self.show_uid);
        prefs["time_with_date"] = serde_json::json!(self.time_with_date);
        prefs["sound_enabled"] = serde_json::json!(self.sound_enabled);
        prefs["muted_rooms"] =
            serde_json::json!(self.muted_room_ids.iter().cloned().collect::<Vec<String>>());
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(prefs_path, pretty);
        }
    }

    /// 将自定义服务器地址写入 preferences.json
    fn save_server_address(&self) {
        let prefs_path = "config/preferences.json";
        let content = fs::read_to_string(prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["server_address"] = serde_json::json!(self.connector.base_url());
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(prefs_path, pretty);
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
    fn save_session_preferences(token: &str, user_id: &str) {
        let prefs_path = "config/preferences.json";
        let content = fs::read_to_string(prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["token"] = serde_json::json!(crypto::encrypt_at_rest(token));
        prefs["user_id"] = serde_json::json!(user_id);
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(prefs_path, pretty);
        }
    }

    /// 读取已保存的登录会话；令牌先解密，凭证缺失或解密失败时返回 None
    fn load_saved_session() -> Option<(String, String)> {
        let prefs_path = "config/preferences.json";
        let content = fs::read_to_string(prefs_path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&content).ok()?;
        let token = crypto::decrypt_at_rest(v.get("token")?.as_str()?)?;
        let user_id = v.get("user_id")?.as_str()?;
        Some((token, user_id.to_string()))
    }

    /// 清除已保存的登录会话（token 失效或不再需要自动登录时调用）
    fn clear_saved_session() {
        let prefs_path = "config/preferences.json";
        let content = fs::read_to_string(prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        if let Some(map) = prefs.as_object_mut() {
            map.remove("token");
            map.remove("user_id");
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(prefs_path, pretty);
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
        debug_log("JWT AUTO-LOGIN: list_rooms 成功，设置用户状态");
        // 自动登录同样立即探测服务端版本（token 已 set），令后续线上决策匹配真实版本
        self.detect_and_apply_api_version();
        self.current_user_id = Some(user_id);
        self.current_page = CurrentPage::Chat;
        self.focus_index = 0;
        // 与普通登录保持完全一致的流程：先加载房间列表，再启动后台线程
        self.load_rooms();
        self.start_polling_thread();
        self.start_websocket_thread(&token, None);
        self.push_notification(self.t("auto_login_notification"));
        debug_log("=== JWT AUTO-LOGIN COMPLETE ===");
        true
    }
}

/// 内置聊天命令表，元素为 (命令名, 描述的语言键名)。
/// 扩展新命令时在此追加条目，并在 App::execute_chat_command 中增加对应执行分支即可。
fn chat_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("quit", "command_quit"),
        ("quit_group", "command_quit_group"),
        ("kick", "command_kick"),
        ("info", "command_info"),
        ("language", "command_language"),
        ("logout", "command_logout"),
        ("server_address", "command_server_address"),
        ("add_member", "command_add_member"),
        ("list_member", "command_list_member"),
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
        match self.current_page {
            CurrentPage::Login => 1,
            CurrentPage::Register => 2,
            CurrentPage::Chat => {
                if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup)
                    || matches!(self.displaying_overlay, DisplayingOverlay::Login)
                {
                    1
                } else if matches!(self.displaying_overlay, DisplayingOverlay::Register) {
                    2
                } else {
                    0
                }
            }
        }
    }

    fn get_focused_state(&mut self) -> Option<&mut TextInputState> {
        match self.current_page {
            CurrentPage::Login => match self.focus_index {
                0 => Some(&mut self.input_collector.login_name_state),
                1 => Some(&mut self.input_collector.login_password_state),
                _ => None,
            },
            CurrentPage::Register => match self.focus_index {
                0 => Some(&mut self.input_collector.register_name_state),
                1 => Some(&mut self.input_collector.register_email_state),
                2 => Some(&mut self.input_collector.register_password_state),
                _ => None,
            },
            CurrentPage::Chat => {
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
                } else if matches!(
                    self.displaying_overlay,
                    DisplayingOverlay::PendingRequests | DisplayingOverlay::SettingsMenu
                ) {
                    // 列表与菜单类弹窗不聚焦任何输入框
                    None
                } else {
                    // 聊天页无弹窗时聚焦多行消息输入框，经 dispatch_focused_input_event 单独处理
                    None
                }
            }
        }
    }

    /// 将键盘/鼠标事件分发到当前聚焦的输入框：
    /// 聊天页无弹窗时转发到多行消息输入框，其余页面/弹窗转发到单行输入框
    fn dispatch_focused_input_event(&mut self, focus: bool, event: &Event) {
        if self.current_page == CurrentPage::Chat
            && self.displaying_overlay == DisplayingOverlay::Nothing
        {
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
        match self.current_page {
            CurrentPage::Login => vec![layout[2], layout[4]],
            CurrentPage::Register => vec![layout[2], layout[4], layout[6]],
            CurrentPage::Chat => {
                if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup) {
                    vec![]
                } else {
                    vec![layout[8]]
                }
            }
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
                self.connector.set_token(&data.token);
                // 登录后立即探测服务端版本，使后续所有线上决策匹配真实版本
                self.detect_and_apply_api_version();
                self.current_page = CurrentPage::Chat;
                self.focus_index = 0;
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.load_rooms();
                self.start_polling_thread();
                self.start_websocket_thread(&data.token, None);
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
        if let Some(selected) = self.rooms_state.selected()
            && let Some(room) = self.rooms.get(selected)
        {
            // 整房（重新）加载一律把滚动位置拉回最底部并配合下方重写消息列表：
            // 本方法任何路径都会用最新消息整表替换 self.messages，旧的"距底部偏移"对新列表
            // 已无意义——若残留较大偏移，会被夹取到顶部而误触发自动拉取、停在高位置。
            // 因此切换群聊与同房刷新统一归零贴底，用户主动上滚后才会再次累积偏移
            self.messages_scroll_from_bottom = 0;
            debug_log(&format!("整房加载 room={} 滚动偏移归零", room.id));
            // 用户正在查看该房间，清零其未读消息计数
            self.unread_counts.remove(&room.id);
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
                    self.messages = loaded;
                    // 记录更早消息分页游标（服务器无更多时返回 None），供滚到顶部时自动翻页
                    self.messages_older_cursor = data.next_cursor;
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                    self.messages.clear();
                    self.messages_older_cursor = None;
                }
            }
            self.messages_reloaded_at = Instant::now();
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
        let request_message = "请求建立私密聊天".to_string();
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
                self.refresh_pending_requests();
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
                self.refresh_pending_requests();
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_decline_request_failed")));
            }
        }
    }

    /// 重新拉取待处理聊天请求列表并修正选中项
    fn refresh_pending_requests(&mut self) {
        match self.connector.list_pending_requests() {
            Ok(requests) => {
                self.pending_requests = requests;
                if self.pending_requests.is_empty() {
                    self.request_list_state.select(None);
                } else if self
                    .request_list_state
                    .selected()
                    .is_none_or(|index| index >= self.pending_requests.len())
                {
                    self.request_list_state.select(Some(0));
                }
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_get_request_failed")));
            }
        }
    }

    /// 获取待处理请求列表当前选中项的 ID
    fn selected_request_id(&self) -> Option<String> {
        self.request_list_state
            .selected()
            .and_then(|index| self.pending_requests.get(index))
            .map(|request| request.id.clone())
    }

    /// 处理终端事件；返回 true 表示应用请求退出（由聊天命令或退出快捷键触发）
    pub fn handle_event(&mut self, event: &Event) -> bool {
        match self.displaying_overlay {
            DisplayingOverlay::CreateGroup => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            if self.focus_index == 1 {
                                self.focus_index = 0;
                            } else {
                                self.displaying_overlay = DisplayingOverlay::Nothing;
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
                            self.displaying_overlay = DisplayingOverlay::Nothing;
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
                    match key.code {
                        KeyCode::Esc => {
                            self.displaying_overlay = DisplayingOverlay::Nothing;
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            if !self.pending_requests.is_empty() {
                                let count = self.pending_requests.len();
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
                            self.accept_selected_request();
                            if self.pending_requests.is_empty() {
                                self.displaying_overlay = DisplayingOverlay::Nothing;
                            }
                            return false;
                        }
                        KeyCode::Char('d') => {
                            self.decline_selected_request();
                            if self.pending_requests.is_empty() {
                                self.displaying_overlay = DisplayingOverlay::Nothing;
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::SettingsMenu => {
                // 0-3 项为导航动作（与 menu_actions 索引对应），4-6 项为开关拨动项，
                // 7 项为服务器地址，8 项为退出登录，9 项登录浮层，10 项注册浮层
                let menu_actions = [
                    DisplayingOverlay::CreateGroup,
                    DisplayingOverlay::CreatePrivate,
                    DisplayingOverlay::PendingRequests,
                    DisplayingOverlay::LanguageSelect,
                ];
                let menu_count = 11usize;
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.displaying_overlay = DisplayingOverlay::Nothing;
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
                            match selected {
                                4 => {
                                    self.show_uid = !self.show_uid;
                                    self.save_display_preferences();
                                }
                                5 => {
                                    self.time_with_date = !self.time_with_date;
                                    self.save_display_preferences();
                                }
                                6 => {
                                    self.sound_enabled = !self.sound_enabled;
                                    self.save_display_preferences();
                                }
                                7 => {
                                    // 服务器地址：打开输入框并预填当前地址
                                    self.input_collector
                                        .server_address_state
                                        .set_text(self.connector.base_url());
                                    self.displaying_overlay = DisplayingOverlay::ServerAddress;
                                }
                                8 => {
                                    self.logout();
                                    self.displaying_overlay = DisplayingOverlay::Nothing;
                                }
                                9 => {
                                    self.displaying_overlay = DisplayingOverlay::Login;
                                    self.focus_index = 0;
                                }
                                10 => {
                                    self.displaying_overlay = DisplayingOverlay::Register;
                                    self.focus_index = 0;
                                }
                                _ => {
                                    if let Some(action) = menu_actions.get(selected) {
                                        self.displaying_overlay = action.clone();
                                        match action {
                                            DisplayingOverlay::PendingRequests => {
                                                if self.pending_requests.is_empty() {
                                                    self.request_list_state.select(None);
                                                } else {
                                                    self.request_list_state.select(Some(0));
                                                }
                                            }
                                            DisplayingOverlay::LanguageSelect => {
                                                let languages = Self::get_available_languages();
                                                let current = Self::current_language();
                                                let idx =
                                                    languages.iter().position(|l| l == &current);
                                                self.language_list_state.select(idx);
                                            }
                                            _ => {
                                                self.focus_index = 0;
                                            }
                                        }
                                    }
                                }
                            }
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
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
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
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
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
                                self.displaying_overlay = DisplayingOverlay::Nothing;
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

        let max_index = self.max_focus_index();

        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        // 聊天页 Ctrl+P 打开设置菜单（创建群聊/私聊与待处理请求入口）
                        KeyCode::Char('p') if matches!(self.current_page, CurrentPage::Chat) => {
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                            self.menu_list_state.select(Some(0));
                            return false;
                        }
                        _ => {}
                    }
                }

                match self.current_page {
                    CurrentPage::Chat => match key.code {
                        KeyCode::Up | KeyCode::Down => {
                            let input_text = self.input_collector.message_input_state.text();
                            if let Some(command_prefix) = input_text.strip_prefix('/') {
                                // 补全列表开启时上下键选择命令，禁用群聊切换
                                let candidate_count =
                                    self.completion_candidates(command_prefix).len();
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
                                // 光标未移动说明已在边界，执行群聊切换
                                if before == after && !self.rooms.is_empty() {
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
                            self.dispatch_focused_input_event(true, event);
                        }
                        KeyCode::Enter => {
                            // Enter 发送消息
                            return self.handle_chat_submit();
                        }
                        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+J 插入换行
                            self.input_collector.message_input_state.insert_newline();
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+U 删除光标所在整行
                            self.input_collector.message_input_state.delete_line();
                        }
                        _ => {
                            self.dispatch_focused_input_event(true, event);
                            // 输入变化后命令选择回到第一项；由组件自身完成插入以保持光标位置
                            let input_text = self.input_collector.message_input_state.text();
                            if input_text.starts_with('/') {
                                self.command_list_state.select(Some(0));
                            }
                        }
                    },
                    _ => match key.code {
                        KeyCode::Tab => {
                            if max_index > 0 {
                                self.focus_index = (self.focus_index + 1) % (max_index + 1);
                            }
                        }
                        KeyCode::Esc => {
                            if max_index > 0 && self.focus_index != 0 {
                                self.focus_index -= 1;
                            }
                        }
                        KeyCode::Enter => {
                            if self.focus_index == max_index {
                                match self.current_page {
                                    CurrentPage::Login => self.do_login(),
                                    CurrentPage::Register => self.do_register(),
                                    _ => {}
                                }
                            } else if max_index > 0 {
                                self.focus_index += 1;
                            }
                        }
                        _ => {
                            self.dispatch_focused_input_event(true, event);
                        }
                    },
                }
            }
            Event::Mouse(mouse) => {
                // 聊天页无弹窗时滚轮控制消息显示区滚动，其余界面忽略滚轮
                if matches!(
                    mouse.kind,
                    MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                ) {
                    if matches!(self.current_page, CurrentPage::Chat)
                        && self.displaying_overlay == DisplayingOverlay::Nothing
                    {
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
                // 聊天页无弹窗时，鼠标左键拖拽框选文本后松开：复制所选文本到剪贴板并取消框选
                if matches!(self.current_page, CurrentPage::Chat)
                    && self.displaying_overlay == DisplayingOverlay::Nothing
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
        // 命令后带空格时进入参数补全：
        // 列出群成员或可用语言，按 Enter 将选中项补全进输入框，再次 Enter 才执行
        if (name == "kick" || name == "language" || name == "mute")
            && input_text.contains(' ')
            && !is_kick_all
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
        // 未登录时仅放行登录/注册/退出/ quit/语言/服务器地址，其余聊天操作先弹提示拒绝
        let allowed_signed_out = matches!(
            name,
            "login" | "register" | "logout" | "quit" | "language" | "server_address"
        );
        if !allowed_signed_out && !self.is_logged_in() {
            self.push_notification(self.t("error_not_logged_in"));
            return false;
        }
        match name {
            "quit" => {
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
            "list" => {
                // 获取当前选中的房间
                let Some(room_id) = self.selected_room_id() else {
                    self.push_error(self.t("error_no_room_selected"));
                    return false;
                };
                // 调用 API 获取成员列表
                match self.connector.list_members(&room_id) {
                    Ok(members_data) => {
                        debug_log(&format!("/list API 返回 {} 个成员", members_data.count));
                        if members_data.members.is_empty() {
                            self.push_notification(self.t("list_no_members"));
                        } else {
                            let member_list = members_data
                                .members
                                .iter()
                                .map(|m| format!("{} ({})", m.username, m.role))
                                .collect::<Vec<_>>()
                                .join("\n");
                            self.push_notification(format!(
                                "{}:\n{}",
                                self.t("list_members_title"),
                                member_list
                            ));
                        }
                    }
                    Err(e) => {
                        self.push_error(format!("{}: {e}", self.t("error_list_members_failed")));
                    }
                }
                false
            }
            "login" => {
                // /login 无参 → 打开登录浮层；/login <用户名> <密码> → 直接登录
                let args: Vec<&str> = command_line
                    .strip_prefix("/login")
                    .unwrap_or("")
                    .split_whitespace()
                    .collect();
                if args.is_empty() {
                    self.displaying_overlay = DisplayingOverlay::Login;
                    self.focus_index = 0;
                    return false;
                }
                if args.len() >= 2 && !args[0].starts_with('<') {
                    self.perform_login(args[0].to_string(), args[1].to_string());
                } else {
                    self.push_notification(self.t("login_usage_hint"));
                }
                false
            }
            "register" => {
                // /register 无参 → 打开注册浮层；/register <用户名> <密码> <邮箱> → 直接注册
                let args: Vec<&str> = command_line
                    .strip_prefix("/register")
                    .unwrap_or("")
                    .split_whitespace()
                    .collect();
                if args.is_empty() {
                    self.displaying_overlay = DisplayingOverlay::Register;
                    self.focus_index = 0;
                    return false;
                }
                if args.len() >= 3 && !args[0].starts_with('<') {
                    self.perform_register(
                        args[0].to_string(),
                        args[2].to_string(),
                        args[1].to_string(),
                    );
                } else {
                    self.push_notification(self.t("register_usage_hint"));
                }
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
        Self::clear_saved_session();
        self.current_user_id = None;
        self.rooms.clear();
        self.rooms_state = ListState::default();
        self.messages.clear();
        self.sender_names.clear();
        self.crypto.sessions.clear();
        self.closed_room_ids.clear();
        self.left_room_ids.clear();
        self.notifications.clear();
        self.displaying_overlay = DisplayingOverlay::Nothing;
        self.current_page = CurrentPage::Chat;
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
        // 退出前持久化登录会话（JWT 与企业用户 ID），供下次启动自动登录
        if let (Some(token), Some(user_id)) =
            (self.websocket_token.clone(), self.current_user_id.clone())
        {
            Self::save_session_preferences(&token, &user_id);
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

    /// 本地软关闭一个加密私聊：仅从界面隐藏并清理会话，
    /// 不通知服务器退房，避免对端重连后看到只有一人的残留房间
    fn close_local_room(&mut self, room_id: &str) {
        self.closed_room_ids.insert(room_id.to_string());
        self.crypto.sessions.remove(room_id);
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
        let area = frame.area();

        // 应用恒为单一聊天页：登录/注册改为命令打开的浮层；未登录时聊天页居中显示登录提示。
        self.render_chat_page(frame, area);

        match self.displaying_overlay {
            DisplayingOverlay::CreateGroup => self.render_create_group_modal(frame, area),
            DisplayingOverlay::CreatePrivate => self.render_create_private_modal(frame, area),
            DisplayingOverlay::PendingRequests => self.render_pending_requests(frame, area),
            DisplayingOverlay::SettingsMenu => self.render_settings_menu(frame, area),
            DisplayingOverlay::LanguageSelect => self.render_language_select(frame, area),
            DisplayingOverlay::ServerAddress => self.render_server_address(frame, area),
            DisplayingOverlay::Login => self.render_login_modal(frame, area),
            DisplayingOverlay::Register => self.render_register_modal(frame, area),
            DisplayingOverlay::Nothing => {}
        }

        // 渲染前先移除已到期的通知，再在右上角显示剩余通知
        self.remove_expired_notifications();
        if !self.notifications.is_empty() {
            self.render_notifications(frame, area);
        }

        // 将硬件光标定位到当前聚焦输入框处
        self.place_cursor(frame);
    }

    /// 将终端硬件光标定位到当前聚焦的输入框光标处；
    /// rat-text 仅在输入框标记为聚焦时返回可见光标位置，故先置位聚焦标志
    fn place_cursor(&mut self, frame: &mut Frame) {
        // 聊天页无弹窗时聚焦多行消息输入框，单独经 TextAreaState 处理
        if self.current_page == CurrentPage::Chat
            && self.displaying_overlay == DisplayingOverlay::Nothing
        {
            self.input_collector.message_input_state.focus.set(true);
            if let Some((x, y)) = self.input_collector.message_input_state.screen_cursor() {
                frame.set_cursor_position(Position::new(x, y));
            }
            return;
        }
        if let Some(state) = self.get_focused_state() {
            state.focus.set(true);
            if let Some((x, y)) = state.screen_cursor() {
                frame.set_cursor_position(Position::new(x, y));
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

    /// 居中渲染登录浮层：用户名与密码（星号遮蔽）两个输入框，Tab 切换、Enter 提交。
    fn render_login_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 50u16.min(area.width.saturating_sub(4)).max(30);
        let panel_height = 13u16.min(area.height.saturating_sub(4)).max(9);
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);
        frame.render_widget(Clear, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("page_login")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let focus_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        let name_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_username")))
            .border_style(if self.focus_index == 0 {
                focus_style
            } else {
                Style::default().fg(Color::Gray)
            });
        let pwd_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_password")))
            .border_style(if self.focus_index == 1 {
                focus_style
            } else {
                Style::default().fg(Color::Gray)
            });

        let name_rect = Rect::new(inner.x, inner.y, inner.width, 3);
        let pwd_rect = Rect::new(inner.x, inner.y + 4, inner.width, 3);
        TextInput::new()
            .block(name_block)
            .focus_style(focus_style)
            .render(
                name_rect,
                frame.buffer_mut(),
                &mut self.input_collector.login_name_state,
            );
        TextInput::new()
            .block(pwd_block)
            .focus_style(focus_style)
            .passwd()
            .render(
                pwd_rect,
                frame.buffer_mut(),
                &mut self.input_collector.login_password_state,
            );

        let hint = Paragraph::new(Text::raw(self.t("login_hint")))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, Rect::new(inner.x, inner.y + 8, inner.width, 1));
        frame.render_widget(block, panel_rect);
    }

    /// 居中渲染注册浮层：用户名、邮箱、密码（星号遮蔽）三个输入框，Tab 切换、Enter 提交。
    fn render_register_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 50u16.min(area.width.saturating_sub(4)).max(30);
        let panel_height = 16u16.min(area.height.saturating_sub(4)).max(11);
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);
        frame.render_widget(Clear, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("page_register")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let focus_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        let name_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_username")))
            .border_style(if self.focus_index == 0 {
                focus_style
            } else {
                Style::default().fg(Color::Gray)
            });
        let email_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_email")))
            .border_style(if self.focus_index == 1 {
                focus_style
            } else {
                Style::default().fg(Color::Gray)
            });
        let pwd_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_password")))
            .border_style(if self.focus_index == 2 {
                focus_style
            } else {
                Style::default().fg(Color::Gray)
            });

        TextInput::new()
            .block(name_block)
            .focus_style(focus_style)
            .render(
                Rect::new(inner.x, inner.y, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_name_state,
            );
        TextInput::new()
            .block(email_block)
            .focus_style(focus_style)
            .render(
                Rect::new(inner.x, inner.y + 4, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_email_state,
            );
        TextInput::new()
            .block(pwd_block)
            .focus_style(focus_style)
            .passwd()
            .render(
                Rect::new(inner.x, inner.y + 8, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_password_state,
            );

        let hint = Paragraph::new(Text::raw(self.t("register_hint")))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, Rect::new(inner.x, inner.y + 12, inner.width, 1));
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
            .border_style(Style::default().fg(Color::Cyan));

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
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                // 非选中房间若有未读消息，在名称后追加红色 (数量)
                let unread = if self.rooms_state.selected() == Some(i) {
                    0
                } else {
                    self.unread_counts.get(&room.id).copied().unwrap_or(0)
                };
                let mut spans = vec![Span::styled(name, style)];
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
                    .fg(Color::Yellow)
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

        let hint = Paragraph::new(Text::raw(self.t("command_hint")))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
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
        // 成员/语言等参数补全列表可能较长，允许更高面板；命令名补全保持紧凑
        let max_height = if raw_prefix.starts_with("kick ") || raw_prefix.starts_with("language ") {
            12
        } else {
            7
        };
        let popup_height = (candidates.len() as u16 + 2).min(max_height);
        let popup_width = input_area.width.saturating_sub(2);
        let popup_y = input_area.y.saturating_sub(popup_height);
        let popup_rect = Rect::new(input_area.x + 1, popup_y, popup_width, popup_height);

        let items: Vec<ListItem> = candidates
            .iter()
            .map(|(_, label, description)| {
                let mut spans = vec![Span::styled(
                    label.clone(),
                    Style::default().fg(Color::Yellow),
                )];
                if !description.is_empty() {
                    spans.push(Span::styled(
                        format!("  {}", description),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let title_key = if raw_prefix.starts_with("kick ") {
            "member_select_title"
        } else if raw_prefix.starts_with("language ") {
            "select_language_title"
        } else {
            "command_list"
        };
        let popup_block = Block::default()
            .title(format!(" {} ", self.t(title_key)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));
        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("► ");
        // 缓冲区为叠加式渲染，先清空面板区域防止下层文字透出
        frame.render_widget(Clear, popup_rect);
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
        let title = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .map(|room| {
                let name = room
                    .name
                    .clone()
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                format!(" {} ({}) ", name, room.members.len())
            })
            .unwrap_or_else(|| format!(" {} ", self.t("chat_history")));

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

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

        let current_user_id = self.current_user_id.as_deref().unwrap_or("");
        let mut lines: Vec<Line> = Vec::new();
        let mut last_time_key: Option<String> = None;
        for message in &self.messages {
            // 时间头：与上一条消息同分钟则隐藏，跨分钟才插入居中时间条
            if let Some(time_text) = format_message_time(&message.created_at, self.time_with_date)
                && last_time_key.as_deref() != Some(time_text.as_str())
            {
                lines.push(
                    Line::from(Span::styled(
                        time_text.clone(),
                        Style::default().fg(Color::DarkGray),
                    ))
                    .alignment(Alignment::Center),
                );
                last_time_key = Some(time_text);
            }
            let is_own = message.sender_id == current_user_id;
            let sender_name = if is_own {
                self.t("self_name").to_string()
            } else {
                self.sender_names
                    .get(&message.sender_id)
                    .cloned()
                    .unwrap_or_else(|| message.sender_id.clone())
            };
            let display_sender = if self.show_uid {
                format!("{} ({})", sender_name, message.sender_id)
            } else {
                sender_name
            };
            let name_style = if is_own {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Cyan)
            };
            let body_style = Style::default().fg(Color::White);
            let alignment = if is_own {
                Alignment::Right
            } else {
                Alignment::Left
            };
            for piece in wrap_by_display_width(&display_sender, text_width) {
                lines.push(Line::from(Span::styled(piece, name_style)).alignment(alignment));
            }
            for source_line in message.content.split('\n') {
                for piece in wrap_by_display_width(source_line, text_width) {
                    lines.push(Line::from(Span::styled(piece, body_style)).alignment(alignment));
                }
            }
        }

        let total_lines = lines.len() as u16;
        let visible_height = inner.height.max(1);
        let max_scroll_y = total_lines.saturating_sub(visible_height);
        // 反向偏移夹取到可滚动范围并回写，0 表示贴底跟随最新消息
        self.messages_scroll_from_bottom = self.messages_scroll_from_bottom.min(max_scroll_y);
        let scroll_y = max_scroll_y - self.messages_scroll_from_bottom;

        // 用户滚到消息显示区顶部（偏移离开底部且已抵到最大可滚位置）且服务器仍有更早消息时，
        // 自动拉取一批；前插后总行数增大使 scroll_y 离开顶部，天然避免逐帧重复拉取。
        // 守卫：消息列表必须确实属于当前选中房间（切房加载未完成/失败时列表与选中可能错位），
        // 防止拿旧房间的残留偏移与游标误拉他房更早历史
        let selected_room_id = self.selected_room_id();
        let list_matches_room = self
            .messages
            .last()
            .is_some_and(|message| Some(&message.room_id) == selected_room_id.as_ref());
        if self.messages_scroll_from_bottom > 0 && scroll_y == 0 && list_matches_room {
            debug_log(&format!(
                "触顶自动拉取 room={selected_room_id:?} offset={}",
                self.messages_scroll_from_bottom
            ));
            self.load_older_messages();
        }

        let paragraph = Paragraph::new(Text::from(lines)).scroll((scroll_y, 0));
        frame.render_widget(
            paragraph,
            Rect {
                width: inner.width.saturating_sub(1),
                ..inner
            },
        );

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(None);
        let mut scrollbar_state =
            ScrollbarState::new(max_scroll_y as usize).position(scroll_y as usize);
        frame.render_stateful_widget(scrollbar, scroll_area, &mut scrollbar_state);

        frame.render_widget(block, area);
    }

    fn render_message_input(&mut self, frame: &mut Frame, area: Rect) {
        let cursor_style = Style::default().fg(Color::Green);

        // command 模式下切换输入框标题与边框颜色
        let input_text = self.input_collector.message_input_state.text();
        let (title_text, border_color) = if input_text.starts_with('/') {
            (format!(" {} ", self.t("command_mode")), Color::Yellow)
        } else {
            (format!(" {} ", self.t("message_input")), Color::Cyan)
        };

        let block = Block::default()
            .title(title_text)
            .borders(Borders::ALL)
            .border_style(
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            );

        TextArea::new()
            .block(block)
            .cursor_style(cursor_style)
            .render(
                area,
                frame.buffer_mut(),
                &mut self.input_collector.message_input_state,
            );
    }

    fn render_create_group_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 60;
        let panel_height = 18;
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);

        // 仅清空并覆盖弹窗自身区域，避免破坏底层群聊列表与聊天记录的边框
        frame.render_widget(Clear, panel_rect);

        let focus_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let cursor_style = Style::default().fg(Color::Green);
        let unfocused_style = Style::default().fg(Color::Gray);

        let block = Block::default()
            .title(format!(" {} ", self.t("create_group_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

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
            .block(name_block)
            .focus_style(focus_style)
            .cursor_style(cursor_style)
            .render(
                layout[2],
                frame.buffer_mut(),
                &mut self.input_collector.create_group_name_state,
            );

        TextInput::new()
            .block(members_block)
            .focus_style(focus_style)
            .cursor_style(cursor_style)
            .render(
                layout[4],
                frame.buffer_mut(),
                &mut self.input_collector.create_group_members_state,
            );

        let hint = Paragraph::new(Text::raw(self.t("create_group_hint")))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, layout[5]);
    }

    fn render_create_private_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 50;
        let panel_height = 14;
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);

        // 仅清空并覆盖弹窗自身区域，避免破坏底层群聊列表与聊天记录的边框
        frame.render_widget(Clear, panel_rect);

        let focus_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let cursor_style = Style::default().fg(Color::Green);
        let unfocused_style = Style::default().fg(Color::Gray);

        let block = Block::default()
            .title(format!(" {} ", self.t("create_private_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

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
            .block(name_block)
            .focus_style(focus_style)
            .cursor_style(cursor_style)
            .render(
                layout[2],
                frame.buffer_mut(),
                &mut self.input_collector.create_private_username_state,
            );

        let hint = Paragraph::new(Text::raw(self.t("create_private_hint")))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, layout[4]);
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
        let detail = match self.connector.get_room(&room.id) {
            Ok(detail) => detail,
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_get_room_info_failed")));
                return;
            }
        };
        let room_name = detail
            .name
            .clone()
            .unwrap_or_else(|| self.t("private_chat_fallback"));
        let encrypted_label = if detail.is_encrypted {
            self.t("room_info_yes")
        } else {
            self.t("room_info_no")
        };
        let members_text: Vec<String> = detail
            .members
            .iter()
            .map(|member| format!("{} [{}]", member.username, member.role))
            .collect();
        let info = format!(
            "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
            self.t("room_info_name"),
            room_name,
            self.t("room_info_id"),
            detail.id,
            self.t("room_info_creator"),
            detail.created_by,
            self.t("room_info_created"),
            detail.created_at,
            self.t("room_info_encrypted"),
            encrypted_label,
            self.t("room_info_member_count"),
            detail.member_count,
            self.t("room_info_members"),
            members_text.join(", ")
        );
        self.push_notification(info);
    }

    fn render_settings_menu(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 48u16.min(area.width.saturating_sub(4)).max(30);
        let panel_height = 15u16.min(area.height.saturating_sub(4)).max(13);
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);

        frame.render_widget(Clear, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("settings_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let pending_count = self.pending_requests.len();
        let current_lang = Self::current_language();
        let uid_state = if self.show_uid { "ON" } else { "OFF" };
        let time_state = if self.time_with_date { "ON" } else { "OFF" };
        let sound_state = if self.sound_enabled { "ON" } else { "OFF" };
        let menu_items = vec![
            ListItem::new(Line::from(Span::styled(
                format!(" {}", self.t("option_create_group")),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {}", self.t("option_create_private")),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {} ({pending_count})", self.t("option_pending_requests")),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {} ({current_lang})", self.t("option_language")),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {} [{}]", self.t("option_show_uid"), uid_state),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {} [{}]", self.t("option_time_format"), time_state),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {} [{}]", self.t("option_sound_enabled"), sound_state),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {}", self.t("option_server_address")),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {}", self.t("option_logout")),
                Style::default().fg(Color::Red),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {}", self.t("option_login")),
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                format!(" {}", self.t("option_register")),
                Style::default().fg(Color::White),
            ))),
        ];

        let list = List::new(menu_items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.menu_list_state);
    }

    fn render_language_select(&mut self, frame: &mut Frame, area: Rect) {
        let languages = Self::get_available_languages();
        let panel_width = 30u16.min(area.width.saturating_sub(4)).max(20);
        let panel_height = (languages.len() as u16 + 4)
            .min(area.height.saturating_sub(4))
            .max(5);
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);

        frame.render_widget(Clear, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("select_language_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let current = Self::current_language();
        let items: Vec<ListItem> = languages
            .iter()
            .map(|lang| {
                let label = if lang == &current {
                    format!(" {lang} ✓")
                } else {
                    format!(" {lang}")
                };
                ListItem::new(Line::from(Span::styled(
                    label,
                    Style::default().fg(Color::White),
                )))
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.language_list_state);
    }

    fn render_server_address(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 50u16.min(area.width.saturating_sub(4)).max(30);
        let panel_height = 8u16.min(area.height.saturating_sub(4)).max(5);
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);

        frame.render_widget(Clear, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("server_address_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let label = Paragraph::new(Text::raw(self.t("server_address_label")))
            .style(Style::default().fg(Color::White));
        frame.render_widget(label, Rect::new(inner.x, inner.y, inner.width, 1));

        let input_rect = Rect::new(inner.x, inner.y + 1, inner.width, 3);
        let input_state = &mut self.input_collector.server_address_state;
        input_state.focus.set(true);
        let input = TextInput::new()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Gray)),
            )
            .cursor_style(Style::default().fg(Color::Green));
        frame.render_stateful_widget(input, input_rect, input_state);

        let hint = Paragraph::new(Text::raw(self.t("server_address_hint")))
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, Rect::new(inner.x, inner.y + 5, inner.width, 1));

        frame.render_widget(block, panel_rect);
    }

    /// 居中渲染待处理聊天请求列表弹窗，支持上下选择、回车接受、d 键拒绝
    fn render_pending_requests(&mut self, frame: &mut Frame, area: Rect) {
        let panel_width = 64u16.min(area.width.saturating_sub(4)).max(24);
        let panel_height = 16u16.min(area.height.saturating_sub(4)).max(8);
        let panel_x = area.x + (area.width.saturating_sub(panel_width)) / 2;
        let panel_y = area.y + (area.height.saturating_sub(panel_height)) / 2;
        let panel_rect = Rect::new(panel_x, panel_y, panel_width, panel_height);

        // 仅清空并覆盖弹窗自身区域，避免破坏底层界面边框
        frame.render_widget(Clear, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("pending_requests_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 1,
        });

        let layout = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).split(inner);

        if self.pending_requests.is_empty() {
            let empty_hint = Paragraph::new(Text::raw(self.t("no_pending_requests")))
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(block, panel_rect);
            frame.render_widget(empty_hint, layout[0]);
        } else {
            let items: Vec<ListItem> = self
                .pending_requests
                .iter()
                .map(|request| {
                    let sender_name = request
                        .sender
                        .as_ref()
                        .map(|sender| sender.username.clone())
                        .unwrap_or_else(|| self.t("unknown_user").to_string());
                    let encryption_mark = if request.is_encrypted {
                        self.t("encrypted_mark")
                    } else {
                        String::new()
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(sender_name.to_string(), Style::default().fg(Color::Yellow)),
                        Span::styled(
                            format!("：{}{encryption_mark}", request.message),
                            Style::default().fg(Color::White),
                        ),
                    ]))
                })
                .collect();
            let list = List::new(items)
                .block(block)
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("► ");
            frame.render_stateful_widget(list, layout[0], &mut self.request_list_state);
        }

        let hint = Paragraph::new(Text::raw(self.t("hint_pending_requests")))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, layout[1]);
    }

    /// 在右上角渲染通知弹窗列，每条一个带边框小面板，依次向下堆叠
    fn render_notifications(&self, frame: &mut Frame, area: Rect) {
        let margin_between = 1u16;
        // 整列统一宽度：按最长文本的显示宽度折算并套用最小宽度与半屏上限，保证各来源提示外观一致
        let longest_length = self
            .notifications
            .iter()
            .map(|(text, _, _)| display_width(text))
            .max()
            .unwrap_or(0);
        let max_width = (area.width / 2).max(28);
        let lower_width = 28u16.min(max_width);
        let column_width = (longest_length + 4).clamp(lower_width, max_width);
        let inner_width = column_width.saturating_sub(4).max(1);
        let mut next_top = area.y + 1;

        for (text, is_error, _) in &self.notifications {
            // 行数按 CJK 双列的显示宽度估算，与终端网格一致，避免折行文本被裁切
            // 同时统计显式换行符，确保包含 \n 的文本（如 /list 输出）有足够面板高度
            let text_length = display_width(text);
            let explicit_newlines = text.chars().filter(|&c| c == '\n').count() as u16;
            let wrapped_lines = text_length.div_ceil(inner_width).max(1);
            let line_count = wrapped_lines.max(explicit_newlines + 1);
            // 多行时额外预留一行：按词边界折行可能早于列宽上限换行；
            // 单行保持三行高度维持整列观感
            let panel_height = if line_count > 1 { line_count + 3 } else { 3 };

            let panel_x = area.x + area.width.saturating_sub(column_width + 1);
            if next_top + panel_height > area.y + area.height {
                break;
            }
            let panel_rect = Rect::new(panel_x, next_top, column_width, panel_height);

            // 错误类红色边框标题"错误"，信息类蓝色边框标题"提示"
            let (title_text, border_color) = if *is_error {
                (format!(" {} ", self.t("error_title")), Color::Red)
            } else {
                (format!(" {} ", self.t("info_title")), Color::Blue)
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
                .style(Style::default().fg(Color::White))
                .wrap(ratatui::widgets::Wrap { trim: true });
            // 缓冲区为叠加式渲染，必须先用 Clear 清空面板区域，否则下层文字会透出造成混乱
            frame.render_widget(Clear, panel_rect);
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
