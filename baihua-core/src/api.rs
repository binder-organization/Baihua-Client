use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during API communication
#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {error_code} - {message}")]
    Api { error_code: String, message: String },
    #[error("Missing authentication token")]
    MissingToken,
    #[error("Invalid server response: {0}")]
    InvalidResponse(String),
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

/// 服务端 API 版本。所有随服务端版本变化的线上差异（响应成功码、端点路径、事件名、
/// 报文格式、错误串、心跳/重连时序等）都应通过本枚举的 match 方法集中决策。
/// 新增一个服务端版本 = 在此加一个变体，并在下方各 match 方法补一支分支即可，
/// app.rs 等业务层不感知具体线上格式。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApiVersion {
    /// 0.1.3：响应封装字段为 error_code，成功码 OK
    V0_1_3,
    /// 0.1.4：响应封装字段改为 code，成功码 SUCCESS（私聊须经聊天请求建立）
    V0_1_4,
    /// 未识别版本：按最接近的已知兼容行为处理，并在探测时提示用户核对
    Unknown,
}

impl ApiVersion {
    /// 从 greet 返回的 server_version 字符串解析版本（按 major.minor.patch 前三段匹配，
    /// 兼容前导 'v'）。次/修订号未识别时向上取最近的已知版本行为。
    pub fn from_version_string(version_text: &str) -> Self {
        let normalized = version_text.trim().trim_start_matches('v').to_string();
        let mut segments = normalized.split('.');
        match (segments.next(), segments.next(), segments.next()) {
            (Some("0"), Some("1"), Some("3")) => ApiVersion::V0_1_3,
            (Some("0"), Some("1"), Some(_)) => ApiVersion::V0_1_4,
            _ => ApiVersion::Unknown,
        }
    }

    /// 该版本下 ApiResponse 视为成功的 code 取值集合（用元组切片表达，避免散落 if）
    pub fn success_codes(self) -> &'static [&'static str] {
        match self {
            ApiVersion::V0_1_3 => &["OK"],
            ApiVersion::V0_1_4 | ApiVersion::Unknown => &["SUCCESS", "OK"],
        }
    }
}

/// Standard API response wrapper (0.1.4 字段为 code，兼容 0.1.3 的 error_code)
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    #[allow(dead_code)]
    response_id: String,
    #[serde(alias = "error_code")]
    code: String,
    message: String,
    data: Option<T>,
}

/// Greet response (raw JSON, not wrapped in standard format)
#[derive(Debug, Deserialize, Clone)]
pub struct GreetData {
    pub server_version: String,
    pub api_version: String,
    pub message: String,
}

/// Health check response
#[derive(Debug, Deserialize, Clone)]
pub struct HealthData {
    pub status: String,
}

/// User registration request
#[derive(Debug, Serialize, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// User login request
#[derive(Debug, Serialize, Clone)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// User info returned from API
#[derive(Debug, Deserialize, Clone)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub phone_number: Option<String>,
    pub created_at: String,
    pub is_active: bool,
}

/// User data in registration response
#[derive(Debug, Deserialize, Clone)]
pub struct UserData {
    pub user: UserInfo,
}

/// Login response with token
#[derive(Debug, Deserialize, Clone)]
pub struct LoginData {
    pub token: String,
    pub user: UserInfo,
}

/// 群聊创建请求（0.1.4 起私聊不再直接创建，须经聊天请求接受后由服务器建房间）
#[derive(Debug, Serialize, Clone)]
pub struct CreateRoomRequest {
    pub is_group: bool,
    pub name: String,
    pub usernames: Vec<String>,
}

impl CreateRoomRequest {
    pub fn group(name: String, usernames: Vec<String>) -> Self {
        Self {
            is_group: true,
            name,
            usernames,
        }
    }
}

/// 房间信息
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RoomInfo {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub is_group: bool,
    /// 该房间是否为端到端加密房间（随聊天请求的加密标志建立）
    #[serde(default)]
    pub is_encrypted: bool,
    pub members: Vec<String>,
}

/// Detailed room info
#[derive(Debug, Deserialize, Clone)]
pub struct RoomDetail {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub is_group: bool,
    /// 该房间是否为端到端加密房间
    #[serde(default)]
    pub is_encrypted: bool,
    pub member_count: usize,
    pub members: Vec<RoomMember>,
}

/// Room member info
#[derive(Debug, Deserialize, Clone)]
pub struct RoomMember {
    pub user_id: String,
    pub username: String,
    #[serde(default)]
    pub nickname: Option<String>,
    pub role: String,
    pub joined_at: String,
}

/// Add members request
#[derive(Debug, Serialize, Clone)]
pub struct AddMembersRequest {
    pub usernames: Vec<String>,
}

/// Add members response
#[derive(Debug, Deserialize, Clone)]
pub struct AddMembersData {
    pub added: Vec<AddedMember>,
    pub added_count: usize,
}

/// Added member info
#[derive(Debug, Deserialize, Clone)]
pub struct AddedMember {
    pub user_id: String,
    pub username: String,
    pub joined_at: String,
}

/// Members list response
#[derive(Debug, Deserialize, Clone)]
pub struct MembersData {
    pub members: Vec<RoomMember>,
    pub count: usize,
}

/// Remove member response
#[derive(Debug, Deserialize, Clone)]
pub struct RemoveMemberData {
    pub room_id: String,
    #[serde(default)]
    pub removed_user_id: Option<String>,
    #[serde(default)]
    pub left_user_id: Option<String>,
    #[serde(default)]
    pub room_deleted: bool,
}

/// Message info
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MessageInfo {
    pub id: String,
    pub room_id: String,
    pub sender_id: String,
    /// 加密房间的历史消息此字段为 null（密文存于 encrypted_content），用占位文本兜底
    #[serde(default = "default_encrypted_content")]
    pub content: String,
    pub created_at: String,
}

fn default_encrypted_content() -> String {
    "[加密历史消息，会话结束后已不可读]".to_string()
}

/// Messages response with pagination
#[derive(Debug, Deserialize, Clone)]
pub struct MessagesData {
    pub messages: Vec<MessageInfo>,
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// 用户搜索结果条目
#[derive(Debug, Deserialize, Clone)]
pub struct UserSearchResult {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub nickname: Option<String>,
}

/// 聊天请求中的对端描述（接收列表里是发送者，已发送列表里是接收者）
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RoomRequestPeer {
    pub user_id: String,
    pub username: String,
    #[serde(default)]
    pub nickname: Option<String>,
}

/// 聊天请求条目（待处理/已发送列表共用）
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RoomRequestInfo {
    pub id: String,
    pub message: String,
    pub is_encrypted: bool,
    pub created_at: String,
    #[serde(default)]
    pub sender: Option<RoomRequestPeer>,
    #[serde(default)]
    pub receiver: Option<RoomRequestPeer>,
    #[serde(default)]
    pub status: Option<String>,
}

/// 聊天请求创建载荷
#[derive(Debug, Serialize, Clone)]
pub struct CreateRoomRequestPayload {
    pub receiver_id: String,
    pub is_encrypted: bool,
    pub message: String,
}

/// 聊天请求状态变更结果（创建/接受/拒绝/撤回共用）
#[derive(Debug, Deserialize, Clone)]
pub struct RoomRequestStatusResult {
    pub request_id: String,
    pub status: String,
}

/// 接受聊天请求的结果，含服务器创建的私密房间
#[derive(Debug, Deserialize, Clone)]
pub struct AcceptedRoomRequest {
    pub request_id: String,
    pub status: String,
    pub room: RoomInfo,
}

/// Centralized network communication component for Baihua Server
#[derive(Debug, Clone)]
pub struct Connector {
    client: Client,
    base_url: String,
    token: Option<String>,
    /// 探测得到的服务端 API 版本，决定成功码等线上差异；默认按最新已知版本
    version: ApiVersion,
}

impl Connector {
    /// Create a new Connector with the given base URL
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
            version: ApiVersion::V0_1_4,
        }
    }

    /// Set the JWT authentication token
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(token.to_string());
    }

    /// 当前生效的服务端 API 版本
    pub fn version(&self) -> ApiVersion {
        self.version
    }

    /// 手动指定服务端 API 版本
    pub fn set_version(&mut self, version: ApiVersion) {
        self.version = version;
    }

    /// 探测服务端版本：调用 greet 读取 server_version（回退 api_version）解析并记录。
    /// 登录成功、启动自动登录、切换服务器地址后应调用，使后续线上决策匹配真实版本。
    /// 返回 (探测到的版本, 原始版本串)；原始串供界面提示"未识别版本"时使用
    pub fn probe_version(&mut self) -> Result<(ApiVersion, String)> {
        let greet = self.greet()?;
        let raw = if !greet.server_version.is_empty() {
            greet.server_version
        } else {
            greet.api_version
        };
        let detected = ApiVersion::from_version_string(&raw);
        self.version = detected;
        Ok((detected, raw))
    }

    /// Get the current base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set the base URL (used when user changes server address)
    pub fn set_base_url(&mut self, url: &str) {
        self.base_url = url.trim_end_matches('/').to_string();
    }

    /// Build request headers with optional auth
    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(token) = &self.token {
            let auth_value = HeaderValue::from_str(&authorization_value(token))
                .map_err(|e| ConnectorError::InvalidResponse(format!("Invalid token: {}", e)))?;
            headers.insert(AUTHORIZATION, auth_value);
        }
        Ok(headers)
    }

    /// Parse API response, handling error codes (成功码取值随 ApiVersion 变化，集中在此判定)
    fn parse_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::blocking::Response,
    ) -> Result<T> {
        let _status = response.status();
        let api_response: ApiResponse<T> = response.json()?;

        if self
            .version
            .success_codes()
            .contains(&api_response.code.as_str())
        {
            api_response.data.ok_or_else(|| {
                ConnectorError::InvalidResponse("Missing data in successful response".to_string())
            })
        } else {
            Err(ConnectorError::Api {
                error_code: api_response.code,
                message: api_response.message,
            })
        }
    }

    /// Parse greet response (raw JSON, not wrapped)
    fn parse_greet(response: reqwest::blocking::Response) -> Result<GreetData> {
        let greet: GreetData = response.json()?;
        Ok(greet)
    }

    /// GET /greet - Verify Baihua server and get version info
    pub fn greet(&self) -> Result<GreetData> {
        let url = format!("{}/greet", self.base_url);
        let response = self.client.get(&url).send()?;
        Self::parse_greet(response)
    }

    /// GET /health - Health check with DB connectivity
    pub fn health(&self) -> Result<HealthData> {
        let url = format!("{}/health", self.base_url);
        let response = self.client.get(&url).send()?;
        self.parse_response(response)
    }

    /// POST /api/v1/user/register - Register new user
    pub fn register(&self, req: RegisterRequest) -> Result<UserData> {
        let url = format!("{}/api/v1/user/register", self.base_url);
        let response = self.client.post(&url).json(&req).send()?;
        self.parse_response(response)
    }

    /// POST /api/v1/user/login - Login and get JWT token
    pub fn login(&self, req: LoginRequest) -> Result<LoginData> {
        let url = format!("{}/api/v1/user/login", self.base_url);
        let response = self.client.post(&url).json(&req).send()?;
        self.parse_response(response)
    }

    /// GET /api/v1/user/list - List all active users (requires auth)
    pub fn list_users(&self) -> Result<Vec<UserInfo>> {
        let url = format!("{}/api/v1/user/list", self.base_url);
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;

        #[derive(Deserialize)]
        struct UsersWrapper {
            users: Vec<UserInfo>,
        }
        let wrapper: UsersWrapper = self.parse_response(response)?;
        Ok(wrapper.users)
    }

    /// POST /api/v1/chat/rooms - Create chat room (private or group)
    pub fn create_room(&self, req: CreateRoomRequest) -> Result<RoomInfo> {
        let url = format!("{}/api/v1/chat/rooms", self.base_url);
        let headers = self.headers()?;
        let response = self.client.post(&url).headers(headers).json(&req).send()?;
        self.parse_response(response)
    }

    /// GET /api/v1/chat/rooms - List user's rooms with last message preview
    pub fn list_rooms(&self) -> Result<Vec<RoomInfo>> {
        let url = format!("{}/api/v1/chat/rooms", self.base_url);
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;

        #[derive(Deserialize)]
        struct RoomsWrapper {
            rooms: Vec<RoomInfo>,
        }
        let wrapper: RoomsWrapper = self.parse_response(response)?;
        Ok(wrapper.rooms)
    }

    /// GET /api/v1/chat/rooms/{room_id} - Get room detail with member info
    pub fn get_room(&self, room_id: &str) -> Result<RoomDetail> {
        let url = format!("{}/api/v1/chat/rooms/{}", self.base_url, room_id);
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;
        self.parse_response(response)
    }

    /// POST /api/v1/chat/rooms/{room_id}/members - Add members (group, admin only)
    pub fn add_members(&self, room_id: &str, usernames: &[String]) -> Result<AddMembersData> {
        let url = format!("{}/api/v1/chat/rooms/{}/members", self.base_url, room_id);
        let headers = self.headers()?;
        let req = AddMembersRequest {
            usernames: usernames.to_vec(),
        };
        let response = self.client.post(&url).headers(headers).json(&req).send()?;
        self.parse_response(response)
    }

    /// GET /api/v1/chat/rooms/{room_id}/members - List members with roles
    pub fn list_members(&self, room_id: &str) -> Result<MembersData> {
        let url = format!("{}/api/v1/chat/rooms/{}/members", self.base_url, room_id);
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;
        self.parse_response(response)
    }

    /// DELETE /api/v1/chat/rooms/{room_id}/members/{user_id} - Remove member / leave
    pub fn remove_member(&self, room_id: &str, user_id: &str) -> Result<RemoveMemberData> {
        let url = format!(
            "{}/api/v1/chat/rooms/{}/members/{}",
            self.base_url, room_id, user_id
        );
        let headers = self.headers()?;
        let response = self.client.delete(&url).headers(headers).send()?;
        self.parse_response(response)
    }

    /// GET /api/v1/chat/rooms/{room_id}/messages - Get messages with cursor pagination
    pub fn get_messages(
        &self,
        room_id: &str,
        limit: u32,
        before: Option<&str>,
    ) -> Result<MessagesData> {
        let mut url = format!(
            "{}/api/v1/chat/rooms/{}/messages?limit={}",
            self.base_url, room_id, limit
        );
        if let Some(cursor) = before {
            url.push_str(&format!("&before={}", encode_query_component(cursor)));
        }
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;
        self.parse_response(response)
    }

    /// GET /api/v1/user/search?username= - 按用户名模糊搜索活跃用户
    pub fn search_users(&self, username: &str) -> Result<Vec<UserSearchResult>> {
        let url = format!(
            "{}/api/v1/user/search?username={}",
            self.base_url,
            encode_query_component(username)
        );
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;

        #[derive(Deserialize)]
        struct UsersWrapper {
            users: Vec<UserSearchResult>,
        }
        let wrapper: UsersWrapper = self.parse_response(response)?;
        Ok(wrapper.users)
    }

    /// POST /api/v1/chat/rooms/requests - 发送聊天请求（0.1.4 建立私聊的唯一途径）
    pub fn create_room_request(
        &self,
        receiver_id: &str,
        message: &str,
        is_encrypted: bool,
    ) -> Result<RoomRequestStatusResult> {
        let url = format!("{}/api/v1/chat/rooms/requests", self.base_url);
        let headers = self.headers()?;
        let payload = CreateRoomRequestPayload {
            receiver_id: receiver_id.to_string(),
            is_encrypted,
            message: message.to_string(),
        };
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&payload)
            .send()?;
        self.parse_response(response)
    }

    /// GET /api/v1/chat/rooms/requests/pending - 当前用户待处理的聊天请求列表
    pub fn list_pending_requests(&self) -> Result<Vec<RoomRequestInfo>> {
        let url = format!("{}/api/v1/chat/rooms/requests/pending", self.base_url);
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;

        #[derive(Deserialize)]
        struct RequestsWrapper {
            requests: Vec<RoomRequestInfo>,
        }
        let wrapper: RequestsWrapper = self.parse_response(response)?;
        Ok(wrapper.requests)
    }

    /// GET /api/v1/chat/rooms/requests/sent - 当前用户已发送的聊天请求列表
    pub fn list_sent_requests(&self) -> Result<Vec<RoomRequestInfo>> {
        let url = format!("{}/api/v1/chat/rooms/requests/sent", self.base_url);
        let headers = self.headers()?;
        let response = self.client.get(&url).headers(headers).send()?;

        #[derive(Deserialize)]
        struct RequestsWrapper {
            requests: Vec<RoomRequestInfo>,
        }
        let wrapper: RequestsWrapper = self.parse_response(response)?;
        Ok(wrapper.requests)
    }

    /// POST /api/v1/chat/rooms/requests/{request_id}/accept - 接受聊天请求，服务器随后创建私密房间
    pub fn accept_room_request(&self, request_id: &str) -> Result<AcceptedRoomRequest> {
        let url = format!(
            "{}/api/v1/chat/rooms/requests/{}/accept",
            self.base_url, request_id
        );
        let headers = self.headers()?;
        let response = self.client.post(&url).headers(headers).send()?;
        self.parse_response(response)
    }

    /// POST /api/v1/chat/rooms/requests/{request_id}/decline - 拒绝聊天请求
    pub fn decline_room_request(&self, request_id: &str) -> Result<RoomRequestStatusResult> {
        let url = format!(
            "{}/api/v1/chat/rooms/requests/{}/decline",
            self.base_url, request_id
        );
        let headers = self.headers()?;
        let response = self.client.post(&url).headers(headers).send()?;
        self.parse_response(response)
    }

    /// POST /api/v1/chat/rooms/requests/{request_id}/cancel - 撤回自己发送的聊天请求
    pub fn cancel_room_request(&self, request_id: &str) -> Result<RoomRequestStatusResult> {
        let url = format!(
            "{}/api/v1/chat/rooms/requests/{}/cancel",
            self.base_url, request_id
        );
        let headers = self.headers()?;
        let response = self.client.post(&url).headers(headers).send()?;
        self.parse_response(response)
    }
}

/// 按 RFC 3986 未保留字符集对查询参数做百分号编码
fn encode_query_component(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

impl Default for Connector {
    fn default() -> Self {
        Self::new("http://localhost:2424")
    }
}

// ======================= WebSocket 线协议接缝（入站）=======================
// 本节是"服务端 WebSocket 推送报文"与"客户端领域事件 PollingEvent"之间的唯一翻译层。
// 事件 type 字符串、字段名、错误文案等线上事实集中于此，业务层(app.rs)只见领域事件。
// 未来某版本改名/改结构时，在本节按 ApiVersion 增补 match 即可，app.rs 不感知。

/// 后台线程（轮询/WebSocket）发往主循环的领域事件。变体名与线上 type 字符串解耦。
#[derive(Debug, Clone)]
pub enum PollingEvent {
    /// 更新后的房间列表
    RoomsUpdated(Vec<RoomInfo>),
    /// 更新后的待处理聊天请求列表
    PendingRequestsUpdated(Vec<RoomRequestInfo>),
    /// 自己发送的消息被服务器确认收到
    MessageSent(MessageInfo),
    /// 其他成员发送的新消息（实时推送）
    IncomingMessage(MessageInfo),
    /// 对端发起的加密会话邀请
    EncryptInvitation(EncryptHandshakeData),
    /// 对端对加密会话邀请的接受回应
    EncryptAccepted(EncryptHandshakeData),
    /// 双方就绪，加密会话激活（房间 ID）
    EncryptSessionReady(String),
    /// 收到加密消息（密文）
    EncryptedMessage(EncryptedMessageInfo),
    /// 自己发送的加密消息被服务器确认（消息 ID 回执）
    EncryptedMessageSent(String),
    /// 加密会话结束（房间 ID, 结束原因）
    EncryptSessionEnded((String, String)),
    /// 私聊对端完全离线（用户 ID）
    PartnerOffline(String),
    /// WebSocket 连接就绪：服务器已完成房间订阅，可以安全发送握手与消息
    WebSocketConnected,
    /// 退出清理流程在后台执行完毕，可以安全退出应用
    QuitCleanupFinished,
    /// 轮询或连接错误
    Error(String),
}

/// 加密握手数据（邀请与接受回应共用，peer 为对端）
#[derive(Debug, Clone)]
pub struct EncryptHandshakeData {
    pub room_id: String,
    pub peer_id: String,
    pub public_key: String,
    pub identity_key: String,
    pub signature: String,
}

/// 加密消息载荷（密文，解密前不含明文）
#[derive(Debug, Clone)]
pub struct EncryptedMessageInfo {
    pub id: String,
    pub room_id: String,
    pub sender_id: String,
    pub ciphertext: String,
    pub created_at: String,
}

/// 将服务器推送的 WebSocket 文本消息解析为领域事件；无法识别的内容返回 None
pub fn parse_websocket_event(text: &str, tr: &dyn Fn(&str) -> String) -> Option<PollingEvent> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let event_type = value.get("type")?.as_str()?;
    let data = value.get("data")?;
    match event_type {
        "message_sent" => parse_message_info(data).map(PollingEvent::MessageSent),
        "new_message" => parse_message_info(data).map(PollingEvent::IncomingMessage),
        "encrypt_invitation" => {
            parse_handshake_data(data, "inviter_id").map(PollingEvent::EncryptInvitation)
        }
        "encrypt_accept_response" => {
            parse_handshake_data(data, "acceptor_id").map(PollingEvent::EncryptAccepted)
        }
        "encrypt_session_ready" => Some(PollingEvent::EncryptSessionReady(
            data.get("room_id")?.as_str()?.to_string(),
        )),
        "new_encrypted_message" => Some(PollingEvent::EncryptedMessage(EncryptedMessageInfo {
            id: data.get("id")?.as_str()?.to_string(),
            room_id: data.get("room_id")?.as_str()?.to_string(),
            sender_id: data.get("sender_id")?.as_str()?.to_string(),
            ciphertext: data.get("ciphertext")?.as_str()?.to_string(),
            created_at: data.get("created_at")?.as_str()?.to_string(),
        })),
        "encrypted_message_sent" => Some(PollingEvent::EncryptedMessageSent(
            data.get("id")?.as_str()?.to_string(),
        )),
        "encrypt_session_ended" => Some(PollingEvent::EncryptSessionEnded((
            data.get("room_id")?.as_str()?.to_string(),
            data.get("reason")
                .and_then(|reason| reason.as_str())
                .unwrap_or("unknown")
                .to_string(),
        ))),
        "encrypt_partner_disconnected" => {
            Some(PollingEvent::Error(tr("warning_partner_disconnected")))
        }
        // 连接回执：服务器在此之后才会把后续广播投递给本连接
        "connected" => Some(PollingEvent::WebSocketConnected),
        // 对端最后一个连接关闭，其所在房间会收到此广播
        "user_offline" => Some(PollingEvent::PartnerOffline(
            data.get("user_id")?.as_str()?.to_string(),
        )),
        "encrypt_session_expired" => Some(PollingEvent::Error(tr("warning_session_expired"))),
        "error" => {
            let server_message = data
                .get("message")
                .and_then(|message| message.as_str())
                .map(|message| message.to_string());
            Some(PollingEvent::Error(
                server_message.unwrap_or_else(|| tr("error_server_unknown")),
            ))
        }
        _ => None,
    }
}

/// 从 JSON 数据中解析加密握手数据；peer_id_field 为对端用户 ID 所在字段名
fn parse_handshake_data(
    data: &serde_json::Value,
    peer_id_field: &str,
) -> Option<EncryptHandshakeData> {
    Some(EncryptHandshakeData {
        room_id: data.get("room_id")?.as_str()?.to_string(),
        peer_id: data.get(peer_id_field)?.as_str()?.to_string(),
        public_key: data.get("public_key")?.as_str()?.to_string(),
        identity_key: data.get("identity_key")?.as_str()?.to_string(),
        signature: data.get("signature")?.as_str()?.to_string(),
    })
}

/// 从 JSON 数据中解析消息对象。content 为可选（加密房间历史为 null），
/// 与 HTTP DTO 的 serde default 一致用占位文本兜底，绝不因单字段缺失丢弃整条消息
fn parse_message_info(data: &serde_json::Value) -> Option<MessageInfo> {
    Some(MessageInfo {
        id: data.get("id")?.as_str()?.to_string(),
        room_id: data.get("room_id")?.as_str()?.to_string(),
        sender_id: data.get("sender_id")?.as_str()?.to_string(),
        content: data
            .get("content")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .unwrap_or_else(default_encrypted_content),
        created_at: data.get("created_at")?.as_str()?.to_string(),
    })
}

// ======================= WebSocket 线协议接缝（出站）=======================
// 客户端→服务端的 WebSocket 上行报文（发送消息、加密握手各阶段）在此集中构造。
// 领域命令 WsCommand 与线上 "type"/字段布局解耦；type 名称按 ApiVersion 匹配，
// 未来某版本改线上名/字段只改本节的 outbound_type 与 outbound_ws_payload。

/// 客户端→服务端上行命令（领域语义）。字段用引用借用，避免与调用方所有权纠缠。
pub enum WsCommand<'a> {
    SendMessage {
        room_id: &'a str,
        content: &'a str,
    },
    EncryptMessage {
        room_id: &'a str,
        ciphertext: &'a str,
    },
    EncryptRequest {
        room_id: &'a str,
        public_key: &'a str,
        identity_key: &'a str,
        signature: &'a str,
    },
    EncryptAccept {
        room_id: &'a str,
        public_key: &'a str,
        identity_key: &'a str,
        signature: &'a str,
    },
    EncryptReady {
        room_id: &'a str,
    },
    EncryptLeave {
        room_id: &'a str,
    },
}

/// 上行命令的逻辑类别，用于按版本查线上 type 字符串
enum OutboundKind {
    SendMessage,
    EncryptMessage,
    EncryptRequest,
    EncryptAccept,
    EncryptReady,
    EncryptLeave,
}

impl ApiVersion {
    /// 该版本下某逻辑命令对应的线上 "type" 字符串。已知 0.1.3/0.1.4/未识别当前一致，
    /// 显式列出以便将来对特定版本改名时只改此处。
    fn outbound_type(self, kind: OutboundKind) -> &'static str {
        match kind {
            OutboundKind::SendMessage => "send_message",
            OutboundKind::EncryptMessage => "encrypt_message",
            OutboundKind::EncryptRequest => "encrypt_request",
            OutboundKind::EncryptAccept => "encrypt_accept",
            OutboundKind::EncryptReady => "encrypt_ready",
            OutboundKind::EncryptLeave => "encrypt_leave",
        }
    }
}

/// 将领域上行命令序列化为服务端线上报文（type 名与 data 字段布局集中于接缝）
pub fn outbound_ws_payload(version: ApiVersion, command: WsCommand) -> serde_json::Value {
    match command {
        WsCommand::SendMessage { room_id, content } => serde_json::json!({
            "type": version.outbound_type(OutboundKind::SendMessage),
            "data": { "room_id": room_id, "content": content },
        }),
        WsCommand::EncryptMessage {
            room_id,
            ciphertext,
        } => serde_json::json!({
            "type": version.outbound_type(OutboundKind::EncryptMessage),
            "data": { "room_id": room_id, "ciphertext": ciphertext },
        }),
        WsCommand::EncryptRequest {
            room_id,
            public_key,
            identity_key,
            signature,
        } => serde_json::json!({
            "type": version.outbound_type(OutboundKind::EncryptRequest),
            "data": { "room_id": room_id, "public_key": public_key, "identity_key": identity_key, "signature": signature },
        }),
        WsCommand::EncryptAccept {
            room_id,
            public_key,
            identity_key,
            signature,
        } => serde_json::json!({
            "type": version.outbound_type(OutboundKind::EncryptAccept),
            "data": { "room_id": room_id, "public_key": public_key, "identity_key": identity_key, "signature": signature },
        }),
        WsCommand::EncryptReady { room_id } => serde_json::json!({
            "type": version.outbound_type(OutboundKind::EncryptReady),
            "data": { "room_id": room_id },
        }),
        WsCommand::EncryptLeave { room_id } => serde_json::json!({
            "type": version.outbound_type(OutboundKind::EncryptLeave),
            "data": { "room_id": room_id },
        }),
    }
}

// ==================== WebSocket 连接与保活线上常量（按版本）====================
// HTTP↔WebSocket 地址映射、/websocket 路径、Bearer 头格式、应用层心跳帧、
// 鉴权失败判定标记、心跳/订阅刷新/握手重发时序——全部集中于此，按 ApiVersion 匹配。
impl ApiVersion {
    /// 由 HTTP base_url 推导 WebSocket 连接地址（协议级 scheme 替换 + 固定路径）。
    /// 路径 `/websocket` 是线上契约，未来版本改路径只改这里。
    pub fn websocket_url(self, base_url: &str) -> String {
        let secured = base_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        format!("{secured}/websocket")
    }

    /// 应用层双向心跳帧。服务端对 "pong" 类型静默忽略（无回复），用于在客户端→服务端
    /// 方向产生 TCP 流量，避免中间设备因单向静默判定连接死亡。
    pub fn heartbeat_frame(self) -> String {
        serde_json::json!({ "type": "pong" }).to_string()
    }

    /// 服务端握手鉴权失败的特征串（HTTP 401/403 或令牌过期文案），用于令客户端清会话回登录页。
    /// 小写匹配（调用方需先 lowercase 或此表均为小写片段，数字标记单独判）。
    pub fn auth_failure_markers(self) -> &'static [&'static str] {
        &[
            "401",
            "403",
            "unauthorized",
            "forbidden",
            "invalid token",
            "token expired",
        ]
    }

    /// 判断一条 WebSocket 连接错误文本是否为服务端鉴权失败（应清除本地会话）
    pub fn is_auth_failure(self, error_text: &str) -> bool {
        let lowered = error_text.to_lowercase();
        self.auth_failure_markers()
            .iter()
            .any(|marker| lowered.contains(marker))
    }

    /// 应用层心跳发送间隔（小于服务端 30 秒协议 Ping，保持双向流量）
    pub fn application_heartbeat_interval(self) -> std::time::Duration {
        std::time::Duration::from_secs(20)
    }

    /// 定期重建 WebSocket 以刷新房间订阅的间隔（服务端仅在连接时快照订阅）
    pub fn subscription_refresh_interval(self) -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }

    /// 未激活加密握手超时重发间隔
    pub fn handshake_resend_interval(self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// 服务端"会话结束" reason（线上串）对应的本地化文案键名，集中映射便于按版本调整
    pub fn session_end_reason_key(self, reason: &str) -> &'static str {
        match reason {
            "user_left" => "notification_partner_ended_session",
            "partner_timeout" => "notification_session_timeout_ended",
            _ => "notification_session_ended",
        }
    }

    /// 退房时服务器返回的"房间不存在/非成员"类错误是否属预期内（应静默忽略），串表按版本集中
    pub fn is_ignorable_room_removal_error(self, error_text: &str) -> bool {
        let lowered = error_text.to_lowercase();
        ["not found", "not exist", "not a member", "member"]
            .iter()
            .any(|keyword| lowered.contains(keyword))
    }
}

/// 构造 HTTP/WebSocket 请求的 Authorization 头值（Bearer 方案，线上契约）
pub fn authorization_value(token: &str) -> String {
    format!("Bearer {token}")
}

/// WebSocket 认证失败的内部哨兵（客户端自造，非服务端线上串）。发送与匹配统一取自此处，
/// 避免两端字面量漂移。
pub fn websocket_auth_sentinel() -> &'static str {
    "WS_AUTH_FAILED"
}

/// 服务端运行时错误文本的领域归类。错误文案子串属线上契约，按版本集中判定；
/// app.rs 只据归类决定行为，不再散落 contains 字面量。
pub enum ServerSignal {
    /// 撞上服务器残留的活跃加密会话，需发 encrypt_leave 触发清理
    StuckEncryptedSession,
    /// 对端离线导致握手被拒，需清理本地等待接受的僵死会话
    PartnerOfflineHandshakeRejected,
    /// 无活跃加密会话（/quit 批量清理对无会话房间发 leave 属预期），静默忽略
    NoActiveEncryptedSession,
    /// 非该房间成员（私聊退房已先发 encrypt_leave，属预期），静默忽略
    NotRoomMember,
    /// 其它真实错误，展示给用户
    Displayable,
}

impl ApiVersion {
    /// 把服务端错误文本归类为领域信号（当前已知各版本文案一致，集中于此便于将来按版本分叉）
    pub fn classify_server_error(self, error_text: &str) -> ServerSignal {
        let lowered = error_text.to_lowercase();
        if lowered.contains("already has an active encrypted session") {
            ServerSignal::StuckEncryptedSession
        } else if lowered.contains("both users must be online") {
            ServerSignal::PartnerOfflineHandshakeRejected
        } else if lowered.contains("no active encrypted session") {
            ServerSignal::NoActiveEncryptedSession
        } else if lowered.contains("not a member of this room") {
            ServerSignal::NotRoomMember
        } else {
            ServerSignal::Displayable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use tungstenite::client::IntoClientRequest;
    use tungstenite::Message as WebSocketMessage;

    #[test]
    fn test_connector_creation() {
        let connector = Connector::new("http://localhost:2424");
        assert_eq!(connector.base_url(), "http://localhost:2424");
        assert!(connector.token.is_none());
    }

    #[test]
    fn test_connector_with_token() {
        let mut connector = Connector::new("http://localhost:2424");
        connector.set_token("test-token");
        assert_eq!(connector.token, Some("test-token".to_string()));
    }

    #[test]
    fn test_create_room_request_group() {
        let req = CreateRoomRequest::group("Team".to_string(), vec!["bob".to_string()]);
        assert!(req.is_group);
        assert_eq!(req.name, "Team");
        assert_eq!(req.usernames, vec!["bob"]);
    }

    #[test]
    fn test_encode_query_component() {
        assert_eq!(encode_query_component("alice_01"), "alice_01");
        assert_eq!(encode_query_component("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_query_component("中文"), "%E4%B8%AD%E6%96%87");
    }

    /// 诊断用：双 WebSocket 连接完整模拟加密握手，逐环节打印事件类型，
    /// 用于定位 encrypt_invitation / accept_response / session_ready 断点
    #[test]
    #[ignore]
    fn live_test_encrypted_handshake_flow() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        // —— 准备：注册两账号并建立加密私聊房间（复用请求流程）——
        let mut connector = Connector::new("http://localhost:2424");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let name_a = format!("hs_alice_{suffix}");
        let name_b = format!("hs_bob_{suffix}");
        let encrypted_password = crate::crypto::encrypt_login_password("pass1234");
        for username in [&name_a, &name_b] {
            connector
                .register(RegisterRequest {
                    username: username.clone(),
                    email: format!("{username}@example.com"),
                    password: encrypted_password.clone(),
                })
                .expect("register failed");
        }
        let login_a = connector
            .login(LoginRequest {
                username: name_a.clone(),
                password: encrypted_password.clone(),
            })
            .expect("login a failed");
        connector.set_token(&login_a.token);
        let results = connector.search_users(&name_b).expect("search failed");
        let partner_id = results[0].id.clone();
        connector
            .create_room_request(&partner_id, "握手诊断", true)
            .expect("create request failed");
        let login_b = connector
            .login(LoginRequest {
                username: name_b.clone(),
                password: encrypted_password.clone(),
            })
            .expect("login b failed");
        connector.set_token(&login_b.token);
        let pending = connector.list_pending_requests().expect("pending failed");
        let request_id = pending[0].id.clone();
        let accepted = connector
            .accept_room_request(&request_id)
            .expect("accept failed");
        let room_id = accepted.room.id.clone();
        println!("ROOM: {room_id}");

        // —— 双连接建立 ——
        let build_request = |token: &str| {
            let mut request = "ws://localhost:2424/websocket"
                .to_string()
                .into_client_request()
                .expect("ws request");
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
            );
            request
        };
        let (mut socket_a, _) =
            tungstenite::connect(build_request(&login_a.token)).expect("connect a");
        let (mut socket_b, _) =
            tungstenite::connect(build_request(&login_b.token)).expect("connect b");
        if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket_a.get_ref() {
            let _ = stream.set_nonblocking(true);
        }
        if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket_b.get_ref() {
            let _ = stream.set_nonblocking(true);
        }

        // 在时限内收集两端收到的事件类型序列
        fn drain(
            socket: &mut tungstenite::WebSocket<
                tungstenite::stream::MaybeTlsStream<std::net::TcpStream>,
            >,
            milliseconds: u64,
        ) -> Vec<String> {
            let deadline = std::time::Instant::now() + Duration::from_millis(milliseconds);
            let mut event_types = Vec::new();
            while std::time::Instant::now() < deadline {
                match socket.read() {
                    Ok(WebSocketMessage::Text(text)) => {
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                            event_types.push(value["type"].as_str().unwrap_or("?").to_string());
                        }
                    }
                    _ => {}
                }
                thread::sleep(Duration::from_millis(10));
            }
            event_types
        }
        let write_json = |socket: &mut tungstenite::WebSocket<
            tungstenite::stream::MaybeTlsStream<std::net::TcpStream>,
        >,
                          value: serde_json::Value| {
            socket
                .write(WebSocketMessage::text(value.to_string()))
                .expect("ws write");
            let _ = socket.flush();
        };

        println!(
            "STEP1 connected: A={:?} B={:?}",
            drain(&mut socket_a, 600),
            drain(&mut socket_b, 600)
        );

        // A 发起 encrypt_request（占位密钥，仅验证服务器路由）
        write_json(
            &mut socket_a,
            serde_json::json!({
                "type": "encrypt_request",
                "data": { "room_id": room_id, "public_key": "AAA=", "identity_key": "BBB=", "signature": "CCC=" }
            }),
        );
        println!(
            "STEP2 after request_A: A={:?} B={:?}",
            drain(&mut socket_a, 900),
            drain(&mut socket_b, 900)
        );

        // B 回 accept + ready
        write_json(
            &mut socket_b,
            serde_json::json!({
                "type": "encrypt_accept",
                "data": { "room_id": room_id, "public_key": "DDD=", "identity_key": "EEE=", "signature": "FFF=" }
            }),
        );
        write_json(
            &mut socket_b,
            serde_json::json!({
                "type": "encrypt_ready",
                "data": { "room_id": room_id }
            }),
        );
        println!(
            "STEP3 after accept_B+ready_B: A={:?} B={:?}",
            drain(&mut socket_a, 900),
            drain(&mut socket_b, 900)
        );

        // A 回 ready → 双方就绪应触发 session_ready
        write_json(
            &mut socket_a,
            serde_json::json!({
                "type": "encrypt_ready",
                "data": { "room_id": room_id }
            }),
        );
        println!(
            "STEP4 after ready_A: A={:?} B={:?}",
            drain(&mut socket_a, 900),
            drain(&mut socket_b, 900)
        );

        // A 发加密消息（占位密文）→ 双方都应收到 new_encrypted_message
        write_json(
            &mut socket_a,
            serde_json::json!({
                "type": "encrypt_message",
                "data": { "room_id": room_id, "ciphertext": BASE64.encode(b"payload") }
            }),
        );
        println!(
            "STEP5 after message_A: A={:?} B={:?}",
            drain(&mut socket_a, 900),
            drain(&mut socket_b, 900)
        );
    }

    #[test]
    #[ignore]
    fn live_test_private_chat_flow() {
        // 0.1.4 流程：搜索用户 → 发送聊天请求 → 对方接受 → 房间建立
        let mut connector = Connector::new("http://localhost:2424");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let initiator_name = format!("live_initiator_{suffix}");
        let partner_name = format!("live_partner_{suffix}");
        let encrypted_password = crate::crypto::encrypt_login_password("pass1234");
        connector
            .register(RegisterRequest {
                username: initiator_name.clone(),
                email: format!("{initiator_name}@example.com"),
                password: encrypted_password.clone(),
            })
            .expect("register initiator failed");
        connector
            .register(RegisterRequest {
                username: partner_name.clone(),
                email: format!("{partner_name}@example.com"),
                password: encrypted_password.clone(),
            })
            .expect("register partner failed");

        // 发起方登录（加密密码回传，验证确定性加密可登录）
        let initiator_login = connector
            .login(LoginRequest {
                username: initiator_name.clone(),
                password: encrypted_password.clone(),
            })
            .expect("initiator login with encrypted password failed");

        // 搜索对方拿到 user_id
        connector.set_token(&initiator_login.token);
        let search_results = connector
            .search_users(&partner_name)
            .expect("search failed");
        let partner_id = search_results
            .iter()
            .find(|user| user.username == partner_name)
            .expect("partner not found in search")
            .id
            .clone();

        // 发送聊天请求
        connector
            .create_room_request(&partner_id, "建立私密聊天", false)
            .expect("create room request failed");

        // 对方登录后查看待处理请求并接受
        let partner_login = connector
            .login(LoginRequest {
                username: partner_name.clone(),
                password: encrypted_password.clone(),
            })
            .expect("partner login failed");
        connector.set_token(&partner_login.token);
        let pending = connector
            .list_pending_requests()
            .expect("list pending failed");
        let request_id = pending
            .iter()
            .find(|request| {
                request
                    .sender
                    .as_ref()
                    .is_some_and(|sender| sender.username == initiator_name)
            })
            .expect("pending request not found")
            .id
            .clone();
        let accepted = connector
            .accept_room_request(&request_id)
            .expect("accept failed");
        assert!(!accepted.room.is_group);

        // 双方房间列表都应出现该房间
        let partner_rooms = connector.list_rooms().expect("partner list rooms failed");
        assert_eq!(partner_rooms.len(), 1);
        connector.set_token(&initiator_login.token);
        let initiator_rooms = connector.list_rooms().expect("initiator list rooms failed");
        assert_eq!(initiator_rooms.len(), 1);
        println!("FLOW_OK room: {:?}", initiator_rooms[0].id);
    }
}
