use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub response_id: String,
    pub error_code: String,
    pub message: String,
    pub data: Option<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreetData {
    pub server_version: String,
    pub api_version: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginData {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsersData {
    pub users: Vec<UserInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoomInfo {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub is_group: bool,
    #[serde(default)]
    pub is_encrypted: bool,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub member_count: i64,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub last_message: Option<LastMessage>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoomDetail {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    pub is_group: bool,
    #[serde(default)]
    pub is_encrypted: bool,
    #[serde(default)]
    pub member_count: i64,
    #[serde(default)]
    pub members: Vec<RoomMember>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoomMember {
    pub user_id: String,
    pub username: String,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub joined_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LastMessage {
    pub id: String,
    pub content: String,
    pub sender_username: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoomsData {
    pub rooms: Vec<RoomInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoomRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usernames: Option<Vec<String>>,
    pub is_group: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MessageInfo {
    pub id: String,
    pub room_id: String,
    pub sender_id: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub ciphertext: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MessagesData {
    pub messages: Vec<MessageInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberInfo {
    pub user_id: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MembersData {
    pub members: Vec<MemberInfo>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMembersRequest {
    pub usernames: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddMembersData {
    pub added_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveMemberData {
    pub room_id: String,
    pub room_deleted: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}