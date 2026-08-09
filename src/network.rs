use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as Base64Engine;
use eframe::egui::Context;
use serde::de::DeserializeOwned;
use std::io::ErrorKind as IoErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::{AppState, EncryptionSession, SessionPhase};
use crate::encryption;
use crate::models::*;

const BASE_URL: &str = "http://localhost:2424";

pub struct HttpClient {
    client: reqwest::blocking::Client,
    base_url: String,
}

impl HttpClient {
    pub fn new() -> Self {
        Self::new_with_base_url(BASE_URL)
    }

    pub fn new_with_base_url(base_url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth_header(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn parse_ok<T: DeserializeOwned>(
        response: reqwest::blocking::Response,
        operation: &str,
    ) -> Result<T, String> {
        let api: ApiResponse<T> = response
            .json()
            .map_err(|e| format!("{operation}: response parse failed: {e}"))?;
        if api.error_code == "OK" {
            api.data.ok_or_else(|| format!("{operation}: empty response data"))
        } else {
            Err(format!(
                "{operation} failed: {} (code: {})",
                api.message, api.error_code
            ))
        }
    }

    pub fn greet(&self) -> Result<GreetData, String> {
        let response = self
            .client
            .get(self.url("/greet"))
            .send()
            .map_err(|e| format!("greet request failed: {e}"))?;
        response
            .json::<GreetData>()
            .map_err(|e| format!("greet response parse failed: {e}"))
    }

    pub fn register(&self, request: &RegisterRequest) -> Result<(), String> {
        let response = self
            .client
            .post(self.url("/api/v1/user/register"))
            .json(request)
            .send()
            .map_err(|e| format!("register request failed: {e}"))?;
        Self::parse_ok::<serde_json::Value>(response, "register").map(|_| ())
    }

    pub fn login(&self, request: &LoginRequest) -> Result<LoginData, String> {
        let response = self
            .client
            .post(self.url("/api/v1/user/login"))
            .json(request)
            .send()
            .map_err(|e| format!("login request failed: {e}"))?;
        Self::parse_ok(response, "login")
    }

    pub fn list_rooms(&self, token: &str) -> Result<Vec<RoomInfo>, String> {
        let response = self
            .client
            .get(self.url("/api/v1/chat/rooms"))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("list_rooms request failed: {e}"))?;
        let data: RoomsData = Self::parse_ok(response, "list_rooms")?;
        Ok(data.rooms)
    }

    pub fn create_room(&self, token: &str, request: &CreateRoomRequest) -> Result<RoomInfo, String> {
        let response = self
            .client
            .post(self.url("/api/v1/chat/rooms"))
            .header("Authorization", Self::auth_header(token))
            .json(request)
            .send()
            .map_err(|e| format!("create_room request failed: {e}"))?;
        Self::parse_ok(response, "create_room")
    }

    pub fn get_members(&self, token: &str, room_id: &str) -> Result<Vec<MemberInfo>, String> {
        let response = self
            .client
            .get(self.url(&format!("/api/v1/chat/rooms/{room_id}/members")))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("get_members request failed: {e}"))?;
        let data: MembersData = Self::parse_ok(response, "get_members")?;
        Ok(data.members)
    }

    pub fn add_members(
        &self,
        token: &str,
        room_id: &str,
        usernames: &[String],
    ) -> Result<usize, String> {
        let response = self
            .client
            .post(self.url(&format!("/api/v1/chat/rooms/{room_id}/members")))
            .header("Authorization", Self::auth_header(token))
            .json(&AddMembersRequest {
                usernames: usernames.to_vec(),
            })
            .send()
            .map_err(|e| format!("add_members request failed: {e}"))?;
        let data: AddMembersData = Self::parse_ok(response, "add_members")?;
        Ok(data.added_count)
    }

    pub fn remove_member(
        &self,
        token: &str,
        room_id: &str,
        user_id: &str,
    ) -> Result<RemoveMemberData, String> {
        let response = self
            .client
            .delete(self.url(&format!(
                "/api/v1/chat/rooms/{room_id}/members/{user_id}"
            )))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("remove_member request failed: {e}"))?;
        Self::parse_ok(response, "remove_member")
    }

    pub fn get_messages(
        &self,
        token: &str,
        room_id: &str,
        limit: u32,
    ) -> Result<Vec<MessageInfo>, String> {
        let response = self
            .client
            .get(self.url(&format!(
                "/api/v1/chat/rooms/{room_id}/messages?limit={limit}"
            )))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("get_messages request failed: {e}"))?;
        let data: MessagesData = Self::parse_ok(response, "get_messages")?;
        Ok(data.messages)
    }

    pub fn get_messages_before(
        &self,
        token: &str,
        room_id: &str,
        before: &str,
        limit: u32,
    ) -> Result<Vec<MessageInfo>, String> {
        let response = self
            .client
            .get(self.url(&format!(
                "/api/v1/chat/rooms/{room_id}/messages?limit={limit}&before={before}"
            )))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("get_messages_before request failed: {e}"))?;
        let data: MessagesData = Self::parse_ok(response, "get_messages_before")?;
        Ok(data.messages)
    }

    pub fn list_users(&self, token: &str) -> Result<Vec<UserInfo>, String> {
        let response = self
            .client
            .get(self.url("/api/v1/user/list"))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("list_users request failed: {e}"))?;
        let data: UsersData = Self::parse_ok(response, "list_users")?;
        Ok(data.users)
    }

    pub fn get_room_detail(&self, token: &str, room_id: &str) -> Result<RoomDetail, String> {
        let response = self
            .client
            .get(self.url(&format!("/api/v1/chat/rooms/{room_id}")))
            .header("Authorization", Self::auth_header(token))
            .send()
            .map_err(|e| format!("get_room_detail request failed: {e}"))?;
        Self::parse_ok(response, "get_room_detail")
    }
}

pub fn send_websocket_frame(state: &AppState, frame: String) {
    if let Some(sender) = &state.ws_tx {
        let _ = sender.send(frame);
    }
}

fn decode_base64_key(encoded: &str) -> Option<[u8; 32]> {
    let decoded = base64_engine.decode(encoded).ok()?;
    <[u8; 32]>::try_from(decoded.as_slice()).ok()
}

fn update_session(state: &mut AppState, room_id: &str, update: impl FnOnce(&mut EncryptionSession)) {
    let session = state
        .encryption_sessions
        .entry(room_id.to_string())
        .or_insert_with(|| EncryptionSession::new(room_id.to_string()));
    update(session);
}

fn handle_encrypt_invitation(state: &mut AppState, data: &serde_json::Value) {
    let Some(room_id) = data.get("room_id").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(inviter_username) = data.get("inviter_username").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(public_key) = data.get("public_key").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(identity_key) = data.get("identity_key").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(signature) = data.get("signature").and_then(|v| v.as_str()) else {
        return;
    };
    if state.encryption_sessions.get(room_id).is_some_and(|session| session.is_initiator) {
        return;
    }
    let Some(peer_public) = decode_base64_key(public_key) else {
        return;
    };
    let Some(peer_identity_public) = decode_base64_key(identity_key) else {
        return;
    };
    let Some(signature_bytes) = base64_engine
        .decode(signature)
        .ok()
        .and_then(|decoded| <[u8; 64]>::try_from(decoded.as_slice()).ok())
    else {
        return;
    };
    if !encryption::verify_public_key(&peer_identity_public, &peer_public, &signature_bytes) {
        state.notice = Some("Encryption invitation signature verification failed.".to_string());
        return;
    }
    update_session(state, room_id, |session| {
        session.phase = SessionPhase::AwaitingAccept;
        session.is_initiator = false;
        session.peer_username = Some(inviter_username.to_string());
        session.peer_public = Some(peer_public);
        session.peer_identity_public = Some(peer_identity_public);
    });
}

fn handle_encrypt_accept_response(
    state: &mut AppState,
    data: &serde_json::Value,
) -> Option<String> {
    let Some(room_id) = data.get("room_id").and_then(|v| v.as_str()) else {
        return None;
    };
    let Some(public_key) = data.get("public_key").and_then(|v| v.as_str()) else {
        return None;
    };
    let Some(identity_key) = data.get("identity_key").and_then(|v| v.as_str()) else {
        return None;
    };
    let Some(signature) = data.get("signature").and_then(|v| v.as_str()) else {
        return None;
    };
    let Some(peer_public) = decode_base64_key(public_key) else {
        return None;
    };
    let Some(peer_identity_public) = decode_base64_key(identity_key) else {
        return None;
    };
    let Some(signature_bytes) = base64_engine
        .decode(signature)
        .ok()
        .and_then(|decoded| <[u8; 64]>::try_from(decoded.as_slice()).ok())
    else {
        return None;
    };
    if !encryption::verify_public_key(&peer_identity_public, &peer_public, &signature_bytes) {
        state.notice = Some("Encryption acceptance signature verification failed.".to_string());
        return None;
    }
    let Some(session) = state.encryption_sessions.get(room_id) else {
        return None;
    };
    if !session.is_initiator || session.phase != SessionPhase::AwaitingAccept {
        return None;
    }
    let Some(my_ephemeral_private) = session.my_ephemeral_private else {
        return None;
    };
    let shared_secret = encryption::derive_shared_secret(&my_ephemeral_private, &peer_public);
    let session_key = encryption::derive_session_key(&shared_secret);
    let ready_frame = serde_json::json!({
        "type": "encrypt_ready",
        "data": { "room_id": room_id },
    })
    .to_string();
    update_session(state, room_id, |session| {
        session.phase = SessionPhase::AwaitingReady;
        session.peer_public = Some(peer_public);
        session.peer_identity_public = Some(peer_identity_public);
        session.session_key = Some(session_key);
    });
    Some(ready_frame)
}

fn process_ws_event(state: &Arc<Mutex<AppState>>, ctx: &Context, text: &str) -> Option<String> {
    let event: WebSocketEvent = match serde_json::from_str(text) {
        Ok(event) => event,
        Err(_) => return None,
    };
    let mut state = state.lock().unwrap();
    let Some(data) = &event.data else {
        return None;
    };
    match event.event_type.as_str() {
        "new_message" => {
            if let Ok(message) = serde_json::from_value::<MessageInfo>(data.clone()) {
                if state.selected_room_id.as_deref() == Some(&message.room_id) {
                    state.messages.push(message);
                }
                ctx.request_repaint();
            }
        }
        "error" => {
            if let Some(message) = data.get("message").and_then(|v| v.as_str()) {
                state.notice = Some(format!("{message}"));
            }
            ctx.request_repaint();
        }
        "user_online" | "user_offline" => {
            if let Some(user_id) = data.get("user_id").and_then(|v| v.as_str()) {
                if event.event_type == "user_online" {
                    state.online_user_ids.insert(user_id.to_string());
                } else {
                    state.online_user_ids.remove(user_id);
                }
            }
            ctx.request_repaint();
        }
        "typing" => {
            if let (Some(room_id), Some(user_id)) = (
                data.get("room_id").and_then(|v| v.as_str()),
                data.get("user_id").and_then(|v| v.as_str()),
            ) {
                let current_user_id = state.current_user.as_ref().map(|u| u.id.clone());
                if current_user_id.as_deref() != Some(user_id) {
                    state
                        .typing_room_members
                        .entry(room_id.to_string())
                        .or_default()
                        .insert(user_id.to_string());
                    state
                        .typing_last_received
                        .insert(room_id.to_string(), std::time::Instant::now());
                }
            }
            ctx.request_repaint();
        }
        "encrypt_invitation" => {
            handle_encrypt_invitation(&mut state, data);
            ctx.request_repaint();
        }
        "encrypt_accept_response" => {
            let frame = handle_encrypt_accept_response(&mut state, data);
            ctx.request_repaint();
            return frame;
        }
        "encrypt_session_ready" => {
            if let Some(room_id) = data.get("room_id").and_then(|v| v.as_str()) {
                update_session(&mut state, room_id, |session| {
                    session.phase = SessionPhase::Active;
                });
            }
            ctx.request_repaint();
        }
        "new_encrypted_message" => {
            if let Ok(message) = serde_json::from_value::<MessageInfo>(data.clone()) {
                if state.selected_room_id.as_deref() == Some(&message.room_id) {
                    let mut message = message;
                    if let Some(ciphertext) = message.ciphertext.clone() {
                        if let Some(session) = state.encryption_sessions.get(&message.room_id)
                            && let Some(key) = session.session_key
                        {
                            message.content = encryption::decrypt_message(&key, &ciphertext).ok();
                        }
                    }
                    state.messages.push(message);
                }
                ctx.request_repaint();
            }
        }
        "encrypt_partner_disconnected" | "encrypt_session_ended" | "encrypt_session_expired" => {
            if let Some(room_id) = data.get("room_id").and_then(|v| v.as_str()) {
                update_session(&mut state, room_id, |session| {
                    session.phase = SessionPhase::Ended;
                });
            }
            ctx.request_repaint();
        }
        _ => {}
    }
    None
}

pub fn spawn_websocket_thread(token: String, state: Arc<Mutex<AppState>>, ctx: Context) {
    std::thread::spawn(move || {
        let epoch = state.lock().unwrap().ws_epoch;
        let server_address = state.lock().unwrap().server_address.clone();
        let websocket_url = format!("{}/websocket", server_address.replace("http", "ws"));
        use tungstenite::client::IntoClientRequest;
        let mut request = match websocket_url.into_client_request() {
            Ok(request) => request,
            Err(e) => {
                if let Ok(mut state) = state.lock() {
                    state.notice = Some(format!("websocket request build failed: {e}"));
                }
                ctx.request_repaint();
                return;
            }
        };
        let authorization = format!("Bearer {token}");
        if let Ok(header_value) = http::HeaderValue::from_str(&authorization) {
            request
                .headers_mut()
                .insert(http::header::AUTHORIZATION, header_value);
        }
        let (mut socket, _response) = match tungstenite::connect(request) {
            Ok(connection) => connection,
            Err(e) => {
                if let Ok(mut state) = state.lock() {
                    state.notice = Some(format!("websocket connect failed: {e}"));
                }
                ctx.request_repaint();
                return;
            }
        };
        use tungstenite::stream::MaybeTlsStream;
        if let MaybeTlsStream::Plain(tcp_stream) = socket.get_mut() {
            let _ = tcp_stream.set_read_timeout(Some(Duration::from_millis(50)));
        }

        let (outgoing_sender, outgoing_receiver) = std::sync::mpsc::channel::<String>();
        {
            let mut state = state.lock().unwrap();
            state.ws_connected = true;
            state.ws_tx = Some(outgoing_sender);
        }
        ctx.request_repaint();

        loop {
            if state.lock().unwrap().ws_epoch != epoch {
                break;
            }
            let mut queued_frames = Vec::new();
            while let Ok(frame) = outgoing_receiver.try_recv() {
                queued_frames.push(frame);
            }
            for frame in queued_frames {
                if socket.send(tungstenite::Message::Text(frame.into())).is_err() {
                    break;
                }
            }
            match socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    if let Some(response_frame) = process_ws_event(&state, &ctx, &text) {
                        let _ = socket.send(tungstenite::Message::Text(response_frame.into()));
                    }
                }
                Ok(_) => {}
                Err(tungstenite::Error::Io(ref io_error))
                    if io_error.kind() == IoErrorKind::WouldBlock
                        || io_error.kind() == IoErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(
                    tungstenite::Error::ConnectionClosed
                    | tungstenite::Error::AlreadyClosed,
                ) => break,
                Err(_) => break,
            }
        }

        {
            let mut state = state.lock().unwrap();
            if state.ws_epoch == epoch {
                state.ws_connected = false;
                state.ws_tx = None;
                state.server_status = "WebSocket disconnected.".to_string();
            }
        }
        ctx.request_repaint();
    });
}