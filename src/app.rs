use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as base64_engine;
use eframe::egui::{self, Align2, Color32, Context, Id, PointerButton, Pos2, TextEdit, Ui};
use graphician::{
    BackgroundConfig, BackgroundType, CustomRectConfig, HorizontalAlign, ImageConfig,
    ImageLoadMethod, PanelLayout, PanelLocation, PanelMargin, PositionSizeConfig,
    RenderLayerVisualizationConfig, ResourcePanelConfig, ScrollBarDisplayMethod,
    ScrollLengthMethod, SwitchAppearanceConfig, SwitchClickConfig, SwitchConfig, SwitchState,
    TextConfig, VerticalAlign,
    app::App as GraphicianApp,
    elements::{Element, ElementEntry},
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::process::exit;
use std::sync::{Arc, Mutex};

use crate::encryption;
use crate::models::*;
use crate::network::{self, send_websocket_frame};

const LOGO_BASE_SIZE: f32 = 500.0;
const LOGO_TOP_GRID: f32 = 0.09;

fn format_message_time(created_at: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(created_at)
        .map(|utc| {
            let local = utc.with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap());
            local.format("%m-%d %H:%M").to_string()
        })
        .unwrap_or_else(|_| {
            if created_at.len() >= 19 {
                created_at[11..19].to_string()
            } else {
                String::new()
            }
        })
}
const BASIC_PSC: PositionSizeConfig = PositionSizeConfig {
    x_location_grid: [0.0, 0.0],
    y_location_grid: [0.0, 0.0],
    origin_size: [40.0, 40.0],
    display_method: (HorizontalAlign::Center, VerticalAlign::Center),
    offset: [0.0, 0.0],
    origin_position: [0.0, 0.0],
    x_size_grid: [0.0, 0.0],
    y_size_grid: [0.0, 0.0],
};

#[derive(Debug, Clone, PartialEq)]
pub enum LabelConfig {
    OnHint(String),
    OnText(String, ([f32; 2], (HorizontalAlign, VerticalAlign))),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Login,
    Register,
    Main,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPhase {
    #[default]
    AwaitingAccept,
    AwaitingReady,
    Active,
    Ended,
}

#[derive(Debug, Clone)]
pub struct EncryptionSession {
    pub room_id: String,
    pub phase: SessionPhase,
    pub is_initiator: bool,
    pub peer_username: Option<String>,
    pub peer_public: Option<[u8; 32]>,
    pub peer_identity_public: Option<[u8; 32]>,
    pub my_ephemeral_private: Option<[u8; 32]>,
    pub session_key: Option<[u8; 32]>,
}

impl EncryptionSession {
    pub fn new(room_id: String) -> Self {
        EncryptionSession {
            room_id,
            phase: SessionPhase::default(),
            is_initiator: false,
            peer_username: None,
            peer_public: None,
            peer_identity_public: None,
            my_ephemeral_private: None,
            session_key: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CreateMode {
    #[default]
    None,
    Group,
    Private,
}

#[derive(Debug, Default)]
pub struct AppState {
    pub token: Option<String>,
    pub current_user: Option<UserInfo>,
    pub server_status: String,
    pub ws_connected: bool,
    pub ws_tx: Option<std::sync::mpsc::Sender<String>>,
    pub ws_epoch: u64,
    pub rooms: Vec<RoomInfo>,
    pub room_members: HashMap<String, Vec<MemberInfo>>,
    pub dm_peer_usernames: HashMap<String, String>,
    pub selected_room_id: Option<String>,
    pub messages: Vec<MessageInfo>,
    pub has_older_messages: bool,
    pub message_input: String,
    pub create_group_name: String,
    pub create_group_members: String,
    pub create_mode: CreateMode,
    pub private_chat_username: String,
    pub add_member_usernames: String,
    pub users: Vec<UserInfo>,
    pub online_user_ids: HashSet<String>,
    pub typing_room_members: HashMap<String, HashSet<String>>,
    pub typing_last_sent: HashMap<String, std::time::Instant>,
    pub typing_last_received: HashMap<String, std::time::Instant>,
    pub encryption_sessions: HashMap<String, EncryptionSession>,
    pub notice: Option<String>,
    pub server_address: String,
    pub pending_page: Option<Page>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Theme {
    name: HashMap<String, String>,
}

fn add_input(
    ui: &mut Ui,
    value: &mut String,
    hint: &str,
    width: f32,
    text_color: [u8; 3],
    text_alpha: u8,
    background_color: [u8; 3],
    background_alpha: u8,
    password: bool,
    interactive: bool,
) {
    let mut edit = TextEdit::singleline(value)
        .interactive(interactive)
        .hint_text(hint)
        .desired_width(width)
        .background_color(Color32::from_rgba_unmultiplied(
            background_color[0],
            background_color[1],
            background_color[2],
            background_alpha,
        ))
        .text_color(Color32::from_rgba_unmultiplied(
            text_color[0],
            text_color[1],
            text_color[2],
            text_alpha,
        ));
    if password {
        edit = edit.password(true);
    }
    ui.add(edit);
}

pub struct BaihuaApp {
    graphician: GraphicianApp,
    state: Arc<Mutex<AppState>>,
    context: Context,
    language_code: String,
    theme_code: String,
    page: Page,
    login_username: String,
    login_password: String,
    register_username: String,
    register_password: String,
    register_email: String,
    theme_value: Theme,
    language_values: HashMap<String, serde_json::Value>,
    theme_values: HashMap<String, serde_json::Value>,
    login_prev_pressed: bool,
    register_prev_pressed: bool,
    exit_prev_pressed: bool,
    back_prev_pressed: bool,
    confirm_prev_pressed: bool,
    main_switch_prev: HashMap<String, bool>,
    prev_message_count: HashMap<String, usize>,
}

impl BaihuaApp {
    pub fn new(
        context: &eframe::CreationContext,
        token: Option<String>,
        user: Option<UserInfo>,
        theme_value: Theme,
        language_values: HashMap<String, serde_json::Value>,
        theme_values: HashMap<String, serde_json::Value>,
        language_code: String,
        theme_code: String,
    ) -> Self {
        let mut app_state = AppState {
            token,
            current_user: user,
            server_address: "http://localhost:2424".to_string(),
            ..Default::default()
        };
        if app_state.token.is_some() {
            app_state.pending_page = Some(Page::Main);
        }

        let mut graphician = GraphicianApp::default();

        graphician.set_variable::<Option<String>>("notice", None);

        BaihuaApp {
            graphician,
            state: Arc::new(Mutex::new(app_state)),
            context: context.egui_ctx.clone(),
            language_code,
            theme_code,
            page: Page::Login,
            login_username: String::new(),
            login_password: String::new(),
            register_username: String::new(),
            register_password: String::new(),
            register_email: String::new(),
            theme_value,
            language_values,
            theme_values,
            login_prev_pressed: false,
            register_prev_pressed: false,
            exit_prev_pressed: false,
            back_prev_pressed: false,
            confirm_prev_pressed: false,
            main_switch_prev: HashMap::new(),
            prev_message_count: HashMap::new(),
        }
    }

    fn get_language_text(&self, key: &str) -> String {
        self.language_values
            .get(&self.language_code)
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_str())
            .unwrap_or(key)
            .to_string()
    }

    fn get_theme_color(&self, key: &str) -> [u8; 3] {
        self.theme_values
            .get(&self.theme_code)
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_array())
            .map(|array| {
                [
                    array[0].as_u64().unwrap_or(0) as u8,
                    array[1].as_u64().unwrap_or(0) as u8,
                    array[2].as_u64().unwrap_or(0) as u8,
                ]
            })
            .unwrap_or([255, 255, 255])
    }

    fn get_theme_alpha(&self, key: &str) -> u8 {
        self.theme_values
            .get(&self.theme_code)
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_u64())
            .map(|value| value as u8)
            .unwrap_or(255)
    }

    fn get_theme_image(&self, name: &str) -> String {
        format!("assets/images/{name}/{}.png", self.theme_code)
    }

    fn build_switch_appearance(
        &self,
        label: &LabelConfig,
        text_alpha: u8,
        brightness: u8,
        image_path: &str,
    ) -> SwitchAppearanceConfig {
        let text_color = self.get_theme_color("text_color");
        SwitchAppearanceConfig::default()
            .background_config(BackgroundType::Image(
                ImageConfig::default()
                    .overlay_color(brightness, brightness, brightness)
                    .overlay_alpha(255)
                    .image_load_method(ImageLoadMethod::ByPath(
                        image_path.to_string(),
                        [false, false],
                    )),
            ))
            .text_config(
                TextConfig::default()
                    .content(if let LabelConfig::OnText(content, _) = label {
                        content
                    } else {
                        ""
                    })
                    .font_size(16.0)
                    .color(text_color[0], text_color[1], text_color[2])
                    .alpha(text_alpha),
            )
            .hint_text_config(
                TextConfig::default()
                    .content(if let LabelConfig::OnHint(content) = label {
                        content
                    } else {
                        ""
                    })
                    .font_size(12.0)
                    .color(text_color[0], text_color[1], text_color[2])
                    .alpha(text_alpha),
            )
    }

    fn build_switch(
        &mut self,
        name: &str,
        position_size_config: PositionSizeConfig,
        label: LabelConfig,
        image_name: &str,
    ) {
        let image_path = self.get_theme_image(image_name);
        let base_alpha = self.get_theme_alpha("text_alpha");
        let appearances = vec![
            self.build_switch_appearance(&label, base_alpha, 255, &image_path),
            self.build_switch_appearance(&label, base_alpha, 200, &image_path),
            self.build_switch_appearance(&label, base_alpha, 100, &image_path),
        ];

        let mut config = SwitchConfig::default()
            .appearance(appearances)
            .background_type(BackgroundType::Image(
                ImageConfig::default()
                    .position_size_config(position_size_config)
                    .image_load_method(ImageLoadMethod::ByPath(image_path, [false, false])),
            ))
            .text_config(TextConfig::default().font_size(16.0).position_size_config(
                if let LabelConfig::OnText(_, config) = label {
                    position_size_config
                        .offset(config.0[0], config.0[1])
                        .display_method(config.1.0, config.1.1)
                        .origin_size(position_size_config.origin_size[0], f32::INFINITY)
                } else {
                    position_size_config
                        .origin_size(position_size_config.origin_size[0], f32::INFINITY)
                },
            ))
            .hint_text_config(TextConfig::default().font_size(12.0))
            .enable_animation(true, true)
            .state_amount(1)
            .click_method(vec![SwitchClickConfig {
                click_method: PointerButton::Primary,
                action: true,
            }])
            .enable(true);
        config.state = 0;

        self.graphician.add_switch(name, config);
    }

    fn build_image_switch(
        &mut self,
        name: &str,
        position_size_config: PositionSizeConfig,
        image_name: &str,
    ) {
        let image_path = self.get_theme_image(image_name);
        let appearances = vec![
            self.build_switch_appearance(&LabelConfig::OnHint(String::new()), 0, 255, &image_path),
            self.build_switch_appearance(&LabelConfig::OnHint(String::new()), 0, 200, &image_path),
            self.build_switch_appearance(&LabelConfig::OnHint(String::new()), 0, 100, &image_path),
        ];
        let mut config = SwitchConfig::default()
            .appearance(appearances)
            .background_type(BackgroundType::Image(
                ImageConfig::default()
                    .position_size_config(position_size_config)
                    .image_load_method(ImageLoadMethod::ByPath(image_path, [false, false])),
            ))
            .text_config(
                TextConfig::default()
                    .font_size(0.0)
                    .position_size_config(position_size_config),
            )
            .hint_text_config(TextConfig::default().font_size(0.0))
            .enable_animation(true, true)
            .state_amount(1)
            .click_method(vec![SwitchClickConfig {
                click_method: PointerButton::Primary,
                action: true,
            }])
            .enable(true);
        config.state = 0;
        self.graphician.add_switch(name, config);
    }

    fn build_rect_switch(
        &mut self,
        name: &str,
        position_size_config: PositionSizeConfig,
        label: &str,
    ) {
        let base_alpha = self.get_theme_alpha("text_alpha");
        let rect_color = self.get_theme_color("rect_color");
        let text_color = self.get_theme_color("text_color");
        let build_appearance = |brightness: u8| {
            SwitchAppearanceConfig::default()
                .background_config(BackgroundType::CustomRect(
                    CustomRectConfig::default()
                        .border_width(0.0)
                        .color(
                            (rect_color[0] as u16 * brightness as u16 / 255) as u8,
                            (rect_color[1] as u16 * brightness as u16 / 255) as u8,
                            (rect_color[2] as u16 * brightness as u16 / 255) as u8,
                        )
                        .alpha(255)
                        .position_size_config(position_size_config),
                ))
                .text_config(
                    TextConfig::default()
                        .content(label)
                        .font_size(13.0)
                        .color(text_color[0], text_color[1], text_color[2])
                        .alpha(base_alpha)
                        .position_size_config(position_size_config),
                )
                .hint_text_config(TextConfig::default().content("").font_size(12.0))
        };
        let appearances = vec![
            build_appearance(150),
            build_appearance(180),
            build_appearance(220),
        ];
        let mut config = SwitchConfig::default()
            .appearance(appearances)
            .background_type(BackgroundType::CustomRect(
                CustomRectConfig::default()
                    .border_width(0.0)
                    .color(rect_color[0], rect_color[1], rect_color[2])
                    .alpha(255)
                    .position_size_config(position_size_config),
            ))
            .text_config(
                TextConfig::default()
                    .content(label)
                    .font_size(13.0)
                    .color(text_color[0], text_color[1], text_color[2])
                    .alpha(base_alpha)
                    .position_size_config(position_size_config),
            )
            .hint_text_config(TextConfig::default().content("").font_size(12.0))
            .enable_animation(true, true)
            .state_amount(1)
            .click_method(vec![SwitchClickConfig {
                click_method: PointerButton::Primary,
                action: true,
            }])
            .enable(true);
        config.state = 0;
        self.graphician.add_switch(name, config);
    }

    fn build_auth_common(&mut self) {
        let background_color = self.get_theme_color("background_color");
        let background_alpha = self.get_theme_alpha("background_alpha");
        self.graphician.add_background(
            "AuthBackground",
            BackgroundConfig::default().background_type(BackgroundType::CustomRect(
                CustomRectConfig::default()
                    .position_size_config(PositionSizeConfig::default().origin_size(1920.0, 1080.0))
                    .color(
                        background_color[0],
                        background_color[1],
                        background_color[2],
                    )
                    .alpha(background_alpha),
            )),
        );

        let content_rect = self.context.content_rect();
        let window_side = content_rect.width().min(content_rect.height());
        let logo_side = LOGO_BASE_SIZE.min(window_side - 100.0).max(0.0);
        self.graphician.add_image(
            "AuthLogo",
            ImageConfig::default()
                .position_size_config(
                    PositionSizeConfig::default()
                        .origin_position(
                            (content_rect.width() - logo_side) * 0.5,
                            content_rect.height() * LOGO_TOP_GRID,
                        )
                        .origin_size(logo_side, logo_side),
                )
                .image_load_method(ImageLoadMethod::ByPath(
                    "assets/images/logo.png".to_string(),
                    [false, false],
                )),
        );

        let login_label = self.get_language_text("login");
        let register_label = self.get_language_text("register");
        let exit_label = self.get_language_text("exit");
        let confirm_label = self.get_language_text("confirm");
        let back_label = self.get_language_text("back");

        match self.page {
            Page::Login => {
                self.build_switch(
                    "LoginSwitch",
                    BASIC_PSC
                        .x_location_grid(1.0, 4.0)
                        .y_location_grid(3.0, 4.0),
                    LabelConfig::OnText(
                        login_label,
                        ([0.0, 20.0], (HorizontalAlign::Center, VerticalAlign::Top)),
                    ),
                    "proceed",
                );
                self.build_switch(
                    "RegisterSwitch",
                    BASIC_PSC
                        .x_location_grid(2.0, 4.0)
                        .y_location_grid(3.0, 4.0),
                    LabelConfig::OnText(
                        register_label,
                        ([0.0, 20.0], (HorizontalAlign::Center, VerticalAlign::Top)),
                    ),
                    "register",
                );
                self.build_switch(
                    "ExitSwitch",
                    BASIC_PSC
                        .x_location_grid(3.0, 4.0)
                        .y_location_grid(3.0, 4.0),
                    LabelConfig::OnText(
                        exit_label,
                        ([0.0, 20.0], (HorizontalAlign::Center, VerticalAlign::Top)),
                    ),
                    "exit",
                );
            }
            Page::Register => {
                self.build_switch(
                    "BackSwitch",
                    BASIC_PSC
                        .x_location_grid(1.0, 4.0)
                        .y_location_grid(3.0, 4.0),
                    LabelConfig::OnText(
                        back_label,
                        ([0.0, 20.0], (HorizontalAlign::Center, VerticalAlign::Top)),
                    ),
                    "back",
                );
                self.build_switch(
                    "ConfirmSwitch",
                    BASIC_PSC
                        .x_location_grid(2.0, 4.0)
                        .y_location_grid(3.0, 4.0),
                    LabelConfig::OnText(
                        confirm_label,
                        ([0.0, 20.0], (HorizontalAlign::Center, VerticalAlign::Top)),
                    ),
                    "confirm",
                );
                self.build_switch(
                    "ExitSwitch",
                    BASIC_PSC
                        .x_location_grid(3.0, 4.0)
                        .y_location_grid(3.0, 4.0),
                    LabelConfig::OnText(
                        exit_label,
                        ([0.0, 20.0], (HorizontalAlign::Center, VerticalAlign::Top)),
                    ),
                    "exit",
                );
            }
            Page::Main => {}
        }
    }

    fn build_corner_toggles(&mut self, ui: &mut Ui) {
        let theme_hint = self
            .theme_value
            .name
            .get(&self.language_code)
            .cloned()
            .unwrap_or_default();
        let language_hint = if self.language_code == "en-US" {
            "中文".to_string()
        } else {
            "English".to_string()
        };

        let mut theme_toggled = false;
        let mut language_toggled = false;
        egui::Area::new(Id::new("CornerToggles"))
            .anchor(Align2::RIGHT_TOP, egui::vec2(8.0, 8.0))
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    if ui.button(theme_hint.clone()).clicked() {
                        theme_toggled = true;
                    }
                    if ui.button(language_hint.clone()).clicked() {
                        language_toggled = true;
                    }
                });
            });

        if theme_toggled {
            self.theme_code = if self.theme_code == "dark" {
                "light".to_string()
            } else {
                "dark".to_string()
            };
        }
        if language_toggled {
            self.language_code = if self.language_code == "en-US" {
                "zh-CN".to_string()
            } else {
                "en-US".to_string()
            };
        }
    }

    fn build_login_page(&mut self, ui: &mut Ui) {
        self.build_auth_common();

        let title = self.get_language_text("login");
        let text_color = self.get_theme_color("text_color");
        let text_alpha = self.get_theme_alpha("text_alpha");
        self.graphician.add_text(
            "LoginTitle",
            TextConfig::default()
                .content(&title)
                .font_size(24.0)
                .color(text_color[0], text_color[1], text_color[2])
                .alpha(text_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .x_location_grid(2.0, 4.0)
                        .y_location_grid(1.0, 8.0)
                        .origin_size(100.0, 40.0)
                        .x_size_grid(1.0, 1.0)
                        .display_method(HorizontalAlign::Center, VerticalAlign::Center),
                ),
        );

        let username_hint = self.get_language_text("username");
        let password_hint = self.get_language_text("password");
        let server_address_hint = self.get_language_text("server_address");
        let background_color = self.get_theme_color("background_color");
        let background_alpha = self.get_theme_alpha("background_alpha");
        let status = self.state.lock().unwrap().server_status.clone();

        let content_rect = ui.ctx().content_rect();
        let input_width = 200.0;
        let input_position = Pos2::new(
            content_rect.width() * 0.5 - input_width * 0.5,
            content_rect.height() * 0.5 - 75.0,
        );

        egui::Area::new(Id::new("LoginInputBox"))
            .fixed_pos(input_position)
            .show(ui.ctx(), |ui| {
                let interactive = self
                    .graphician
                    .get_variable::<Option<String>>("notice")
                    .unwrap()
                    .is_none();
                let mut guard = self.state.lock().unwrap();
                ui.add(
                    TextEdit::singleline(&mut guard.server_address)
                        .hint_text(server_address_hint.clone())
                        .desired_width(input_width)
                        .interactive(interactive),
                );
                drop(guard);
                add_input(
                    ui,
                    &mut self.login_username,
                    &username_hint,
                    input_width,
                    text_color,
                    text_alpha,
                    background_color,
                    background_alpha,
                    false,
                    interactive,
                );
                add_input(
                    ui,
                    &mut self.login_password,
                    &password_hint,
                    input_width,
                    text_color,
                    text_alpha,
                    background_color,
                    background_alpha,
                    true,
                    interactive,
                );
                if !status.is_empty() {
                    ui.colored_label(Color32::from_rgb(255, 100, 100), status);
                }
            });

        self.build_corner_toggles(ui);
    }

    fn build_register_page(&mut self, ui: &mut Ui) {
        self.build_auth_common();

        let title = self.get_language_text("register");
        let text_color = self.get_theme_color("text_color");
        let text_alpha = self.get_theme_alpha("text_alpha");
        self.graphician.add_text(
            "RegisterTitle",
            TextConfig::default()
                .content(&title)
                .font_size(24.0)
                .color(text_color[0], text_color[1], text_color[2])
                .alpha(text_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .x_location_grid(2.0, 4.0)
                        .y_location_grid(1.0, 8.0)
                        .x_size_grid(1.0, 4.0)
                        .display_method(HorizontalAlign::Center, VerticalAlign::Center),
                ),
        );

        let username_hint = self.get_language_text("username");
        let password_hint = self.get_language_text("password");
        let email_hint = self.get_language_text("email");
        let background_color = self.get_theme_color("background_color");
        let background_alpha = self.get_theme_alpha("background_alpha");
        let status = self.state.lock().unwrap().server_status.clone();

        let content_rect = ui.ctx().content_rect();
        let input_width = 160.0;
        let input_position = Pos2::new(
            content_rect.width() * 0.5 - input_width * 0.5,
            content_rect.height() * 0.5 - 70.0,
        );

        egui::Area::new(Id::new("RegisterInputBox"))
            .fixed_pos(input_position)
            .show(ui.ctx(), |ui| {
                add_input(
                    ui,
                    &mut self.register_username,
                    &username_hint,
                    input_width,
                    text_color,
                    text_alpha,
                    background_color,
                    background_alpha,
                    false,
                    self.graphician
                        .get_variable::<Option<String>>("notice")
                        .unwrap()
                        .is_none(),
                );
                add_input(
                    ui,
                    &mut self.register_password,
                    &password_hint,
                    input_width,
                    text_color,
                    text_alpha,
                    background_color,
                    background_alpha,
                    true,
                    self.graphician
                        .get_variable::<Option<String>>("notice")
                        .unwrap()
                        .is_none(),
                );
                add_input(
                    ui,
                    &mut self.register_email,
                    &email_hint,
                    input_width,
                    text_color,
                    text_alpha,
                    background_color,
                    background_alpha,
                    false,
                    self.graphician
                        .get_variable::<Option<String>>("notice")
                        .unwrap()
                        .is_none(),
                );
                if !status.is_empty() {
                    ui.colored_label(Color32::from_rgb(255, 100, 100), status);
                }
            });

        self.build_corner_toggles(ui);
    }

    fn build_main_page(&mut self, ui: &mut Ui) {
        let background_color = self.get_theme_color("background_color");
        let background_alpha = self.get_theme_alpha("background_alpha");
        let text_color = self.get_theme_color("text_color");
        let text_alpha = self.get_theme_alpha("text_alpha");
        let sidebar_color = self.get_theme_color("sidebar_color");
        let sidebar_alpha = self.get_theme_alpha("sidebar_alpha");
        let top_bar_color = self.get_theme_color("top_bar_color");
        let top_bar_alpha = self.get_theme_alpha("top_bar_alpha");
        let member_bg_color = self.get_theme_color("member_bg_color");
        let member_bg_alpha = self.get_theme_alpha("member_bg_alpha");
        let header_color = self.get_theme_color("header_color");
        let header_alpha = self.get_theme_alpha("header_alpha");

        let content_rect = ui.ctx().content_rect();
        let window_w = content_rect.width();
        let window_h = content_rect.height();
        let top_bar_h = 40.0;
        let left_w = 220.0;

        let ws_connected_text = self.get_language_text("ws_connected");
        let ws_disconnected_text = self.get_language_text("ws_disconnected");
        let rooms_label = self.get_language_text("rooms");
        let create_group_hint = self.get_language_text("create_group");
        let create_group_members_hint = self.get_language_text("create_group_members");
        let private_chat_username_hint = self.get_language_text("private_chat_username");
        let add_members_label = self.get_language_text("add_members");
        let add_member_hint = self.get_language_text("add_member_hint");
        let message_hint = self.get_language_text("message");
        let load_older_label = self.get_language_text("load_older");
        let is_typing_text = self.get_language_text("is_typing");
        let member_label = self.get_language_text("member");
        let leave_room_label = self.get_language_text("leave_room");
        let role_admin_label = self.get_language_text("role_admin");
        let start_encryption_label = self.get_language_text("start_encryption");
        let accept_encryption_label = self.get_language_text("accept_encryption");
        let end_encryption_label = self.get_language_text("end_encryption");
        let waiting_accept_label = self.get_language_text("waiting_accept");
        let encryption_active_label = self.get_language_text("encryption_active");
        let encryption_ended_label = self.get_language_text("encryption_ended");

        let guard = self.state.lock().unwrap();
        let current_user_id = guard.current_user.as_ref().map(|user| user.id.clone());
        let ws_connected = guard.ws_connected;
        let selected_room_id = guard.selected_room_id.clone();
        let rooms = guard.rooms.clone();
        let dm_names = guard.dm_peer_usernames.clone();
        let message_records = guard.messages.clone();
        let room_members = guard.room_members.clone();
        let server_status = guard.server_status.clone();
        let encryption_sessions = guard.encryption_sessions.clone();
        let has_older_messages = guard.has_older_messages;
        let create_mode = guard.create_mode;
        let online_user_ids = guard.online_user_ids.clone();
        let typing_room_members = guard.typing_room_members.clone();
        let state = self.state.clone();
        drop(guard);

        // --- Background ---
        ui.painter().rect_filled(
            ui.max_rect(),
            0.0,
            Color32::from_rgba_unmultiplied(
                background_color[0],
                background_color[1],
                background_color[2],
                background_alpha,
            ),
        );

        // --- Top bar ---
        self.graphician.add_custom_rect(
            "main_top_bar",
            CustomRectConfig::default()
                .border_width(0.0)
                .color(top_bar_color[0], top_bar_color[1], top_bar_color[2])
                .alpha(top_bar_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .origin_position(0.0, 0.0)
                        .origin_size(window_w, top_bar_h),
                ),
        );
        let connection_text = if ws_connected {
            format!("{ws_connected_text} ✅")
        } else {
            format!("{ws_disconnected_text} ⚠️")
        };
        self.graphician.add_text(
            "main_ws_status",
            TextConfig::default()
                .content(&connection_text)
                .font_size(14.0)
                .color(text_color[0], text_color[1], text_color[2])
                .alpha(text_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .origin_position(10.0, 8.0)
                        .origin_size(200.0, 24.0),
                ),
        );
        self.build_image_switch(
            "main_logout",
            PositionSizeConfig::default()
                .origin_position(window_w - 42.0, 3.0)
                .origin_size(34.0, 34.0),
            "exit",
        );

        // --- Left panel background ---
        self.graphician.add_custom_rect(
            "main_left_panel_bg",
            CustomRectConfig::default()
                .border_width(0.0)
                .color(sidebar_color[0], sidebar_color[1], sidebar_color[2])
                .alpha(sidebar_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .origin_position(0.0, top_bar_h)
                        .origin_size(left_w, window_h - top_bar_h),
                ),
        );
        self.graphician.add_text(
            "main_rooms_title",
            TextConfig::default()
                .content(&rooms_label)
                .font_size(16.0)
                .color(text_color[0], text_color[1], text_color[2])
                .alpha(text_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .origin_position(10.0, top_bar_h + 8.0)
                        .origin_size(100.0, 24.0),
                ),
        );

        // --- Create mode switches ---
        let create_row_y = top_bar_h + 36.0;
        self.build_image_switch(
            "main_create_group",
            PositionSizeConfig::default()
                .origin_position(10.0, create_row_y)
                .origin_size(38.0, 38.0),
            "add_chat_group",
        );
        self.build_image_switch(
            "main_create_private",
            PositionSizeConfig::default()
                .origin_position(54.0, create_row_y)
                .origin_size(38.0, 38.0),
            "add_private_chat",
        );

        // --- Create input area (egui) when a mode is active ---
        if create_mode != CreateMode::None {
            let input_y = create_row_y + 36.0;
            let input_width = 120.0;
            egui::Area::new(Id::new("MainCreateInputArea"))
                .fixed_pos(Pos2::new(10.0, input_y))
                .show(ui.ctx(), |ui| {
                    let interactive = self
                        .graphician
                        .get_variable::<Option<String>>("notice")
                        .unwrap()
                        .is_none();
                    if create_mode == CreateMode::Group {
                        ui.horizontal(|ui| {
                            let mut guard = state.lock().unwrap();
                            ui.add(
                                TextEdit::singleline(&mut guard.create_group_name)
                                    .hint_text(create_group_hint.clone())
                                    .desired_width(input_width)
                                    .interactive(interactive),
                            );
                        });
                        ui.horizontal(|ui| {
                            let mut guard = state.lock().unwrap();
                            ui.add(
                                TextEdit::singleline(&mut guard.create_group_members)
                                    .hint_text(create_group_members_hint.clone())
                                    .desired_width(input_width)
                                    .interactive(interactive),
                            );
                        });
                    } else {
                        ui.horizontal(|ui| {
                            let mut guard = state.lock().unwrap();
                            ui.add(
                                TextEdit::singleline(&mut guard.private_chat_username)
                                    .hint_text(private_chat_username_hint.clone())
                                    .desired_width(input_width)
                                    .interactive(interactive),
                            );
                        });
                    }
                });
            self.build_image_switch(
                "main_confirm_create",
                PositionSizeConfig::default()
                    .origin_position(140.0, input_y)
                    .origin_size(34.0, 34.0),
                "confirm",
            );
        }

        // --- Rooms panel (ResourcePanel with Text children) ---
        // Fixed position below the create input area so the panel's persisted
        // position_size_override never overlaps the input boxes.
        let rooms_panel_y = top_bar_h + 155.0;
        let rooms_panel_h = (window_h - top_bar_h) - rooms_panel_y;
        let room_item_h = 30.0;
        let room_panel_name = "main_rooms_panel";
        self.graphician.add_resource_panel(
            room_panel_name,
            ResourcePanelConfig::default()
                .background(BackgroundType::CustomRect(
                    CustomRectConfig::default()
                        .border_width(0.0)
                        .color(
                            background_color[0],
                            background_color[1],
                            background_color[2],
                        )
                        .alpha(0)
                        .position_size_config(
                            PositionSizeConfig::default()
                                .origin_position(0.0, rooms_panel_y)
                                .origin_size(left_w, rooms_panel_h),
                        ),
                ))
                .movable(false, false)
                .resizable(false, false, false, false)
                .scroll_length_method(None, Some(ScrollLengthMethod::AutoFit(0.0)))
                .scroll_sensitivity(1.0)
                .scroll_bar_display_method(ScrollBarDisplayMethod::Hidden)
                .overall_layout(PanelLayout {
                    panel_margin: PanelMargin::None([4.0, 4.0, 4.0, 4.0], false),
                    panel_location: PanelLocation::Absolute([0.0, 0.0]),
                })
                .raise_on_focus(false),
        );
        for (index, room) in rooms.iter().enumerate() {
            let label = if let Some(name) = &room.name {
                name.clone()
            } else if let Some(peer) = dm_names.get(&room.id) {
                format!("(DM) {peer}")
            } else {
                format!("(DM) {}", room.id.chars().take(8).collect::<String>())
            };
            let label = if room.is_encrypted {
                format!("🔒 {label}")
            } else {
                label
            };
            let is_selected = selected_room_id.as_ref() == Some(&room.id);
            let item_color = if is_selected {
                [120, 200, 255]
            } else {
                text_color
            };
            self.graphician.add_element(
                ElementEntry::new(
                    &format!("room_{}", room.id),
                    Element::Text(
                        TextConfig::default()
                            .content(&label)
                            .font_size(14.0)
                            .color(item_color[0], item_color[1], item_color[2])
                            .alpha(text_alpha)
                            .position_size_config(
                                PositionSizeConfig::default()
                                    .origin_position(0.0, index as f32 * room_item_h)
                                    .origin_size(left_w - 4.0, room_item_h),
                            ),
                    ),
                )
                .tags(
                    &[["panel_name".to_string(), room_panel_name.to_string()]],
                    false,
                ),
            );
        }

        // --- Central area background ---
        let central_x = left_w;
        let central_w = window_w - left_w;
        self.graphician.add_custom_rect(
            "main_central_bg",
            CustomRectConfig::default()
                .border_width(0.0)
                .color(
                    background_color[0],
                    background_color[1],
                    background_color[2],
                )
                .alpha(background_alpha)
                .position_size_config(
                    PositionSizeConfig::default()
                        .origin_position(central_x, top_bar_h)
                        .origin_size(central_w, window_h - top_bar_h),
                ),
        );

        let selected_room = rooms
            .iter()
            .find(|room| Some(&room.id) == selected_room_id.as_ref())
            .cloned();

        if let Some(room) = &selected_room {
            let is_group = room.is_group;
            let header_h = 40.0;
            self.graphician.add_custom_rect(
                "main_header_bg",
                CustomRectConfig::default()
                    .border_width(0.0)
                    .color(header_color[0], header_color[1], header_color[2])
                    .alpha(header_alpha)
                    .position_size_config(
                        PositionSizeConfig::default()
                            .origin_position(central_x, top_bar_h)
                            .origin_size(central_w, header_h),
                    ),
            );
            let room_title = if let Some(name) = &room.name {
                name.clone()
            } else if let Some(peer) = dm_names.get(&room.id) {
                peer.clone()
            } else {
                room.id.clone()
            };
            self.graphician.add_text(
                "main_room_title",
                TextConfig::default()
                    .content(&room_title)
                    .font_size(18.0)
                    .color(text_color[0], text_color[1], text_color[2])
                    .alpha(text_alpha)
                    .position_size_config(
                        PositionSizeConfig::default()
                            .origin_position(central_x + 10.0, top_bar_h + 8.0)
                            .origin_size(central_w - 320.0, 24.0),
                    ),
            );

            // --- Header action switches (top-right) ---
            let header_y = top_bar_h + 4.0;
            let mut header_button_x = central_x + central_w - 60.0;
            if is_group {
                header_button_x -= 86.0;
                self.build_rect_switch(
                    "main_leave_room",
                    PositionSizeConfig::default()
                        .origin_position(header_button_x, header_y)
                        .origin_size(80.0, 30.0),
                    &leave_room_label,
                );
            }
            header_button_x -= 86.0;
            self.build_rect_switch(
                "main_load_older",
                PositionSizeConfig::default()
                    .origin_position(header_button_x, header_y)
                    .origin_size(80.0, 30.0),
                &load_older_label,
            );
            header_button_x -= 96.0;
            self.build_image_switch(
                "main_refresh_rooms",
                PositionSizeConfig::default()
                    .origin_position(header_button_x, header_y)
                    .origin_size(34.0, 34.0),
                "refresh",
            );

            if !is_group && room.is_encrypted {
                let session = encryption_sessions
                    .get(&room.id)
                    .map(|session| session.phase);
                header_button_x -= 106.0;
                match session {
                    None => {
                        self.build_rect_switch(
                            "main_start_encrypt",
                            PositionSizeConfig::default()
                                .origin_position(header_button_x, header_y)
                                .origin_size(100.0, 30.0),
                            &start_encryption_label,
                        );
                    }
                    Some(SessionPhase::AwaitingAccept) => {
                        self.graphician.add_text(
                            "main_encrypt_status",
                            TextConfig::default()
                                .content(&waiting_accept_label)
                                .font_size(12.0)
                                .color(text_color[0], text_color[1], text_color[2])
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(header_button_x, header_y)
                                        .origin_size(120.0, 24.0),
                                ),
                        );
                    }
                    Some(SessionPhase::AwaitingReady) => {
                        self.build_rect_switch(
                            "main_accept_encrypt",
                            PositionSizeConfig::default()
                                .origin_position(header_button_x, header_y)
                                .origin_size(100.0, 30.0),
                            &accept_encryption_label,
                        );
                    }
                    Some(SessionPhase::Active) => {
                        self.graphician.add_text(
                            "main_encrypt_status",
                            TextConfig::default()
                                .content(&encryption_active_label)
                                .font_size(12.0)
                                .color(text_color[0], text_color[1], text_color[2])
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(header_button_x, header_y)
                                        .origin_size(100.0, 24.0),
                                ),
                        );
                        self.build_rect_switch(
                            "main_end_encrypt",
                            PositionSizeConfig::default()
                                .origin_position(header_button_x + 106.0, header_y)
                                .origin_size(100.0, 30.0),
                            &end_encryption_label,
                        );
                    }
                    Some(SessionPhase::Ended) => {
                        self.graphician.add_text(
                            "main_encrypt_status",
                            TextConfig::default()
                                .content(&encryption_ended_label)
                                .font_size(12.0)
                                .color(text_color[0], text_color[1], text_color[2])
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(header_button_x, header_y)
                                        .origin_size(100.0, 24.0),
                                ),
                        );
                    }
                }
            }

            // --- Member column (right side, groups only) ---
            let member_col_w = 190.0;
            let message_w = if is_group {
                central_w - member_col_w - 30.0
            } else {
                central_w - 30.0
            };

            if is_group {
                let members = room_members.get(&room.id);
                let member_count = members.map(|m| m.len()).unwrap_or(room.members.len());
                let member_col_x = central_x + central_w - member_col_w - 10.0;
                let member_col_y = top_bar_h + 44.0;
                let member_col_bottom = window_h - 40.0;
                self.graphician.add_custom_rect(
                    "main_member_bg",
                    CustomRectConfig::default()
                        .border_width(0.0)
                        .color(member_bg_color[0], member_bg_color[1], member_bg_color[2])
                        .alpha(member_bg_alpha)
                        .position_size_config(
                            PositionSizeConfig::default()
                                .origin_position(member_col_x, member_col_y)
                                .origin_size(member_col_w, member_col_bottom - member_col_y),
                        ),
                );
                let title = format!("{member_label} ({member_count})");
                self.graphician.add_text(
                    "main_member_title",
                    TextConfig::default()
                        .content(&title)
                        .font_size(13.0)
                        .color(text_color[0], text_color[1], text_color[2])
                        .alpha(text_alpha)
                        .position_size_config(
                            PositionSizeConfig::default()
                                .origin_position(member_col_x, member_col_y)
                                .origin_size(150.0, 20.0),
                        ),
                );
                let mut member_y = top_bar_h + 70.0;
                if let Some(members) = members {
                    for member in members {
                        let is_self = current_user_id.as_ref() == Some(&member.user_id);
                        let online_mark = if online_user_ids.contains(&member.user_id) {
                            "🟢"
                        } else {
                            "⚪"
                        };
                        let role_mark = if member.role == "admin" {
                            format!(" [{}]", role_admin_label)
                        } else {
                            String::new()
                        };
                        let name_text = format!("{online_mark} {}{role_mark}", member.username);
                        self.graphician.add_text(
                            &format!("main_member_{}", member.user_id),
                            TextConfig::default()
                                .content(&name_text)
                                .font_size(13.0)
                                .auto_fit(false, false)
                                .color(text_color[0], text_color[1], text_color[2])
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(member_col_x, member_y)
                                        .origin_size(130.0, 26.0),
                                ),
                        );
                        if !is_self {
                            self.build_image_switch(
                                &format!("main_kick_{}", member.user_id),
                                PositionSizeConfig::default()
                                    .origin_position(member_col_x + 135.0, member_y)
                                    .origin_size(26.0, 26.0),
                                "exit",
                            );
                        }
                        member_y += 32.0;
                    }
                }
                // Add-member input + switch on separate rows at the bottom of the column
                let add_input_y = window_h - 116.0;
                egui::Area::new(Id::new("MainAddMemberArea"))
                    .fixed_pos(Pos2::new(member_col_x, add_input_y))
                    .show(ui.ctx(), |ui| {
                        let interactive = self
                            .graphician
                            .get_variable::<Option<String>>("notice")
                            .unwrap()
                            .is_none();
                        let mut guard = state.lock().unwrap();
                        ui.add(
                            TextEdit::singleline(&mut guard.add_member_usernames)
                                .hint_text(add_member_hint.clone())
                                .desired_width(160.0)
                                .interactive(interactive),
                        );
                    });
                self.build_rect_switch(
                    "main_add_members",
                    PositionSizeConfig::default()
                        .origin_position(member_col_x, add_input_y + 32.0)
                        .origin_size(90.0, 26.0),
                    &add_members_label,
                );
            }

            // --- Message panel (ResourcePanel with Text children) ---
            // Keep the panel well above the message input area so the last
            // message row is never covered by the egui TextEdit below.
            let msg_panel_y = top_bar_h + 44.0;
            let msg_panel_h = window_h - msg_panel_y - 64.0;
            let msg_panel_w = message_w;
            let msg_panel_name = "main_messages_panel";
            self.graphician.add_resource_panel(
                msg_panel_name,
                ResourcePanelConfig::default()
                    .background(BackgroundType::CustomRect(
                        CustomRectConfig::default()
                            .border_width(0.0)
                            .color(
                                background_color[0],
                                background_color[1],
                                background_color[2],
                            )
                            .alpha(0)
                            .position_size_config(
                                PositionSizeConfig::default()
                                    .origin_position(central_x + 10.0, msg_panel_y)
                                    .origin_size(msg_panel_w, msg_panel_h),
                            ),
                    ))
                    .movable(false, false)
                    .resizable(false, false, false, false)
                    .scroll_length_method(None, Some(ScrollLengthMethod::AutoFit(0.0)))
                    .scroll_sensitivity(1.0)
                    .scroll_bar_display_method(ScrollBarDisplayMethod::Hidden)
                    .overall_layout(PanelLayout {
                        panel_margin: PanelMargin::None([4.0, 4.0, 4.0, 4.0], false),
                        panel_location: PanelLocation::Absolute([0.0, 0.0]),
                    })
                    .raise_on_focus(false),
            );

            let typing_names: Vec<String> = typing_room_members
                .get(&room.id)
                .map(|members| {
                    members
                        .iter()
                        .filter_map(|user_id| {
                            room_members
                                .get(&room.id)
                                .and_then(|list| {
                                    list.iter().find(|member| member.user_id == *user_id)
                                })
                                .map(|member| member.username.clone())
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mut msg_y = 0.0;
            if has_older_messages {
                self.graphician.add_element(
                    ElementEntry::new(
                        "main_load_older_hint",
                        Element::Text(
                            TextConfig::default()
                                .content(&load_older_label)
                                .font_size(13.0)
                                .color(text_color[0], text_color[1], text_color[2])
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(0.0, msg_y)
                                        .origin_size(msg_panel_w, 24.0),
                                ),
                        ),
                    )
                    .tags(
                        &[["panel_name".to_string(), msg_panel_name.to_string()]],
                        false,
                    ),
                );
                msg_y += 26.0;
            }
            for message in &message_records {
                let is_mine = current_user_id.as_ref() == Some(&message.sender_id);
                let time = format_message_time(&message.created_at);
                let sender_name = if is_group {
                    room_members
                        .get(&room.id)
                        .and_then(|members| {
                            members
                                .iter()
                                .find(|member| member.user_id == message.sender_id)
                        })
                        .map(|member| member.username.clone())
                        .unwrap_or_else(|| message.sender_id.chars().take(8).collect())
                } else if let Some(peer) = dm_names.get(&room.id) {
                    if is_mine { String::new() } else { peer.clone() }
                } else {
                    String::new()
                };
                let body = message.content.clone().unwrap_or_default();
                let sender_part = if sender_name.is_empty() {
                    String::new()
                } else {
                    format!("{sender_name}: ")
                };
                let line = format!("[{time}] {sender_part}{body}");
                let line_color = if is_mine { text_color } else { [180, 180, 180] };
                self.graphician.add_element(
                    ElementEntry::new(
                        &format!("main_msg_{}", message.id),
                        Element::Text(
                            TextConfig::default()
                                .content(&line)
                                .font_size(13.0)
                                .color(line_color[0], line_color[1], line_color[2])
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(0.0, msg_y)
                                        .origin_size(msg_panel_w, 22.0),
                                ),
                        ),
                    )
                    .tags(
                        &[["panel_name".to_string(), msg_panel_name.to_string()]],
                        false,
                    ),
                );
                msg_y += 24.0;
            }
            if !typing_names.is_empty() {
                let typing_line = format!("{} {is_typing_text}", typing_names.join(", "));
                self.graphician.add_element(
                    ElementEntry::new(
                        "main_typing_hint",
                        Element::Text(
                            TextConfig::default()
                                .content(&typing_line)
                                .font_size(12.0)
                                .color(120, 200, 255)
                                .alpha(text_alpha)
                                .position_size_config(
                                    PositionSizeConfig::default()
                                        .origin_position(0.0, msg_y)
                                        .origin_size(msg_panel_w, 20.0),
                                ),
                        ),
                    )
                    .tags(
                        &[["panel_name".to_string(), msg_panel_name.to_string()]],
                        false,
                    ),
                );
            }

            // --- Message input area (egui) + send switch ---
            let input_y = window_h - 44.0;
            let input_width = message_w - 70.0;
            egui::Area::new(Id::new("MainMessageInputArea"))
                .fixed_pos(Pos2::new(central_x + 10.0, input_y))
                .show(ui.ctx(), |ui| {
                    let interactive = self
                        .graphician
                        .get_variable::<Option<String>>("notice")
                        .unwrap()
                        .is_none();
                    let mut guard = state.lock().unwrap();
                    let edit = TextEdit::singleline(&mut guard.message_input)
                        .hint_text(message_hint.clone())
                        .desired_width(input_width)
                        .interactive(interactive);
                    let response = ui.add(edit);
                    if interactive && response.changed() {
                        let room_id = guard.selected_room_id.clone();
                        if let Some(room_id) = room_id {
                            let frame = serde_json::json!({
                                "type": "typing",
                                "room_id": room_id,
                            })
                            .to_string();
                            let now = std::time::Instant::now();
                            let should_send = guard
                                .typing_last_sent
                                .get(&room_id)
                                .map(|last| now.duration_since(*last).as_secs() >= 2)
                                .unwrap_or(true);
                            if should_send {
                                guard.typing_last_sent.insert(room_id, now);
                                send_websocket_frame(&guard, frame);
                            }
                        }
                    }
                });
            self.build_image_switch(
                "main_send",
                PositionSizeConfig::default()
                    .origin_position(central_x + 10.0 + input_width + 10.0, input_y)
                    .origin_size(34.0, 34.0),
                "proceed",
            );
        } else {
            self.graphician.add_text(
                "main_no_room",
                TextConfig::default()
                    .content(&server_status)
                    .font_size(14.0)
                    .color(text_color[0], text_color[1], text_color[2])
                    .alpha(text_alpha)
                    .position_size_config(
                        PositionSizeConfig::default()
                            .origin_position(central_x + 20.0, top_bar_h + 40.0)
                            .origin_size(300.0, 24.0),
                    ),
            );
        }
    }

    fn reconnect_websocket(state: Arc<Mutex<AppState>>, context: Context) {
        let token = state.lock().unwrap().token.clone();
        if let Some(token) = token {
            {
                let mut guard = state.lock().unwrap();
                guard.ws_epoch += 1;
                guard.ws_connected = false;
                guard.ws_tx = None;
            }
            network::spawn_websocket_thread(token, state, context);
        }
    }

    fn refresh_rooms(state: Arc<Mutex<AppState>>, context: Context) {
        let token = state.lock().unwrap().token.clone();
        if let Some(token) = token {
            let state = state.clone();
            std::thread::spawn(move || {
                if let Ok(rooms) = Self::client_for(&state).list_rooms(&token) {
                    state.lock().unwrap().rooms = rooms;
                }
                context.request_repaint();
            });
        }
    }

    fn client_for(state: &Arc<Mutex<AppState>>) -> network::HttpClient {
        let server_address = state.lock().unwrap().server_address.clone();
        network::HttpClient::new_with_base_url(&server_address)
    }

    fn spawn_login(
        state: Arc<Mutex<AppState>>,
        context: Context,
        username: String,
        password: String,
    ) {
        std::thread::spawn(move || {
            match Self::client_for(&state).login(&LoginRequest { username, password }) {
                Ok(data) => {
                    let token = data.token;
                    let user = data.user;
                    {
                        let mut guard = state.lock().unwrap();
                        guard.token = Some(token.clone());
                        guard.current_user = Some(user);
                        guard.pending_page = Some(Page::Main);
                    }
                    network::spawn_websocket_thread(token, state.clone(), context.clone());
                }
                Err(error) => {
                    state.lock().unwrap().notice = Some(format!("{error}"));
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_register(
        state: Arc<Mutex<AppState>>,
        context: Context,
        username: String,
        password: String,
        email: String,
    ) {
        std::thread::spawn(move || {
            match Self::client_for(&state).register(&RegisterRequest {
                username,
                email,
                password,
            }) {
                Ok(_) => {
                    let mut guard = state.lock().unwrap();
                    guard.pending_page = Some(Page::Login);
                    guard.notice = Some("Registered successfully. Please login.".to_string());
                }
                Err(error) => {
                    state.lock().unwrap().notice = Some(format!("{error}"));
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_logout(state: Arc<Mutex<AppState>>, context: Context) {
        std::thread::spawn(move || {
            let mut guard = state.lock().unwrap();
            guard.token = None;
            guard.current_user = None;
            guard.ws_connected = false;
            guard.ws_tx = None;
            guard.ws_epoch += 1;
            guard.rooms.clear();
            guard.room_members.clear();
            guard.dm_peer_usernames.clear();
            guard.selected_room_id = None;
            guard.messages.clear();
            guard.encryption_sessions.clear();
            guard.pending_page = Some(Page::Login);
            drop(guard);
            context.request_repaint();
        });
    }

    fn spawn_fetch_rooms(state: Arc<Mutex<AppState>>, context: Context, token: String) {
        std::thread::spawn(move || {
            match Self::client_for(&state).list_rooms(&token) {
                Ok(rooms) => {
                    let user = state.lock().unwrap().current_user.clone();
                    {
                        let mut guard = state.lock().unwrap();
                        guard.rooms = rooms.clone();
                    }
                    if let Some(user) = user {
                        for room in &rooms {
                            if !room.is_group {
                                if let Ok(members) =
                                    Self::client_for(&state).get_members(&token, &room.id)
                                {
                                    let peer = members
                                        .iter()
                                        .find(|member| member.user_id != user.id)
                                        .map(|member| member.username.clone())
                                        .unwrap_or_default();
                                    state
                                        .lock()
                                        .unwrap()
                                        .dm_peer_usernames
                                        .insert(room.id.clone(), peer);
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    state.lock().unwrap().notice = Some(format!("{error}"));
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_fetch_messages(state: Arc<Mutex<AppState>>, context: Context, room_id: String) {
        std::thread::spawn(move || {
            let token = state.lock().unwrap().token.clone();
            if let Some(token) = token {
                if let Ok(mut messages) =
                    Self::client_for(&state).get_messages(&token, &room_id, 100)
                {
                    // Server returns newest-first; store oldest-first for chat display.
                    messages.reverse();
                    let mut guard = state.lock().unwrap();
                    if guard.selected_room_id.as_ref() == Some(&room_id) {
                        guard.messages = messages;
                        guard.has_older_messages = guard.messages.len() >= 100;
                    }
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_fetch_older_messages(state: Arc<Mutex<AppState>>, context: Context, room_id: String) {
        std::thread::spawn(move || {
            let token = state.lock().unwrap().token.clone();
            // Messages are stored oldest-first; the oldest is the first element.
            let oldest_id = state.lock().unwrap().messages.first().map(|m| m.id.clone());
            if let (Some(token), Some(oldest_id)) = (token, oldest_id) {
                if let Ok(mut older) =
                    Self::client_for(&state).get_messages_before(&token, &room_id, &oldest_id, 50)
                {
                    older.reverse();
                    let older_len = older.len();
                    let mut guard = state.lock().unwrap();
                    if guard.selected_room_id.as_ref() == Some(&room_id) {
                        let mut merged = older;
                        merged.extend(guard.messages.clone());
                        guard.messages = merged;
                        guard.has_older_messages = older_len >= 50;
                    }
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_fetch_users(state: Arc<Mutex<AppState>>, context: Context, token: String) {
        std::thread::spawn(move || {
            if let Ok(users) = Self::client_for(&state).list_users(&token) {
                state.lock().unwrap().users = users;
            }
            context.request_repaint();
        });
    }

    fn spawn_fetch_room_detail(
        state: Arc<Mutex<AppState>>,
        context: Context,
        token: String,
        room_id: String,
    ) {
        std::thread::spawn(move || {
            if let Ok(detail) = Self::client_for(&state).get_room_detail(&token, &room_id) {
                let mut guard = state.lock().unwrap();
                guard.room_members.insert(
                    room_id,
                    detail
                        .members
                        .iter()
                        .map(|member| MemberInfo {
                            user_id: member.user_id.clone(),
                            username: member.username.clone(),
                            role: member.role.clone(),
                        })
                        .collect(),
                );
            }
            context.request_repaint();
        });
    }

    fn spawn_create_private_chat(
        state: Arc<Mutex<AppState>>,
        context: Context,
        token: String,
        username: String,
    ) {
        std::thread::spawn(move || {
            match Self::client_for(&state).create_room(
                &token,
                &CreateRoomRequest {
                    username: Some(username),
                    name: None,
                    usernames: None,
                    is_group: false,
                },
            ) {
                Ok(_) => {
                    Self::refresh_rooms(state.clone(), context.clone());
                    Self::reconnect_websocket(state.clone(), context.clone());
                }
                Err(error) => {
                    state.lock().unwrap().notice = Some(format!("{error}"));
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_fetch_members(state: Arc<Mutex<AppState>>, context: Context, room_id: String) {
        std::thread::spawn(move || {
            let token = state.lock().unwrap().token.clone();
            if let Some(token) = token {
                if let Ok(members) = Self::client_for(&state).get_members(&token, &room_id) {
                    state
                        .lock()
                        .unwrap()
                        .room_members
                        .insert(room_id.clone(), members);
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_create_group(
        state: Arc<Mutex<AppState>>,
        context: Context,
        token: String,
        name: String,
        members: String,
    ) {
        std::thread::spawn(move || {
            let usernames: Vec<String> = members
                .split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect();
            let name = if name.trim().is_empty() {
                None
            } else {
                Some(name.trim().to_string())
            };
            match Self::client_for(&state).create_room(
                &token,
                &CreateRoomRequest {
                    username: None,
                    name,
                    usernames: Some(usernames),
                    is_group: true,
                },
            ) {
                Ok(_) => {
                    Self::refresh_rooms(state.clone(), context.clone());
                    Self::reconnect_websocket(state.clone(), context.clone());
                }
                Err(error) => {
                    state.lock().unwrap().notice = Some(format!("{error}"));
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_add_members(
        state: Arc<Mutex<AppState>>,
        context: Context,
        token: String,
        room_id: String,
        usernames: String,
    ) {
        std::thread::spawn(move || {
            let usernames: Vec<String> = usernames
                .split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect();
            match Self::client_for(&state).add_members(&token, &room_id, &usernames) {
                Ok(_) => {
                    if let Ok(members) = Self::client_for(&state).get_members(&token, &room_id) {
                        state
                            .lock()
                            .unwrap()
                            .room_members
                            .insert(room_id.clone(), members);
                    }
                }
                Err(error) => {
                    state.lock().unwrap().notice = Some(format!("{error}"));
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_remove_member(
        state: Arc<Mutex<AppState>>,
        context: Context,
        token: String,
        room_id: String,
        user_id: String,
    ) {
        std::thread::spawn(move || {
            match Self::client_for(&state).remove_member(&token, &room_id, &user_id) {
                Ok(result) => {
                    let is_self_leave = state
                        .lock()
                        .unwrap()
                        .current_user
                        .as_ref()
                        .is_some_and(|user| user.id == user_id);
                    if is_self_leave {
                        let mut guard = state.lock().unwrap();
                        guard.rooms.retain(|room| room.id != room_id);
                        if guard.selected_room_id.as_deref() == Some(&room_id) {
                            guard.selected_room_id = None;
                            guard.messages.clear();
                            guard.room_members.remove(&room_id);
                        }
                        drop(guard);
                    } else if !result.room_deleted
                        && let Ok(members) = Self::client_for(&state).get_members(&token, &room_id)
                    {
                        state
                            .lock()
                            .unwrap()
                            .room_members
                            .insert(room_id.clone(), members);
                    }
                }
                Err(error) => {
                    let mut guard = state.lock().unwrap();
                    guard.notice = Some(format!("{error}"));
                    drop(guard);
                    if let Ok(members) = Self::client_for(&state).get_members(&token, &room_id) {
                        state.lock().unwrap().room_members.insert(room_id, members);
                    }
                }
            }
            context.request_repaint();
        });
    }

    fn spawn_start_encryption(state: Arc<Mutex<AppState>>, context: Context, room_id: String) {
        std::thread::spawn(move || {
            let (my_identity_public, my_identity_private) = encryption::generate_identity_keypair();
            let (my_public, my_private) = encryption::generate_ephemeral_keypair();
            let signature = encryption::sign_public_key(&my_identity_private, &my_public);

            let mut session = EncryptionSession::new(room_id.clone());
            session.is_initiator = true;
            session.my_ephemeral_private = Some(my_private);

            let sender = {
                let mut guard = state.lock().unwrap();
                guard.encryption_sessions.insert(room_id.clone(), session);
                guard.ws_tx.clone()
            };
            if let Some(sender) = sender {
                let frame = serde_json::json!({
                    "type": "encrypt_request",
                    "data": {
                        "room_id": room_id.clone(),
                        "public_key": base64_engine.encode(my_public),
                        "identity_key": base64_engine.encode(my_identity_public),
                        "signature": base64_engine.encode(signature),
                    }
                })
                .to_string();
                let _ = sender.send(frame);
            }
            Self::refresh_rooms(state.clone(), context.clone());
            context.request_repaint();
        });
    }

    fn accept_encryption(state: Arc<Mutex<AppState>>, context: Context, room_id: String) {
        let (session_data, sender) = {
            let guard = state.lock().unwrap();
            let session = guard.encryption_sessions.get(&room_id).cloned();
            let sender = guard.ws_tx.clone();
            (session, sender)
        };
        let Some(session) = session_data else {
            context.request_repaint();
            return;
        };
        let Some(peer_public) = session.peer_public else {
            context.request_repaint();
            return;
        };

        let (my_identity_public, my_identity_private) = encryption::generate_identity_keypair();
        let (my_public, my_private) = encryption::generate_ephemeral_keypair();
        let signature = encryption::sign_public_key(&my_identity_private, &my_public);
        let shared_secret = encryption::derive_shared_secret(&my_private, &peer_public);
        let session_key = encryption::derive_session_key(&shared_secret);

        {
            let mut guard = state.lock().unwrap();
            if let Some(session) = guard.encryption_sessions.get_mut(&room_id) {
                session.phase = SessionPhase::AwaitingReady;
                session.my_ephemeral_private = Some(my_private);
                session.session_key = Some(session_key);
            }
        }

        if let Some(sender) = sender {
            let accept_frame = serde_json::json!({
                "type": "encrypt_accept",
                "data": {
                    "room_id": room_id.clone(),
                    "public_key": base64_engine.encode(my_public),
                    "identity_key": base64_engine.encode(my_identity_public),
                    "signature": base64_engine.encode(signature),
                }
            })
            .to_string();
            let _ = sender.send(accept_frame);
            let ready_frame = serde_json::json!({
                "type": "encrypt_ready",
                "data": { "room_id": room_id },
            })
            .to_string();
            let _ = sender.send(ready_frame);
        }
        Self::refresh_rooms(state.clone(), context.clone());
        context.request_repaint();
    }

    fn leave_encryption(state: Arc<Mutex<AppState>>, room_id: String) {
        let sender = state.lock().unwrap().ws_tx.clone();
        if let Some(sender) = sender {
            let frame = serde_json::json!({
                "type": "encrypt_leave",
                "data": { "room_id": room_id },
            })
            .to_string();
            let _ = sender.send(frame);
        }
    }

    fn handle_auth_switches(&mut self) {
        let pressed = |state: Option<&SwitchState>| {
            state
                .map(|switch_state| switch_state.last_frame_clicked.is_some())
                .unwrap_or(false)
        };
        let hovered = |state: Option<&SwitchState>| {
            state
                .map(|switch_state| switch_state.last_frame_hovered)
                .unwrap_or(false)
        };
        let released = |prev_pressed: bool, state: Option<&SwitchState>| {
            prev_pressed && !pressed(state) && hovered(state)
        };

        let login_state = self.graphician.switch_states.get("LoginSwitch");
        let register_state = self.graphician.switch_states.get("RegisterSwitch");
        let back_state = self.graphician.switch_states.get("BackSwitch");
        let confirm_state = self.graphician.switch_states.get("ConfirmSwitch");
        let exit_state = self.graphician.switch_states.get("ExitSwitch");

        if released(self.login_prev_pressed, login_state) && self.page == Page::Login {
            let username = self.login_username.clone();
            let password = self.login_password.clone();
            if username.is_empty() || password.is_empty() {
                self.state.lock().unwrap().notice = Some(self.get_language_text("fields_required"));
            } else {
                Self::spawn_login(self.state.clone(), self.context.clone(), username, password);
            }
        }
        self.login_prev_pressed = pressed(login_state);

        if released(self.register_prev_pressed, register_state) && self.page == Page::Login {
            self.page = Page::Register;
        }
        self.register_prev_pressed = pressed(register_state);

        if released(self.back_prev_pressed, back_state) && self.page == Page::Register {
            self.page = Page::Login;
        }
        self.back_prev_pressed = pressed(back_state);

        if released(self.confirm_prev_pressed, confirm_state) && self.page == Page::Register {
            let username = self.register_username.clone();
            let password = self.register_password.clone();
            let email = self.register_email.clone();
            if username.is_empty() || password.is_empty() || email.is_empty() {
                self.state.lock().unwrap().notice = Some(self.get_language_text("fields_required"));
            } else {
                Self::spawn_register(
                    self.state.clone(),
                    self.context.clone(),
                    username,
                    password,
                    email,
                );
            }
        }
        self.confirm_prev_pressed = pressed(confirm_state);

        if released(self.exit_prev_pressed, exit_state) {
            exit(0);
        }
        self.exit_prev_pressed = pressed(exit_state);
    }

    fn build_overlay_notice(&mut self) {
        let notice_message = self
            .graphician
            .get_variable::<Option<String>>("notice")
            .and_then(|notice| notice.clone());
        if let Some(notice_message) = notice_message {
            let overlay_color = self.get_theme_color("notice_overlay_color");
            let overlay_alpha = self.get_theme_alpha("notice_overlay_alpha");
            self.graphician.add_element(
                ElementEntry::new(
                    "notice_overlay",
                    Element::CustomRect(
                        CustomRectConfig::default()
                            .border_width(0.0)
                            .color(overlay_color[0], overlay_color[1], overlay_color[2])
                            .alpha(overlay_alpha)
                            .position_size_config(
                                PositionSizeConfig::default()
                                    .x_size_grid(1.0, 1.0)
                                    .y_size_grid(1.0, 1.0),
                            ),
                    ),
                )
                .tags(
                    &[["render_layer".to_string(), "foreground".to_string()]],
                    false,
                ),
            );

            let content_rect = self.context.content_rect();
            let panel_size = [content_rect.width() * 0.5, content_rect.height() * 0.5];
            let margin = 16.0;
            let close_size = 40.0;
            let title_height = 30.0;
            let body_gap = 8.0;

            let panel_color = self.get_theme_color("notice_panel_color");
            let panel_alpha = self.get_theme_alpha("notice_panel_alpha");
            let title_color = self.get_theme_color("notice_title_color");
            let title_alpha = self.get_theme_alpha("notice_title_alpha");
            let text_color = self.get_theme_color("notice_text_color");
            let text_alpha = self.get_theme_alpha("notice_text_alpha");
            let notice_title = self.get_language_text("notice_title");
            let close_path = self.get_theme_image("close");

            let title_pos = PositionSizeConfig::default()
                .origin_position(margin, margin)
                .origin_size(panel_size[0] - close_size - margin * 2.0, title_height);
            self.graphician.add_element(
                ElementEntry::new(
                    "notice_title",
                    Element::Text(
                        TextConfig::default()
                            .content(&notice_title)
                            .font_size(18.0)
                            .color(title_color[0], title_color[1], title_color[2])
                            .alpha(title_alpha)
                            .position_size_config(title_pos),
                    ),
                )
                .tags(
                    &[
                        ["panel_name".to_string(), "notice".to_string()],
                        ["disable_y_scrolling".to_string(), String::new()],
                    ],
                    false,
                ),
            );

            let close_pos = PositionSizeConfig::default()
                .origin_position(panel_size[0] - close_size - margin, margin)
                .origin_size(close_size, close_size);
            self.graphician.add_element(
                ElementEntry::new(
                    "notice_close",
                    Element::Image(
                        ImageConfig::default()
                            .position_size_config(close_pos)
                            .image_load_method(ImageLoadMethod::ByPath(close_path, [false, false])),
                    ),
                )
                .tags(
                    &[
                        ["panel_name".to_string(), "notice".to_string()],
                        ["disable_y_scrolling".to_string(), String::new()],
                    ],
                    false,
                ),
            );

            let body_pos = PositionSizeConfig::default()
                .origin_position(margin, margin + title_height + body_gap)
                .origin_size(
                    panel_size[0] - margin * 2.0,
                    panel_size[1] - margin * 2.0 - title_height - body_gap,
                );
            self.graphician.add_element(
                ElementEntry::new(
                    "notice_body",
                    Element::Text(
                        TextConfig::default()
                            .content(&notice_message)
                            .font_size(14.0)
                            .color(text_color[0], text_color[1], text_color[2])
                            .alpha(text_alpha)
                            .position_size_config(body_pos),
                    ),
                )
                .tags(&[["panel_name".to_string(), "notice".to_string()]], false),
            );

            self.graphician.add_element(
                ElementEntry::new(
                    "notice",
                    Element::ResourcePanel(Box::new(
                        ResourcePanelConfig::default()
                            .background(BackgroundType::CustomRect(
                                CustomRectConfig::default()
                                    .border_width(0.0)
                                    .color(panel_color[0], panel_color[1], panel_color[2])
                                    .alpha(panel_alpha)
                                    .position_size_config(
                                        PositionSizeConfig::default()
                                            .x_location_grid(1.0, 2.0)
                                            .y_location_grid(1.0, 2.0)
                                            .x_size_grid(1.0, 2.0)
                                            .y_size_grid(1.0, 2.0)
                                            .display_method(
                                                HorizontalAlign::Center,
                                                VerticalAlign::Center,
                                            ),
                                    ),
                            ))
                            .movable(false, false)
                            .resizable(false, false, false, false)
                            .scroll_length_method(None, Some(ScrollLengthMethod::AutoFit(0.0)))
                            .scroll_sensitivity(1.0)
                            .overall_layout(PanelLayout {
                                panel_margin: PanelMargin::None([0.0, 0.0, 0.0, 0.0], false),
                                panel_location: PanelLocation::Absolute([0.0, 0.0]),
                            })
                            .raise_on_focus(false),
                    )),
                )
                .tags(
                    &[["render_layer".to_string(), "foreground".to_string()]],
                    false,
                ),
            );
        }
    }

    fn handle_main_switches(&mut self) {
        let pressed = |state: Option<&SwitchState>| {
            state
                .map(|switch_state| switch_state.last_frame_clicked.is_some())
                .unwrap_or(false)
        };
        let hovered = |state: Option<&SwitchState>| {
            state
                .map(|switch_state| switch_state.last_frame_hovered)
                .unwrap_or(false)
        };
        let released = |prev_pressed: bool, state: Option<&SwitchState>| {
            prev_pressed && !pressed(state) && hovered(state)
        };

        let switch_names: Vec<String> = self.graphician.switch_states.keys().cloned().collect();
        let mut released_names: Vec<String> = Vec::new();
        for name in &switch_names {
            let state = self.graphician.switch_states.get(name);
            let prev = self.main_switch_prev.get(name).copied().unwrap_or(false);
            if released(prev, state) {
                released_names.push(name.clone());
            }
        }
        for name in &switch_names {
            let state = self.graphician.switch_states.get(name);
            self.main_switch_prev.insert(name.clone(), pressed(state));
        }
        self.main_switch_prev
            .retain(|name, _| self.graphician.switch_states.contains_key(name));

        for name in &released_names {
            match name.as_str() {
                "main_logout" => {
                    Self::spawn_logout(self.state.clone(), self.context.clone());
                }
                "main_create_group" => {
                    let mut guard = self.state.lock().unwrap();
                    guard.create_mode = if guard.create_mode == CreateMode::Group {
                        CreateMode::None
                    } else {
                        CreateMode::Group
                    };
                }
                "main_create_private" => {
                    let mut guard = self.state.lock().unwrap();
                    guard.create_mode = if guard.create_mode == CreateMode::Private {
                        CreateMode::None
                    } else {
                        CreateMode::Private
                    };
                }
                "main_confirm_create" => {
                    let guard = self.state.lock().unwrap();
                    let token = guard.token.clone();
                    let mode = guard.create_mode;
                    if let Some(token) = token {
                        match mode {
                            CreateMode::Group => {
                                let group_name = guard.create_group_name.clone();
                                let group_members = guard.create_group_members.clone();
                                drop(guard);
                                Self::spawn_create_group(
                                    self.state.clone(),
                                    self.context.clone(),
                                    token,
                                    group_name,
                                    group_members,
                                );
                            }
                            CreateMode::Private => {
                                let username = guard.private_chat_username.clone();
                                drop(guard);
                                Self::spawn_create_private_chat(
                                    self.state.clone(),
                                    self.context.clone(),
                                    token,
                                    username,
                                );
                            }
                            CreateMode::None => {}
                        }
                    }
                    let mut guard = self.state.lock().unwrap();
                    guard.create_mode = CreateMode::None;
                    guard.create_group_name.clear();
                    guard.create_group_members.clear();
                    guard.private_chat_username.clear();
                }
                "main_add_members" => {
                    let guard = self.state.lock().unwrap();
                    let token = guard.token.clone();
                    let room_id = guard.selected_room_id.clone();
                    let usernames = guard.add_member_usernames.clone();
                    drop(guard);
                    if let (Some(token), Some(room_id)) = (token, room_id) {
                        Self::spawn_add_members(
                            self.state.clone(),
                            self.context.clone(),
                            token,
                            room_id,
                            usernames,
                        );
                    }
                }
                "main_refresh_members" => {
                    let room_id = self.state.lock().unwrap().selected_room_id.clone();
                    if let Some(room_id) = room_id {
                        Self::spawn_fetch_members(
                            self.state.clone(),
                            self.context.clone(),
                            room_id,
                        );
                    }
                }
                "main_refresh_rooms" => {
                    let token = self.state.lock().unwrap().token.clone();
                    if let Some(token) = token {
                        Self::spawn_fetch_rooms(self.state.clone(), self.context.clone(), token);
                    }
                }
                "main_leave_room" => {
                    let guard = self.state.lock().unwrap();
                    let token = guard.token.clone();
                    let room_id = guard.selected_room_id.clone();
                    let user_id = guard.current_user.as_ref().map(|user| user.id.clone());
                    drop(guard);
                    if let (Some(token), Some(room_id), Some(user_id)) = (token, room_id, user_id) {
                        Self::spawn_remove_member(
                            self.state.clone(),
                            self.context.clone(),
                            token,
                            room_id,
                            user_id,
                        );
                    }
                }
                "main_load_older" => {
                    let room_id = self.state.lock().unwrap().selected_room_id.clone();
                    if let Some(room_id) = room_id {
                        Self::spawn_fetch_older_messages(
                            self.state.clone(),
                            self.context.clone(),
                            room_id,
                        );
                    }
                }
                "main_send" => {
                    self.send_current_message();
                }
                "main_start_encrypt" => {
                    let room_id = self.state.lock().unwrap().selected_room_id.clone();
                    if let Some(room_id) = room_id {
                        Self::spawn_start_encryption(
                            self.state.clone(),
                            self.context.clone(),
                            room_id,
                        );
                    }
                }
                "main_accept_encrypt" => {
                    let room_id = self.state.lock().unwrap().selected_room_id.clone();
                    if let Some(room_id) = room_id {
                        Self::accept_encryption(self.state.clone(), self.context.clone(), room_id);
                    }
                }
                "main_end_encrypt" => {
                    let room_id = self.state.lock().unwrap().selected_room_id.clone();
                    if let Some(room_id) = room_id {
                        Self::leave_encryption(self.state.clone(), room_id);
                    }
                }
                _ => {
                    if let Some(user_id) = name.strip_prefix("main_kick_") {
                        let guard = self.state.lock().unwrap();
                        let token = guard.token.clone();
                        let room_id = guard.selected_room_id.clone();
                        drop(guard);
                        if let (Some(token), Some(room_id)) = (token, room_id) {
                            Self::spawn_remove_member(
                                self.state.clone(),
                                self.context.clone(),
                                token,
                                room_id,
                                user_id.to_string(),
                            );
                        }
                    }
                }
            }
        }
    }

    fn handle_main_room_clicks(&mut self, ui: &Ui) {
        let clicked = ui.ctx().input(|input| input.pointer.primary_clicked());
        if !clicked {
            return;
        }
        // Do not treat a click over any switch as a room selection. Scrolled room
        // rows can overlap the create switches; this keeps switch clicks working.
        let over_switch = self
            .graphician
            .switch_states
            .values()
            .any(|switch_state| switch_state.last_frame_hovered);
        if over_switch {
            return;
        }
        let Some(mouse_pos) = ui.ctx().input(|input| input.pointer.hover_pos()) else {
            return;
        };
        let rooms = self.state.lock().unwrap().rooms.clone();
        for room in &rooms {
            let name = format!("room_{}", room.id);
            if let Some(rect) = self.graphician.panel_child_rects.get(&name) {
                if rect.contains(mouse_pos) {
                    let room_id = room.id.clone();
                    let is_group = room.is_group;
                    let mut guard = self.state.lock().unwrap();
                    guard.selected_room_id = Some(room_id.clone());
                    guard.messages.clear();
                    guard.create_mode = CreateMode::None;
                    let token = guard.token.clone();
                    drop(guard);
                    Self::spawn_fetch_messages(
                        self.state.clone(),
                        self.context.clone(),
                        room_id.clone(),
                    );
                    if let Some(token) = token {
                        if is_group {
                            Self::spawn_fetch_room_detail(
                                self.state.clone(),
                                self.context.clone(),
                                token,
                                room_id,
                            );
                        }
                    }
                    break;
                }
            }
        }
    }

    fn send_current_message(&mut self) {
        let mut guard = self.state.lock().unwrap();
        let content = guard.message_input.clone();
        let room_id = guard.selected_room_id.clone();
        let is_encrypted_room = guard
            .rooms
            .iter()
            .find(|room| Some(&room.id) == room_id.as_ref())
            .map(|room| room.is_encrypted)
            .unwrap_or(false);
        let session_key = guard
            .encryption_sessions
            .get(room_id.as_deref().unwrap_or(""))
            .and_then(|session| session.session_key);
        let Some(room_id) = room_id else {
            return;
        };
        if is_encrypted_room {
            match session_key {
                Some(key) => match encryption::encrypt_message(&key, &content) {
                    Ok(ciphertext) => {
                        let frame = serde_json::json!({
                            "type": "encrypt_message",
                            "data": {
                                "room_id": room_id,
                                "ciphertext": ciphertext,
                            }
                        })
                        .to_string();
                        send_websocket_frame(&guard, frame);
                        guard.message_input.clear();
                    }
                    Err(error) => {
                        guard.notice = Some(format!("{error}"));
                    }
                },
                None => {
                    guard.notice = Some(self.get_language_text("encrypt_required"));
                }
            }
        } else {
            let frame = serde_json::json!({
                "type": "send_message",
                "data": {
                    "room_id": room_id,
                    "content": content,
                }
            })
            .to_string();
            send_websocket_frame(&guard, frame);
            guard.message_input.clear();
        }
    }
}

impl eframe::App for BaihuaApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        static FONTS_REGISTERED: std::sync::Once = std::sync::Once::new();
        FONTS_REGISTERED.call_once(|| {
            let _ = self.graphician.register_fonts(
                ui,
                vec![["sans-serif", "assets/fonts/SourceHanSansSC-VF.ttf"]],
            );
        });

        // if ui.input(|input| input.key_pressed(Key::Z) || input.key_pressed(Key::E)) {
        //     if self.language_code == "en-US" {
        //         self.language_code = "zh-CN".to_string();
        //     } else {
        //         self.language_code = "en-US".to_string();
        //     }
        // }
        // if ui.input(|input| input.key_pressed(Key::D) || input.key_pressed(Key::L)) {
        //     if self.theme_code == "dark" {
        //         self.theme_code = "light".to_string();
        //     } else {
        //         self.theme_code = "dark".to_string();
        //     }
        // }
        // if ui.input(|input| input.key_pressed(Key::T)) {
        //     if self
        //         .graphician
        //         .get_variable::<Option<String>>("notice")
        //         .unwrap()
        //         == &None
        //     {
        //         self.graphician.set_variable(
        //             "notice",
        //             Some("Test Message: Nothing, Nothing, Nothing".to_string()),
        //         );
        //     } else {
        //         self.graphician
        //             .set_variable::<Option<String>>("notice", None);
        //     }
        // }

        if self.page == Page::Main {
            let now = std::time::Instant::now();
            let mut guard = self.state.lock().unwrap();
            let expired: Vec<String> = guard
                .typing_room_members
                .keys()
                .filter(|room_id| {
                    guard
                        .typing_last_received
                        .get(*room_id)
                        .map(|last| now.duration_since(*last).as_secs() >= 5)
                        .unwrap_or(true)
                })
                .cloned()
                .collect();
            for room_id in expired {
                guard.typing_room_members.remove(&room_id);
            }
        }

        match self.page {
            Page::Login => self.build_login_page(ui),
            Page::Register => self.build_register_page(ui),
            Page::Main => self.build_main_page(ui),
        }

        self.build_overlay_notice();

        let pending_notice = self.state.lock().unwrap().notice.take();
        if let Some(message) = pending_notice {
            self.graphician
                .set_variable::<Option<String>>("notice", Some(message));
        }

        let elements = self.graphician.elements.clone();

        let _ = self.graphician.loop_handler(ui);

        self.graphician.render_layer_visualization_custom(
            ui,
            RenderLayerVisualizationConfig::default(),
            &elements,
        );

        if self.page == Page::Main {
            if let Some(panel_state) = self.graphician.panel_states.get_mut("main_messages_panel") {
                let message_count = self.state.lock().unwrap().messages.len();
                let prev = self
                    .state
                    .lock()
                    .unwrap()
                    .selected_room_id
                    .as_ref()
                    .and_then(|room_id| self.prev_message_count.get(room_id).copied())
                    .unwrap_or(0);
                let new_message_arrived = message_count > prev && message_count - prev < 10;
                // Pin to bottom when a new message arrives or by default.
                if new_message_arrived || !panel_state.scrolled[1] {
                    panel_state.scroll_progress[1] = panel_state.scroll_length[1].max(0.0);
                }
            }
            let guard = self.state.lock().unwrap();
            if let Some(room_id) = &guard.selected_room_id {
                self.prev_message_count
                    .insert(room_id.clone(), guard.messages.len());
            }
        }

        if let Some(close_rect) = self.graphician.panel_child_rects.get("notice_close") {
            let click_position = ui.ctx().input(|input| input.pointer.interact_pos());
            let clicked = click_position.is_some_and(|position| close_rect.contains(position))
                && ui.ctx().input(|input| input.pointer.primary_clicked());
            if clicked {
                self.graphician
                    .set_variable::<Option<String>>("notice", None);
            }
        }

        let state = self.state.clone();
        let pending_page = state.lock().unwrap().pending_page.take();
        if let Some(page) = pending_page {
            if page == Page::Main && self.page != Page::Main {
                let token = state.lock().unwrap().token.clone();
                if let Some(token) = token {
                    Self::spawn_fetch_rooms(state.clone(), self.context.clone(), token.clone());
                    Self::spawn_fetch_users(state.clone(), self.context.clone(), token);
                }
            }
            self.page = page;
        }
        if self.page == Page::Login || self.page == Page::Register {
            self.handle_auth_switches();
        } else if self.page == Page::Main {
            self.handle_main_switches();
            self.handle_main_room_clicks(ui);
        }
    }
}
