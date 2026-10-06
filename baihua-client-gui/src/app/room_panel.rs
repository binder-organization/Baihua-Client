//! The left room list panel: room rows with unread badges, row selection, and
//! the header buttons (create menu, settings gear).

use super::*;

/// The room list label: the title with the member count right after it, and the
/// encrypted marker last; the unread badge is a separate atom at the row's end.
fn room_row_label(title: &str, member_count: usize, encrypted_badge: Option<&str>) -> String {
    let mut label = format!("{title}({member_count})");
    if let Some(marker) = encrypted_badge {
        label.push_str(&format!(" [{marker}]"));
    }
    label
}

/// How many characters of an unsent draft the room list may show: a row is one line wide
/// and already carries the title, the count and the badge, so a long draft is cut short.
const DRAFT_PREVIEW_CHARS: usize = 16;

/// The room-list suffix for a draft: the localized "[Draft]" mark followed by a one-line
/// preview of the unsent text (whitespace collapsed, over-long text elided with "…").
/// An empty draft yields an empty suffix, so the caller never has to special-case it.
pub(crate) fn room_row_draft_suffix(mark: &str, draft: &str) -> String {
    let flattened = draft.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return String::new();
    }
    if flattened.chars().count() <= DRAFT_PREVIEW_CHARS {
        return format!(" {mark}{flattened}");
    }
    let preview: String = flattened.chars().take(DRAFT_PREVIEW_CHARS - 1).collect();
    format!(" {mark}{preview}…")
}

/// A room list row
pub(crate) struct RoomRow {
    pub(crate) index: usize,
    pub(crate) label: String,
    pub(crate) id: String,
    pub(crate) unread_badge: Option<String>,
}

/// One button per row, full width and all the same height: title at the left, unread
/// badge at the right. Returns the index of the row clicked this frame, if any.
pub(crate) fn draw_room_rows(
    ui: &mut Ui,
    skin: &Skin,
    rows: &[RoomRow],
    selected: Option<usize>,
) -> Option<usize> {
    let mut picked: Option<usize> = None;
    for row in rows {
        let is_selected = selected == Some(row.index);
        let row_width = ui.available_width();
        let mut atoms = Atoms::new(RichText::new(row.label.clone()).color(selectable_color(
            skin,
            is_selected,
            skin.message_text,
        )));
        // The grow atom eats the slack between the title and the badge: that is what
        // keeps the title at the left edge instead of centered in the button.
        atoms.push_right(Atom::grow());
        if let Some(badge) = &row.unread_badge {
            atoms.push_right(RichText::new(badge.clone()).color(skin.notice_error_border));
        }
        let response = ui
            .add_sized(
                [row_width, room_row_height()],
                Button::selectable(is_selected, atoms)
                    .frame_when_inactive(true)
                    .truncate()
                    .min_size(Vec2::new(row_width, room_row_height())),
            )
            .on_hover_text(row.id.clone());
        if response.clicked() {
            picked = Some(row.index);
        }
    }
    picked
}

impl BaihuaApp {
    pub(crate) fn room_rows(&self) -> Vec<RoomRow> {
        let draft_mark = self.text("draft_mark");
        self.client
            .room_entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let marker = entry.encrypted.then(|| self.text("encrypted_badge"));
                let mut label = room_row_label(&entry.title, entry.member_count, marker.as_deref());
                label.push_str(&room_row_draft_suffix(&draft_mark, &entry.draft));
                RoomRow {
                    index,
                    label,
                    id: entry.id.clone(),
                    unread_badge: match (entry.unread, entry.muted) {
                        (0, _) => None,
                        (count, false) => Some(count.to_string()),
                        (_, true) => Some("·".to_string()),
                    },
                }
            })
            .collect()
    }

    pub(crate) fn draw_room_panel(&mut self, ui: &mut Ui) {
        let skin = self.skin.clone();
        let icons = self.frame_icons(ui.ctx());
        let rows = self.room_rows();
        let selected = self.client.selected_room_index;
        let empty_label = self.text("rooms_empty");
        let list_title = self.text("room_list_title");
        let create_group_title = self.text("create_group_title");
        let create_private_title = self.text("create_private_title");
        let settings_title = self.text("settings_title");
        let login_title = self.text("option_login");
        let signed_in = self.client.is_signed_in();
        let mut picked: Option<usize> = None;
        let mut open_login_page = false;
        let mut open_creation_page: Option<CreationPage> = None;
        let mut toggle_settings = false;
        // Narrow layout: the list IS the whole layer, so it wears the same frame
        // as a full-width central panel instead of the resizable left panel.
        let narrow = window_is_narrow(ui.ctx());
        let contents = |ui: &mut Ui| {
            ui.horizontal(|ui| {
                ui.colored_label(skin.room_border, list_title);
                // To the right of the title are the gear (settings window) and plus (create group/private chat), in order:
                // Clicking the plus button expands the selection list; selecting an item opens the corresponding creation window
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    open_creation_page = draw_creation_menu(
                        ui,
                        &skin,
                        &icons,
                        &create_group_title,
                        &create_private_title,
                    );
                    // Gear and plus side by side: the gear is the settings image, the
                    // plus stays text because no single "add" image exists.
                    if icon_button(ui, &skin, &icons, IconName::Settings, None)
                        .on_hover_text(settings_title)
                        .clicked()
                    {
                        toggle_settings = true;
                    }
                });
            });
            // The login row docks to the panel's bottom and reserves its space before
            // the list is laid out; below a full-height scroll area it pushed past it.
            if !signed_in {
                egui::Panel::bottom("room-login-row")
                    .resizable(false)
                    .show(ui, |ui| {
                        ui.separator();
                        // The settings entry is the gear to the right of the title;
                        // only the login entry for when not logged in is kept here.
                        if icon_button(
                            ui,
                            &skin,
                            &icons,
                            IconName::Proceed,
                            Some(login_title.to_string()),
                        )
                        .clicked()
                        {
                            open_login_page = true;
                        }
                    });
            }
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let had_rooms = !rows.is_empty();
                    picked = draw_room_rows(ui, &skin, &rows, selected);
                    if !had_rooms {
                        ui.colored_label(skin.hint_text, empty_label);
                    }
                });
        };
        if narrow {
            egui::CentralPanel::default()
                .frame(window_layer_frame(&skin, skin.room_border))
                .show(ui, contents);
        } else {
            room_panel(&skin).show(ui, contents);
        }
        if let Some(index) = picked {
            // Clicking the already-open row closes the selection again (the
            // narrow layout's gesture back to the list, accepted in wide too).
            self.client.toggle_room(index);
        }
        if toggle_settings {
            self.settings_open = !self.settings_open;
        }
        if open_login_page {
            self.auth_page = Some(AuthPage::Login);
        }
        if let Some(page) = open_creation_page {
            self.creation_page = Some(page);
        }
    }

    // ==================== Middle: Message Area, Command Panel, Input Box ====================
}

#[cfg(test)]
mod room_list_tests {
    use super::{
        DRAFT_PREVIEW_CHARS, RoomRow, draw_room_rows, room_row_draft_suffix, room_row_label,
    };
    use crate::app::auth::auth_draft_tests::test_app;
    use crate::app::room_row_height;
    use crate::app::test_support::frame;
    use crate::appearance::Skin;
    use baihua_core::config::{self, Palette};
    use egui::{CentralPanel, Context, Rect};

    /// The whole room panel (real app, signed out: header, list, login row) must
    /// paint its background inside the window, on the same bottom line the insets give.
    #[test]
    fn room_bottom_inside() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut app = test_app();
        app.auth_page = None;
        let mut bottoms: Vec<f32> = Vec::new();
        for _ in 0..4 {
            context
                .run_ui(frame(720.0, 922.0, Vec::new()), |ui| {
                    app.draw_status_bar(ui);
                    app.draw_room_panel(ui);
                    bottoms = ui.graphics_mut(|graphics| {
                        let mut bottoms: Vec<f32> = Vec::new();
                        if let Some(list) = graphics.get(egui::LayerId::background()) {
                            for entry in list.all_entries() {
                                if let egui::Shape::Rect(rect) = &entry.shape
                                    && rect.stroke.width == 1.0
                                    && rect.stroke.color == skin.room_border
                                    && rect.rect.height() > 200.0
                                {
                                    bottoms.push(rect.rect.bottom());
                                }
                            }
                        }
                        bottoms
                    });
                })
                .drop_without_applying_deltas();
        }
        let expected = 922.0 - crate::app::panel_inset() as f32;
        assert!(
            !bottoms.is_empty(),
            "the room panel background must be painted"
        );
        for bottom in &bottoms {
            assert!(
                (bottom - expected).abs() < 1.5,
                "the room panel background must end on the inset bottom line {expected}, got {bottom}"
            );
        }
    }

    /// One row of the list, as the panel would get it from the session layer.
    fn row(index: usize, label: &str, badge: Option<&str>) -> RoomRow {
        RoomRow {
            index,
            label: label.to_string(),
            id: format!("room-{index}"),
            unread_badge: badge.map(str::to_string),
        }
    }

    /// Draw the rows once: the button rectangles, the painted text spans
    /// (left and right edge) and the width the rows had available.
    fn painted_rows(rows: &[RoomRow]) -> (Vec<Rect>, Vec<(String, f32, f32)>, f32) {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut available = 0.0;
        let mut rects: Vec<Rect> = Vec::new();
        let mut texts: Vec<(String, f32, f32)> = Vec::new();
        context
            .run_ui(frame(500.0, 400.0, Vec::new()), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    available = ui.available_width();
                    let _ = draw_room_rows(ui, &skin, rows, None);
                });
                let shapes = ctx.graphics_mut(|graphics| {
                    let mut shapes: Vec<(Rect, Option<String>)> = Vec::new();
                    if let Some(list) = graphics.get(egui::LayerId::background()) {
                        for entry in list.all_entries() {
                            match &entry.shape {
                                egui::Shape::Rect(shape) => shapes.push((shape.rect, None)),
                                egui::Shape::Text(text) => shapes.push((
                                    entry.shape.visual_bounding_rect(),
                                    Some(text.galley.text().to_string()),
                                )),
                                _ => {}
                            }
                        }
                    }
                    shapes
                });
                for (rect, text) in shapes {
                    match text {
                        None if (rect.height() - room_row_height()).abs() < 0.6 => rects.push(rect),
                        Some(text) => texts.push((text, rect.min.x, rect.max.x)),
                        _ => {}
                    }
                }
            })
            .drop_without_applying_deltas();
        (rects, texts, available)
    }

    /// The draft suffix: the localized mark plus a one-line preview of the unsent
    /// text. Blanks collapse, an over-long draft is cut short with an ellipsis, and
    /// an empty (or blank-only) draft yields no suffix at all.
    #[test]
    fn draft_suffix_is_short_and_never_blank() {
        assert_eq!(
            room_row_draft_suffix("[Draft]", ""),
            "",
            "a room without unsent text must not be marked"
        );
        assert_eq!(
            room_row_draft_suffix("[Draft]", "   \n "),
            "",
            "blanks are not something unsent, so they must not mark the row either"
        );
        assert_eq!(
            room_row_draft_suffix("[草稿]", "half a line"),
            " [草稿]half a line",
            "the mark sits in front of the text, separated by one space"
        );
        assert_eq!(
            room_row_draft_suffix("[Draft]", "  spaced   \t out  "),
            " [Draft]spaced out",
            "the preview must stay one line: runs of blanks collapse"
        );
        let over_long = "x".repeat(DRAFT_PREVIEW_CHARS + 5);
        let suffix = room_row_draft_suffix("[Draft]", &over_long);
        assert!(
            suffix.starts_with(" [Draft]xxx"),
            "the preview must keep the start of the text, got {suffix:?}"
        );
        assert!(
            suffix.ends_with('…'),
            "an over-long draft must be marked as cut short, got {suffix:?}"
        );
        assert_eq!(
            suffix.chars().count(),
            1 + "[Draft]".chars().count() + DRAFT_PREVIEW_CHARS,
            "the whole suffix must stay as wide as one preview, got {suffix:?}"
        );
        assert_eq!(
            room_row_draft_suffix("[Draft]", &"x".repeat(DRAFT_PREVIEW_CHARS)),
            format!(" [Draft]{}", "x".repeat(DRAFT_PREVIEW_CHARS)),
            "text exactly on the limit is shown whole, without an ellipsis"
        );
    }

    /// The row really carries the suffix: a room holding unsent text is marked behind
    /// its name, while the room whose text sits in the input box is not.
    #[test]
    fn row_marks_the_room_that_is_not_open() {
        let Ok(language) = config::Language::load("zh-CN") else {
            return;
        };
        let mut app = test_app();
        app.client.language = language;
        app.client.rooms = vec![
            room_info("room-1", "team one"),
            room_info("room-2", "team two"),
        ];
        // Room 2 is open (its text is in the box), room 1 is the one left behind with a draft.
        app.client.selected_room_index = Some(1);
        app.client
            .room_drafts
            .insert("room-1".to_string(), "half a line".to_string());
        let rows = app.room_rows();
        let mark = app.text("draft_mark");
        assert_eq!(
            rows[0].label,
            format!("team one(1) {mark}half a line"),
            "the left-behind room must show the mark and its text behind the name"
        );
        assert_eq!(
            rows[1].label, "team two(1)",
            "the open room must not repeat text that is sitting in the input box"
        );
    }

    /// One room as the session layer hands it to the list: a group chat with a name.
    fn room_info(id: &str, name: &str) -> baihua_core::api::RoomInfo {
        baihua_core::api::RoomInfo {
            id: id.to_string(),
            name: Some(name.to_string()),
            created_by: "user-a".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
            is_group: true,
            is_encrypted: false,
            members: vec!["user-a".to_string()],
        }
    }

    /// The member count follows the title with no gap; the encrypted marker last.
    #[test]
    fn count_in_label() {
        assert_eq!(room_row_label("team chat", 3, None), "team chat(3)");
        assert_eq!(
            room_row_label("team", 1, Some("secret")),
            "team(1) [secret]"
        );
    }

    /// Every row is one full-width button of exactly the shared height, whatever the
    /// title length or whether it carries an unread badge.
    #[test]
    fn rows_fill_and_match() {
        let rows = [
            row(0, "a", Some("12")),
            row(
                1,
                "a much longer room title that would overflow its row",
                None,
            ),
            row(2, "b", Some("*")),
        ];
        let (rects, _, available) = painted_rows(&rows);
        assert_eq!(
            rects.len(),
            rows.len(),
            "each row must paint exactly one button, got {rects:?}"
        );
        for rect in &rects {
            assert!(
                (rect.width() - available).abs() < 1.0,
                "the row {rect:?} must fill the available width {available}"
            );
            assert!(
                (rect.height() - room_row_height()).abs() < 0.6,
                "the row {rect:?} must be {} tall",
                room_row_height()
            );
        }
    }

    /// The title keeps the left edge and the badge the right one, both inside the
    /// button: a long title truncates instead of pushing the badge out.
    #[test]
    fn badge_after_label() {
        let title = "a much longer room title that would overflow its row";
        let rows = [row(0, title, Some("7"))];
        let (rects, texts, _) = painted_rows(&rows);
        let button = rects
            .first()
            .unwrap_or_else(|| panic!("the row must paint its button, got {rects:?}"));
        let (_, title_left, _) = texts
            .iter()
            .find(|(text, _, _)| text.starts_with("a much longer"))
            .unwrap_or_else(|| panic!("the title must be drawn, got {texts:?}"));
        let (_, badge_left, badge_right) = texts
            .iter()
            .find(|(text, _, _)| text == "7")
            .unwrap_or_else(|| panic!("the badge must be drawn, got {texts:?}"));
        assert!(
            (title_left - button.min.x).abs() < 20.0,
            "the title must sit at the left of the button, got {title_left} against {button:?}"
        );
        assert!(
            badge_left > title_left,
            "the badge must come after the title, got {badge_left} against {title_left}"
        );
        assert!(
            *badge_right <= button.max.x + 0.5,
            "the badge must stay inside the button, got {badge_right} against {button:?}"
        );
    }
}
