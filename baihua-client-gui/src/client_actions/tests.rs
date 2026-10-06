use super::*;
use baihua_core::api::RoomMember;

/// Publishing an event through the session sink must invoke the waker the
/// interface supplied, which is what replaced the old fixed repaint beat.
#[test]
fn event_wakes_loop() {
    let mut client = Client::default();
    client.open_event_channel();
    let woken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let woken = woken.clone();
        client.set_event_waker(std::sync::Arc::new(move || {
            woken.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
    }
    let sink = client
        .events
        .clone()
        .expect("the event channel was opened above");
    sink.send(PollingEvent::RoomsUpdated(vec![room(
        "room-1", "one", false,
    )]));
    assert_eq!(
        woken.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "sending an event must wake the frame loop exactly once"
    );
    assert!(
        client.next_event().is_some(),
        "the event must still reach the interface through the channel"
    );
}

fn room(id: &str, name: &str, encrypted: bool) -> RoomInfo {
    RoomInfo {
        id: id.to_string(),
        name: Some(name.to_string()),
        created_by: "user-a".to_string(),
        created_at: "2026-09-06T00:00:00+00:00".to_string(),
        is_group: true,
        is_encrypted: encrypted,
        members: vec!["user-a".to_string()],
    }
}

fn request(id: &str, status: Option<&str>) -> RoomRequestInfo {
    RoomRequestInfo {
        id: id.to_string(),
        message: "requests a private chat".to_string(),
        is_encrypted: true,
        created_at: "2026-09-06T00:00:00+00:00".to_string(),
        sender: None,
        receiver: None,
        status: status.map(str::to_string),
    }
}

/// The room list entries: a locally closed room disappears, while a muted room
/// keeps its unread count and carries the flag the interface draws as a dot.
#[test]
fn room_list_entries() {
    let mut client = Client::default();
    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", true),
    ];
    client.close_local_room("room-2");
    let entries = client.room_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "room-1");
    assert!(!entries[0].encrypted);

    client.rooms = vec![room("room-1", "team one", false)];
    client.unread_counts.insert("room-1".to_string(), 7);
    client.muted_room_ids.insert("room-1".to_string());
    let muted = client.room_entries();
    assert_eq!(muted[0].unread, 7);
    assert!(muted[0].muted, "a muted room must carry the mute flag");
}

/// Nothing ever selects a room on its own: not the first snapshot after login,
/// not a snapshot where the open room vanished, and not a local close.
#[test]
fn selection_is_manual() {
    let mut client = Client::default();
    client.apply_room_snapshot(vec![
        room("room-1", "team one", false),
        room("room-2", "team two", true),
    ]);
    assert!(
        client.selected_room_index.is_none(),
        "the first batch of rooms after login must not auto-select any"
    );
    client.selected_room_index = Some(0);
    client.apply_room_snapshot(vec![room("room-2", "team two", true)]);
    assert_eq!(
        client.selected_room_index, None,
        "a vanished selection returns to nothing selected instead of jumping away"
    );

    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", true),
    ];
    client.selected_room_index = Some(0);
    client.close_local_room("room-1");
    assert!(
        client.selected_room_index.is_none(),
        "a locally closed room must not make the view jump to the next one"
    );
    assert!(!client.rooms.is_empty(), "the other rooms must stay listed");
}

/// Clicking the already-open row closes the selection (the wide and narrow room
/// lists share the toggle); another row still moves the selection as before.
#[test]
fn row_click_toggles() {
    let mut client = Client::default();
    client.connector.set_base_url("http://127.0.0.1:1");
    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", true),
    ];
    client.toggle_room(0);
    assert_eq!(
        client.selected_room_index,
        Some(0),
        "clicking an unselected row opens that room"
    );
    client.toggle_room(0);
    assert!(
        client.selected_room_index.is_none(),
        "clicking the selected row again cancels the selection"
    );
    assert!(
        client.messages.is_empty(),
        "after cancelling, the message area must not keep the previous room content"
    );
    client.toggle_room(1);
    assert_eq!(
        client.selected_room_index,
        Some(1),
        "after cancelling, clicking another row opens it as usual"
    );
}

/// The unsent text belongs to the room it was typed in: switching chats empties the
/// box, the room just left keeps its own text (which is what the list marks), and
/// reopening a room hands that same text back to the input box.
#[test]
fn draft_follows_the_room() {
    let mut client = Client::default();
    // The reloads of the switched-to rooms must not reach a server; a connection
    // failure is the silent branch, exactly like the row-click test above.
    client.connector.set_base_url("http://127.0.0.1:1");
    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", true),
    ];
    client.open_room(0);
    client.draft = "half a sentence".to_string();
    client.open_room(1);
    assert!(
        client.draft.is_empty(),
        "switching chats must empty the input box"
    );
    let entries = client.room_entries();
    assert_eq!(
        entries[0].draft, "half a sentence",
        "the room just left keeps the text typed in it"
    );
    assert_eq!(
        entries[1].draft, "",
        "the open room must never be marked with text that sits in the box"
    );

    client.draft = "another half".to_string();
    client.open_room(0);
    assert_eq!(
        client.draft, "half a sentence",
        "reopening a room must restore that room's own text"
    );
    let entries = client.room_entries();
    assert_eq!(
        entries[0].draft, "",
        "text living in the box is no longer a list marker"
    );
    assert_eq!(
        entries[1].draft, "another half",
        "the room just left keeps its own text, not the other room's"
    );
}

/// Leaving the chat records what was typed and empties the box; coming back gives it
/// back. An empty box drops the entry instead of keeping an empty draft alive, so the
/// list only marks rooms that really hold something unsent.
#[test]
fn closing_a_selection_keeps_the_draft_with_the_room() {
    let mut client = Client::default();
    client.connector.set_base_url("http://127.0.0.1:1");
    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", true),
    ];
    client.open_room(0);
    client.draft = "unsent line".to_string();
    client.close_room_selection();
    assert!(
        client.draft.is_empty(),
        "leaving the chat must clear the input box"
    );
    assert_eq!(
        client.room_entries()[0].draft,
        "unsent line",
        "the closed selection must keep the text with its room"
    );
    client.open_room(0);
    assert_eq!(
        client.draft, "unsent line",
        "the room reopened after closing gets its text back"
    );

    client.draft = String::new();
    client.close_room_selection();
    assert_eq!(
        client.room_entries()[0].draft,
        "",
        "an empty box must not leave a marker behind"
    );
}

/// When a snapshot takes the open room away, the text in the box goes into that
/// room's own cache instead of being dropped or handed to whatever room comes next.
#[test]
fn a_vanishing_room_records_the_draft() {
    let mut client = Client::default();
    client.connector.set_base_url("http://127.0.0.1:1");
    client.apply_room_snapshot(vec![
        room("room-1", "team one", false),
        room("room-2", "team two", false),
    ]);
    client.selected_room_index = Some(0);
    client.draft = "unfinished".to_string();
    client.apply_room_snapshot(vec![room("room-2", "team two", false)]);
    assert_eq!(
        client.draft, "",
        "the box must be emptied with the room that vanished"
    );
    assert_eq!(
        client.room_drafts.get("room-1").map(String::as_str),
        Some("unfinished"),
        "the text stays cached under the id of the room it was typed in"
    );
    assert_eq!(
        client.selected_room_index, None,
        "a vanished selection returns to nothing selected, never another room"
    );
}

#[test]
fn unread_on_open() {
    let mut client = Client::default();
    client.rooms = vec![room("room-1", "team one", false)];
    client.selected_room_index = Some(0);
    client.unread_counts.insert("room-1".to_string(), 4);
    // Opening a room counts as read: clear that room's unread when switching the selection
    client.open_room(0);
    assert!(
        !client.unread_counts.contains_key("room-1"),
        "opening a room must zero its unread counter"
    );
}

#[test]
fn pending_badge_count() {
    let mut client = Client::default();
    client.pending_requests = vec![
        request("received-1", None),
        request("received-2", Some("accepted")),
    ];
    client.sent_requests = vec![
        request("sent-1", Some("pending")),
        request("sent-2", Some("declined")),
        request("sent-3", Some("cancelled")),
    ];
    assert_eq!(
        client.pending_count(),
        2,
        "only received entries lacking a decision and still-pending sent entries count"
    );
}

/// Locally handled invitations survive a poll (the server only lists rows still
/// waiting), and a declined status is never rendered as a withdrawn one.
#[test]
fn request_status_text() {
    let mut client = Client::default();
    client.pending_requests = vec![
        request("waiting", None),
        request("handled", Some("accepted")),
    ];
    client.apply_requests(vec![request("waiting", None), request("newly", None)]);
    let ids: Vec<String> = client
        .pending_requests
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    assert_eq!(ids, vec!["waiting", "newly", "handled"]);
    assert_eq!(
        client
            .pending_requests
            .iter()
            .find(|entry| entry.id == "handled")
            .and_then(|entry| entry.status.as_deref()),
        Some("accepted"),
        "merging polled results must not wipe the state this end recorded"
    );
    assert_ne!(
        client.request_status_label("declined"),
        client.request_status_label("cancelled"),
        "declined and withdrawn must be two distinct texts"
    );
    assert_eq!(
        client.request_status_label("withdrawn_by_server"),
        "withdrawn_by_server",
        "an unknown status is displayed as-is, never guessed as withdrawn"
    );
}

/// A declined sent invitation is announced once, from last round's pending records
/// (and the language placeholder name must match).
#[test]
fn declined_announced() {
    fn sent_invitation(status: &str) -> RoomRequestInfo {
        RoomRequestInfo {
            id: "request-1".to_string(),
            message: "requests a private chat".to_string(),
            is_encrypted: true,
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
            sender: None,
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: Some(status.to_string()),
        }
    }
    // If the language file can't be read, just skip (not a failure when the test machine has no config directory)
    let Ok(language) = config::Language::load("zh-CN") else {
        return;
    };
    let declined_text = language.text("request_declined_notice");
    assert!(
        declined_text.contains("{user}"),
        "the language placeholder is named {{user}}; text edits must keep it: {declined_text:?}"
    );
    let mut client = Client::default();
    client.language = language;
    // Last round's local record was "still waiting", this round's poll says "rejected": report once
    client.sent_requests = vec![sent_invitation("pending")];
    client.announce_declined(&[sent_invitation("declined")]);
    let notices: Vec<String> = client
        .notices
        .iter()
        .map(|notice| notice.text.clone())
        .collect();
    assert_eq!(notices.len(), 1, "actual notices: {notices:?}");
    assert!(
        notices[0].contains("carol"),
        "the notice must name who declined: {notices:?}"
    );
    assert!(
        !notices[0].contains("{user}"),
        "the placeholder must be substituted, never shown raw: {notices:?}"
    );
    // After this side has already recorded declined, another round with the same status shouldn't report again
    client.notices.clear();
    client.sent_requests = vec![sent_invitation("declined")];
    client.announce_declined(&[sent_invitation("declined")]);
    assert!(
        client.notices.is_empty(),
        "the same state change must not be reported twice"
    );
    // When just logged in, this side doesn't have the record of "invitations I sent"; old rejections in history shouldn't be treated as just happening
    client.notices.clear();
    client.sent_requests.clear();
    client.announce_declined(&[sent_invitation("declined")]);
    assert!(
        client.notices.is_empty(),
        "after login, previously declined invitations must not be announced again: {:?}",
        client
            .notices
            .iter()
            .map(|notice| notice.text.clone())
            .collect::<Vec<String>>()
    );
}

#[test]
fn search_wraps() {
    let mut client = Client::default();
    client.messages = vec![
        MessageInfo {
            id: "msg-1".to_string(),
            room_id: "room-1".to_string(),
            sender_id: "user-a".to_string(),
            content: "first segment with the keyword".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        },
        MessageInfo {
            id: "msg-2".to_string(),
            room_id: "room-1".to_string(),
            sender_id: "user-a".to_string(),
            content: "unrelated content".to_string(),
            created_at: "2026-09-06T00:00:01+00:00".to_string(),
        },
        MessageInfo {
            id: "msg-3".to_string(),
            room_id: "room-1".to_string(),
            sender_id: "user-a".to_string(),
            content: "second segment with the keyword".to_string(),
            created_at: "2026-09-06T00:00:02+00:00".to_string(),
        },
    ];
    client.run_search("keyword");
    let (matches, _) = client.search_matches();
    assert_eq!(matches, vec!["msg-1".to_string(), "msg-3".to_string()]);
    // Default to the last match
    assert_eq!(client.pending_scroll_message_id.as_deref(), Some("msg-3"));
    client.navigate_search(false);
    assert_eq!(client.pending_scroll_message_id.as_deref(), Some("msg-1"));
    client.navigate_search(true);
    assert_eq!(client.pending_scroll_message_id.as_deref(), Some("msg-3"));
}

/// Two messages with keywords + one irrelevant message, shared by search-related test cases
fn searchable_client() -> Client {
    let mut client = Client::default();
    client.messages = vec![
        MessageInfo {
            id: "msg-1".to_string(),
            room_id: "room-1".to_string(),
            sender_id: "user-a".to_string(),
            content: "first segment with the keyword".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        },
        MessageInfo {
            id: "msg-2".to_string(),
            room_id: "room-1".to_string(),
            sender_id: "user-a".to_string(),
            content: "unrelated content".to_string(),
            created_at: "2026-09-06T00:00:01+00:00".to_string(),
        },
    ];
    client
}

/// regression for feedback "fast search doesn't work": when the switch is on, rescan on-the-fly as you type, no need to press Enter
#[test]
fn quick_search_rescans() {
    let mut client = searchable_client();
    client.quick_search = true;
    client.draft = "#keyword".to_string();
    client.handle_draft_changed();
    assert_eq!(
        client.search_matches().0,
        vec!["msg-1".to_string()],
        "with quick search on, typing up to #keyword already yields hits this frame"
    );
}

/// When fast search is off, if the keyword changes but Enter isn't pressed, old results must be invalidated (otherwise the title and highlight backgrounds stay on the old keyword)
#[test]
fn plain_search_expires() {
    let mut client = searchable_client();
    client.quick_search = false;
    client.draft = "#keyword".to_string();
    client.run_search("keyword");
    assert!(
        !client.search_matches().0.is_empty(),
        "a formal search must come first"
    );
    client.draft = "#keyword edited".to_string();
    client.handle_draft_changed();
    assert!(
        client.search_matches().0.is_empty(),
        "the keyword changed without Enter, so stale results must not linger"
    );
}

/// Clear search results when exiting search mode (input no longer starts with #)
#[test]
fn exit_search_clears() {
    let mut client = searchable_client();
    client.draft = "#keyword".to_string();
    client.run_search("keyword");
    client.draft = "plain message".to_string();
    client.handle_draft_changed();
    assert!(
        client.search_result.is_none(),
        "leaving search mode must clear the search results"
    );
}

/// With quick search off the panel only moves on Enter: `run_panel_search` stores
/// the keyword with its matches, an empty keyword clears them, and nothing scrolls.
#[test]
fn panel_enter_commits() {
    let mut client = searchable_client();
    client.quick_search = false;
    assert!(
        client.panel_match_ids("keyword").is_empty(),
        "before Enter the panel must show no results at all"
    );
    client.run_panel_search("keyword");
    assert_eq!(
        client.panel_match_ids("keyword"),
        vec!["msg-1".to_string()],
        "after an Enter search the same keyword must list the hits"
    );
    assert!(
        client.panel_match_ids("keyword edited").is_empty(),
        "the keyword changed without a fresh Enter, so old results must not stay"
    );
    assert!(
        client.pending_scroll_message_id.is_none(),
        "the Enter search itself must not scroll the message area"
    );
    client.run_panel_search("   ");
    assert!(
        client.panel_search_result.is_none(),
        "Enter on an empty keyword clears the results instead of listing the room"
    );
    assert!(client.panel_match_ids("").is_empty());
}

/// With quick search on, the panel rescans live: a message that arrives after the last
/// keystroke shows up without anyone pressing Enter.
#[test]
fn panel_quick_rescans() {
    let mut client = searchable_client();
    client.quick_search = true;
    assert_eq!(
        client.panel_match_ids("keyword"),
        vec!["msg-1".to_string()],
        "with quick search on, typing alone yields results without Enter"
    );
    client.messages.push(MessageInfo {
        id: "msg-3".to_string(),
        room_id: "room-1".to_string(),
        sender_id: "user-a".to_string(),
        content: "a freshly arrived message with the keyword".to_string(),
        created_at: "2026-09-06T00:00:02+00:00".to_string(),
    });
    assert_eq!(
        client.panel_match_ids("keyword"),
        vec!["msg-1".to_string(), "msg-3".to_string()],
        "a new message arriving under an unchanged keyword must join the quick-search results"
    );
}

/// Switching rooms or dropping the selection drops the panel's stored matches with the room:
/// the IDs named messages of the room that was just left.
#[test]
fn panel_drops_on_close() {
    let mut client = searchable_client();
    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", false),
    ];
    client.selected_room_index = Some(0);
    client.run_panel_search("keyword");
    client.close_room_selection();
    assert!(
        client.panel_search_result.is_none(),
        "after cancelling the selection the panel results point at the room just left and must be cleared"
    );
    client.run_panel_search("keyword");
    client.open_room(1);
    assert!(
        client.panel_search_result.is_none(),
        "switching rooms likewise: hits from the old room must not enter the new room's panel"
    );
}

/// The same person must not be shown twice as typing (stale records survive a
/// reconnection), and typing in another room never joins the current list.
#[test]
fn typing_dedup() {
    let mut client = Client::default();
    client.rooms = vec![
        room("room-1", "team one", false),
        room("room-2", "team two", false),
    ];
    client.selected_room_index = Some(0);
    client.typing_members.push((
        "room-1".to_string(),
        "alice".to_string(),
        std::time::Instant::now(),
    ));
    client.typing_members.push((
        "room-1".to_string(),
        "alice".to_string(),
        std::time::Instant::now(),
    ));
    client.typing_members.push((
        "room-2".to_string(),
        "bob".to_string(),
        std::time::Instant::now(),
    ));
    assert_eq!(
        client.typing_names(),
        vec!["alice".to_string()],
        "the same name shows once; names from other rooms do not count"
    );
}

#[test]
fn deleted_user_names() {
    let mut client = Client::default();
    // Server ON DELETE SET NULL: after the speaker deletes their account, the seam gives an empty string
    assert_eq!(
        client.sender_display_name(""),
        client.text("unknown_user"),
        "an empty user id must fall back to the unknown-user label, not an empty string"
    );
    client.sender_names =
        std::collections::HashMap::from([("user-a".to_string(), "alice".to_string())]);
    assert_eq!(client.sender_display_name("user-a"), "alice");
    assert_eq!(client.sender_display_name("user-unknown"), "user-unknown");
}

#[test]
fn blank_fields_skipped() {
    assert_eq!(profile_field_value("   "), None);
    assert_eq!(
        profile_field_value(" nickname "),
        Some(Some("nickname".to_string())),
        "surrounding blanks are trimmed; the server's three states ride on the Option"
    );
}

/// The signed-out whitelist: login, registration, logout, the update and quit
/// commands plus the local switches pass, everything else is refused.
#[test]
fn signed_out_commands() {
    for name in [
        "login",
        "register",
        "logout",
        "language",
        "appearance",
        "server_address",
        "update",
        "quit",
        "exit",
    ] {
        assert!(
            allowed_signed_out(name),
            "/{name} must work while signed out"
        );
    }
    for name in ["info", "mute", "quit_group", "add_member"] {
        assert!(
            !allowed_signed_out(name),
            "/{name} must be refused while signed out"
        );
    }
}

/// Encrypted rooms never reach the message cache, and reloading one must not let
/// the server's empty body overwrite the plaintext this end already decrypted.
#[test]
fn encrypted_room_cache() {
    let mut client = Client::default();
    client.rooms = vec![room("room-enc", "private chat", true)];
    client.messages = vec![MessageInfo {
        id: "msg-1".to_string(),
        room_id: "room-enc".to_string(),
        sender_id: "user-a".to_string(),
        content: "plaintext out of the ciphertext".to_string(),
        created_at: "2026-09-06T00:00:00+00:00".to_string(),
    }];
    client.selected_room_index = Some(0);
    assert!(client.room_is_encrypted("room-enc"));
    client.cache_messages("room-enc");
    assert!(
        client.chat_cache.is_none(),
        "signed out there must be no cache object"
    );

    // The reload points at an address that cannot answer, which exercises exactly
    // the "keep the local content when the server page fails" branch.
    client.connector.set_base_url("http://localhost:1");
    client.rooms = vec![RoomInfo {
        id: "room-secret".to_string(),
        name: None,
        created_by: "user-a".to_string(),
        created_at: String::new(),
        is_group: false,
        is_encrypted: true,
        members: vec!["user-a".to_string(), "user-b".to_string()],
    }];
    client.messages = vec![MessageInfo {
        id: "message-secret".to_string(),
        room_id: "room-secret".to_string(),
        sender_id: "user-b".to_string(),
        content: "plaintext that only lives in memory".to_string(),
        created_at: "2026-09-06T00:00:00+00:00".to_string(),
    }];
    client.load_room_messages("room-secret");
    assert!(
        client.messages.iter().any(|message| {
            message.id == "message-secret"
                && message.content == "plaintext that only lives in memory"
        }),
        "a full-room reload must not replace local plaintext with an empty body, got {:?}",
        client
            .messages
            .iter()
            .map(|message| message.content.clone())
            .collect::<Vec<String>>()
    );
}

#[test]
fn member_row_format() {
    let member = RoomMember {
        user_id: "user-a".to_string(),
        username: "alice".to_string(),
        nickname: Some("Alice".to_string()),
        role: "admin".to_string(),
        joined_at: "2026-09-06T00:00:00+00:00".to_string(),
    };
    assert_eq!(member.nickname.clone().unwrap_or(member.username), "Alice");
}

#[test]
fn avatar_whitelist() {
    for (name, expected) in [
        ("me.png", Some("image/png")),
        ("me.JPG", Some("image/jpeg")),
        ("me.jpeg", Some("image/jpeg")),
        ("me.gif", Some("image/gif")),
        ("me.webp", Some("image/webp")),
        ("me.txt", None),
        ("noextension", None),
    ] {
        assert_eq!(
            image_content_type(std::path::Path::new(name)),
            expected,
            "the format verdict for {name} is wrong"
        );
    }
}

#[test]
fn time_text_switch() {
    let created_at = "2026-09-06T00:00:00+00:00";
    let with_date = crate::app::format_time_for_test(created_at, true);
    let without_date = crate::app::format_time_for_test(created_at, false);
    assert!(
        with_date.contains("-"),
        "with the date enabled the year/month/day separators must appear"
    );
    assert!(
        !without_date.contains("-"),
        "time-only mode must not carry a date"
    );
}

/// Every ported command has its own branch and interface intent, and the
/// graphical table (completion list and command panel) carries no `/login`.
#[test]
fn command_branches() {
    let names: Vec<&str> = crate::command_entries()
        .into_iter()
        .map(|(name, _description)| name)
        .collect();
    assert!(
        !names.contains(&"login"),
        "the graphical end no longer lists /login, table is {names:?}"
    );
    assert!(names.contains(&"register"), "register remains a command");
    assert!(names.contains(&"logout"), "logout remains a command");

    // The sign-in form is opened by the interface itself, so `/login` falls
    // through to "unknown command" like any other name outside the table.
    let mut client = Client::default();
    client.notices.clear();
    assert!(matches!(client.execute_command("login"), UiIntent::Nothing));
    assert!(
        client
            .notices
            .iter()
            .any(|notice| notice.kind == NoticeKind::Error),
        "/login must report an unknown command, not stay silent"
    );
    assert!(matches!(
        client.execute_command("register bob"),
        UiIntent::OpenSignUp(Some(name)) if name == "bob"
    ));
    assert!(matches!(
        client.execute_command("logout"),
        UiIntent::OpenSignIn(None)
    ));
    for name in ["language", "appearance", "server_address"] {
        assert!(
            matches!(client.execute_command(name), UiIntent::OpenSettings),
            "/{name} without arguments must open the settings panel"
        );
    }
    assert!(matches!(client.execute_command("quit"), UiIntent::Quit));
    assert!(matches!(client.execute_command("exit"), UiIntent::Quit));
    assert!(
        client.quit_requested,
        "both quit and exit must request shutdown"
    );
}

/// The status bar's pipes live inside the texts (same as the terminal end); with no server version the right side must not keep a lone pipe.
#[test]
fn status_bar_pipes() {
    let mut client = Client::default();
    if let Ok(language) = config::Language::load("zh-CN") {
        client.language = language;
    }
    client.current_username = "alice".to_string();
    let (_connection_label, _mark, user_text, right_text) = client.status_bar_texts();
    assert_eq!(
        user_text.matches('|').count(),
        1,
        "the current-user segment must hold exactly one pipe, got {user_text:?}"
    );
    assert!(
        user_text.trim_start().starts_with('|'),
        "pipes belong to the texts, the interface draws none itself, got {user_text:?}"
    );
    assert!(
        !right_text.trim_start().starts_with('|'),
        "without a server version the right side must not start with a pipe, got {right_text:?}"
    );
    assert_eq!(
        right_text.matches('|').count(),
        0,
        "with only the client version the right side must have no separator pipe, got {right_text:?}"
    );
}

/// Every language key added or reused this round must really exist in the shipped language tables:
/// one missing key and the interface shows that key verbatim (`Language::text` falls back to the key name).
#[test]
fn new_keys_resolve() {
    let Ok(language) = config::Language::load("zh-CN") else {
        return;
    };
    for key in [
        "message_encrypted_history_unavailable",
        "error_update_download_failed",
        "logged_out_hint_graphical",
        "error_not_logged_in_graphical",
    ] {
        let wording = language.text(key);
        assert_ne!(
            wording, key,
            "the language tables lack {key}; the interface would show the raw key"
        );
        assert!(!wording.is_empty(), "the text of {key} must not be empty");
    }
}

/// The default appearance and whatever this machine saved must both load clean:
/// the name sticks, the palette matches the code fallback and no notice appears.
#[test]
fn appearance_loads() {
    let mut client = Client::default();
    client.language =
        config::Language::load("zh-CN").expect("the repository language files must load");
    client.apply_appearance(config::Palette::default_name());
    assert_eq!(
        client.appearance_name,
        config::Palette::default_name(),
        "after applying the default appearance the current name must stay on it"
    );
    assert_eq!(
        client.palette,
        config::Palette::built_in(),
        "the default appearance file must match the code fallback palette exactly"
    );
    assert!(
        client.notices.is_empty(),
        "the default appearance is complete and must not pop any notice, got {:?}",
        client
            .notices
            .iter()
            .map(|notice| notice.text.clone())
            .collect::<Vec<String>>()
    );

    // A fresh machine without user preferences is not a failure, so skip then.
    let Some(saved) = config::read_preferences()
        .get("appearance")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
    else {
        return;
    };
    client.apply_appearance(&saved);
    assert!(
        client.notices.is_empty(),
        "the saved appearance {saved:?} must load cleanly, got {:?}",
        client
            .notices
            .iter()
            .map(|notice| notice.text.clone())
            .collect::<Vec<String>>()
    );
}

/// A theme name with no file must be reported honestly, including the retired
/// reserved name `built_in`, instead of falling back in silence.
#[test]
fn appearance_missing() {
    let mut client = Client::default();
    client.language =
        config::Language::load("zh-CN").expect("the repository language files must load");
    for name in ["built_in", "this-theme-does-not-exist"] {
        client.notices.clear();
        client.apply_appearance(name);
        let last = client
            .notices
            .last()
            .expect("an unreadable appearance file must produce a notice");
        assert!(
            last.kind == NoticeKind::Error && last.text.contains(name),
            "the incompleteness must name the appearance {name}, got {:?}",
            last.text
        );
    }
}

/// Command names and arguments are case-sensitive end to end: `/PROFILE` and an
/// uppercased language or appearance name are refused, and so is `ALL` in `/kick`.
#[test]
fn case_sensitivity() {
    assert!(is_kick_all_argument("all"));
    for argument in ["ALL", "All", " all ", ""] {
        assert!(
            !is_kick_all_argument(argument),
            "{argument:?} must be read as a username, never as the batch parameter"
        );
    }
    // Reading a real language file is what proves the placeholder is substituted.
    let Some(available_code) = config::Language::available_codes().first().cloned() else {
        return;
    };
    let Ok(language) = config::Language::load(&available_code) else {
        return;
    };
    let mut client = Client::default();
    client.language = language;
    client.current_user_id = Some("user-self".to_string());
    assert!(
        matches!(client.execute_command("PROFILE alice"), UiIntent::Nothing),
        "a differently-cased command name must not run as /profile"
    );
    let last = client
        .notices
        .last()
        .expect("there must be an error notice");
    assert!(
        last.kind == NoticeKind::Error,
        "an unknown command must be styled as an error"
    );
    assert!(
        last.text.contains("PROFILE"),
        "the error must name the command actually typed: {}",
        last.text
    );

    // A folded language code is rejected and never written back to preferences.
    let folded_code = available_code.to_uppercase();
    if folded_code == available_code {
        return;
    }
    let before = client.language.code.clone();
    client.execute_command(&format!("language {folded_code}"));
    let last = client
        .notices
        .last()
        .expect("there must be an error notice");
    assert!(
        last.kind == NoticeKind::Error,
        "an uppercased language code must be rejected: {folded_code}"
    );
    assert_eq!(
        client.language.code, before,
        "a rejected language code must not switch the current language"
    );

    // The same rule holds for appearance names.
    let Some(name) = config::Palette::available_names().first().cloned() else {
        return;
    };
    let folded = name.to_uppercase();
    if folded == name {
        return;
    }
    client.execute_command(&format!("appearance {folded}"));
    let last = client
        .notices
        .last()
        .expect("there must be an error notice");
    assert!(
        last.kind == NoticeKind::Error,
        "an uppercased appearance name must be rejected: {folded}"
    );
}

/// /mute without arguments toggles, with arguments sets according to the parameter; both forms must land in the local do-not-disturb set
#[test]
fn mute_flag_optional() {
    let mut client = Client::default();
    client.rooms = vec![room("room-1", "team one", false)];
    client.selected_room_index = Some(0);
    client.apply_mute_command("");
    assert!(
        client.muted_room_ids.contains("room-1"),
        "without arguments the mute flag must toggle on"
    );
    client.apply_mute_command("off");
    assert!(
        !client.muted_room_ids.contains("room-1"),
        "off must switch muting off"
    );
    client.apply_mute_command("1");
    assert!(
        client.muted_room_ids.contains("room-1"),
        "1 must switch muting on"
    );
}

/// /add_member's two local errors (no room selected, not a group chat) and the silent empty name
#[test]
fn add_member_refuses() {
    let mut client = Client::default();
    // No room selected
    client.add_member("alice");
    let last = client
        .notices
        .last()
        .expect("there must be an error notice");
    assert!(
        last.kind == NoticeKind::Error,
        "with no room selected an error is expected"
    );
    // Selected room is a private chat (not a group)
    let mut private = room("room-2", "(private)", false);
    private.is_group = false;
    client.rooms = vec![private];
    client.selected_room_index = Some(0);
    client.add_member("alice");
    let last = client
        .notices
        .last()
        .expect("there must be an error notice");
    assert!(
        last.kind == NoticeKind::Error,
        "a non-group room must error"
    );
    // Group chat with an empty username: the call is now silent, no notice may appear
    client.rooms = vec![room("room-3", "team three", false)];
    let notices_before = client.notices.len();
    client.add_member("   ");
    assert_eq!(
        client.notices.len(),
        notices_before,
        "an empty username must not notify anything"
    );
}

/// The prompt is a decision, not a download: asking only queries the feed, and without
/// a downloaded package nothing is handed off and the client never closes itself.
#[test]
fn ask_before_download() {
    let mut client = Client::default();
    client.connector.set_base_url("http://127.0.0.1:1");
    assert!(
        matches!(client.execute_command("update"), UiIntent::Nothing),
        "the command must not quit and not install anything on its own"
    );
    assert!(
        client.pending_update.is_none(),
        "a check alone must not open any prompt yet"
    );

    let package = baihua_core::update::ReleasePackage {
        version: "9.9.9".to_string(),
        tag: "gui-v9.9.9".to_string(),
        file_name: "baihua-gui-9.9.9-aarch64-apple-darwin.dmg".to_string(),
        download_url: "https://example.invalid/package.dmg".to_string(),
        size_bytes: 1,
    };
    client.apply_event(PollingEvent::UpdateAvailable(package));
    let (_, stage) = client
        .pending_update
        .clone()
        .expect("the offer must become a prompt");
    assert!(
        matches!(stage, crate::client::UpdateStage::AwaitingAnswer),
        "the prompt waits for the answer before anything is fetched"
    );

    // Nothing was downloaded, so the handoff must refuse and stay silent about quitting
    assert!(
        !client.start_update_install(),
        "there is no package to install yet"
    );
    assert!(
        !client.notices.is_empty(),
        "the refusal must be explained to the user"
    );
    assert!(
        !client.quit_requested,
        "a refused handoff must never close the client"
    );

    client.apply_event(PollingEvent::UpdateUpToDate("0.1.0".to_string()));
    let expected = client
        .text("update_up_to_date")
        .replace("{version}", "0.1.0");
    assert!(
        client.notices.iter().any(|notice| notice.text == expected),
        "an up-to-date answer must be shown with the version that was checked"
    );
}
