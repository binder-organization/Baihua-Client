pub mod app;
pub mod encryption;
pub mod models;
pub mod network;

use std::collections::HashMap;
use std::process::exit;

use crate::app::{BaihuaApp, Theme};
use eframe::egui::{Vec2, ViewportBuilder};
use eframe::{NativeOptions, run_native};
use env_logger::{Builder, Env};
use serde_json::Value;

fn load_json(path: &str) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null)
}

fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    let language_values: HashMap<String, Value> = ["zh-CN", "en-US"]
        .into_iter()
        .filter_map(|code| {
            let value = load_json(&format!("assets/config/languages/{code}.json"));
            if value.is_null() {
                None
            } else {
                Some((code.to_string(), value))
            }
        })
        .collect();

    let theme_values: HashMap<String, Value> = ["light", "dark"]
        .into_iter()
        .filter_map(|code| {
            let value = load_json(&format!("assets/config/themes/{code}.json"));
            if value.is_null() {
                None
            } else {
                Some((code.to_string(), value))
            }
        })
        .collect();

    let preferences = load_json("assets/config/preferences.json");
    let language_code = preferences
        .get("language")
        .and_then(|value| value.as_str())
        .unwrap_or("zh-CN")
        .to_string();
    let theme_code = preferences
        .get("theme")
        .and_then(|value| value.as_str())
        .unwrap_or("light")
        .to_string();

    let theme_value: Theme = theme_values
        .get(&theme_code)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(|| {
            serde_json::from_value(
                theme_values
                    .get("light")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
            .unwrap_or_else(|_| {
                eprintln!("Missing theme configuration under assets/config/themes/");
                exit(1);
            })
        });

    let _ = run_native(
        "Baihua Client v0.1.0",
        NativeOptions {
            viewport: ViewportBuilder {
                min_inner_size: Some(Vec2::new(450.0, 400.0)),
                ..Default::default()
            },
            ..Default::default()
        },
        Box::new(move |creation_context| {
            Ok(Box::new(BaihuaApp::new(
                creation_context,
                None,
                None,
                theme_value,
                language_values,
                theme_values,
                language_code,
                theme_code,
            )))
        }),
    );
}
