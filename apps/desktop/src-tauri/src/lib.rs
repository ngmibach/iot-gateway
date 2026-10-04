//! Phase-0 Tauri shell: Setup Wizard UI + navigate WebView to Streamlit.
//!
//! The Python control service (:9137) and Streamlit (:8501) are started by the
//! desktop shell (`python -m shell`) or a sidecar; this binary hosts the UI.
//! Windows: UI ports use localhostForwarding — do not portproxy :9137/:8501.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

const STREAMLIT_URL: &str = "http://127.0.0.1:8501";
const WIZARD_URL: &str = "http://127.0.0.1:9138/wizard.html";

#[tauri::command]
fn streamlit_url() -> String {
    STREAMLIT_URL.to_string()
}

#[tauri::command]
fn wizard_url() -> String {
    WIZARD_URL.to_string()
}

#[tauri::command]
fn open_streamlit_in_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("main") {
        w.eval(&format!("window.location.href = '{}';", STREAMLIT_URL))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            streamlit_url,
            wizard_url,
            open_streamlit_in_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
