//! Clickable Tauri desktop app: spawn Python shell, open Setup Wizard window.
//!
//! On launch the Rust side starts `python -m shell --start-services --no-browser`
//! (wizard on :9138, control API on :9137). The WebView loads `splash.html` then
//! navigates to the wizard once `/api/wizard/env` responds — so Monitoring's
//! same-origin `/api/v1` proxy works.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, RunEvent};

const WIZARD_URL: &str = "http://127.0.0.1:9138/wizard.html";
const STREAMLIT_URL: &str = "http://127.0.0.1:8501";

struct Backend(Mutex<Option<Child>>);

fn repo_paths(app: &AppHandle) -> (PathBuf, PathBuf) {
    // Dev: CARGO_MANIFEST_DIR = apps/desktop/src-tauri → desktop + control-service.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let desktop = manifest.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| manifest.clone());
    let control = desktop
        .parent()
        .map(|p| p.join("control-service"))
        .unwrap_or_else(|| desktop.join("control-service"));

    // Packaged: resource dir may contain bundled python packages.
    if let Ok(res) = app.path().resource_dir() {
        let bundled_desktop = res.join("desktop");
        let bundled_cs = res.join("control-service");
        if bundled_desktop.is_dir() && bundled_cs.is_dir() {
            return (bundled_desktop, bundled_cs);
        }
    }
    (desktop, control)
}

fn find_python() -> PathBuf {
    if cfg!(windows) {
        for name in ["python.exe", "python3.exe", "py.exe"] {
            if let Ok(out) = Command::new("where").arg(name).output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Some(line) = text.lines().next() {
                        return PathBuf::from(line.trim());
                    }
                }
            }
        }
        PathBuf::from("python")
    } else {
        for name in ["python3", "python"] {
            if let Ok(out) = Command::new("which").arg(name).output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Some(line) = text.lines().next() {
                        return PathBuf::from(line.trim());
                    }
                }
            }
        }
        PathBuf::from("python3")
    }
}

fn spawn_backend(app: &AppHandle) -> Result<Child, String> {
    let (desktop, control) = repo_paths(app);
    let py = find_python();
    let path_sep = if cfg!(windows) { ";" } else { ":" };
    let pythonpath = format!(
        "{}{}{}{}{}",
        desktop.display(),
        path_sep,
        control.display(),
        path_sep,
        std::env::var("PYTHONPATH").unwrap_or_default()
    );

    let mut cmd = Command::new(&py);
    cmd.args([
        "-m",
        "shell",
        "--start-services",
        "--no-browser",
    ])
    .env("PYTHONPATH", pythonpath)
    .current_dir(&desktop)
    .stdout(Stdio::null())
    .stderr(Stdio::null());

    // Hide console window on Windows child.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    cmd.spawn()
        .map_err(|e| format!("failed to start python shell with {:?}: {e}", py))
}

fn wait_wizard_ready(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(resp) = ureq_get("http://127.0.0.1:9138/api/wizard/env") {
            if resp {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(400));
    }
    false
}

/// Tiny HTTP GET without adding a dependency — use std only via TcpStream-ish is heavy;
/// splash.html already polls. This helper uses `curl`/`powershell` if present, else skip.
fn ureq_get(url: &str) -> Result<bool, ()> {
    let status = if cfg!(windows) {
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("try {{ (Invoke-WebRequest -UseBasicParsing '{url}').StatusCode }} catch {{ 0 }}"),
            ])
            .output()
    } else {
        Command::new("curl")
            .args(["-fsS", "-o", "/dev/null", "-w", "%{http_code}", url])
            .output()
    };
    match status {
        Ok(out) if out.status.success() => {
            let code = String::from_utf8_lossy(&out.stdout);
            Ok(code.trim().starts_with('2') || code.trim() == "200")
        }
        _ => Err(()),
    }
}

#[tauri::command]
fn streamlit_url() -> String {
    STREAMLIT_URL.to_string()
}

#[tauri::command]
fn wizard_url() -> String {
    WIZARD_URL.to_string()
}

#[tauri::command]
fn open_wizard_in_window(app: AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("main") {
        w.eval(&format!("window.location.href = '{}';", WIZARD_URL))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn open_streamlit_in_window(app: AppHandle) -> Result<(), String> {
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
        .manage(Backend(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            streamlit_url,
            wizard_url,
            open_wizard_in_window,
            open_streamlit_in_window
        ])
        .setup(|app| {
            match spawn_backend(app.handle()) {
                Ok(child) => {
                    if let Ok(mut slot) = app.state::<Backend>().0.lock() {
                        *slot = Some(child);
                    }
                }
                Err(e) => {
                    eprintln!("iot-gateway-monitor: {e}");
                }
            }
            let handle = app.handle().clone();
            thread::spawn(move || {
                if wait_wizard_ready(Duration::from_secs(45)) {
                    let _ = open_wizard_in_window(handle);
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app_handle.try_state::<Backend>() {
                    if let Ok(mut slot) = state.0.lock() {
                        if let Some(mut child) = slot.take() {
                            let _ = child.kill();
                            let _ = child.wait();
                        }
                    }
                }
            }
        });
}
