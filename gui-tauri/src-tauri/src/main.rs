// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use tauri::State;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScanResult {
    url: String,
    classification: String,
    confidence: f64,
    risk_score: i32,
    explanation: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AppState {
    project_root: String,
}

impl AppState {
    fn new() -> Self {
        // Get project root from current executable path
        let current_dir = std::env::current_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        Self {
            project_root: current_dir,
        }
    }
}

/// Internal function to scan a URL
fn scan_url_internal(url: &str, project_root: &str) -> Result<ScanResult, String> {
    // Call Python script directly
    let output = Command::new("python3")
        .arg("detect_enhanced.py")
        .arg("--json")
        .arg(url)
        .current_dir(project_root)
        .output()
        .map_err(|e| format!("Failed to execute Python: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Python error: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON result
    let result: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("Failed to parse result: {}", e))?;

    Ok(ScanResult {
        url: result["url"].as_str().unwrap_or(url).to_string(),
        classification: result["classification"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        confidence: result["confidence"].as_f64().unwrap_or(0.0),
        risk_score: result["risk_score"].as_i64().unwrap_or(0) as i32,
        explanation: result["explanation"].as_str().unwrap_or("").to_string(),
    })
}

/// Scan a URL by calling Python script directly (no server needed)
#[tauri::command]
fn scan_url(url: String, state: State<'_, Mutex<AppState>>) -> Result<ScanResult, String> {
    let app_state = state.lock().map_err(|e| e.to_string())?;
    scan_url_internal(&url, &app_state.project_root)
}

/// Batch scan multiple URLs
#[tauri::command]
fn scan_batch(
    urls: Vec<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<ScanResult>, String> {
    let mut results = Vec::new();

    let app_state = state.lock().map_err(|e| e.to_string())?;

    for url in urls {
        match scan_url_internal(&url, &app_state.project_root) {
            Ok(result) => results.push(result),
            Err(e) => {
                results.push(ScanResult {
                    url: url,
                    classification: "error".to_string(),
                    confidence: 0.0,
                    risk_score: 0,
                    explanation: e,
                });
            }
        }
    }

    Ok(results)
}

/// Check if Python environment is available
#[tauri::command]
fn check_environment() -> Result<serde_json::Value, String> {
    let output = Command::new("python3")
        .arg("--version")
        .output()
        .map_err(|e| format!("Python not found: {}", e))?;

    let version = String::from_utf8_lossy(&output.stdout);

    // Check if required packages are installed
    let pkg_check = Command::new("python3")
        .args(&["-c", "import sklearn, colorama; print('OK')"])
        .output();

    let packages_ok = match pkg_check {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains("OK"),
        Err(_) => false,
    };

    Ok(serde_json::json!({
        "python_version": version.trim(),
        "packages_installed": packages_ok,
        "status": if packages_ok { "ready" } else { "missing_dependencies" }
    }))
}

/// Get application info
#[tauri::command]
fn get_app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "Phishing Guard",
        "version": "2.0.0",
        "mode": "standalone",
        "python_required": true,
        "features": [
            "Real-time URL scanning",
            "93 ML features",
            "4-category classification",
            "Offline capability",
            "Batch processing"
        ]
    })
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Mutex::new(AppState::new()))
        .invoke_handler(tauri::generate_handler![
            scan_url,
            scan_batch,
            check_environment,
            get_app_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
