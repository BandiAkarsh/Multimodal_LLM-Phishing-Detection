// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem, CustomMenuItem};
use serde::{Deserialize, Serialize};

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command

#[derive(Serialize, Deserialize)]
struct ScanResult {
    url: String,
    classification: String,
    confidence: f64,
    risk_score: i32,
    explanation: String,
}

#[derive(Serialize, Deserialize)]
struct ApiResponse {
    url: String,
    classification: String,
    confidence: f64,
    risk_score: i32,
    explanation: String,
    features: serde_json::Value,
}

/// Command to scan a URL via the API
#[tauri::command]
async fn scan_url(url: String, token: String) -> Result<ScanResult, String> {
    // Call the Python API
    let client = reqwest::Client::new();
    let api_url = "http://localhost:8000/api/v1/analyze";
    
    let request_body = serde_json::json!({
        "url": url,
        "force_scan": false
    });
    
    let response = client
        .post(api_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(format!("API error {}: {}", status, error_text));
    }
    
    let api_result: ApiResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    Ok(ScanResult {
        url: api_result.url,
        classification: api_result.classification,
        confidence: api_result.confidence,
        risk_score: api_result.risk_score,
        explanation: api_result.explanation,
    })
}

/// Command to authenticate with the API
#[tauri::command]
async fn authenticate(username: String, password: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let api_url = "http://localhost:8000/auth/login";
    
    let request_body = serde_json::json!({
        "username": username,
        "password": password
    });
    
    let response = client
        .post(api_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Auth request failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err("Authentication failed".to_string());
    }
    
    let auth_result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse auth response: {}", e))?;
    
    let token = auth_result["access_token"]
        .as_str()
        .ok_or("Invalid token format")?;
    
    Ok(token.to_string())
}

/// Command to check API health
#[tauri::command]
async fn check_api_health() -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let api_url = "http://localhost:8000/health";
    
    let response = client
        .get(api_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Health check failed: {}", e))?;
    
    let health: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse health response: {}", e))?;
    
    Ok(health)
}

/// Command to save authentication token
#[tauri::command]
fn save_token(token: String) -> Result<(), String> {
    // In a real app, use secure storage
    // For now, we'll rely on the frontend to manage it
    Ok(())
}

/// Command to show notification
#[tauri::command]
fn show_notification(title: String, body: String) {
    tauri::api::notification::Notification::new(&title)
        .title(title)
        .body(body)
        .show()
        .unwrap_or_default();
}

fn main() {
    // System tray menu
    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("open", "Open"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit", "Quit"));

    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_url,
            authenticate,
            check_api_health,
            save_token,
            show_notification
        ])
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick {
                position: _,
                size: _,
                ..
            } => {
                let window = app.get_window("main").unwrap();
                window.show().unwrap();
                window.set_focus().unwrap();
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    std::process::exit(0);
                }
                "open" => {
                    let window = app.get_window("main").unwrap();
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                // Hide to tray instead of closing
                event.window().hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
