pub mod ipc;

use ipc::types::{AgentStatus, EntryDetail, EntrySummary, TotpResult};
use ipc::DuckPassIpcClient;

#[tauri::command]
fn ping_agent() -> Result<bool, String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.ping().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_agent_status() -> Result<AgentStatus, String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.get_status().map_err(|e| e.to_string())
}

#[tauri::command]
fn unlock_vault(master_password: String) -> Result<(), String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.unlock(&master_password).map_err(|e| e.to_string())
}

#[tauri::command]
fn lock_vault() -> Result<(), String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.lock().map_err(|e| e.to_string())
}

#[tauri::command]
fn list_entries(query: Option<String>) -> Result<Vec<EntrySummary>, String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    let q = query.unwrap_or_default();
    client.list_entries(&q).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_entry(service: String) -> Result<EntryDetail, String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.get_entry(&service).map_err(|e| e.to_string())
}

#[tauri::command]
fn add_entry(entry: EntryDetail) -> Result<(), String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.add_entry(entry).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_entry(service: String) -> Result<(), String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.delete_entry(&service).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_totp(service: String) -> Result<TotpResult, String> {
    let client = DuckPassIpcClient::connect().map_err(|e| e.to_string())?;
    client.get_totp(&service).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            ping_agent,
            get_agent_status,
            unlock_vault,
            lock_vault,
            list_entries,
            get_entry,
            add_entry,
            delete_entry,
            get_totp
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
