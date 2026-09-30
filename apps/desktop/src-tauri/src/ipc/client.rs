use std::env;
use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use super::protocol::{append_string, extract_string, extract_u32, CommandOpcode, ResponseStatus};
use super::types::{AgentStatus, EntryDetail, EntrySummary, TotpResult};

const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024; // 2 MiB protocol limit
const SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

pub fn resolve_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        if !runtime_dir.is_empty() {
            let path = PathBuf::from(runtime_dir).join("duckpass.sock");
            if path.exists() {
                return path;
            }
        }
    }

    if let Ok(home) = env::var("HOME") {
        let path = PathBuf::from(home).join(".duckpass").join("agent.sock");
        if path.exists() {
            return path;
        }
    }

    // Default fallback
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("duckpass.sock")
    } else if let Ok(home) = env::var("HOME") {
        PathBuf::from(home).join(".duckpass").join("agent.sock")
    } else {
        PathBuf::from("/tmp/duckpass.sock")
    }
}

pub struct DuckPassIpcClient {
    socket_path: PathBuf,
}

impl DuckPassIpcClient {
    pub fn connect() -> io::Result<Self> {
        let socket_path = resolve_socket_path();
        if !socket_path.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("DuckPass agent socket not found at {:?}", socket_path),
            ));
        }
        Ok(Self { socket_path })
    }

    /// Protocol v1 uses exactly one request/response transaction per socket connection.
    fn exchange_packet(
        &self,
        opcode: CommandOpcode,
        payload: &[u8],
    ) -> io::Result<(ResponseStatus, Vec<u8>)> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Request payload size {} exceeds 2 MiB limit", payload.len()),
            ));
        }

        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;

        // Send request: [len (4B BE)][opcode (1B)][payload]
        let length = (payload.len() as u32).to_be_bytes();
        stream.write_all(&length)?;
        stream.write_all(&[opcode as u8])?;
        if !payload.is_empty() {
            stream.write_all(payload)?;
        }
        stream.flush()?;

        // Read response: [len (4B BE)][status (1B)][payload]
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        if resp_len > MAX_PAYLOAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Response payload size {} exceeds 2 MiB limit", resp_len),
            ));
        }

        let mut status_buf = [0u8; 1];
        stream.read_exact(&mut status_buf)?;
        let status = ResponseStatus::from_u8(status_buf[0])?;

        let mut resp_payload = vec![0u8; resp_len];
        if resp_len > 0 {
            stream.read_exact(&mut resp_payload)?;
        }

        // Socket is closed when stream drops, adhering strictly to single-transaction lifecycle
        Ok((status, resp_payload))
    }

    pub fn ping(&self) -> io::Result<bool> {
        let (status, payload) = self.exchange_packet(CommandOpcode::Ping, &[])?;
        // Protocol v1 returns 0x81 (Pong) with empty payload
        Ok(status == ResponseStatus::Pong && payload.is_empty())
    }

    pub fn get_status(&self) -> io::Result<AgentStatus> {
        let (status, payload) = self.exchange_packet(CommandOpcode::Status, &[])?;
        if status != ResponseStatus::Ok {
            let mut offset = 0;
            let msg = extract_string(&payload, &mut offset)
                .unwrap_or_else(|_| format!("Get status failed with status: {:?}", status));
            return Err(Error::new(ErrorKind::Other, msg));
        }
        if payload.len() < 9 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Status response payload too short (expected 9 bytes)",
            ));
        }

        let is_unlocked = payload[0] != 0;
        let timeout_remaining_seconds =
            u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let total_entries = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);

        Ok(AgentStatus {
            is_unlocked,
            timeout_remaining_seconds,
            total_entries,
        })
    }

    pub fn unlock(&self, master_password: &str) -> io::Result<()> {
        let mut payload = Vec::new();
        append_string(&mut payload, master_password);

        let (status, resp) = self.exchange_packet(CommandOpcode::Unlock, &payload)?;
        match status {
            ResponseStatus::Ok => Ok(()),
            ResponseStatus::Error => {
                let mut offset = 0;
                let err_msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Failed to unlock vault".to_string());
                Err(Error::new(ErrorKind::PermissionDenied, err_msg))
            }
            other => Err(Error::new(
                ErrorKind::Other,
                format!("Unexpected unlock status: {:?}", other),
            )),
        }
    }

    pub fn lock(&self) -> io::Result<()> {
        let (status, _) = self.exchange_packet(CommandOpcode::Lock, &[])?;
        if status == ResponseStatus::Ok {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "Lock vault failed"))
        }
    }

    pub fn list_entries(&self, query: &str) -> io::Result<Vec<EntrySummary>> {
        let mut payload = Vec::new();
        append_string(&mut payload, query);

        let (status, resp) = self.exchange_packet(CommandOpcode::ListEntries, &payload)?;
        match status {
            ResponseStatus::Ok => {
                let mut offset = 0;
                let count = extract_u32(&resp, &mut offset)?;
                let mut entries = Vec::with_capacity(count as usize);

                for _ in 0..count {
                    let service = extract_string(&resp, &mut offset)?;
                    let username = extract_string(&resp, &mut offset)?;
                    entries.push(EntrySummary { service, username });
                }

                Ok(entries)
            }
            ResponseStatus::Locked => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Vault session is locked in agent".to_string());
                Err(Error::new(ErrorKind::PermissionDenied, msg))
            }
            ResponseStatus::Error => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Failed to list entries".to_string());
                Err(Error::new(ErrorKind::Other, msg))
            }
            other => Err(Error::new(
                ErrorKind::Other,
                format!("Unexpected list status: {:?}", other),
            )),
        }
    }

    pub fn get_entry(&self, service: &str) -> io::Result<EntryDetail> {
        let mut payload = Vec::new();
        append_string(&mut payload, service);

        let (status, resp) = self.exchange_packet(CommandOpcode::GetEntry, &payload)?;
        match status {
            ResponseStatus::Ok => {
                let mut offset = 0;
                let s = extract_string(&resp, &mut offset)?;
                let u = extract_string(&resp, &mut offset)?;
                let p = extract_string(&resp, &mut offset)?;
                let t = extract_string(&resp, &mut offset)?;
                Ok(EntryDetail {
                    service: s,
                    username: u,
                    password: p,
                    totp_secret: t,
                })
            }
            ResponseStatus::Locked => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Vault session is locked in agent".to_string());
                Err(Error::new(ErrorKind::PermissionDenied, msg))
            }
            ResponseStatus::NotFound => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| format!("Entry '{}' not found", service));
                Err(Error::new(ErrorKind::NotFound, msg))
            }
            other => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| format!("Get entry failed with status: {:?}", other));
                Err(Error::new(ErrorKind::Other, msg))
            }
        }
    }

    pub fn add_entry(&self, entry: EntryDetail) -> io::Result<()> {
        let mut payload = Vec::new();
        append_string(&mut payload, &entry.service);
        append_string(&mut payload, &entry.username);
        append_string(&mut payload, &entry.password);
        append_string(&mut payload, &entry.totp_secret);

        let (status, resp) = self.exchange_packet(CommandOpcode::AddEntry, &payload)?;
        match status {
            ResponseStatus::Ok => Ok(()),
            ResponseStatus::Locked => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Vault session is locked in agent".to_string());
                Err(Error::new(ErrorKind::PermissionDenied, msg))
            }
            ResponseStatus::Error => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Failed to add entry".to_string());
                Err(Error::new(ErrorKind::InvalidInput, msg))
            }
            other => Err(Error::new(
                ErrorKind::Other,
                format!("Unexpected add entry status: {:?}", other),
            )),
        }
    }

    pub fn delete_entry(&self, service: &str) -> io::Result<()> {
        let mut payload = Vec::new();
        append_string(&mut payload, service);

        let (status, resp) = self.exchange_packet(CommandOpcode::DeleteEntry, &payload)?;
        match status {
            ResponseStatus::Ok => Ok(()),
            ResponseStatus::Locked => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Vault session is locked in agent".to_string());
                Err(Error::new(ErrorKind::PermissionDenied, msg))
            }
            // In protocol v1, missing entry returns ERROR with "Service not found."
            ResponseStatus::Error => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| format!("Service '{}' not found", service));
                Err(Error::new(ErrorKind::NotFound, msg))
            }
            other => Err(Error::new(
                ErrorKind::Other,
                format!("Unexpected delete status: {:?}", other),
            )),
        }
    }

    pub fn get_totp(&self, service: &str) -> io::Result<TotpResult> {
        let mut payload = Vec::new();
        append_string(&mut payload, service);

        let (status, resp) = self.exchange_packet(CommandOpcode::GetTotp, &payload)?;
        match status {
            ResponseStatus::Ok => {
                let mut offset = 0;
                let code = extract_string(&resp, &mut offset)?;
                let remaining_seconds = extract_u32(&resp, &mut offset)?;
                Ok(TotpResult {
                    code,
                    remaining_seconds,
                })
            }
            ResponseStatus::Locked => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| "Vault session is locked in agent".to_string());
                Err(Error::new(ErrorKind::PermissionDenied, msg))
            }
            // In protocol v1, missing service or missing secret returns ERROR
            ResponseStatus::Error => {
                let mut offset = 0;
                let msg = extract_string(&resp, &mut offset)
                    .unwrap_or_else(|_| format!("No TOTP secret configured for '{}'", service));
                Err(Error::new(ErrorKind::NotFound, msg))
            }
            other => Err(Error::new(
                ErrorKind::Other,
                format!("Unexpected TOTP status: {:?}", other),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_ping_and_status() {
        let client = DuckPassIpcClient::connect().expect("Failed to connect to agent socket");
        let pong = client.ping().expect("Ping failed");
        assert!(pong, "Ping should return true");
        let status = client.get_status().expect("Status failed");
        println!(
            "Connected to agent: is_unlocked={}, timeout={}, total_entries={}",
            status.is_unlocked, status.timeout_remaining_seconds, status.total_entries
        );
    }
}
