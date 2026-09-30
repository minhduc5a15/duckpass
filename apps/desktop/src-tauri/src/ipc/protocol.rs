use std::io::{self, Error, ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandOpcode {
    Ping = 0x01,
    Status = 0x02,
    Unlock = 0x03,
    Lock = 0x04,
    GetEntry = 0x05,
    AddEntry = 0x06,
    DeleteEntry = 0x07,
    ListEntries = 0x08,
    GetTotp = 0x09,
    Stop = 0x0A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Ok = 0x00,
    Locked = 0x01,
    Error = 0x02,
    NotFound = 0x03,
    Pong = 0x81,
}

impl ResponseStatus {
    pub fn from_u8(value: u8) -> io::Result<Self> {
        match value {
            0x00 => Ok(ResponseStatus::Ok),
            0x01 => Ok(ResponseStatus::Locked),
            0x02 => Ok(ResponseStatus::Error),
            0x03 => Ok(ResponseStatus::NotFound),
            0x81 => Ok(ResponseStatus::Pong),
            other => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unknown response status code: 0x{:02x}", other),
            )),
        }
    }
}

pub fn append_string(buf: &mut Vec<u8>, s: &str) {
    let len = (s.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(s.as_bytes());
}

pub fn extract_string(buf: &[u8], offset: &mut usize) -> io::Result<String> {
    if *offset + 4 > buf.len() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Buffer too short for string length prefix",
        ));
    }
    let len_bytes = [
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ];
    *offset += 4;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if *offset + len > buf.len() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Buffer too short for string content",
        ));
    }
    let s_bytes = &buf[*offset..*offset + len];
    *offset += len;

    String::from_utf8(s_bytes.to_vec())
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Invalid UTF-8: {}", e)))
}

pub fn extract_u32(buf: &[u8], offset: &mut usize) -> io::Result<u32> {
    if *offset + 4 > buf.len() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Buffer too short for u32 integer",
        ));
    }
    let bytes = [
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ];
    *offset += 4;
    Ok(u32::from_be_bytes(bytes))
}
