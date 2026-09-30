# DuckPass Agent IPC Protocol Specification (v1.0)

> **Status:** Normative specification for the current DuckPass agent protocol.  
> **Transport:** UNIX domain socket (`AF_UNIX`, `SOCK_STREAM`).  
> **Byte order:** Big-endian / network byte order for all `uint32_t` fields.  
> **Maximum payload:** 2 MiB (`2 * 1024 * 1024` bytes).  
> **Connection model:** One request / one response per connection. The server closes the accepted client connection after handling one packet.

This document specifies the Inter-Process Communication (IPC) protocol used between DuckPass clients — including the CLI and the Tauri desktop application — and the background session daemon (`duckpass-agent`).

The protocol described here intentionally matches the current C++ implementation. Section 8 documents several v1 compatibility quirks that future protocol versions may clean up.

---

## 1. Architecture & Transport Layer

```text
+-----------------------------------+        +-----------------------------------+
|            duckpass CLI           |        |      DuckPass Desktop (Tauri)     |
+-----------------+-----------------+        +-----------------+-----------------+
                  |                                            |
                  | UNIX Domain Socket                         | UNIX Domain Socket
                  | AF_UNIX / SOCK_STREAM                     | AF_UNIX / SOCK_STREAM
                  +---------------------+----------------------+
                                        |
                                        v
                       +---------------------------------+
                       |      duckpass-agent (daemon)    |
                       |---------------------------------|
                       | - Vault session owner           |
                       | - Same-UID peer verification    |
                       | - Auto-lock inactivity timer    |
                       | - VaultService / secure state   |
                       +---------------------------------+
```

The desktop application is expected to remain a thin client. It communicates with `duckpass-agent` through this protocol instead of reading or decrypting the vault file directly.

### 1.1 Socket location resolution

Clients and the daemon resolve the socket path in the following order:

1. `$XDG_RUNTIME_DIR/duckpass.sock`, if `XDG_RUNTIME_DIR` is non-empty and the referenced directory exists.
2. `~/.duckpass/agent.sock` as the fallback path on Linux/macOS.

DuckPass creates `~/.duckpass` with mode `0700` when the fallback configuration directory does not already exist, and applies `chmod(..., 0700)` to that directory in the utility layer.

On typical systemd-based Linux systems, `$XDG_RUNTIME_DIR` is a per-user runtime directory (commonly `/run/user/<UID>`). The protocol does **not** assume that DuckPass itself verifies that this directory is tmpfs-backed or mode `0700`; those properties belong to the host environment.

### 1.2 Same-UID peer authentication

DuckPass performs peer-credential verification on both sides of the connection.

#### Server verifying client

On Linux, `duckpass-agent` calls:

```cpp
getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, ...)
```

and accepts the connection only when:

```text
peer.uid == getuid()
```

On macOS, the implementation uses `getpeereid()` and compares the effective UID.

#### Client verifying daemon

The native DuckPass client also verifies the connected daemon after `connect()`. A Tauri/Rust client SHOULD do the same before sending any sensitive payload such as the master password.

This produces the intended trust relationship:

```text
client  -- verifies daemon UID --> daemon
daemon  -- verifies client UID --> client
```

> **Security boundary:** Same-UID authentication prevents access by other OS users. It does not protect against a malicious process already running as the same user.

### 1.3 Connection lifecycle

Protocol v1 uses exactly one request/response transaction per socket connection:

```text
client
  |
  | socket()
  | connect()
  | verify daemon credentials
  | write request packet
  | read response packet
  | close()
  v

duckpass-agent
  |
  | accept()
  | verify client credentials
  | read one request packet
  | process command
  | write one response packet
  | close accepted socket
  v
```

Clients MUST NOT assume that one connection can be reused for multiple commands.

---

## 2. Binary Framing

All ordinary packets have a 5-byte header followed by a variable-length payload.

### 2.1 Generic packet format

```text
Offset  Size  Field
------  ----  ------------------------------------
0       4     Payload Length (uint32_t, Big-Endian)
4       1     Opcode / Response Status
5       N     Payload bytes
```

Wire layout:

```text
+---------------------------------------------------------------+
|               Payload Length (uint32_t BE)                    |
+---------------+-----------------------------------------------+
| Opcode/Status | Payload Bytes ...                             |
+---------------+-----------------------------------------------+
```

`Payload Length` counts only the bytes after the 5-byte header. It does not include the four-byte length field or the opcode/status byte.

### 2.2 Maximum payload

The current implementation rejects any packet whose declared payload length is greater than:

```text
2 MiB = 2 * 1024 * 1024 bytes
```

A client MUST enforce the same limit before allocating a receive buffer.

A sender SHOULD reject command payloads larger than 2 MiB before serialization.

### 2.3 Partial I/O

Because `SOCK_STREAM` does not preserve message boundaries, a single `read()` or `write()` is not guaranteed to transfer all requested bytes.

Implementations MUST use `read_exact` / `write_all` semantics and retry interrupted operations where appropriate.

---

## 3. Wire Types

### 3.1 `uint8_t`

One byte, no byte-order conversion.

### 3.2 `uint32_t`

Four bytes in Big-Endian / network byte order.

C++ uses `htonl()` / `ntohl()`.

Rust clients should use:

```rust
u32::to_be_bytes()
u32::from_be_bytes()
```

### 3.3 Length-prefixed string

All protocol strings use:

```text
[uint32_t length BE] [exactly length bytes]
```

Example:

```text
"abc"

00 00 00 03 61 62 63
```

A zero-length string is represented as:

```text
00 00 00 00
```

Strings are intended to contain UTF-8 data. The current C++ framing layer treats the bytes as length-delimited data and does not add a NUL terminator.

### 3.4 Error payload

For commands that return an error description, the payload is normally one length-prefixed string:

```text
[string error_message]
```

Clients SHOULD tolerate an empty or malformed error payload and fall back to a generic local error message.

---

## 4. Command Opcodes

|    Hex | Name           | Description                                                                        |
| -----: | -------------- | ---------------------------------------------------------------------------------- |
| `0x01` | `PING`         | Probe whether the agent is responsive.                                             |
| `0x02` | `STATUS`       | Retrieve unlock state, inactivity timeout, and entry count.                        |
| `0x03` | `UNLOCK`       | Submit the master password and create an unlocked agent session.                   |
| `0x04` | `LOCK`         | Drop the active `VaultService` session from the agent.                             |
| `0x05` | `GET_ENTRY`    | Retrieve full data for one entry.                                                  |
| `0x06` | `ADD_ENTRY`    | Add a new entry. Existing service names are rejected by the current service layer. |
| `0x07` | `DELETE_ENTRY` | Delete an entry by service name.                                                   |
| `0x08` | `LIST_ENTRIES` | Return all entries or entries matching a fuzzy query.                              |
| `0x09` | `GET_TOTP`     | Generate the current TOTP code for an entry.                                       |
| `0x0A` | `STOP`         | Request clean shutdown of `duckpass-agent`.                                        |

---

## 5. Response Status Codes

Ordinary responses use the following values in byte 4 of the packet:

|    Hex | Name        | Meaning                                                                  |
| -----: | ----------- | ------------------------------------------------------------------------ |
| `0x00` | `OK`        | Operation completed successfully.                                        |
| `0x01` | `LOCKED`    | The requested operation requires an unlocked vault.                      |
| `0x02` | `ERROR`     | Validation, internal, vault, or command-specific failure.                |
| `0x03` | `NOT_FOUND` | Entry not found. Currently used by `GET_ENTRY`; see compatibility notes. |

### 5.1 PING exception

`PING` is a historical v1 exception.

Instead of returning `ResponseStatus::OK`, the current server returns:

```text
response byte = 0x81
payload       = empty
```

Clients implementing protocol v1 MUST treat `0x81` with a valid empty packet as a successful `PING`.

---

## 6. Detailed Command Specifications

### 6.1 `PING` (`0x01`)

**Request**

```text
Opcode:  0x01
Payload: empty
```

**Current v1 response**

```text
Response byte: 0x81
Payload:       empty
```

No `ResponseStatus::OK` value is used for this command in the current implementation.

---

### 6.2 `STATUS` (`0x02`)

**Request payload**

Empty.

**Response**

```text
Status: OK (0x00)
Payload: exactly 9 bytes
```

Payload:

```text
Offset  Size  Field
------  ----  -----------------------------------
0       1     is_unlocked
1       4     timeout_remaining_seconds (BE)
5       4     total_entries (BE)
```

`is_unlocked` is `1` when an active vault session exists and `0` otherwise.

`total_entries` is `0` while the agent is locked.

---

### 6.3 `UNLOCK` (`0x03`)

**Request payload**

```text
[string master_password]
```

**Response**

Success:

```text
Status:  OK (0x00)
Payload: empty
```

Failure:

```text
Status:  ERROR (0x02)
Payload: [string error_message]
```

The current implementation uses `ERROR` both for an incorrect password and other vault-loading failures.

The master password is transmitted as plaintext bytes over the local UNIX socket. Security therefore depends on the local socket boundary and same-UID peer verification.

---

### 6.4 `LOCK` (`0x04`)

**Request payload**

Empty.

**Response**

```text
Status:  OK (0x00)
Payload: empty
```

---

### 6.5 `GET_ENTRY` (`0x05`)

**Request payload**

```text
[string service]
```

**Successful response**

```text
Status: OK (0x00)

Payload:
[string service]
[string username]
[string password]
[string totp_secret]
```

**Other statuses**

```text
LOCKED    (0x01)  Agent session is locked.
NOT_FOUND (0x03)  Service does not exist.
ERROR     (0x02)  Other failure.
```

For non-`OK` responses, the payload normally contains:

```text
[string error_message]
```

> **Sensitive response:** `GET_ENTRY` exposes the plaintext password and plaintext TOTP secret to the client process. A desktop client should avoid calling this command merely to render a list or to implement operations that can remain inside the agent.

---

### 6.6 `ADD_ENTRY` (`0x06`)

**Request payload**

```text
[string service]
[string username]
[string password]
[string totp_secret]
```

`totp_secret` may be an empty string.

**Successful response**

```text
Status:  OK (0x00)
Payload: empty
```

**Failure statuses**

```text
LOCKED (0x01)
ERROR  (0x02)
```

The current `VaultService::add_entry()` rejects an existing service name. `ADD_ENTRY` is therefore **not** an upsert/update operation in protocol v1.

---

### 6.7 `DELETE_ENTRY` (`0x07`)

**Request payload**

```text
[string service]
```

**Successful response**

```text
Status:  OK (0x00)
Payload: empty
```

**Current failure behavior**

```text
LOCKED (0x01)  Agent session is locked.
ERROR  (0x02)  Entry not found or another service-layer failure.
```

The current implementation does **not** emit `NOT_FOUND (0x03)` when deletion targets a missing entry.

---

### 6.8 `LIST_ENTRIES` (`0x08`)

**Request payload**

```text
[string query]
```

An empty query requests all entries.

**Successful response**

```text
Status: OK (0x00)

Payload:
uint32_t count (BE)
repeat count times:
    [string service]
    [string username]
```

Passwords and TOTP secrets are not returned.

**Failure statuses**

```text
LOCKED (0x01)
ERROR  (0x02)
```

For a Tauri list/explorer view, this command SHOULD be preferred over `GET_ENTRY`.

---

### 6.9 `GET_TOTP` (`0x09`)

**Request payload**

```text
[string service]
```

**Successful response**

```text
Status: OK (0x00)

Payload:
[string code]
uint32_t remaining_seconds (BE)
```

Example logical result:

```text
code              = "123456"
remaining_seconds = 24
```

**Current failure behavior**

```text
LOCKED (0x01)
ERROR  (0x02)
```

A missing service or missing TOTP secret currently becomes `ERROR (0x02)`, not `NOT_FOUND`.

---

### 6.10 `STOP` (`0x0A`)

**Request payload**

Empty.

**Server response**

```text
Status:  OK (0x00)
Payload: empty
```

After handling the request, the agent leaves its main event loop and shuts down.

The current native `IpcClient::stop_agent()` sends the request and closes its socket without waiting for the acknowledgement. New clients MAY read the acknowledgement before closing.

---

## 7. Unknown or Malformed Requests

### 7.1 Unknown opcode

An unknown command opcode produces:

```text
Status:  ERROR (0x02)
Payload: [string "Unknown command opcode."]
```

### 7.2 Oversized packet

If the declared payload length exceeds 2 MiB, the server rejects the packet and closes the transaction.

### 7.3 Truncated or malformed payload

Malformed command payloads generally produce `ERROR` when the command handler can detect the malformed data.

If framing itself cannot be read successfully, the connection may simply be closed without an application-level error response.

---

## 8. Protocol v1 Compatibility Notes

Protocol v1 contains several historical inconsistencies. They are documented here so clients can interoperate correctly without guessing.

### 8.1 PING uses `0x81`

All ordinary command responses use `ResponseStatus`, but `PING` returns the special byte `0x81`.

A future protocol version may normalize this to:

```text
Status = OK
Payload = empty
```

Changing it in v1 would require updating existing clients.

### 8.2 `NOT_FOUND` is not used consistently

Current behavior:

```text
GET_ENTRY missing service    -> NOT_FOUND (0x03)
DELETE_ENTRY missing service -> ERROR     (0x02)
GET_TOTP missing service     -> ERROR     (0x02)
GET_TOTP missing secret      -> ERROR     (0x02)
```

A future protocol revision may normalize command-specific missing-resource cases.

### 8.3 `ADD_ENTRY` is not an update operation

Despite earlier documentation describing `ADD_ENTRY` as “add or update,” current service semantics reject duplicate service names.

An explicit update opcode should be introduced if desktop editing requires partial or full entry updates.

### 8.4 No protocol-version field exists on the wire

The current 5-byte header does not contain a protocol version or magic value.

Therefore, backward-compatible extension of v1 should preferably use:

- new opcodes;
- new response statuses only when old clients can safely reject them;
- optional trailing fields only where explicitly versioned by command semantics.

A future v2 protocol may introduce explicit version negotiation.

---

## 9. Security Guidance for Desktop/Tauri Clients

### 9.1 Keep the Rust backend thin

Recommended boundary:

```text
Tauri WebView
    |
    | invoke()
    v
Rust backend
    |
    | UNIX socket IPC
    v
duckpass-agent
    |
    v
VaultService / encrypted vault
```

The desktop application should not open or decrypt `.duckvault` directly.

### 9.2 Minimize plaintext crossing into the WebView

Prefer agent-side operations when possible.

For example, a future IPC command such as:

```text
COPY_PASSWORD(service)
```

would be preferable to:

```text
GET_ENTRY(service)
-> password reaches Rust
-> password crosses Tauri IPC
-> password reaches JS
-> JS writes clipboard
```

Protocol v1 does not currently provide such a command, so desktop code must treat `GET_ENTRY` data as sensitive.

### 9.3 Do not cache sensitive responses

The Tauri backend SHOULD avoid long-lived caches containing:

- master passwords;
- entry passwords;
- TOTP secrets.

Sensitive buffers should be dropped as soon as they are no longer needed.

### 9.4 Verify the daemon before sending `UNLOCK`

On platforms where peer credentials are available, the client SHOULD verify the daemon UID before sending the master password.

---

## 10. Rust / Tauri Client Reference

The example below focuses on the protocol framing and current Linux connection model.

It deliberately opens one socket per request.

```rust
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct Packet {
    pub code: u8,
    pub payload: Vec<u8>,
}

pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    fn connect(&self) -> io::Result<UnixStream> {
        let stream = UnixStream::connect(&self.socket_path)?;

        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;

        // IMPORTANT:
        // Verify the connected daemon's peer credentials here before sending
        // sensitive material. On Linux this can be implemented with
        // getsockopt(SOL_SOCKET, SO_PEERCRED).
        verify_daemon_peer(&stream)?;

        Ok(stream)
    }

    pub fn request(&self, opcode: u8, payload: &[u8]) -> io::Result<Packet> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DuckPass IPC payload exceeds 2 MiB",
            ));
        }

        let mut stream = self.connect()?;
        write_packet(&mut stream, opcode, payload)?;
        read_packet(&mut stream)
    }
}

pub fn write_packet(
    stream: &mut UnixStream,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DuckPass IPC payload exceeds 2 MiB",
        ));
    }

    let length = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "payload length overflow")
    })?;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&[opcode])?;
    stream.write_all(payload)?;
    Ok(())
}

pub fn read_packet(stream: &mut UnixStream) -> io::Result<Packet> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;

    let length = u32::from_be_bytes(len_buf) as usize;
    if length > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DuckPass IPC peer declared payload larger than 2 MiB",
        ));
    }

    let mut code_buf = [0u8; 1];
    stream.read_exact(&mut code_buf)?;

    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;

    Ok(Packet {
        code: code_buf[0],
        payload,
    })
}

pub fn append_string(buf: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "string length overflow")
    })?;

    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
    Ok(())
}

pub fn read_string(payload: &[u8], offset: &mut usize) -> io::Result<String> {
    let end_len = offset
        .checked_add(4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offset overflow"))?;

    if end_len > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated DuckPass string length",
        ));
    }

    let len = u32::from_be_bytes(
        payload[*offset..end_len]
            .try_into()
            .expect("slice length was checked"),
    ) as usize;

    *offset = end_len;

    let end = offset
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offset overflow"))?;

    if end > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated DuckPass string",
        ));
    }

    let value = std::str::from_utf8(&payload[*offset..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8"))?
        .to_owned();

    *offset = end;
    Ok(value)
}

#[cfg(target_os = "linux")]
fn verify_daemon_peer(stream: &UnixStream) -> io::Result<()> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred = MaybeUninit::<libc::ucred>::zeroed();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };

    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let cred = unsafe { cred.assume_init() };
    let expected_uid = unsafe { libc::geteuid() };

    if cred.uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "duckpass-agent UID does not match current user",
        ));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_daemon_peer(_stream: &UnixStream) -> io::Result<()> {
    // Implement the platform-specific equivalent before treating this
    // reference client as security-complete on non-Linux platforms.
    Ok(())
}
```

For Linux builds using the peer-verification example above, add:

```toml
[dependencies]
libc = "0.2"
```

---

## 11. Suggested Tauri Command Mapping

A thin Rust backend can expose typed Tauri commands while keeping raw protocol details out of JavaScript.

Example mapping:

```text
Tauri command             DuckPass IPC
------------------------  ----------------
agent_status()            STATUS
unlock(password)          UNLOCK
lock()                    LOCK
list_entries(query)       LIST_ENTRIES
get_entry(service)        GET_ENTRY
add_entry(...)            ADD_ENTRY
delete_entry(service)     DELETE_ENTRY
get_totp(service)         GET_TOTP
stop_agent()              STOP
```

The JavaScript/TypeScript frontend should consume typed Rust results rather than construct DuckPass binary packets itself.

---

## 12. v1 Implementation Checklist

A compatible new client should satisfy all of the following:

- [ ] Resolve the same socket path as DuckPass.
- [ ] Verify the connected daemon's same-user credentials where supported.
- [ ] Open a fresh socket for every request.
- [ ] Use a 4-byte Big-Endian payload length.
- [ ] Use one-byte command/status fields.
- [ ] Enforce the 2 MiB maximum before allocating the payload.
- [ ] Use length-prefixed strings with Big-Endian 32-bit lengths.
- [ ] Treat `PING -> 0x81 + empty payload` as success.
- [ ] Handle `LOCKED`, `ERROR`, and `NOT_FOUND`.
- [ ] Do not expect `NOT_FOUND` from `DELETE_ENTRY` or `GET_TOTP` in v1.
- [ ] Treat `GET_ENTRY` as sensitive because it returns plaintext secrets.
- [ ] Do not assume persistent/reusable socket connections.
- [ ] Apply read/write timeouts so a stalled agent cannot block the UI indefinitely.

---

## 13. Future Protocol Evolution

Protocol v1 is intentionally kept compatible with the current C++ implementation.

Before introducing a v2 protocol, the following changes are candidates:

1. Normalize `PING` to ordinary `OK`.
2. Normalize `NOT_FOUND` across entry-related commands.
3. Add an explicit `UPDATE_ENTRY` command.
4. Add explicit protocol version negotiation.
5. Add secret-minimizing operations such as agent-side clipboard copy.
6. Consider request identifiers only if persistent or multiplexed connections are introduced.
7. Preserve the 2 MiB hard maximum unless a concrete use case requires a larger bound.

Until a v2 migration is explicitly implemented, clients should follow the v1 behavior documented above.
