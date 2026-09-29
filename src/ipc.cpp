#include "duckpass/ipc.h"

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "duckpass/utils.h"

namespace duckpass::ipc {

    namespace {
        bool write_all(int fd, const void* buffer, size_t length) {
            const auto* ptr = static_cast<const uint8_t*>(buffer);
            size_t remaining = length;
            while (remaining > 0) {
                ssize_t written = write(fd, ptr, remaining);
                if (written < 0) {
                    if (errno == EINTR) continue;
                    return false;
                }
                remaining -= written;
                ptr += written;
            }
            return true;
        }

        bool read_all(int fd, void* buffer, size_t length) {
            auto* ptr = static_cast<uint8_t*>(buffer);
            size_t remaining = length;
            while (remaining > 0) {
                ssize_t bytes_read = read(fd, ptr, remaining);
                if (bytes_read < 0) {
                    if (errno == EINTR) continue;
                    return false;
                }
                if (bytes_read == 0) {
                    return false;  // EOF
                }
                remaining -= bytes_read;
                ptr += bytes_read;
            }
            return true;
        }

        void append_string(std::vector<uint8_t>& buf, std::string_view str) {
            uint32_t const len = htonl(static_cast<uint32_t>(str.size()));
            const auto* len_ptr = reinterpret_cast<const uint8_t*>(&len);
            buf.insert(buf.end(), len_ptr, len_ptr + 4);
            buf.insert(buf.end(), str.begin(), str.end());
        }

        void append_secure_string(std::vector<uint8_t>& buf, const duckpass::SecureString& str) {
            uint32_t const len = htonl(static_cast<uint32_t>(str.size()));
            const auto* len_ptr = reinterpret_cast<const uint8_t*>(&len);
            buf.insert(buf.end(), len_ptr, len_ptr + 4);
            buf.insert(buf.end(), str.data(), str.data() + str.size());
        }

        struct ScopedCleanse {
            std::vector<uint8_t>& buf;
            explicit ScopedCleanse(std::vector<uint8_t>& b) : buf(b) {}
            ~ScopedCleanse() {
                if (!buf.empty()) {
                    OPENSSL_cleanse(buf.data(), buf.size());
                }
            }
        };

        bool extract_string(const std::vector<uint8_t>& buf, size_t& offset, std::string& out_str) {
            if (offset + 4 > buf.size()) return false;
            uint32_t raw_len = 0;
            std::memcpy(&raw_len, buf.data() + offset, 4);
            offset += 4;
            uint32_t const len = ntohl(raw_len);
            if (len > buf.size() - offset) return false;
            out_str.assign(reinterpret_cast<const char*>(buf.data() + offset), len);
            offset += len;
            return true;
        }

        bool extract_secure_string(const std::vector<uint8_t>& buf, size_t& offset, duckpass::SecureString& out_str) {
            if (offset + 4 > buf.size()) return false;
            uint32_t raw_len = 0;
            std::memcpy(&raw_len, buf.data() + offset, 4);
            offset += 4;
            uint32_t const len = ntohl(raw_len);
            if (len > buf.size() - offset) return false;
            out_str.assign(reinterpret_cast<const char*>(buf.data() + offset), len);
            offset += len;
            return true;
        }
    }  // namespace

    std::filesystem::path get_socket_path() {
        if (const char* runtime_dir = std::getenv("XDG_RUNTIME_DIR")) {
            if (std::strlen(runtime_dir) > 0 && std::filesystem::exists(runtime_dir)) {
                return std::filesystem::path(runtime_dir) / "duckpass.sock";
            }
        }
        return utils::get_config_directory() / "agent.sock";
    }

    std::vector<uint8_t> serialize_packet(uint8_t opcode, const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> packet;
        uint32_t const len = htonl(static_cast<uint32_t>(payload.size()));
        const auto* len_ptr = reinterpret_cast<const uint8_t*>(&len);
        packet.insert(packet.end(), len_ptr, len_ptr + 4);
        packet.push_back(opcode);
        packet.insert(packet.end(), payload.begin(), payload.end());
        return packet;
    }

    bool read_packet(int fd, uint8_t& out_opcode, std::vector<uint8_t>& out_payload) {
        uint32_t raw_len = 0;
        if (!read_all(fd, &raw_len, 4)) {
            return false;
        }
        uint32_t const payload_len = ntohl(raw_len);
        if (payload_len > 2 * 1024 * 1024) {  // 2MB sanity limit
            return false;
        }

        if (!read_all(fd, &out_opcode, 1)) {
            return false;
        }

        try {
            out_payload.resize(payload_len);
        } catch (const std::bad_alloc&) {
            return false;
        }

        if (payload_len > 0) {
            if (!read_all(fd, out_payload.data(), payload_len)) {
                OPENSSL_cleanse(out_payload.data(), out_payload.size());
                out_payload.clear();
                return false;
            }
        }
        return true;
    }

    bool write_packet(int fd, uint8_t opcode, const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> packet = serialize_packet(opcode, payload);
        bool const ok = write_all(fd, packet.data(), packet.size());
        OPENSSL_cleanse(packet.data(), packet.size());
        return ok;
    }

    bool verify_peer_credentials(int fd) {
#if defined(__linux__)
        struct ucred cred {};
        socklen_t len = sizeof(cred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
            return false;
        }
        return cred.uid == getuid();
#elif defined(__APPLE__)
        uid_t euid = 0;
        gid_t egid = 0;
        if (getpeereid(fd, &euid, &egid) == -1) {
            return false;
        }
        return euid == getuid();
#else
        return true;  // Fallback for systems without peercred
#endif
    }

    // --- IpcClient Implementation ---

    IpcClient::IpcClient() : socket_path_(get_socket_path()) {}

    IpcClient::IpcClient(std::filesystem::path socket_path) : socket_path_(std::move(socket_path)) {}

    IpcClient::~IpcClient() = default;

    int IpcClient::connect_socket() {
        if (!std::filesystem::exists(socket_path_)) {
            return -1;
        }

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }

        // Set 2.0s timeout to prevent client hanging if daemon stalls
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }

        if (!verify_peer_credentials(fd)) {
            close(fd);
            return -1;
        }

        return fd;
    }

    bool IpcClient::is_agent_available() { return ping(); }

    bool IpcClient::ping() {
        int fd = connect_socket();
        if (fd < 0) return false;

        bool const sent = write_packet(fd, static_cast<uint8_t>(CommandOpcode::PING), {});
        if (!sent) {
            close(fd);
            return false;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> payload;
        bool const recv = read_packet(fd, resp_opcode, payload);
        close(fd);
        return recv && (resp_opcode == 0x81);
    }

    std::optional<AgentStatus> IpcClient::get_status() {
        int fd = connect_socket();
        if (fd < 0) return std::nullopt;

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::STATUS), {})) {
            close(fd);
            return std::nullopt;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> payload;
        if (!read_packet(fd, resp_opcode, payload) || payload.size() < 9) {
            close(fd);
            return std::nullopt;
        }
        close(fd);

        AgentStatus status;
        status.is_unlocked = (payload[0] != 0);

        uint32_t raw_timeout = 0;
        std::memcpy(&raw_timeout, payload.data() + 1, 4);
        status.timeout_remaining_seconds = ntohl(raw_timeout);

        uint32_t raw_total = 0;
        std::memcpy(&raw_total, payload.data() + 5, 4);
        status.total_entries = ntohl(raw_total);

        return status;
    }

    bool IpcClient::unlock(const duckpass::SecureString& master_password, std::string& out_error) {
        int fd = connect_socket();
        if (fd < 0) {
            out_error = "Could not connect to duckpass-agent.";
            return false;
        }

        std::vector<uint8_t> payload;
        ScopedCleanse sc_p(payload);
        append_secure_string(payload, master_password);

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::UNLOCK), payload)) {
            close(fd);
            out_error = "Failed to send unlock command.";
            return false;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        ScopedCleanse sc_r(resp_payload);
        if (!read_packet(fd, resp_opcode, resp_payload)) {
            close(fd);
            out_error = "Agent closed connection.";
            return false;
        }
        close(fd);

        if (resp_opcode == static_cast<uint8_t>(ResponseStatus::OK)) {
            return true;
        }

        size_t offset = 0;
        extract_string(resp_payload, offset, out_error);
        return false;
    }

    bool IpcClient::lock() {
        int fd = connect_socket();
        if (fd < 0) return false;

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::LOCK), {})) {
            close(fd);
            return false;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        bool ok = read_packet(fd, resp_opcode, resp_payload) && (resp_opcode == static_cast<uint8_t>(ResponseStatus::OK));
        close(fd);
        return ok;
    }

    bool IpcClient::stop_agent() {
        int fd = connect_socket();
        if (fd < 0) return false;

        write_packet(fd, static_cast<uint8_t>(CommandOpcode::STOP), {});
        close(fd);
        return true;
    }

    std::optional<EntryData> IpcClient::get_entry(const duckpass::SecureString& service, std::string& out_error) {
        int fd = connect_socket();
        if (fd < 0) {
            out_error = "Agent not running.";
            return std::nullopt;
        }

        std::vector<uint8_t> payload;
        ScopedCleanse sc_p(payload);
        append_secure_string(payload, service);

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::GET_ENTRY), payload)) {
            close(fd);
            out_error = "Failed to send get request.";
            return std::nullopt;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        ScopedCleanse sc_r(resp_payload);
        if (!read_packet(fd, resp_opcode, resp_payload)) {
            close(fd);
            out_error = "Agent disconnected.";
            return std::nullopt;
        }
        close(fd);

        if (resp_opcode == static_cast<uint8_t>(ResponseStatus::OK)) {
            size_t offset = 0;
            EntryData entry;
            extract_secure_string(resp_payload, offset, entry.service);
            extract_secure_string(resp_payload, offset, entry.username);
            extract_secure_string(resp_payload, offset, entry.password);
            extract_secure_string(resp_payload, offset, entry.totp_secret);
            return entry;
        }

        size_t offset = 0;
        extract_string(resp_payload, offset, out_error);
        return std::nullopt;
    }

    bool IpcClient::add_entry(const EntryData& entry, std::string& out_error) {
        int fd = connect_socket();
        if (fd < 0) {
            out_error = "Agent not running.";
            return false;
        }

        std::vector<uint8_t> payload;
        ScopedCleanse sc_p(payload);
        append_secure_string(payload, entry.service);
        append_secure_string(payload, entry.username);
        append_secure_string(payload, entry.password);
        append_secure_string(payload, entry.totp_secret);

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::ADD_ENTRY), payload)) {
            close(fd);
            out_error = "Failed to send add request.";
            return false;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        ScopedCleanse sc_r(resp_payload);
        if (!read_packet(fd, resp_opcode, resp_payload)) {
            close(fd);
            out_error = "Agent disconnected.";
            return false;
        }
        close(fd);

        if (resp_opcode == static_cast<uint8_t>(ResponseStatus::OK)) {
            return true;
        }

        size_t offset = 0;
        extract_string(resp_payload, offset, out_error);
        return false;
    }

    bool IpcClient::delete_entry(const duckpass::SecureString& service, std::string& out_error) {
        int fd = connect_socket();
        if (fd < 0) {
            out_error = "Agent not running.";
            return false;
        }

        std::vector<uint8_t> payload;
        ScopedCleanse sc_p(payload);
        append_secure_string(payload, service);

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::DELETE_ENTRY), payload)) {
            close(fd);
            out_error = "Failed to send delete request.";
            return false;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        ScopedCleanse sc_r(resp_payload);
        if (!read_packet(fd, resp_opcode, resp_payload)) {
            close(fd);
            out_error = "Agent disconnected.";
            return false;
        }
        close(fd);

        if (resp_opcode == static_cast<uint8_t>(ResponseStatus::OK)) {
            return true;
        }

        size_t offset = 0;
        extract_string(resp_payload, offset, out_error);
        return false;
    }

    std::vector<std::pair<std::string, std::string>> IpcClient::list_entries(const std::string& query) {
        std::vector<std::pair<std::string, std::string>> list;
        int fd = connect_socket();
        if (fd < 0) return list;

        std::vector<uint8_t> payload;
        ScopedCleanse sc_payload(payload);
        append_string(payload, query);

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::LIST_ENTRIES), payload)) {
            close(fd);
            return list;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        ScopedCleanse sc_resp(resp_payload);
        if (!read_packet(fd, resp_opcode, resp_payload) || resp_opcode != static_cast<uint8_t>(ResponseStatus::OK)) {
            close(fd);
            return list;
        }
        close(fd);

        if (resp_payload.size() < 4) return list;
        size_t offset = 0;
        uint32_t raw_count = 0;
        std::memcpy(&raw_count, resp_payload.data() + offset, 4);
        offset += 4;
        uint32_t const count = ntohl(raw_count);

        for (uint32_t i = 0; i < count; ++i) {
            std::string svc;
            std::string usr;
            if (!extract_string(resp_payload, offset, svc) || !extract_string(resp_payload, offset, usr)) {
                break;
            }
            list.emplace_back(std::move(svc), std::move(usr));
        }

        return list;
    }

    std::optional<TotpResult> IpcClient::get_totp(const duckpass::SecureString& service, std::string& out_error) {
        int fd = connect_socket();
        if (fd < 0) {
            out_error = "Agent not running.";
            return std::nullopt;
        }

        std::vector<uint8_t> payload;
        ScopedCleanse sc_p(payload);
        append_secure_string(payload, service);

        if (!write_packet(fd, static_cast<uint8_t>(CommandOpcode::GET_TOTP), payload)) {
            close(fd);
            out_error = "Failed to send TOTP request.";
            return std::nullopt;
        }

        uint8_t resp_opcode = 0;
        std::vector<uint8_t> resp_payload;
        ScopedCleanse sc_r(resp_payload);
        if (!read_packet(fd, resp_opcode, resp_payload)) {
            close(fd);
            out_error = "Agent disconnected.";
            return std::nullopt;
        }
        close(fd);

        if (resp_opcode == static_cast<uint8_t>(ResponseStatus::OK)) {
            size_t offset = 0;
            TotpResult res;
            extract_string(resp_payload, offset, res.code);
            if (offset + 4 <= resp_payload.size()) {
                uint32_t raw_rem = 0;
                std::memcpy(&raw_rem, resp_payload.data() + offset, 4);
                res.remaining_seconds = ntohl(raw_rem);
            }
            return res;
        }

        size_t offset = 0;
        extract_string(resp_payload, offset, out_error);
        return std::nullopt;
    }

}  // namespace duckpass::ipc
