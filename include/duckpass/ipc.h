#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "duckpass/secure_allocator.h"

namespace duckpass::ipc {

    enum class CommandOpcode : uint8_t {
        PING = 0x01,
        STATUS = 0x02,
        UNLOCK = 0x03,
        LOCK = 0x04,
        GET_ENTRY = 0x05,
        ADD_ENTRY = 0x06,
        DELETE_ENTRY = 0x07,
        LIST_ENTRIES = 0x08,
        GET_TOTP = 0x09,
        STOP = 0x0A
    };

    enum class ResponseStatus : uint8_t { OK = 0x00, LOCKED = 0x01, ERROR = 0x02, NOT_FOUND = 0x03 };

    struct AgentStatus {
        bool is_unlocked = false;
        uint32_t timeout_remaining_seconds = 0;
        uint32_t total_entries = 0;
    };

    struct EntryData {
        duckpass::SecureString service;
        duckpass::SecureString username;
        duckpass::SecureString password;
        duckpass::SecureString totp_secret;
    };

    struct TotpResult {
        std::string code;
        uint32_t remaining_seconds = 0;
    };

    /**
     * @brief Resolves the canonical UNIX domain socket path for the current user.
     * Uses $XDG_RUNTIME_DIR/duckpass.sock if available, else ~/.duckpass/agent.sock.
     */
    std::filesystem::path get_socket_path();

    /**
     * @brief Serializes a packet with a 4-byte big-endian length prefix and 1-byte opcode.
     */
    std::vector<uint8_t> serialize_packet(uint8_t opcode, const std::vector<uint8_t>& payload);

    /**
     * @brief Reads a full packet from a socket file descriptor.
     * Returns true if packet read successfully, false on disconnect/error.
     */
    bool read_packet(int fd, uint8_t& out_opcode, std::vector<uint8_t>& out_payload);

    /**
     * @brief Writes a packet to a socket file descriptor.
     */
    bool write_packet(int fd, uint8_t opcode, const std::vector<uint8_t>& payload);

    /**
     * @brief Verifies that the connected peer belongs to the same UID.
     */
    bool verify_peer_credentials(int fd);

    /**
     * @brief Client interface to communicate with the duckpass-agent daemon.
     */
    class IpcClient {
    public:
        IpcClient();
        explicit IpcClient(std::filesystem::path socket_path);
        ~IpcClient();

        bool is_agent_available();
        bool ping();

        std::optional<AgentStatus> get_status();
        bool unlock(const duckpass::SecureString& master_password, std::string& out_error);
        bool lock();
        bool stop_agent();

        std::optional<EntryData> get_entry(const duckpass::SecureString& service, std::string& out_error);
        bool add_entry(const EntryData& entry, std::string& out_error);
        bool delete_entry(const duckpass::SecureString& service, std::string& out_error);
        std::vector<std::pair<std::string, std::string>> list_entries(const std::string& query);
        std::optional<TotpResult> get_totp(const duckpass::SecureString& service, std::string& out_error);

    private:
        std::filesystem::path socket_path_;
        int connect_socket();
    };

}  // namespace duckpass::ipc
