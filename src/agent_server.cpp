#include "duckpass/agent_server.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <csignal>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include <openssl/crypto.h>

#include <cstring>
#include <iostream>

#include "duckpass/config_handler.h"
#include "duckpass/ipc.h"

namespace duckpass::ipc {

    namespace {
        std::atomic<bool> g_stop_requested{false};

        void signal_handler(int /*signum*/) { g_stop_requested = true; }

        struct ScopedCleanse {
            std::vector<uint8_t>& buf;
            explicit ScopedCleanse(std::vector<uint8_t>& b) : buf(b) {}
            ~ScopedCleanse() {
                if (!buf.empty()) {
                    OPENSSL_cleanse(buf.data(), buf.size());
                }
            }
        };

        void append_str(std::vector<uint8_t>& buf, std::string_view str) {
            uint32_t const len = htonl(static_cast<uint32_t>(str.size()));
            const auto* len_ptr = reinterpret_cast<const uint8_t*>(&len);
            buf.insert(buf.end(), len_ptr, len_ptr + 4);
            buf.insert(buf.end(), str.begin(), str.end());
        }

        void append_sec_str(std::vector<uint8_t>& buf, const duckpass::SecureString& str) {
            uint32_t const len = htonl(static_cast<uint32_t>(str.size()));
            const auto* len_ptr = reinterpret_cast<const uint8_t*>(&len);
            buf.insert(buf.end(), len_ptr, len_ptr + 4);
            buf.insert(buf.end(), str.data(), str.data() + str.size());
        }

        bool extract_sec_str(const std::vector<uint8_t>& buf, size_t& offset, duckpass::SecureString& out_str) {
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

        bool extract_str(const std::vector<uint8_t>& buf, size_t& offset, std::string& out_str) {
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

    AgentServer::AgentServer(std::filesystem::path socket_path, uint32_t idle_timeout_seconds)
        : socket_path_(std::move(socket_path)), idle_timeout_seconds_(idle_timeout_seconds) {}

    AgentServer::~AgentServer() {
        stop();
        cleanup_socket();
    }

    void AgentServer::cleanup_socket() {
        if (server_fd_ >= 0) {
            close(server_fd_);
            server_fd_ = -1;
        }
        std::error_code ec;
        if (std::filesystem::exists(socket_path_)) {
            std::filesystem::remove(socket_path_, ec);
        }
    }

    void AgentServer::stop() {
        running_ = false;
        lock();
    }

    bool AgentServer::is_unlocked() const {
        std::lock_guard<std::mutex> const lock(vault_mutex_);
        return vault_service_ != nullptr;
    }

    void AgentServer::lock() {
        std::lock_guard<std::mutex> const lock(vault_mutex_);
        vault_service_.reset();
    }

    bool AgentServer::unlock(const duckpass::SecureString& master_password, std::string& out_error) {
        try {
            config_handler const config;
            auto vault_path = config.get_vault_path();
            if (!std::filesystem::exists(vault_path)) {
                out_error = "Vault has not been initialized. Run 'duckpass init'.";
                return false;
            }
            auto service = std::make_unique<duckpass::service::VaultService>(vault_path, master_password);
            {
                std::lock_guard<std::mutex> const lock(vault_mutex_);
                vault_service_ = std::move(service);
                last_activity_ = std::chrono::steady_clock::now();
            }
            return true;
        } catch (const std::exception& e) {
            out_error = e.what();
            return false;
        }
    }

    void AgentServer::check_idle_timeout() {
        std::lock_guard<std::mutex> const lock(vault_mutex_);
        if (!vault_service_ || idle_timeout_seconds_ == 0) return;

        auto const now = std::chrono::steady_clock::now();
        auto const elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_).count();
        if (elapsed >= idle_timeout_seconds_) {
            vault_service_.reset();
        }
    }

    int AgentServer::run() {
#if defined(__linux__)
        // Disable core dumps and ptrace memory extraction
        prctl(PR_SET_DUMPABLE, 0);
#endif

        if (std::filesystem::exists(socket_path_)) {
            IpcClient client(socket_path_);
            if (client.is_agent_available()) {
                std::cerr << "Error: An active duckpass-agent is already listening on " << socket_path_ << std::endl;
                return 1;
            }
            std::error_code ec;
            std::filesystem::remove(socket_path_, ec);
        }

        // Ensure parent directory exists with restrictive permissions
        auto const parent_dir = socket_path_.parent_path();
        if (!std::filesystem::exists(parent_dir)) {
            std::filesystem::create_directories(parent_dir);
#if defined(__linux__) || defined(__APPLE__)
            chmod(parent_dir.c_str(), 0700);
#endif
        }

        server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            std::cerr << "Failed to create UNIX domain socket." << std::endl;
            return 1;
        }

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

#if defined(__linux__) || defined(__APPLE__)
        mode_t const old_mask = umask(0177);  // Only owner can RW socket
#endif
        if (bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "Failed to bind socket to " << socket_path_ << std::endl;
#if defined(__linux__) || defined(__APPLE__)
            umask(old_mask);
#endif
            close(server_fd_);
            server_fd_ = -1;
            return 1;
        }
#if defined(__linux__) || defined(__APPLE__)
        umask(old_mask);
#endif

        if (listen(server_fd_, 16) < 0) {
            std::cerr << "Failed to listen on socket." << std::endl;
            cleanup_socket();
            return 1;
        }

        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGPIPE, SIG_IGN);

        running_ = true;
        g_stop_requested = false;

        while (running_ && !g_stop_requested) {
            check_idle_timeout();

            pollfd pfd{};
            pfd.fd = server_fd_;
            pfd.events = POLLIN;

            int const ret = poll(&pfd, 1, 1000);  // 1 second timeout to check idle timer
            if (ret < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (ret == 0) {
                continue;  // Timeout, loop to re-check idle timer
            }

            if (pfd.revents & POLLIN) {
                int client_fd = accept(server_fd_, nullptr, nullptr);
                if (client_fd >= 0) {
                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 250000;  // 250ms I/O timeout to prevent stalled client DoS
                    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                    if (verify_peer_credentials(client_fd)) {
                        try {
                            handle_client(client_fd);
                        } catch (const std::exception& e) {
                            std::vector<uint8_t> resp;
                            append_str(resp, e.what());
                            write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                        } catch (...) {
                            std::vector<uint8_t> resp;
                            append_str(resp, "Internal agent server error.");
                            write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                        }
                    }
                    close(client_fd);
                }
            }
        }

        stop();
        cleanup_socket();
        return 0;
    }

    void AgentServer::handle_client(int client_fd) {
        uint8_t opcode = 0;
        std::vector<uint8_t> payload;
        ScopedCleanse sc_payload(payload);
        if (!read_packet(client_fd, opcode, payload)) {
            return;
        }

        auto const cmd = static_cast<CommandOpcode>(opcode);

        switch (cmd) {
            case CommandOpcode::PING: {
                write_packet(client_fd, 0x81, {});
                break;
            }
            case CommandOpcode::STATUS: {
                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);

                {
                    std::lock_guard<std::mutex> const lock(vault_mutex_);
                    resp.push_back(vault_service_ != nullptr ? 1 : 0);

                    uint32_t rem = 0;
                    if (vault_service_ && idle_timeout_seconds_ > 0) {
                        auto const now = std::chrono::steady_clock::now();
                        auto const elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_).count();
                        rem = (elapsed < idle_timeout_seconds_) ? static_cast<uint32_t>(idle_timeout_seconds_ - elapsed) : 0;
                    }
                    uint32_t const rem_be = htonl(rem);
                    const auto* rem_ptr = reinterpret_cast<const uint8_t*>(&rem_be);
                    resp.insert(resp.end(), rem_ptr, rem_ptr + 4);

                    uint32_t total = 0;
                    if (vault_service_) {
                        total = static_cast<uint32_t>(vault_service_->get_all_entries().size());
                    }
                    uint32_t const total_be = htonl(total);
                    const auto* total_ptr = reinterpret_cast<const uint8_t*>(&total_be);
                    resp.insert(resp.end(), total_ptr, total_ptr + 4);
                }

                write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::OK), resp);
                break;
            }
            case CommandOpcode::UNLOCK: {
                size_t offset = 0;
                duckpass::SecureString pwd;
                if (!extract_sec_str(payload, offset, pwd)) {
                    std::vector<uint8_t> resp;
                    ScopedCleanse sc_resp(resp);
                    append_str(resp, "Invalid unlock payload.");
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                    break;
                }
                std::string err;
                if (unlock(pwd, err)) {
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::OK), {});
                } else {
                    std::vector<uint8_t> resp;
                    ScopedCleanse sc_resp(resp);
                    append_str(resp, err);
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                }
                break;
            }
            case CommandOpcode::LOCK: {
                lock();
                write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::OK), {});
                break;
            }
            case CommandOpcode::STOP: {
                running_ = false;
                write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::OK), {});
                break;
            }
            case CommandOpcode::GET_ENTRY: {
                size_t offset = 0;
                duckpass::SecureString service;
                if (!extract_sec_str(payload, offset, service)) {
                    std::vector<uint8_t> resp;
                    ScopedCleanse sc_resp(resp);
                    append_str(resp, "Malformed get payload.");
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                    break;
                }

                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);
                uint8_t status = static_cast<uint8_t>(ResponseStatus::OK);

                {
                    std::lock_guard<std::mutex> const lock(vault_mutex_);
                    if (!vault_service_) {
                        append_str(resp, "Vault is locked in agent.");
                        status = static_cast<uint8_t>(ResponseStatus::LOCKED);
                    } else {
                        last_activity_ = std::chrono::steady_clock::now();
                        try {
                            auto entry = vault_service_->get_entry(service);
                            if (entry.has_value()) {
                                append_sec_str(resp, entry->service.unprotect());
                                append_sec_str(resp, entry->username.unprotect());
                                append_sec_str(resp, entry->password.unprotect());
                                append_sec_str(resp, entry->totp_secret.unprotect());
                                status = static_cast<uint8_t>(ResponseStatus::OK);
                            } else {
                                append_str(resp, "Entry not found.");
                                status = static_cast<uint8_t>(ResponseStatus::NOT_FOUND);
                            }
                        } catch (const std::exception& e) {
                            append_str(resp, e.what());
                            status = static_cast<uint8_t>(ResponseStatus::ERROR);
                        }
                    }
                }

                write_packet(client_fd, status, resp);
                break;
            }
            case CommandOpcode::ADD_ENTRY: {
                size_t offset = 0;
                duckpass::SecureString s, u, p, t;
                if (!extract_sec_str(payload, offset, s) || !extract_sec_str(payload, offset, u) || !extract_sec_str(payload, offset, p) ||
                    !extract_sec_str(payload, offset, t)) {
                    std::vector<uint8_t> resp;
                    ScopedCleanse sc_resp(resp);
                    append_str(resp, "Malformed add payload.");
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                    break;
                }

                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);
                uint8_t status = static_cast<uint8_t>(ResponseStatus::OK);

                {
                    std::lock_guard<std::mutex> const lock(vault_mutex_);
                    if (!vault_service_) {
                        append_str(resp, "Vault is locked in agent.");
                        status = static_cast<uint8_t>(ResponseStatus::LOCKED);
                    } else {
                        last_activity_ = std::chrono::steady_clock::now();
                        try {
                            vault_service_->add_entry(s, u, p, t);
                            status = static_cast<uint8_t>(ResponseStatus::OK);
                        } catch (const std::exception& e) {
                            append_str(resp, e.what());
                            status = static_cast<uint8_t>(ResponseStatus::ERROR);
                        }
                    }
                }

                write_packet(client_fd, status, resp);
                break;
            }
            case CommandOpcode::DELETE_ENTRY: {
                size_t offset = 0;
                duckpass::SecureString s;
                if (!extract_sec_str(payload, offset, s)) {
                    std::vector<uint8_t> resp;
                    ScopedCleanse sc_resp(resp);
                    append_str(resp, "Malformed delete payload.");
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                    break;
                }

                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);
                uint8_t status = static_cast<uint8_t>(ResponseStatus::OK);

                {
                    std::lock_guard<std::mutex> const lock(vault_mutex_);
                    if (!vault_service_) {
                        append_str(resp, "Vault is locked in agent.");
                        status = static_cast<uint8_t>(ResponseStatus::LOCKED);
                    } else {
                        last_activity_ = std::chrono::steady_clock::now();
                        try {
                            vault_service_->delete_entry(s);
                            status = static_cast<uint8_t>(ResponseStatus::OK);
                        } catch (const std::exception& e) {
                            append_str(resp, e.what());
                            status = static_cast<uint8_t>(ResponseStatus::ERROR);
                        }
                    }
                }

                write_packet(client_fd, status, resp);
                break;
            }
            case CommandOpcode::LIST_ENTRIES: {
                size_t offset = 0;
                std::string query;
                extract_str(payload, offset, query);

                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);
                uint8_t status = static_cast<uint8_t>(ResponseStatus::OK);

                {
                    std::lock_guard<std::mutex> const lock(vault_mutex_);
                    if (!vault_service_) {
                        append_str(resp, "Vault is locked in agent.");
                        status = static_cast<uint8_t>(ResponseStatus::LOCKED);
                    } else {
                        last_activity_ = std::chrono::steady_clock::now();
                        try {
                            auto entries = vault_service_->list_entries(query);
                            uint32_t const count_be = htonl(static_cast<uint32_t>(entries.size()));
                            const auto* count_ptr = reinterpret_cast<const uint8_t*>(&count_be);
                            resp.insert(resp.end(), count_ptr, count_ptr + 4);

                            for (const auto& entry : entries) {
                                auto svc = entry.service.unprotect();
                                auto usr = entry.username.unprotect();
                                append_str(resp, std::string_view(svc.data(), svc.size()));
                                append_str(resp, std::string_view(usr.data(), usr.size()));
                            }
                            status = static_cast<uint8_t>(ResponseStatus::OK);
                        } catch (const std::exception& e) {
                            append_str(resp, e.what());
                            status = static_cast<uint8_t>(ResponseStatus::ERROR);
                        }
                    }
                }

                write_packet(client_fd, status, resp);
                break;
            }
            case CommandOpcode::GET_TOTP: {
                size_t offset = 0;
                duckpass::SecureString service;
                if (!extract_sec_str(payload, offset, service)) {
                    std::vector<uint8_t> resp;
                    ScopedCleanse sc_resp(resp);
                    append_str(resp, "Malformed TOTP payload.");
                    write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                    break;
                }

                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);
                uint8_t status = static_cast<uint8_t>(ResponseStatus::OK);

                {
                    std::lock_guard<std::mutex> const lock(vault_mutex_);
                    if (!vault_service_) {
                        append_str(resp, "Vault is locked in agent.");
                        status = static_cast<uint8_t>(ResponseStatus::LOCKED);
                    } else {
                        last_activity_ = std::chrono::steady_clock::now();
                        try {
                            uint32_t remaining = 0;
                            std::string code = vault_service_->get_totp_code(service, &remaining);
                            append_str(resp, code);
                            uint32_t const rem_be = htonl(remaining);
                            const auto* rem_ptr = reinterpret_cast<const uint8_t*>(&rem_be);
                            resp.insert(resp.end(), rem_ptr, rem_ptr + 4);
                            status = static_cast<uint8_t>(ResponseStatus::OK);
                        } catch (const std::exception& e) {
                            append_str(resp, e.what());
                            status = static_cast<uint8_t>(ResponseStatus::ERROR);
                        }
                    }
                }

                write_packet(client_fd, status, resp);
                break;
            }
            default: {
                std::vector<uint8_t> resp;
                ScopedCleanse sc_resp(resp);
                append_str(resp, "Unknown command opcode.");
                write_packet(client_fd, static_cast<uint8_t>(ResponseStatus::ERROR), resp);
                break;
            }
        }
    }

}  // namespace duckpass::ipc
