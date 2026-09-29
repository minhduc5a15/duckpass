#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

#include "duckpass/ipc.h"
#include "duckpass/vault_service.h"

namespace duckpass::ipc {

    class AgentServer {
    public:
        explicit AgentServer(std::filesystem::path socket_path = get_socket_path(), uint32_t idle_timeout_seconds = 900);
        ~AgentServer();

        // Start listening and run the event loop
        int run();

        // Signal daemon to shut down
        void stop();

        // Check if vault is currently unlocked in memory
        bool is_unlocked() const;

        // Manually lock vault and purge memory
        void lock();

        // Manually unlock vault with master password
        bool unlock(const duckpass::SecureString& master_password, std::string& out_error);

    private:
        std::filesystem::path socket_path_;
        uint32_t idle_timeout_seconds_;
        std::atomic<bool> running_{false};
        int server_fd_{-1};

        std::unique_ptr<duckpass::service::VaultService> vault_service_;
        std::chrono::steady_clock::time_point last_activity_{};
        mutable std::mutex vault_mutex_;

        void check_idle_timeout();
        void handle_client(int client_fd);
        void cleanup_socket();
    };

}  // namespace duckpass::ipc
