#include "duckpass/agent_command.h"

#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

#include "CLI/CLI.hpp"
#include "duckpass/ipc.h"
#include "duckpass/terminal_utils.h"

namespace {
    std::filesystem::path resolve_agent_binary() {
        std::error_code ec;
#if defined(__linux__)
        auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
        if (!ec) {
            auto candidate = self.parent_path() / "duckpass-agent";
            if (std::filesystem::exists(candidate)) {
                return candidate;
            }
        }
#endif
        if (std::filesystem::exists("/usr/local/bin/duckpass-agent")) {
            return "/usr/local/bin/duckpass-agent";
        }
        if (std::filesystem::exists("/usr/bin/duckpass-agent")) {
            return "/usr/bin/duckpass-agent";
        }
        return "duckpass-agent";
    }
}  // namespace

void agent_command::setup(CLI::App &app) {
    auto *agent_cmd = app.add_subcommand("agent", "Manage the DuckPass background session agent");

    // 1. Status subcommand
    auto *status_cmd = agent_cmd->add_subcommand("status", "Show agent running and unlock status");
    status_cmd->callback([]() {
        duckpass::ipc::IpcClient client;
        if (!client.is_agent_available()) {
            std::cout << "[Agent]: NOT RUNNING\n"
                      << "Hint: Run 'duckpass agent start' to launch the background agent.\n";
            return;
        }

        auto status = client.get_status();
        if (!status) {
            std::cerr << "Error: Could not retrieve status from agent.\n";
            return;
        }

        std::cout << "[Agent]: RUNNING\n";
        std::cout << "  State: " << (status->is_unlocked ? "UNLOCKED" : "LOCKED") << "\n";
        if (status->is_unlocked) {
            std::cout << "  Vault Entries: " << status->total_entries << "\n";
            std::cout << "  Auto-lock in:  " << status->timeout_remaining_seconds << "s\n";
        }
    });

    // 2. Unlock subcommand
    auto *unlock_cmd = agent_cmd->add_subcommand("unlock", "Unlock the vault session in the background agent");
    unlock_cmd->callback([]() {
        duckpass::ipc::IpcClient client;
        if (!client.is_agent_available()) {
            std::cerr << "Error: duckpass-agent is not running. Start it with 'duckpass agent start'.\n";
            return;
        }

        auto status = client.get_status();
        if (status && status->is_unlocked) {
            std::cout << "Info: Agent is already unlocked (" << status->total_entries << " entries loaded).\n";
            return;
        }

        auto const master_password = terminal_utils::read_password("Enter master password to unlock agent: ");
        std::string err;
        if (client.unlock(master_password, err)) {
            std::cout << "Success: Agent unlocked successfully! Subsequent CLI commands will execute without prompting.\n";
        } else {
            std::cerr << "Error unlocking agent: " << err << "\n";
        }
    });

    // 3. Lock subcommand
    auto *lock_cmd = agent_cmd->add_subcommand("lock", "Lock the agent session and purge keys from memory");
    lock_cmd->callback([]() {
        duckpass::ipc::IpcClient client;
        if (!client.is_agent_available()) {
            std::cout << "Info: Agent is not running.\n";
            return;
        }

        if (client.lock()) {
            std::cout << "Success: Agent locked. In-memory keys have been securely purged.\n";
        } else {
            std::cerr << "Error: Failed to lock agent.\n";
        }
    });

    // 4. Stop subcommand
    auto *stop_cmd = agent_cmd->add_subcommand("stop", "Stop the background agent daemon");
    stop_cmd->callback([]() {
        duckpass::ipc::IpcClient client;
        if (!client.is_agent_available()) {
            std::cout << "Info: Agent is not running.\n";
            return;
        }

        if (client.stop_agent()) {
            std::cout << "Success: duckpass-agent stopped.\n";
        } else {
            std::cerr << "Error: Failed to stop agent.\n";
        }
    });

    // 5. Start subcommand
    auto *start_cmd = agent_cmd->add_subcommand("start", "Start the background agent daemon");
    auto timeout_opt = std::make_shared<uint32_t>(900);
    start_cmd->add_option("-t,--timeout", *timeout_opt, "Auto-lock idle timeout in seconds (default: 900)");
    start_cmd->callback([timeout_opt]() {
        duckpass::ipc::IpcClient client;
        if (client.is_agent_available()) {
            std::cout << "Info: duckpass-agent is already running.\n";
            return;
        }

        auto agent_bin = resolve_agent_binary();
        std::string timeout_str = std::to_string(*timeout_opt);

        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Failed to fork process to start duckpass-agent.\n";
            return;
        }
        if (pid == 0) {
            char *const argv[] = {const_cast<char *>("duckpass-agent"), const_cast<char *>("--daemon"), const_cast<char *>("--timeout"),
                                  timeout_str.data(), nullptr};
            execv(agent_bin.c_str(), argv);
            execvp(agent_bin.c_str(), argv);
            _exit(127);
        }

        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            std::cerr << "Failed to launch duckpass-agent (" << agent_bin << "). Exit code: " << WEXITSTATUS(status) << "\n";
            return;
        }

        // Wait up to 1 second for socket to appear
        for (int i = 0; i < 10; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (client.is_agent_available()) {
                std::cout << "Success: duckpass-agent started and ready.\n";
                return;
            }
        }
        std::cout << "Agent launched. Run 'duckpass agent status' to check state.\n";
    });

    // Default if just 'duckpass agent'
    agent_cmd->callback([agent_cmd]() {
        if (agent_cmd->get_subcommands().empty()) {
            std::cout << agent_cmd->help() << std::endl;
        }
    });
}
