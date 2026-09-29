#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "CLI/CLI.hpp"
#include "duckpass/agent_server.h"
#include "duckpass/ipc.h"

int main(int argc, char* argv[]) {
    CLI::App app{"DuckPass Background Agent Daemon"};

    uint32_t timeout_seconds = 900;  // 15 minutes default
    std::string socket_path_str = duckpass::ipc::get_socket_path().string();
    bool daemonize = false;

    app.add_option("-t,--timeout", timeout_seconds, "Idle auto-lock timeout in seconds (default: 900, 0 = disabled)");
    app.add_option("-s,--socket", socket_path_str, "Custom UNIX domain socket path");
    app.add_flag("-d,--daemon", daemonize, "Run as background daemon (fork)");

    CLI11_PARSE(app, argc, argv);

    std::filesystem::path const socket_path(socket_path_str);

    // Check if another agent is already running
    duckpass::ipc::IpcClient client(socket_path);
    if (client.is_agent_available()) {
        std::cerr << "Error: Another duckpass-agent is already running at " << socket_path << std::endl;
        return 1;
    }

    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Failed to fork daemon process." << std::endl;
            return 1;
        }
        if (pid > 0) {
            // Parent process exits cleanly
            std::cout << "duckpass-agent started in background (PID: " << pid << ")" << std::endl;
            return 0;
        }
        // Child continues: detach session
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }
        chdir("/");
        umask(0077);
    }

    // Initialize secure heap in the actual server process
    CRYPTO_secure_malloc_init(1048576, 32);

    duckpass::ipc::AgentServer server(socket_path, timeout_seconds);
    int const exit_code = server.run();

    CRYPTO_secure_malloc_done();
    return exit_code;
}
