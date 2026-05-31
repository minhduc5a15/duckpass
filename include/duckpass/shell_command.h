#pragma once

#include <filesystem>

#include "CLI/CLI.hpp"
#include "duckpass/secure_allocator.h"

namespace duckpass::shell {

    /**
     * @brief Sets up the shell subcommand.
     *
     * @param app The CLI11 application.
     */
    void setup(CLI::App& app);

    /**
     * @brief Runs an interactive shell for duckpass.
     *
     * @param vault_path Path to the vault file.
     * @param master_password The master password to decrypt the vault.
     */
    void run_interactive_shell(const std::filesystem::path& vault_path, const duckpass::SecureString& master_password);

}  // namespace duckpass::shell
