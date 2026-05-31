#include "duckpass/generate_command.h"

#include <iostream>
#include <random>
#include <string>

#include "CLI/CLI.hpp"

void generate_command::setup(CLI::App &app) {
    auto gen_cmd = app.add_subcommand("generate", "Generate a random password");

    auto length = std::make_shared<int>(16);
    gen_cmd->add_option("-l,--length", *length, "The desired password length")->default_val(16);

    gen_cmd->callback([length]() {
        const std::string chars =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[]{}|;:',.<>?/";

        if (*length <= 0) {
            std::cerr << "Error: Password length must be positive." << std::endl;
            return;
        }

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<int> distribution(0, static_cast<int>(chars.length()) - 1);

        std::string password;
        password.reserve(*length);

        for (int i = 0; i < *length; ++i) {
            password += chars[distribution(generator)];
        }

        std::cout << "Generated Password: " << password << std::endl;
    });
}
