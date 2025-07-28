#include "duckpass/generate_command.h"
#include "CLI/CLI.hpp"
#include <iostream>
#include <string>
#include <random>

CLI::App *generate_command::setup(CLI::App &app) {
    CLI::App *gen_cmd = app.add_subcommand("generate", "Generate a random password");
    gen_cmd->add_option("-l,--length", "The desired password length")->default_val(16);
    return gen_cmd;
}

generate_command::generate_command(CLI::App *app) {
    length_ = app->get_option("--length")->as<int>();
}

void generate_command::execute() {
    const std::string chars =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[]{}|;:',.<>?/";

    if (length_ <= 0) {
        std::cerr << "Error: Password length must be positive." << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, chars.length() - 1);

    std::string password;
    password.reserve(length_);

    for (int i = 0; i < length_; ++i) {
        password += chars[distribution(generator)];
    }

    std::cout << "Generated Password: " << password << std::endl;
}
