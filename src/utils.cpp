#include "duckpass/utils.h"
#include <iostream>

// For get_password_silent on Linux/macOS
#include <termios.h>
#include <unistd.h>

std::string get_password_silent(const std::string &prompt) {
    std::cout << prompt;
    termios old_term;
    tcgetattr(STDIN_FILENO, &old_term);
    termios new_term = old_term;
    new_term.c_lflag &= ~ECHO; // Turn off terminal echo
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term); // Restore terminal settings
    std::cout << std::endl;
    return password;
}

std::filesystem::path get_config_directory() {
    std::filesystem::path config_path;
#ifdef _WIN32
    // On Windows, use %APPDATA%/duckpass
    const char* appdata = std::getenv("APPDATA");
    if (appdata == nullptr) {
        throw std::runtime_error("Error: APPDATA environment variable not set.");
    }
    config_path = std::filesystem::path(appdata) / "duckpass";
#else
    // On Linux/macOS, use ~/.duckpass
    const char *home = std::getenv("HOME");
    if (home == nullptr) {
        throw std::runtime_error("Error: HOME environment variable not set.");
    }
    config_path = std::filesystem::path(home) / ".duckpass";
#endif

    // Create the directory if it doesn't exist
    if (!std::filesystem::exists(config_path)) {
        std::filesystem::create_directories(config_path);
    }
    return config_path;
}
