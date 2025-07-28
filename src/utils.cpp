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
