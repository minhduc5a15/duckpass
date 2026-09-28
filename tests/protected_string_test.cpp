#include "duckpass/protected_string.h"

#include <gtest/gtest.h>

TEST(ProtectedStringTest, DefaultConstructorIsEmpty) {
    duckpass::ProtectedString ps;
    EXPECT_TRUE(ps.empty());
    EXPECT_TRUE(ps.unprotect().empty());
}

TEST(ProtectedStringTest, EncryptAndUnprotectRoundTrip) {
    duckpass::SecureString original("super_secret_password_#42");
    duckpass::ProtectedString ps(original);

    EXPECT_FALSE(ps.empty());
    auto decrypted = ps.unprotect();
    EXPECT_EQ(original, decrypted);
}

TEST(ProtectedStringTest, StringViewConstructor) {
    std::string_view sv = "api_key_secret_value";
    duckpass::ProtectedString ps(sv);

    EXPECT_FALSE(ps.empty());
    EXPECT_EQ(ps.unprotect(), duckpass::SecureString("api_key_secret_value"));
}

TEST(ProtectedStringTest, CopyAndMoveSemantics) {
    duckpass::ProtectedString original(duckpass::SecureString("test_credentials"));

    // Copy
    duckpass::ProtectedString copied = original;
    EXPECT_EQ(copied.unprotect(), duckpass::SecureString("test_credentials"));
    EXPECT_EQ(original.unprotect(), duckpass::SecureString("test_credentials"));

    // Move
    duckpass::ProtectedString moved = std::move(copied);
    EXPECT_EQ(moved.unprotect(), duckpass::SecureString("test_credentials"));
}

TEST(ProtectedStringTest, EraseWithInvalidBoundsIsSafe) {
    duckpass::SecureString s("HelloWorld");
    const char* first = s.data() + 5;
    const char* last = s.data() + 2;

    // Erase with inverted bounds should be a safe no-op
    s.erase(first, last);
    EXPECT_EQ(std::string(s.c_str()), "HelloWorld");

    // Null pointers should be safe no-ops
    s.erase(static_cast<const char*>(nullptr), last);
    s.erase(first, static_cast<const char*>(nullptr));
    EXPECT_EQ(std::string(s.c_str()), "HelloWorld");

    // Valid erase
    s.erase(s.data() + 5, s.data() + 10);
    EXPECT_EQ(std::string(s.c_str()), "Hello");
}
