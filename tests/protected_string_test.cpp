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
