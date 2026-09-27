#include "duckpass/totp.h"

#include <gtest/gtest.h>

TEST(TotpTest, Base32DecodingHandlesValidStringsAndPadding) {
    // "JBSWY3DPEHPK3PXP" is standard test secret for "Hello!\xde\xad\xbe\xef"
    auto decoded = duckpass::totp::decode_base32("JBSWY3DPEHPK3PXP");
    EXPECT_FALSE(decoded.empty());

    // Strips spaces, hyphens, and padding
    auto decoded_with_formatting = duckpass::totp::decode_base32("JBSW-Y3DP EHPK-3PXP==");
    EXPECT_EQ(decoded, decoded_with_formatting);

    // Case insensitivity
    auto decoded_lower = duckpass::totp::decode_base32("jbswy3dpehpk3pxp");
    EXPECT_EQ(decoded, decoded_lower);
}

TEST(TotpTest, Base32DecodingInvalidCharactersThrow) {
    EXPECT_THROW({ duckpass::totp::decode_base32("INVALID_CHAR_189!"); }, std::invalid_argument);

    EXPECT_THROW({ duckpass::totp::decode_base32(""); }, std::invalid_argument);
}

// Official RFC 6238 Appendix B Test Vectors
TEST(TotpTest, Rfc6238OfficialTestVectorsSha1) {
    // Secret = "12345678901234567890" in Base32
    constexpr std::string_view rfc_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    uint32_t remaining = 0;

    EXPECT_EQ(duckpass::totp::generate_totp(rfc_secret, 59, 30, 6, &remaining), "287082");
    EXPECT_EQ(remaining, 30 - (59 % 30));

    EXPECT_EQ(duckpass::totp::generate_totp(rfc_secret, 1111111109, 30, 6, &remaining), "081804");
    EXPECT_EQ(remaining, 30 - (1111111109 % 30));

    EXPECT_EQ(duckpass::totp::generate_totp(rfc_secret, 1111111111, 30, 6), "050471");
    EXPECT_EQ(duckpass::totp::generate_totp(rfc_secret, 1234567890, 30, 6), "005924");
    EXPECT_EQ(duckpass::totp::generate_totp(rfc_secret, 2000000000, 30, 6), "279037");
}
