#include <gtest/gtest.h>
#include <array>

#include "sm_symmetric_key.h"
#include "sm_common.h"

#define TEST_ECDSA_PRIVATE_KEY_SIZE (32u)
#define TEST_ECDSA_PUBLIC_KEY_SIZE (64u)
#define TEST_SIGNATURE_SIZE (64u)

#define TEST_RSA_KEY_SIZE (256u)
#define TEST_RSA_PUBLIC_EXPONENT_SIZE (4u)

class SymmetricKeyTest : public testing::Test
{
protected:
	SymmetricKeyTest() = default;
	~SymmetricKeyTest() = default;

	void SetUp() override
	{
	}

	void TearDown() override
	{
	}
};

TEST_F(SymmetricKeyTest, PBKDF2)
{
	std::array<uint8_t, 8> passpword = { 0X70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	Buffer buf_pass = {.ptr = passpword.data(), .size = passpword.size()};

    std::array<uint8_t, 4> salt = { 0x73, 0x61, 0x6c, 0x74  };
	Buffer buf_salt = {.ptr = salt.data(), .size = salt.size()};

	std::array<uint8_t, 32> key = { 0 };
	Buffer buf_key = {.ptr = key.data(), .size = key.size()};
	bool result = generate_pbkdf2(&buf_pass, &buf_salt, 20, &buf_key );

	print_hex("PBKDF2", buf_key.ptr, buf_key.size);
	ASSERT_EQ(result, true);
}
