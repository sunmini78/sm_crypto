#include <gtest/gtest.h>
#include <array>

#include "sm_digest.h"
#include "sm_common.h"


class DigestTest : public testing::Test
{
protected:
	DigestTest() = default;
	~DigestTest() = default;

	void SetUp() override
	{
	}

	void TearDown() override
	{
	}

	uint8_t buf[64] = {0x00};
	Buffer message = {.ptr = buf, .size = 64};
};

TEST_F(DigestTest, SHA1)
{
	std::array<uint8_t, DIGEST_SHA1_SIZE> digest;
	bool result = generate_sha(&message, digest.data(), DIGEST_SHA1_SIZE);
	print_hex("SHA1", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_224)
{
	std::array<uint8_t, DIGEST_SHA224_SIZE> digest;
	bool result = generate_sha(&message, digest.data(), DIGEST_SHA224_SIZE);
	print_hex("SHA2-224", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_256)
{
	std::array<uint8_t, DIGEST_SHA256_SIZE> digest;
	bool result = generate_sha(&message, digest.data(), DIGEST_SHA256_SIZE);
	print_hex("SHA2-256", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_384)
{
	std::array<uint8_t, DIGEST_SHA384_SIZE> digest;
	bool result = generate_sha(&message, digest.data(), DIGEST_SHA384_SIZE);
	print_hex("SHA2-384", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_512)
{
	std::array<uint8_t, DIGEST_SHA512_SIZE> digest;
	bool result = generate_sha(&message, digest.data(), DIGEST_SHA512_SIZE);
	print_hex("SHA2-512", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}
