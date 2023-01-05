#include <gtest/gtest.h>
#include <array>

#include "sm_digest.h"
#include "sm_rng.h"
#include "sm_common.h"

#define CMAC_SIZE (16u)
#define HMAC_SIZE (32u)

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
	std::array<uint8_t, DIGEST_SHA1_SIZE> digest = {0};
	Buffer buf_digest = {.ptr = digest.data(), .size = digest.size()};
	bool result = generate_sha(&message, &buf_digest);
	print_hex("SHA1", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_224)
{
	std::array<uint8_t, DIGEST_SHA224_SIZE> digest = {0};
	Buffer buf_digest = {.ptr = digest.data(), .size = digest.size()};
	bool result = generate_sha(&message, &buf_digest);
	print_hex("SHA2-224", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_256)
{
	std::array<uint8_t, DIGEST_SHA256_SIZE> digest = {0};
	Buffer buf_digest = {.ptr = digest.data(), .size = digest.size()};
	bool result = generate_sha(&message, &buf_digest);
	print_hex("SHA2-256", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_384)
{
	std::array<uint8_t, DIGEST_SHA384_SIZE> digest = {0};
	Buffer buf_digest = {.ptr = digest.data(), .size = digest.size()};
	bool result = generate_sha(&message, &buf_digest);
	print_hex("SHA2-384", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, SHA2_512)
{
	std::array<uint8_t, DIGEST_SHA512_SIZE> digest = {0};
	Buffer buf_digest = {.ptr = digest.data(), .size = digest.size()};
	bool result = generate_sha(&message, &buf_digest);
	print_hex("SHA2-512", digest.data(), digest.size());

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, HMAC)
{
	std::array<uint8_t, HMAC_SIZE> key = {0};
	Buffer buf_key = {.ptr = key.data(), .size = key.size()};
	generate_random(&buf_key);

	std::array<uint8_t, HMAC_SIZE> mac = {0};
	Buffer buf_mac = {.ptr = mac.data(), .size = mac.size()};

	bool result = generate_hmac(&buf_key, &message, &buf_mac);
	print_hex("HMAC", buf_mac.ptr, buf_mac.size);

	ASSERT_EQ(result, true);
}

TEST_F(DigestTest, CMAC)
{
	std::array<uint8_t, CMAC_SIZE> key = {0};
	Buffer buf_key = {.ptr = key.data(), .size = key.size()};
	generate_random(&buf_key);
	std::array<uint8_t, CMAC_SIZE> mac = {0};
	Buffer buf_mac = {.ptr = mac.data(), .size = mac.size()};

	bool result = generate_cmac(&buf_key, &message, &buf_mac);
	print_hex("AES-128 CMAC", buf_mac.ptr, buf_mac.size);
	ASSERT_EQ(result, true);
}