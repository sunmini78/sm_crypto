#include <gtest/gtest.h>
#include <array>

#include "sm_signature.h"
#include "sm_digest.h"
#include "sm_rng.h"
#include "sm_common.h"

#define TEST_ECDSA_PRIVATE_KEY_SIZE (32u)
#define TEST_ECDSA_PUBLIC_KEY_SIZE (64u)
#define TEST_SIGNATURE_SIZE (64u)

class SignatureEccTest : public testing::Test
{
protected:
	SignatureEccTest() = default;
	~SignatureEccTest() = default;

	void SetUp() override
	{
		generate_random(&message);
	}

	void TearDown() override
	{
	}

	std::array<uint8_t, 256> buf = {0};
	Buffer message = {.ptr = buf.data(), .size = buf.size()};
};

TEST_F(SignatureEccTest, ECDSA_SECP256_R1)
{
	bool result = false;
	uint8_t pri_key[TEST_ECDSA_PRIVATE_KEY_SIZE] = { 0 };
    uint8_t pub_key[TEST_ECDSA_PUBLIC_KEY_SIZE] = { 0 };

	Buffer buf_pri = {.ptr = pri_key, .size = sizeof(pri_key)};
    Buffer buf_pub = {.ptr = pub_key, .size = sizeof(pub_key)};

	generate_ecdsa_key(&buf_pri, &buf_pub);

	uint8_t signature[TEST_SIGNATURE_SIZE] = {0};
    Buffer buf_sig = {.ptr = signature, .size = sizeof(signature)};

	ecdsa_sign(&buf_pri, &message, DIGEST_SHA256_SIZE, &buf_sig);
	print_hex("ECDSA secp256r1 SIGNATURE", buf_sig.ptr, buf_sig.size);

	if(ecdsa_verify(&buf_pub, &message, DIGEST_SHA256_SIZE, &buf_sig) == 0)
	{
		result = true;
	}
	ASSERT_EQ(result, true);
}


TEST_F(SignatureEccTest, ECDSA_SECP256_R1_KEY_FIX)
{
	bool result = false;
	uint8_t pri_key[TEST_ECDSA_PRIVATE_KEY_SIZE] = {
		0xA5,0x5A,0x22,0xAC,0xDB,0x79,0x10,0x5A,0x68,0x29,0x04,0xF0,0x24,0x6E,0xDD,0xA4,
		0x2C,0xAB,0xAB,0x82,0xF0,0x5A,0x98,0xA2,0x13,0x59,0x5B,0x68,0xD7,0x55,0xCE,0xF5,
    };

    uint8_t pub_key[TEST_ECDSA_PUBLIC_KEY_SIZE] = {
		0xA3,0xC7,0xED,0x61,0x29,0x69,0x09,0x06,0x1D,0x61,0x55,0xB2,0x47,0xD5,0x6D,0x45,
		0x9E,0xDB,0xF3,0x6C,0x92,0x83,0xEB,0xA8,0x53,0x67,0x5C,0xEC,0x9E,0x56,0x64,0x0F,
		0x48,0x7B,0xED,0x5E,0x2A,0x06,0x2A,0xBD,0x1D,0x9E,0x4C,0x2B,0x58,0xEC,0xE6,0xDA,
		0xAD,0xDF,0x5A,0x13,0xC6,0x85,0x65,0xE0,0xF7,0xAB,0xDA,0x8D,0x87,0x5D,0x62,0x3C,
    };

	Buffer buf_pri = {.ptr = pri_key, .size = sizeof(pri_key)};
    Buffer buf_pub = {.ptr = pub_key, .size = sizeof(pub_key)};

	uint8_t signature[TEST_SIGNATURE_SIZE] = {0};
    Buffer buf_sig = {.ptr = signature, .size = sizeof(signature)};

	ecdsa_sign(&buf_pri, &message, DIGEST_SHA256_SIZE, &buf_sig);
	print_hex("ECDSA secp256r1 SIGNATURE", buf_sig.ptr, buf_sig.size);

	if(ecdsa_verify(&buf_pub, &message, DIGEST_SHA256_SIZE, &buf_sig) == 0)
	{
		result = true;
	}
	ASSERT_EQ(result, true);
}
