#include <gtest/gtest.h>
#include <array>

#include "sm_asymmetric_key.h"
#include "sm_common.h"

#define TEST_ECDSA_PRIVATE_KEY_SIZE (32u)
#define TEST_ECDSA_PUBLIC_KEY_SIZE (64u)
#define TEST_ECDH_KEY_SIZE (32u)
#define TEST_SIGNATURE_SIZE (64u)

#define TEST_RSA_KEY_SIZE (256u)
#define TEST_RSA_PUBLIC_EXPONENT_SIZE (4u)

class AsymmetricKeyTest : public testing::Test
{
protected:
	AsymmetricKeyTest() = default;
	~AsymmetricKeyTest() = default;

	void SetUp() override
	{
	}

	void TearDown() override
	{
	}
};

TEST_F(AsymmetricKeyTest, RSA_1024)
{
	std::array<uint8_t, 2048> pri_key = { 0 };
    std::array<uint8_t, 2048> pub_key = { 0 };

	Buffer buf_pri = {.ptr = pri_key.data(), .size = pri_key.size()};
    Buffer buf_pub = {.ptr = pub_key.data(), .size = pub_key.size()};

	bool result = generate_rsa_cert(1024, &buf_pri, &buf_pub);
	ASSERT_EQ(result, true);

	printf("RSA Private Key \n%s\n", buf_pri.ptr);
	printf("RSA Public Key \n%s\n", buf_pub.ptr);
}

TEST_F(AsymmetricKeyTest, RSA_2048)
{
	std::array<uint8_t, 2048> pri_key = { 0 };
    std::array<uint8_t, 2048> pub_key = { 0 };

	Buffer buf_pri = {.ptr = pri_key.data(), .size = pri_key.size()};
    Buffer buf_pub = {.ptr = pub_key.data(), .size = pub_key.size()};

	bool result = generate_rsa_cert(2048, &buf_pri, &buf_pub);
	ASSERT_EQ(result, true);

	printf("RSA Private Key \n%s\n", buf_pri.ptr);
	printf("RSA Public Key \n%s\n", buf_pub.ptr);
}

TEST_F(AsymmetricKeyTest, RSA_2048_export_private_key)
{
	std::array<uint8_t, 2048> pri_cert = { 0 };
    std::array<uint8_t, 2048> pub_cert = { 0 };

	Buffer buf_pri_cert = {.ptr = pri_cert.data(), .size = pri_cert.size()};
    Buffer buf_pub_cert = {.ptr = pub_cert.data(), .size = pub_cert.size()};

	generate_rsa_cert(2048, &buf_pri_cert, &buf_pub_cert);

	uint8_t pri_e[TEST_RSA_KEY_SIZE] = {0};
    uint8_t mod_n[TEST_RSA_KEY_SIZE] = {0};
    uint8_t pub_e[TEST_RSA_PUBLIC_EXPONENT_SIZE] = {0};

    Buffer buf_pri = {.ptr = pri_e, .size = sizeof(pri_e)};
    Buffer buf_pub = {.ptr = pub_e, .size = sizeof(pub_e)};
    Buffer buf_mod = {.ptr = mod_n, .size = sizeof(mod_n)};

	bool result = export_rsa_private_key_from_cert(&buf_pri_cert, &buf_pri, &buf_mod, &buf_pub);
	print_hex("RSA Private Key Private exponent",buf_pri.ptr, buf_pri.size );
	print_hex("RSA Private Key modules n",buf_mod.ptr, buf_mod.size );
	print_hex("RSA Private Key Public exponent",buf_pub.ptr, buf_pub.size );

	ASSERT_EQ(result, true);
}

TEST_F(AsymmetricKeyTest, RSA_2048_export_public_key)
{
	std::array<uint8_t, 2048> pri_cert = { 0 };
    std::array<uint8_t, 2048> pub_cert = { 0 };

	Buffer buf_pri_cert = {.ptr = pri_cert.data(), .size = pri_cert.size()};
    Buffer buf_pub_cert = {.ptr = pub_cert.data(), .size = pub_cert.size()};

	generate_rsa_cert(2048, &buf_pri_cert, &buf_pub_cert);

	uint8_t pri_e[TEST_RSA_KEY_SIZE] = {0};
    uint8_t mod_n[TEST_RSA_KEY_SIZE] = {0};
    uint8_t pub_e[TEST_RSA_PUBLIC_EXPONENT_SIZE] = {0};

    Buffer buf_pub = {.ptr = pub_e, .size = sizeof(pub_e)};
    Buffer buf_mod = {.ptr = mod_n, .size = sizeof(mod_n)};

	bool result = export_rsa_public_key_from_cert(&buf_pub_cert, &buf_mod, &buf_pub);
	print_hex("RSA Public Key modules n",buf_mod.ptr, buf_mod.size );
	print_hex("RSA Public Key Public exponent",buf_pub.ptr, buf_pub.size );

	ASSERT_EQ(result, true);
}


TEST_F(AsymmetricKeyTest, ECDSA_secp256r1)
{
	std::array<uint8_t, 2048> pri_key = { 0 };
    std::array<uint8_t, 2048> pub_key = { 0 };

	Buffer buf_pri = {.ptr = pri_key.data(), .size = pri_key.size()};
    Buffer buf_pub = {.ptr = pub_key.data(), .size = pub_key.size()};

	bool result = generate_ec_cert(&buf_pri, &buf_pub);
	ASSERT_EQ(result, true);
	printf("ECC Private Key \n%s\n", buf_pri.ptr);
	printf("ECC Public Key \n%s\n", buf_pub.ptr);
}

TEST_F(AsymmetricKeyTest, ECDSA_export_key)
{
	std::array<uint8_t, 2048> pri_cert = { 0 };
    std::array<uint8_t, 2048> pub_cert = { 0 };

	Buffer buf_pri_cert = {.ptr = pri_cert.data(), .size = pri_cert.size()};
    Buffer buf_pub_cert = {.ptr = pub_cert.data(), .size = pub_cert.size()};

	bool result = generate_ec_cert(&buf_pri_cert, &buf_pub_cert);

	uint8_t pri_key[TEST_ECDSA_PRIVATE_KEY_SIZE] = { 0 };
    uint8_t pub_key[TEST_ECDSA_PUBLIC_KEY_SIZE] = { 0 };

	Buffer buf_pri = {.ptr = pri_key, .size = sizeof(pri_key)};
    Buffer buf_pub = {.ptr = pub_key, .size = sizeof(pub_key)};

	export_ec_private_key_from_cert(&buf_pri_cert, &buf_pri);
	export_ec_public_key_from_cert(&buf_pub_cert, &buf_pub);

	print_hex("ECC Private Key", buf_pri.ptr, buf_pri.size);
	print_hex("ECC Public Key", buf_pub.ptr, buf_pub.size);

	ASSERT_EQ(result, true);
}

TEST_F(AsymmetricKeyTest, ECDH)
{
	uint8_t pri_key1[TEST_ECDSA_PRIVATE_KEY_SIZE] = { 0 };
    uint8_t pub_key1[TEST_ECDSA_PUBLIC_KEY_SIZE] = { 0 };
	uint8_t pri_key2[TEST_ECDSA_PRIVATE_KEY_SIZE] = { 0 };
    uint8_t pub_key2[TEST_ECDSA_PUBLIC_KEY_SIZE] = { 0 };

	Buffer buf_pri1 = {.ptr = pri_key1, .size = sizeof(pri_key1)};
    Buffer buf_pub1 = {.ptr = pub_key1, .size = sizeof(pub_key1)};

	Buffer buf_pri2 = {.ptr = pri_key2, .size = sizeof(pri_key2)};
    Buffer buf_pub2 = {.ptr = pub_key2, .size = sizeof(pub_key2)};

	bool result = generate_ec_key(&buf_pri1, &buf_pub1);
	ASSERT_EQ(result, true);

	result = generate_ec_key(&buf_pri2, &buf_pub2);
	ASSERT_EQ(result, true);

	uint8_t key1[TEST_ECDH_KEY_SIZE] = { 0 };
	Buffer buf_key1 = {.ptr = key1, .size = sizeof(key1)};

	result = generate_ecdh_key(&buf_pri1, &buf_pub2, &buf_key1);
	ASSERT_EQ(result, true);
	print_hex("ECDH key1", buf_key1.ptr, buf_key1.size);

	uint8_t key2[TEST_ECDH_KEY_SIZE] = { 0 };
	Buffer buf_key2 = {.ptr = key2, .size = sizeof(key2)};

	result = generate_ecdh_key(&buf_pri2, &buf_pub1, &buf_key2);
	ASSERT_EQ(result, true);
	print_hex("ECDH key2", buf_key2.ptr, buf_key2.size);


	ASSERT_EQ(memcmp(buf_key1.ptr, buf_key2.ptr, buf_key1.size), 0);
}


TEST_F(AsymmetricKeyTest, ECDH_KEY_FIX)
{
	uint8_t pri_key1[TEST_ECDSA_PRIVATE_KEY_SIZE] = {
		0x7E, 0x93, 0x1D, 0xEF, 0x4C, 0xF3, 0x89, 0x64, 0x38, 0xC4, 0x2C, 0x95, 0xD5, 0x23, 0xE6, 0x3A,
		0xD7, 0xE8, 0xB5, 0x5C, 0xCA, 0xC9, 0x36, 0xA1, 0x8B, 0x63, 0x10, 0xF1, 0x23, 0x83, 0xA0, 0x0E };

	uint8_t pri_key2[TEST_ECDSA_PRIVATE_KEY_SIZE] = {
		0x49, 0x3B, 0x58, 0x0A, 0xDC, 0x07, 0x0A, 0xB6, 0x40, 0xF7, 0xD9, 0x80, 0xDB, 0x0B, 0xD9, 0x90,
		0x1B, 0xC0, 0x33, 0xAA, 0xEB, 0x81, 0x73, 0x0C, 0x97, 0x62, 0x14, 0x05, 0x4C, 0x60, 0x8B, 0x52 };

	uint8_t pub_key1[TEST_ECDSA_PUBLIC_KEY_SIZE] = {
		0xB9, 0xE2, 0xD6, 0x42, 0xFB, 0x56, 0x30, 0xA5, 0x97, 0x81, 0xED, 0x47, 0x1F, 0x99, 0x71, 0x1F,
		0x3F, 0x0A, 0x3E, 0x2D, 0x66, 0xDB, 0x35, 0x99, 0x50, 0x8C, 0x70, 0x75, 0xE9, 0x31, 0x6F, 0x11,
		0x02, 0x79, 0xDC, 0x05, 0xC7, 0x44, 0x49, 0x8B, 0xBA, 0xB9, 0x21, 0xDA, 0x3F, 0x09, 0x3F, 0x27,
		0x52, 0xD7, 0x2A, 0x3E, 0xD2, 0x30, 0x8B, 0xED, 0x59, 0x39, 0xFF, 0x21, 0xCE, 0xAA, 0xAD, 0xBE };

	uint8_t pub_key2[TEST_ECDSA_PUBLIC_KEY_SIZE] = {
		0xE9, 0x04, 0x77, 0x31, 0x61, 0x39, 0x81, 0x06, 0x44, 0x4E, 0xF0, 0x56, 0x07, 0x93, 0x36, 0x7A,
		0xE1, 0xA3, 0xAE, 0x5A, 0x88, 0x20, 0xFF, 0xDF, 0x0B, 0x56, 0xEB, 0x6B, 0x0F, 0x0F, 0x82, 0x23,
		0x4F, 0x53, 0x44, 0xEA, 0x32, 0xD8, 0x4C, 0x67, 0x96, 0xB9, 0x59, 0xAD, 0x90, 0x99, 0xEB, 0xB6,
		0x65, 0x65, 0x6A, 0xFB, 0x96, 0xBA, 0xD5, 0xC8, 0x21, 0x02, 0xAB, 0x4C, 0x09, 0x91, 0x5C, 0xCA };

	Buffer buf_pri1 = { .ptr = pri_key1, .size = sizeof(pri_key1) };
	Buffer buf_pub1 = { .ptr = pub_key1, .size = sizeof(pub_key1) };

	Buffer buf_pri2 = { .ptr = pri_key2, .size = sizeof(pri_key2) };
	Buffer buf_pub2 = { .ptr = pub_key2, .size = sizeof(pub_key2) };


	uint8_t key1[TEST_ECDH_KEY_SIZE] = { 0 };
	Buffer buf_key1 = { .ptr = key1, .size = sizeof(key1) };

	bool result = generate_ecdh_key(&buf_pri1, &buf_pub2, &buf_key1);
	ASSERT_EQ(result, true);
	print_hex("ECDH key1", buf_key1.ptr, buf_key1.size);

	uint8_t key2[TEST_ECDH_KEY_SIZE] = { 0 };
	Buffer buf_key2 = { .ptr = key2, .size = sizeof(key2) };

	result = generate_ecdh_key(&buf_pri2, &buf_pub1, &buf_key2);
	ASSERT_EQ(result, true);
	print_hex("ECDH key2", buf_key2.ptr, buf_key2.size);


	ASSERT_EQ(memcmp(buf_key1.ptr, buf_key2.ptr, buf_key1.size), 0);
}
