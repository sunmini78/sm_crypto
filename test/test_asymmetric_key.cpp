#include <gtest/gtest.h>
#include <array>

#include "sm_asymmetric_key.h"
#include "sm_common.h"

#define TEST_ECDSA_PRIVATE_KEY_SIZE (32u)
#define TEST_ECDSA_PUBLIC_KEY_SIZE (64u)
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