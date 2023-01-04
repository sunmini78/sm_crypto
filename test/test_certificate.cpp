#include <gtest/gtest.h>
#include <array>

#include "sm_certificate.h"
#include "sm_common.h"

#define TEST_ECDSA_PRIVATE_KEY_SIZE (32u)
#define TEST_ECDSA_PUBLIC_KEY_SIZE (64u)
#define TEST_SIGNATURE_SIZE (64u)

class CertificateTest : public testing::Test
{
protected:
	CertificateTest() = default;
	~CertificateTest() = default;

	void SetUp() override
	{
	}

	void TearDown() override
	{
	}
};

TEST_F(CertificateTest, RSA_2048)
{
	std::array<uint8_t, 2048> pri_key = { 0 };
    std::array<uint8_t, 2048> pub_key = { 0 };

	Buffer buf_pri = {.ptr = pri_key.data(), .size = pri_key.size()};
    Buffer buf_pub = {.ptr = pub_key.data(), .size = pub_key.size()};

	bool result = generate_rsa_cert(2048, &buf_pri, &buf_pub);
	ASSERT_EQ(result, true);

	// print_hex("RSA Private key",buf_pri.ptr, buf_pri.size );
	printf("RSA Private Key \n%s\n", buf_pri.ptr);
	// print_hex("RSA Public key",buf_pub.ptr, buf_pub.size );
	printf("RSA Public Key \n%s\n", buf_pub.ptr);
}


TEST_F(CertificateTest, ECDSA_secp256r1)
{
	std::array<uint8_t, 2048> pri_key = { 0 };
    std::array<uint8_t, 2048> pub_key = { 0 };

	Buffer buf_pri = {.ptr = pri_key.data(), .size = pri_key.size()};
    Buffer buf_pub = {.ptr = pub_key.data(), .size = pub_key.size()};

	bool result = generate_ecdsa_cert(&buf_pri, &buf_pub);
	ASSERT_EQ(result, true);
	printf("ECC Private Key \n%s\n", buf_pri.ptr);
	printf("ECC Public Key \n%s\n", buf_pub.ptr);
}
