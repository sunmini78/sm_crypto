#include <gtest/gtest.h>
#include <array>

#include "sm_asymmetric_encryption.h"
#include "sm_digest.h"
#include "sm_rng.h"
#include "sm_asymmetric_key.h"
#include "sm_common.h"

#define TEST_RSA_KEY_SIZE (256u)
#define TEST_RSA_PUBLIC_EXPONENT_SIZE (4u)
#define TEST_RSA_SIGNATURE_SIZEE (256u)

class EncryptionRsaTest : public testing::Test
{
protected:
	EncryptionRsaTest() = default;
	~EncryptionRsaTest() = default;

	void SetUp() override
	{
		generate_rsa_key(2048, &buf_pri, &buf_mod, &buf_pub);
		// print_hex("RSA private e", buf_pri.ptr, buf_pri.size);
		// print_hex("RSA modulus N", buf_mod.ptr, buf_mod.size);
		// print_hex("RSA pubilc e", buf_pub.ptr, buf_pub.size);
		generate_random(&buf_message);
		print_hex("RSA message", buf_message.ptr, buf_message.size);
	}

	void TearDown() override
	{
	}

	std::array<uint8_t, 256> pri_e = {0};
    std::array<uint8_t, 4> pub_e = {0};
    std::array<uint8_t, 256> mod_n = {0};

    Buffer buf_pri = {.ptr = pri_e.data(), .size = pri_e.size()};
    Buffer buf_pub = {.ptr = pub_e.data(), .size = pub_e.size()};
    Buffer buf_mod = {.ptr = mod_n.data(), .size = mod_n.size()};

	std::array<uint8_t, 190> buf = {0}; // RSA 2048
	// std::array<uint8_t, 86> buf = {0}; // RSA 1024
	Buffer buf_message = {.ptr = buf.data(), .size = buf.size()};

	std::array<uint8_t, 256> encrypted = {0};
	Buffer buf_encryption = {.ptr = encrypted.data(), .size = encrypted.size()};

	std::array<uint8_t, 256> decrypted = {0};
	Buffer buf_decryption = {.ptr = decrypted.data(), .size = decrypted.size()};

};

TEST_F(EncryptionRsaTest, RSA_ES_PKCS)
{
	bool result = rsaes_pkcs1_encrypt(&buf_message, &buf_pub, &buf_mod, &buf_encryption);
	ASSERT_EQ(result, true);

	print_hex("RSA PKCS1 encrypt", buf_encryption.ptr, buf_encryption.size);

	result = rsaes_pkcs1_decrypt(&buf_encryption, &buf_pri, &buf_mod, &buf_pub, &buf_decryption);
	print_hex("RSA PKCS1 dencrypt", buf_decryption.ptr, buf_decryption.size);
	ASSERT_EQ(result, true);
	ASSERT_EQ(memcmp(buf_message.ptr, buf_decryption.ptr, buf_message.size), 0);

}

TEST_F(EncryptionRsaTest, RSA_ES_OAEP)
{
    bool result = rsaes_oaep_encrypt(&buf_message, &buf_pub, &buf_mod, &buf_encryption);
	ASSERT_EQ(result, true);

    print_hex("RSA OAEP encrypt", buf_encryption.ptr, buf_encryption.size);

    result = rsaes_oaep_decrypt(&buf_encryption, &buf_pri, &buf_mod, &buf_pub, &buf_decryption);
	print_hex("RSA OAEP dencrypt", buf_decryption.ptr, buf_decryption.size);
    ASSERT_EQ(result, true);
	ASSERT_EQ(memcmp(buf_message.ptr, buf_decryption.ptr, buf_message.size), 0);
}