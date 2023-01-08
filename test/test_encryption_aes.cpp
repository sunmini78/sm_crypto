#include <gtest/gtest.h>
#include <array>

#include "sm_symmetric_key.h"
#include "sm_symmetric_encryption.h"
#include "sm_rng.h"


class EncryptionAesTest : public testing::Test
{
protected:
	EncryptionAesTest() = default;
	~EncryptionAesTest() = default;

	void SetUp() override
	{
		generate_blcok_cipher_key(&bkey);
		print_hex("AES KEY", bkey.ptr, bkey.size);

		generate_random(&biv);
		print_hex("AES IV", biv.ptr, biv.size);

		generate_random(&bplain);
	}

	void TearDown() override
	{
	}

	std::array<uint8_t, 32> key = {0x00};
	Buffer bkey = {.ptr = key.data(), .size = key.size()};

	std::array<uint8_t, 16> iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
	Buffer biv = {.ptr = iv.data(), .size = iv.size()};

	uint8_t plain[128] = {0x00};
	Buffer bplain = {.ptr = plain, .size = sizeof(plain)};

	uint8_t cipher[144] = {0x00};
	Buffer bcipher = {.ptr = cipher, .size = sizeof(cipher)};

	uint8_t decrypt[144] = {0x00};
	Buffer bdecrypt = {.ptr = decrypt, .size = sizeof(decrypt)};
};

TEST_F(EncryptionAesTest, CBC)
{
	bool result = true;
	result = aes_cbc_encrypt(&bkey, &biv, &bplain, &bcipher);
	ASSERT_EQ(result, true);
	print_hex("AES CBC ENC", bcipher.ptr, bcipher.size);

	result = aes_cbc_decrypt(&bkey, &biv, &bcipher, &bdecrypt);
	ASSERT_EQ(result, true);
	print_hex("AES CBC DEC", bdecrypt.ptr, bdecrypt.size);

	ASSERT_EQ(bplain.size, bdecrypt.size);
	ASSERT_EQ(memcmp(bplain.ptr, bdecrypt.ptr, bplain.size), 0);
}

TEST_F(EncryptionAesTest, CTR)
{
	bool result = true;
	result = aes_ctr_encrypt(&bkey, &biv, 0xffffffff, NIST_SP800_39A_COUNTER_BLOCK, &bplain, &bcipher);
	ASSERT_EQ(result, true);
	print_hex("AES CTR ENC", bcipher.ptr, bcipher.size);

	result = aes_ctr_decrypt(&bkey, &biv, 0xffffffff, NIST_SP800_39A_COUNTER_BLOCK, &bcipher, &bdecrypt);
	ASSERT_EQ(result, true);
	print_hex("AES CTR DEC", bdecrypt.ptr, bdecrypt.size);

	ASSERT_EQ(bplain.size, bdecrypt.size);
	ASSERT_EQ(memcmp(bplain.ptr, bdecrypt.ptr, bplain.size), 0);

	ASSERT_EQ(result, true);
}

TEST_F(EncryptionAesTest, CCM)
{
	bool result = true;

	std::array<uint8_t, 16> aad = {0};
	Buffer baad = {.ptr = aad.data(), .size = aad.size()};
	generate_random(&baad);

	std::array<uint8_t, 7> nonce = {0};
	Buffer bnonce = {.ptr = nonce.data(), .size = nonce.size()};
	generate_random(&bnonce);

	std::array<uint8_t, 4> tag = {0};
	Buffer btag = {.ptr = tag.data(), .size = tag.size()};

	result = aes_ccm_encrypt(&bkey, &bnonce, &baad, &bplain, &bcipher, &btag);
	ASSERT_EQ(result, true);
	print_hex("AES CCM ENC", bcipher.ptr, bcipher.size);
	print_hex("AES CCM ENC TAG", btag.ptr, btag.size);

	result = aes_ccm_decrypt(&bkey, &bnonce, &baad, &btag, &bcipher, &bdecrypt);
	ASSERT_EQ(result, true);
	print_hex("AES CCM DEC", bdecrypt.ptr, bdecrypt.size);

	ASSERT_EQ(bplain.size, bdecrypt.size);
	ASSERT_EQ(memcmp(bplain.ptr, bdecrypt.ptr, bplain.size), 0);

	ASSERT_EQ(result, true);
}

TEST_F(EncryptionAesTest, GCM)
{
	bool result = true;
	std::array<uint8_t, 16> aad = {0};
	Buffer baad = {.ptr = aad.data(), .size = aad.size()};
	generate_random(&baad);

	biv.size = 12;
	std::array<uint8_t, 16> tag = {0};
	Buffer btag = {.ptr = tag.data(), .size = tag.size()};

	result = aes_gcm_encrypt(&bkey, &biv, &baad, &bplain, &bcipher, &btag);
	ASSERT_EQ(result, true);
	print_hex("AES GCM ENC", bcipher.ptr, bcipher.size);
	print_hex("AES GCM ENC TAG", btag.ptr, btag.size);

	result = aes_gcm_decrypt(&bkey, &biv, &baad, &btag, &bcipher, &bdecrypt);
	ASSERT_EQ(result, true);
	print_hex("AES GCM DEC", bdecrypt.ptr, bdecrypt.size);

	ASSERT_EQ(bplain.size, bdecrypt.size);
	ASSERT_EQ(memcmp(bplain.ptr, bdecrypt.ptr, bplain.size), 0);

	ASSERT_EQ(result, true);
}