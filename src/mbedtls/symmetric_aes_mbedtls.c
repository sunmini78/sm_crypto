#include "sm_symmetric_encryption.h"

#include "mbedtls/cipher.h"

#include <string.h>
#include <stdlib.h>

static mbedtls_cipher_type_t get_cbc_type(uint32_t key_bit)
{
	mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
	switch(key_bit)
	{
	case 128:
		type = MBEDTLS_CIPHER_AES_128_CBC;
		break;
	case 192:
		type = MBEDTLS_CIPHER_AES_192_CBC;
		break;
	case 256:
		type = MBEDTLS_CIPHER_AES_256_CBC;
		break;
	}

	return type;
}

static bool crypt_cbc(mbedtls_operation_t operation, const Buffer *key, const Buffer* iv, const Buffer* input, Buffer* output)
{
	uint32_t key_bit = key->size * 8;

	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	mbedtls_cipher_type_t type = get_cbc_type(key_bit);
	const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);
	mbedtls_cipher_setkey(&ctx, key->ptr, key_bit, operation);

	mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);

	mbedtls_cipher_reset(&ctx);
	int ret = mbedtls_cipher_crypt(&ctx, iv->ptr, iv->size, input->ptr, input->size, output->ptr, &output->size);
	mbedtls_cipher_free(&ctx);

	return ret == 0 ? true : false;
}

bool aes_cbc_encrypt(const Buffer *key, const Buffer* iv, const Buffer* plain, Buffer* cipher)
{
	return crypt_cbc(MBEDTLS_ENCRYPT, key, iv, plain, cipher);
}

bool aes_cbc_decrypt(const Buffer *key, const Buffer* iv, const Buffer* cipher, Buffer* plain)
{
	return crypt_cbc(MBEDTLS_DECRYPT, key, iv, cipher, plain);
}

static mbedtls_cipher_type_t get_ctr_type(uint32_t key_bit)
{
	mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
	switch(key_bit)
	{
	case 128:
		type = MBEDTLS_CIPHER_AES_128_CTR;
		break;
	case 192:
		type = MBEDTLS_CIPHER_AES_192_CTR;
		break;
	case 256:
		type = MBEDTLS_CIPHER_AES_256_CTR;
		break;
	}

	return type;
}

static void make_ctr_iv(uint32_t counter, uint32_t counter_size, uint8_t *nonce, uint8_t* iv)
{
	uint32_t nonce_size = AES_BLOCK_SIZE - counter_size;
	memcpy(iv, nonce, nonce_size);
	memcpy(&iv[12], &counter, sizeof(uint32_t));
}

static bool crypt_ctr(mbedtls_operation_t operation, const Buffer *key, const Buffer* nonce, uint32_t counter, uint32_t counter_size, const Buffer* input, Buffer* output)
{
	uint32_t key_bit = key->size * 8;

	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	mbedtls_cipher_type_t type = get_ctr_type(key_bit);
	const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);
	mbedtls_cipher_setkey(&ctx, key->ptr, key_bit, operation);

	uint8_t iv[AES_BLOCK_SIZE] = {0};
	make_ctr_iv(counter, counter_size, nonce->ptr, iv);

	mbedtls_cipher_reset(&ctx);
	int ret = mbedtls_cipher_crypt(&ctx, iv, AES_BLOCK_SIZE, input->ptr, input->size, output->ptr, &output->size);
	mbedtls_cipher_free(&ctx);

	return ret == 0 ? true : false;
}

bool aes_ctr_encrypt(const Buffer *key, const Buffer* nonce, uint32_t counter, uint32_t counter_size, const Buffer* plain, Buffer* cipher)
{
	return crypt_ctr(MBEDTLS_ENCRYPT, key, nonce, counter, counter_size, plain, cipher);
}

bool aes_ctr_decrypt(const Buffer *key, const Buffer* nonce, uint32_t counter, uint32_t counter_size, const Buffer* cipher, Buffer* plain)
{
	return crypt_ctr(MBEDTLS_DECRYPT, key, nonce, counter, counter_size, cipher, plain);
}

static mbedtls_cipher_type_t get_ccm_type(uint32_t key_bit)
{
	mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
	switch(key_bit)
	{
	case 128:
		type = MBEDTLS_CIPHER_AES_128_CCM;
		break;
	case 192:
		type = MBEDTLS_CIPHER_AES_192_CCM;
		break;
	case 256:
		type = MBEDTLS_CIPHER_AES_256_CCM;
		break;
	}

	return type;
}

bool aes_ccm_encrypt(const Buffer *key, const Buffer* nonce, const Buffer *aad, const Buffer *plain, Buffer *cipher, Buffer* tag)
{
	uint32_t key_bit = key->size * 8;
	mbedtls_cipher_type_t type = get_ccm_type(key_bit);
	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);
	mbedtls_cipher_setkey(&ctx, key->ptr, key_bit, MBEDTLS_ENCRYPT);

	mbedtls_cipher_set_iv(&ctx, nonce->ptr, nonce->size);
	mbedtls_cipher_reset(&ctx);

	uint8_t* output = calloc(cipher->size + tag->size, sizeof(uint8_t));
	size_t olen = 0;
	int ret = mbedtls_cipher_auth_encrypt_ext(&ctx, nonce->ptr, nonce->size, aad->ptr, aad->size, plain->ptr, plain->size, output, (cipher->size + tag->size), &olen, tag->size);
	cipher->size = olen - tag->size;
	memcpy(cipher->ptr, output, cipher->size);
	memcpy(tag->ptr, &output[cipher->size], tag->size);

	mbedtls_cipher_free(&ctx);
	free(output);

	return ret == 0 ? true : false;
}

bool aes_ccm_decrypt(const Buffer *key, const Buffer* nonce, const Buffer *aad, const Buffer* tag, const Buffer *cipher, Buffer *plain)
{
	uint32_t key_bit = key->size * 8;
	mbedtls_cipher_type_t type = get_ccm_type(key_bit);
	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);
	mbedtls_cipher_setkey(&ctx, key->ptr, key_bit, MBEDTLS_ENCRYPT);

	mbedtls_cipher_set_iv(&ctx, nonce->ptr, nonce->size);
	mbedtls_cipher_reset(&ctx);

	uint8_t* input = calloc(cipher->size + tag->size, sizeof(uint8_t));
	memcpy(input, cipher->ptr, cipher->size);
	memcpy(&input[cipher->size], tag->ptr, tag->size);

	size_t ilen = cipher->size + tag->size;
	int ret = mbedtls_cipher_auth_decrypt_ext(&ctx, nonce->ptr, nonce->size, aad->ptr, aad->size, input, ilen, plain->ptr, plain->size, &plain->size, tag->size);

	mbedtls_cipher_free(&ctx);
	free(input);

	return ret == 0 ? true : false;
}

static mbedtls_cipher_type_t get_gcm_type(uint32_t key_bit)
{
	mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
	switch(key_bit)
	{
	case 128:
		type = MBEDTLS_CIPHER_AES_128_GCM;
		break;
	case 192:
		type = MBEDTLS_CIPHER_AES_192_GCM;
		break;
	case 256:
		type = MBEDTLS_CIPHER_AES_256_GCM;
		break;
	}

	return type;
}

bool aes_gcm_encrypt(const Buffer *key, const Buffer* iv, const Buffer *aad, const Buffer *plain, Buffer *cipher, Buffer* tag)
{
	uint32_t key_bit = key->size * 8;
	mbedtls_cipher_type_t type = get_gcm_type(key_bit);

	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);
	mbedtls_cipher_setkey(&ctx, key->ptr, key_bit, MBEDTLS_ENCRYPT);

	mbedtls_cipher_set_iv(&ctx, iv->ptr, iv->size);
	mbedtls_cipher_update_ad(&ctx, aad->ptr, aad->size);

	mbedtls_cipher_reset(&ctx);
	mbedtls_cipher_update(&ctx, plain->ptr, plain->size, cipher->ptr, &cipher->size);

	size_t olen = 0;
	mbedtls_cipher_finish(&ctx, &cipher->ptr[cipher->size], &olen);
	cipher->size += olen;

	int ret = mbedtls_cipher_write_tag(&ctx, tag->ptr, tag->size);

	mbedtls_cipher_free(&ctx);
	return ret == 0 ? true : false;
}

bool aes_gcm_decrypt(const Buffer* key, const Buffer* iv, const Buffer *aad, const Buffer* tag, const Buffer *cipher, Buffer *plain)
{
	uint32_t key_bit = key->size * 8;
	mbedtls_cipher_type_t type = get_gcm_type(key_bit);

	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);
	mbedtls_cipher_setkey(&ctx, key->ptr, key_bit, MBEDTLS_DECRYPT);

	mbedtls_cipher_set_iv(&ctx, iv->ptr, iv->size);
	mbedtls_cipher_update_ad(&ctx, aad->ptr, aad->size);

	mbedtls_cipher_reset(&ctx);
	mbedtls_cipher_update(&ctx, cipher->ptr, cipher->size, plain->ptr, &plain->size);

	size_t olen = 0;
	mbedtls_cipher_finish(&ctx, &plain->ptr[plain->size], &olen);
	plain->size += olen;
	int ret = mbedtls_cipher_check_tag(&ctx, tag->ptr, tag->size);

	mbedtls_cipher_free(&ctx);
	return ret == 0 ? true : false;
}
