
#include "sm_symmetric_encryption.h"

#include <string.h>
#include <openssl/evp.h>


#define CIPHER_ENCRYPT 1
#define CIPHER_DECRYPT 0

static bool openssl_crypt(const EVP_CIPHER *evp_cipher, const Buffer *key, const Buffer* iv, const Buffer *input, Buffer *output, int mode)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, evp_cipher, NULL, key->ptr, iv->ptr, mode);

	int output_len = 0;
	EVP_CipherUpdate(ctx, output->ptr, &output_len, input->ptr, input->size);

	int tag_len = 0;
	EVP_CipherFinal_ex(ctx, &output->ptr[output_len], &tag_len);
	output->size = output_len + tag_len;

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

static const EVP_CIPHER* get_aes_cbc_cipher_by_key_size(uint32_t size)
{
	const EVP_CIPHER *cipher = NULL;
	switch(size)
	{
	case AES_KEY_SIZE_128:
		cipher = EVP_aes_128_cbc();
		break;
	case AES_KEY_SIZE_192:
		cipher = EVP_aes_192_cbc();
		break;
	case AES_KEY_SIZE_256:
		cipher = EVP_aes_256_cbc();
		break;
	}

	return cipher;
}

bool aes_cbc_encrypt(const Buffer *key, const Buffer* iv, const Buffer* plain, Buffer* cipher)
{
	const EVP_CIPHER *evp_cipher = get_aes_cbc_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}
	uint32_t ret2 = openssl_crypt(evp_cipher, key, iv, plain, cipher, CIPHER_ENCRYPT);
}

bool aes_cbc_decrypt(const Buffer *key, const Buffer* iv, const Buffer* cipher, Buffer* plain)
{
	const EVP_CIPHER *evp_cipher = get_aes_cbc_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}
	return openssl_crypt(evp_cipher,  key, iv, cipher, plain, CIPHER_DECRYPT);
}

static const EVP_CIPHER* get_aes_ctr_cipher_by_key_size(uint32_t size)
{
	const EVP_CIPHER *cipher = NULL;
	switch(size)
	{
	case AES_KEY_SIZE_128:
		cipher = EVP_aes_128_ctr();
		break;
	case AES_KEY_SIZE_192:
		cipher = EVP_aes_192_ctr();
		break;
	case AES_KEY_SIZE_256:
		cipher = EVP_aes_256_ctr();
		break;
	}
	return cipher;
}

static void increse_counter(uint32_t counter, uint32_t counter_size, uint8_t *nonce, uint8_t* iv)
{
	uint32_t nonce_size = AES_BLOCK_SIZE - counter_size;
	memcpy(iv, nonce, nonce_size);
	memcpy(&iv[12], &counter, sizeof(uint32_t));
}

bool aes_ctr_encrypt(const Buffer *key, const Buffer* nonce, uint32_t counter, uint32_t counter_size, const Buffer* plain, Buffer* cipher)
{
	const EVP_CIPHER* evp_cipher = get_aes_ctr_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}

	uint8_t iv[AES_BLOCK_SIZE] = {0};
	Buffer bIv = {.ptr= iv, .size = AES_BLOCK_SIZE};
	increse_counter(counter, counter_size, nonce->ptr, iv);

	return openssl_crypt(evp_cipher, key, &bIv, plain, cipher, CIPHER_ENCRYPT);
}

bool aes_ctr_decrypt(const Buffer *key, const Buffer* nonce, uint32_t counter, uint32_t counter_size, const Buffer* cipher, Buffer* plain)
{
	const EVP_CIPHER* evp_cipher = get_aes_ctr_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}

	uint32_t nonce_size = AES_BLOCK_SIZE - counter_size;

	uint8_t iv[AES_BLOCK_SIZE] = {0};
	Buffer bIv = {.ptr= iv, .size = AES_BLOCK_SIZE};

	increse_counter(counter, counter_size, nonce->ptr, iv);

	return openssl_crypt(evp_cipher,  key, &bIv, cipher, plain, CIPHER_DECRYPT);
}

static const EVP_CIPHER* get_aes_ccm_cipher_by_key_size(uint32_t size)
{
	const EVP_CIPHER *cipher = NULL;
	switch(size)
	{
	case AES_KEY_SIZE_128:
		cipher = EVP_aes_128_ccm();
		break;
	case AES_KEY_SIZE_192:
		cipher = EVP_aes_192_ccm();
		break;
	case AES_KEY_SIZE_256:
		cipher = EVP_aes_256_ccm();
		break;
	}
	return cipher;
}

bool aes_ccm_encrypt(const Buffer *key, const Buffer* nonce, const Buffer *aad, const Buffer *plain, Buffer *cipher, Buffer* tag)
{
	const EVP_CIPHER* evp_cipher = get_aes_ccm_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, CIPHER_ENCRYPT);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce->size, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag->size, NULL);

	EVP_CipherInit_ex(ctx, NULL, NULL,  key->ptr, nonce->ptr, CIPHER_ENCRYPT);

	int cipher_len = 0;
	/* Provide any AAD data. This can be called zero or one times as required */
	EVP_CipherUpdate(ctx, NULL, &cipher_len, NULL, plain->size);
	EVP_CipherUpdate(ctx, NULL, &cipher_len, aad->ptr, aad->size);

	EVP_CipherUpdate(ctx, cipher->ptr, &cipher_len, plain->ptr, plain->size);

	int32_t len = 0;
	EVP_CipherFinal_ex(ctx, &cipher->ptr[cipher_len], &len);
	cipher->size = cipher_len + len;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag->size, tag->ptr);

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

bool aes_ccm_decrypt(const Buffer *key, const Buffer* nonce, const Buffer *aad, const Buffer* tag, const Buffer *cipher, Buffer *plain)
{
	const EVP_CIPHER* evp_cipher = get_aes_ccm_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}

	int result = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, CIPHER_DECRYPT);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce->size, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag->size, tag->ptr);

	EVP_CipherInit_ex(ctx, NULL, NULL,  key->ptr, nonce->ptr, CIPHER_DECRYPT);
	int len = 0;
	/* Provide any AAD data. This can be called zero or more times as required */
	EVP_CipherUpdate(ctx, NULL, &len, NULL, cipher->size);
    EVP_CipherUpdate(ctx, NULL, &len, aad->ptr, aad->size);

	result = EVP_CipherUpdate(ctx, plain->ptr, &plain->size, cipher->ptr, cipher->size);
	EVP_CIPHER_CTX_free(ctx);


	return result == 1 ? true : false;
}

static const EVP_CIPHER* get_aes_gcm_cipher_by_key_size(uint32_t size)
{
	const EVP_CIPHER *cipher = NULL;
	switch(size)
	{
	case AES_KEY_SIZE_128:
		cipher = EVP_aes_128_gcm();
		break;
	case AES_KEY_SIZE_192:
		cipher = EVP_aes_192_gcm();
		break;
	case AES_KEY_SIZE_256:
		cipher = EVP_aes_256_gcm();
		break;
	}
	return cipher;
}

bool aes_gcm_encrypt(const Buffer *key, const Buffer* iv, const Buffer *aad, const Buffer *plain, Buffer *cipher, Buffer* tag)
{
	const EVP_CIPHER* evp_cipher = get_aes_gcm_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, CIPHER_ENCRYPT);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv->size, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag->size, NULL);

	EVP_CipherInit_ex(ctx, NULL, NULL,  key->ptr, iv->ptr, CIPHER_ENCRYPT);
	int cipher_len = 0;
	EVP_CipherUpdate(ctx, NULL, &cipher_len, aad->ptr, aad->size);
	EVP_CipherUpdate(ctx, cipher->ptr, &cipher_len, plain->ptr, plain->size);

	int32_t len = 0;
	EVP_CipherFinal_ex(ctx, &cipher->ptr[cipher_len], &len);
	cipher->size = cipher_len + len;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag->size, tag->ptr);

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

bool aes_gcm_decrypt(const Buffer* key, const Buffer* iv, const Buffer *aad, const Buffer* tag, const Buffer *cipher, Buffer *plain)
{
	const EVP_CIPHER* evp_cipher = get_aes_gcm_cipher_by_key_size(key->size);
	if(evp_cipher == NULL)
	{
		return false;
	}

	int result = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, CIPHER_DECRYPT);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv->size, NULL);

	EVP_CipherInit_ex(ctx, NULL, NULL,  key->ptr, iv->ptr, CIPHER_DECRYPT);
	int plain_len = 0;
	EVP_CipherUpdate(ctx, NULL, &plain_len, aad->ptr, aad->size);
	EVP_CipherUpdate(ctx, plain->ptr, &plain_len, cipher->ptr, cipher->size);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag->size, tag->ptr);

	int final_len = 0;
	result = EVP_CipherFinal_ex(ctx, &plain->ptr[plain_len], &final_len);
	plain->size = plain_len + final_len;

	EVP_CIPHER_CTX_free(ctx);

	return result > 0 ? true : false;
}
