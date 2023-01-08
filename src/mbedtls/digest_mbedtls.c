
#include "sm_digest.h"

#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"

static bool generate_sha1(const Buffer *src, Buffer *digest)
{
	int ret;
	mbedtls_sha1_context ctx;
	mbedtls_sha1_init(&ctx);
	mbedtls_sha1_update(&ctx, src->ptr, src->size);

	ret = mbedtls_sha1_finish(&ctx, digest->ptr);
	mbedtls_sha1_free(&ctx);
	return ret == 0 ? true : false;
}

static bool generate_sha224(const Buffer *src, Buffer *digest)
{
	int ret;
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 1);
	mbedtls_sha256_update(&ctx, src->ptr, src->size);

	ret = mbedtls_sha256_finish(&ctx, digest->ptr);
	mbedtls_sha256_free(&ctx);
	return ret == 0 ? true : false;
}

static bool generate_sha256(const Buffer *src, Buffer *digest)
{
	int ret;
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_update(&ctx, src->ptr, src->size);

	ret = mbedtls_sha256_finish(&ctx, digest->ptr);
	mbedtls_sha256_free(&ctx);
	return ret == 0 ? true : false;
}

static bool generate_sha384(const Buffer *src, Buffer *digest)
{
	int ret;
	mbedtls_sha512_context ctx;
	mbedtls_sha512_init(&ctx);
	mbedtls_sha512_starts(&ctx, 1);
	mbedtls_sha512_update(&ctx, src->ptr, src->size);

	ret = mbedtls_sha512_finish(&ctx, digest->ptr);
	mbedtls_sha512_free(&ctx);
	return ret == 0 ? true : false;
}

static bool generate_sha512(const Buffer *src, Buffer *digest)
{
	int ret;
	mbedtls_sha512_context ctx;
	mbedtls_sha512_init(&ctx);
	mbedtls_sha512_update(&ctx, src->ptr, src->size);

	ret = mbedtls_sha512_finish(&ctx, digest->ptr);
	mbedtls_sha512_free(&ctx);
	return ret == 0 ? true : false;
}


bool generate_sha(const Buffer *src, Buffer *digest)
{
	bool ret = false;

	if (digest->size != DIGEST_SHA1_SIZE &&
		digest->size != DIGEST_SHA224_SIZE && digest->size != DIGEST_SHA256_SIZE &&
		digest->size != DIGEST_SHA384_SIZE && digest->size != DIGEST_SHA512_SIZE)
	{
		return ret;
	}

	switch (digest->size)
	{
		case DIGEST_SHA1_SIZE:
			ret = generate_sha1(src, digest);
			break;
		case DIGEST_SHA224_SIZE:
			ret = generate_sha224(src, digest);
			break;
		case DIGEST_SHA256_SIZE:
			ret = generate_sha256(src, digest);
			break;
		case DIGEST_SHA384_SIZE:
			ret = generate_sha384(src, digest);
			break;
		case DIGEST_SHA512_SIZE:
			ret = generate_sha512(src, digest);
			break;
		default:
			break;
	}

	return ret;
}

bool generate_hmac(const Buffer* key, const Buffer *src, Buffer* mac)
{
	int ret = 0;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_setup(&ctx, md_info, 1);

    // Perform calculation
    mbedtls_md_hmac_starts(&ctx, key->ptr, key->size);
    mbedtls_md_hmac_update(&ctx, src->ptr, src->size);
    ret = mbedtls_md_hmac_finish(&ctx, mac->ptr);
	mbedtls_md_free(&ctx);

	return ret == 0 ? true : false;
}

static mbedtls_cipher_type_t get_cipher_type(int key_bit)
{
	mbedtls_cipher_type_t type = MBEDTLS_CIPHER_NONE;
	switch(key_bit)
	{
	case 128:
		type = MBEDTLS_CIPHER_AES_128_ECB;
		break;
	case 192:
		type = MBEDTLS_CIPHER_AES_192_ECB;
		break;
	case 256:
		type = MBEDTLS_CIPHER_AES_256_ECB;
		break;
	}

	return type;

}
bool generate_cmac(const Buffer *key, const Buffer *src, Buffer *mac)
{
	int ret = 0;
	uint32_t key_bit = key->size * 8;
	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);

	mbedtls_cipher_type_t type = get_cipher_type(key_bit);
	const mbedtls_cipher_info_t * cipher_info =  mbedtls_cipher_info_from_type(type);
	mbedtls_cipher_setup(&ctx, cipher_info);

	mbedtls_cipher_cmac_starts(&ctx, key->ptr, key_bit);
	mbedtls_cipher_cmac_update(&ctx, src->ptr, src->size);

	ret = mbedtls_cipher_cmac_finish(&ctx, mac->ptr);

	mbedtls_cipher_free(&ctx);
	return ret == 0 ? true : false;
}