
#include "sm_digest.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

#define SHA_RESULT_SUCCESS 1

static bool generate_sha1(const Buffer *src, uint8_t *digest)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, src->ptr, src->size);
	return SHA1_Final(digest, &ctx) == SHA_RESULT_SUCCESS ? true : false;
}

static bool generate_sha224(const Buffer *src, uint8_t *digest)
{
	SHA256_CTX ctx;
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, src->ptr, src->size);
	return SHA224_Final(digest, &ctx) == SHA_RESULT_SUCCESS ? true : false;
}

static bool generate_sha256(const Buffer *src, uint8_t *digest)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, src->ptr, src->size);
	return SHA256_Final(digest, &ctx) == SHA_RESULT_SUCCESS ? true : false;
}

static bool generate_sha384(const Buffer *src, uint8_t *digest)
{
	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, src->ptr, src->size);
	return SHA384_Final(digest, &ctx) == SHA_RESULT_SUCCESS ? true : false;
}

static bool generate_sha512(const Buffer *src, uint8_t *digest)
{
	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, src->ptr, src->size);
	return SHA512_Final(digest, &ctx) == SHA_RESULT_SUCCESS ? true : false;
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
			ret = generate_sha1(src, digest->ptr);
			break;
		case DIGEST_SHA224_SIZE:
			ret = generate_sha224(src, digest->ptr);
			break;
		case DIGEST_SHA256_SIZE:
			ret = generate_sha256(src, digest->ptr);
			break;
		case DIGEST_SHA384_SIZE:
			ret = generate_sha384(src, digest->ptr);
			break;
		case DIGEST_SHA512_SIZE:
			ret = generate_sha512(src, digest->ptr);
			break;
		default:
			break;
	}

	return ret;
}

bool generate_hmac(const Buffer* key, const Buffer *src, Buffer* mac)
{
	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key->ptr, key->size, EVP_sha256(), NULL);
	HMAC_Update(ctx, src->ptr, src->size);
	HMAC_Final(ctx, mac->ptr, &mac->size);
	HMAC_CTX_free(ctx);

	return true;
}

bool generate_cmac(const Buffer *key, const Buffer *src, Buffer *mac)
{
	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, key->ptr, key->size, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, src->ptr, src->size);
	CMAC_Final(ctx, mac->ptr, &mac->size);
	CMAC_CTX_free(ctx);

	return true;
}