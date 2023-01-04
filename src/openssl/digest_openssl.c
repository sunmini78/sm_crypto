
#include "sm_digest.h"
#include <openssl/sha.h>

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

bool generate_sha(const Buffer *src, uint8_t *digest, uint32_t digest_size)
{
	bool ret = false;

	if(digest_size != DIGEST_SHA1_SIZE &&
		digest_size != DIGEST_SHA224_SIZE && digest_size != DIGEST_SHA256_SIZE &&
		digest_size != DIGEST_SHA384_SIZE && digest_size != DIGEST_SHA512_SIZE)
	{
		return ret;
	}

	switch(digest_size)
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
