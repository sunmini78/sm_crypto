#include "sm_signature.h"

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include "sm_digest.h"

#define SHA_MAX_SIZE (64u)
#define EC_POINT_SIZE (32u)

const EVP_MD * get_sha_method(uint32_t digest_size)
{
	const EVP_MD * md = NULL;
	switch(digest_size)
	{
		case DIGEST_SHA1_SIZE:
			md = EVP_sha1();
		break;
		case DIGEST_SHA224_SIZE:
			md = EVP_sha224();
		break;
		case DIGEST_SHA256_SIZE:
			md = EVP_sha256();
		break;
		case DIGEST_SHA384_SIZE:
			md = EVP_sha384();
		break;
		case DIGEST_SHA512_SIZE:
			md = EVP_sha512();
		break;
	}

	return md;
}

static RSA *convertRSAPrivateKey(const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e)
{
	RSA *rsa = RSA_new();

	if(rsa != NULL)
	{
		BIGNUM *n = BN_bin2bn(mod_n->ptr, mod_n->size, NULL);
		BIGNUM *e = BN_bin2bn(pub_e->ptr, pub_e->size, NULL);
		BIGNUM *d = BN_bin2bn(pri_e->ptr, pri_e->size, NULL);

		if(RSA_set0_key(rsa, n, e, d) == 0)
		{
			BN_free(n);
			BN_free(e);
			BN_free(d);
			RSA_free(rsa);
			rsa = NULL;
		}
	}

	return rsa;
}

static RSA *convertRSAPublicKey(const Buffer *pub_e, const Buffer *mod_n)
{
	RSA *rsa = RSA_new();
	if(rsa != NULL)
	{
		BIGNUM *n = BN_bin2bn(mod_n->ptr, mod_n->size, NULL);
		BIGNUM *e = BN_bin2bn(pub_e->ptr, pub_e->size, NULL);
		if(RSA_set0_key(rsa, n, e, NULL) == 0)
		{
			BN_free(n);
			BN_free(e);
			RSA_free(rsa);
			rsa = NULL;
		}
	}

	return rsa;
}

static uint32_t openssl_rsa_sign(RSA *rsa, const EVP_MD *ed, int pad, const Buffer *digest, Buffer *sig)
{
	uint32_t result = 0;
	size_t siglen = 0;

	EVP_PKEY *key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(key, rsa);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL /* no engine */);
	if(EVP_PKEY_sign_init(ctx) != 1)
	{
		printLastError("EVP_PKEY_sign_init failed");
		return 1;
	}

	if(EVP_PKEY_CTX_set_rsa_padding(ctx, pad) != 1)
	{
		printLastError("EVP_PKEY_CTX_set_rsa_padding failed");
		return 1;
	}
	if(EVP_PKEY_CTX_set_signature_md(ctx, ed) != 1)
	{
		printLastError("EVP_PKEY_CTX_set_signature_md failed");
		return 1;
	}

	if(pad == RSA_PKCS1_PSS_PADDING)
	{
		EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST);
	}

	if(EVP_PKEY_sign(ctx, NULL, &siglen, digest->ptr, digest->size) <= 0)
	{
		printLastError("EVP_PKEY_sign failed");
		return 1;
	}

	if(EVP_PKEY_sign(ctx, sig->ptr, &siglen, digest->ptr, digest->size) <= 0)
	{
		printLastError("EVP_PKEY_sign failed");
		result = 1;
	}

	EVP_PKEY_CTX_free(ctx);
	// EVP_PKEY_free(key);

	return result;
}

static uint32_t openssl_rsa_verify(RSA *rsa, const EVP_MD *ed, int pad, const Buffer *digest, Buffer *sig)
{
    uint32_t result = 0;

    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL /* no engine */);
    EVP_PKEY_verify_init(ctx);

    EVP_PKEY_CTX_set_rsa_padding(ctx, pad);
    EVP_PKEY_CTX_set_signature_md(ctx, ed);

    if(pad == RSA_PKCS1_PSS_PADDING)
    {
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST);
    }

    if(EVP_PKEY_verify(ctx, sig->ptr, sig->size, digest->ptr, digest->size) <= 0)
    {
        printLastError("EVP_PKEY_verify failed");
        result = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    // EVP_PKEY_free(key);
    return result;
}

uint32_t rsa_pkcs1_sign(const Buffer *pri_key, const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	RSA* rsa = convertRSAPrivateKey(pri_key, modN, pub_key);
	uint8_t digest[DIGEST_SHA512_SIZE] = {0};
	Buffer buf_digest = {.ptr = digest, .size = digest_size};
	generate_sha(message, digest, digest_size);

	uint32_t result = openssl_rsa_sign(rsa, get_sha_method(digest_size), RSA_PKCS1_PADDING, &buf_digest, sig);
	RSA_free(rsa);

	return result;
}

uint32_t rsa_pkcs1_verify(const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
    // uint32_t result = 0;
    RSA* rsa = convertRSAPublicKey(pub_key, modN);
    uint8_t digest[DIGEST_SHA512_SIZE] = {0};
    Buffer buf_digest = {.ptr = digest, .size = digest_size};
    generate_sha(message, digest, digest_size);
    uint32_t result = openssl_rsa_verify(rsa, get_sha_method(digest_size), RSA_PKCS1_PADDING, &buf_digest, sig);
    RSA_free(rsa);

    return result;
}

uint32_t rsa_pss_sign(const Buffer *pri_key, const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	RSA* rsa = convertRSAPrivateKey(pri_key, modN, pub_key);
	uint8_t digest[SHA_MAX_SIZE] = {0};
	Buffer buf_digest = {.ptr = digest, .size = digest_size};

	generate_sha(message, digest, digest_size);

	uint32_t result = openssl_rsa_sign(rsa, get_sha_method(digest_size), RSA_PKCS1_PSS_PADDING, &buf_digest, sig);

	RSA_free(rsa);

	return result;
}

uint32_t rsa_pss_verify(const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
    RSA* rsa = convertRSAPublicKey(pub_key, modN);
    uint8_t digest[DIGEST_SHA512_SIZE] = {0};
    Buffer buf_digest = {.ptr = digest, .size = digest_size};
    generate_sha(message, digest, digest_size);

    uint32_t result = openssl_rsa_verify(rsa, get_sha_method(digest_size), RSA_PKCS1_PSS_PADDING, &buf_digest, sig);
    RSA_free(rsa);

    return result;
}

// static EC_KEY* key_regenerate(const BIGNUM *bn)
// {
// 	EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
// 	const EC_GROUP* grp = EC_KEY_get0_group(key);
// 	BN_CTX* ctx = BN_CTX_new();

// 	EC_POINT* pub_key = EC_POINT_new(grp);
// 	EC_POINT_mul(grp, pub_key, bn, NULL, NULL, ctx);

// 	EC_KEY_set_public_key(key, pub_key);
// 	EC_KEY_set_private_key(key, bn);

// 	EC_POINT_free(pub_key);
// 	BN_CTX_free(ctx);

// 	if(EC_KEY_check_key(key) <= 0)
// 	{
// 		printLastError("openssl_ecdsa_sign EC_KEY_check_key faield");
// 		EC_KEY_free(key);
// 		key = NULL;
// 	}

// 	return key;
// }

static EC_KEY* convert_private_ec_key(const Buffer *key)
{
	BIGNUM* bnKey = BN_bin2bn(key->ptr, EC_POINT_SIZE, NULL);

    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP* grp = EC_KEY_get0_group(eckey);
    BN_CTX* ctx = BN_CTX_new();

    EC_POINT* point = EC_POINT_new(grp);
    EC_POINT_mul(grp, point, bnKey, NULL, NULL, ctx);

    EC_KEY_set_public_key(eckey, point);
    EC_KEY_set_private_key(eckey, bnKey);

    EC_POINT_free(point);
    BN_CTX_free(ctx);

    if(EC_KEY_check_key(eckey) <= 0)
    {
        printLastError("openssl_ecdsa_sign EC_KEY_check_key faield");
        EC_KEY_free(eckey);
        eckey = NULL;
    }

    return eckey;
}

uint32_t ecdsa_sign(const Buffer *key, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	uint32_t result = 0;
	EC_KEY* ec_key = convert_private_ec_key(key);
	uint8_t digest[SHA_MAX_SIZE] = {0};
	generate_sha(message, digest, digest_size);

	ECDSA_SIG* ec_sig = ECDSA_do_sign(digest, digest_size, ec_key);

	const BIGNUM *r = ECDSA_SIG_get0_r(ec_sig);
	BN_bn2bin(r, sig->ptr);
	const BIGNUM *s = ECDSA_SIG_get0_s(ec_sig);
	BN_bn2bin(s, &sig->ptr[32]);

	EC_KEY_free(ec_key);
	ECDSA_SIG_free(ec_sig);
	return result;
}

static EC_KEY* convert_public_ec_key(const Buffer *key)
{
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *p_x = BN_bin2bn(key->ptr, EC_POINT_SIZE, NULL);
    BIGNUM* p_y = BN_bin2bn(&key->ptr[EC_POINT_SIZE], EC_POINT_SIZE, NULL);

    if (EC_KEY_set_public_key_affine_coordinates(ec_key, p_x, p_y) <= 0)
    {
        printLastError("EC_KEY_set_public_key_affine_coordinates faield\n");
    }

    if(EC_KEY_check_key(ec_key) <= 0)
    {
        printf("EC_KEY_check_key faield\n");
		EC_KEY_free(ec_key);
        return NULL;
    }

	return ec_key;
}

uint32_t ecdsa_verify(const Buffer *key, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	uint32_t result = 0;
	EC_KEY* ec_key = convert_public_ec_key(key);

	uint8_t digest[SHA_MAX_SIZE] = {0};
	generate_sha(message, digest, digest_size);

	ECDSA_SIG* ec_sig = ECDSA_SIG_new();
	BIGNUM* sig_r = BN_bin2bn(sig->ptr, EC_POINT_SIZE, NULL);
	BIGNUM* sig_s = BN_bin2bn(&sig->ptr[EC_POINT_SIZE], EC_POINT_SIZE, NULL);
	ECDSA_SIG_set0(ec_sig, sig_r, sig_s);

	if(ECDSA_do_verify(digest, digest_size, ec_sig, ec_key) <= 0)
	{
		printLastError("ECDSA_verify faield");
		result = 1;
	}

	ECDSA_SIG_free(ec_sig);
	EC_KEY_free(ec_key);

	return result;
}
