#include "sm_signature.h"

#include <mbedtls/pk.h>
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <mbedtls/bignum.h>
#include <string.h>

#include "sm_asymmetric_key.h"
#include "sm_digest.h"


static bool rsassa_sign(int padding, const Buffer *pri_e, const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	int ret = 0;
	uint8_t digest[DIGEST_SHA512_SIZE] = {0};
	Buffer buf_digest = {.ptr = digest, .size = digest_size};

	mbedtls_rsa_context ctx;
	mbedtls_rsa_init(&ctx);

	mbedtls_rsa_set_padding(&ctx, padding, MBEDTLS_MD_SHA256);

	mbedtls_rsa_import_raw(&ctx, mod_n->ptr, mod_n->size, NULL, 0, NULL, 0, pri_e->ptr, pri_e->size, pub_e->ptr, pub_e->size);
	mbedtls_rsa_complete(&ctx);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	const char *pers = "rsassa_sign";

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	generate_sha(message, &buf_digest);

	if(padding == MBEDTLS_RSA_PKCS_V15)
	{
		ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_MD_SHA256, buf_digest.size, buf_digest.ptr, sig->ptr);
	}
	else
	{
		ret = mbedtls_rsa_rsassa_pss_sign_ext(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_MD_SHA256, buf_digest.size, buf_digest.ptr, buf_digest.size, sig->ptr);
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_rsa_free(&ctx);

	return ret == 0 ? true : false;
}

bool rsa_pkcs1_sign(const Buffer *pri_e, const Buffer *pub_key, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	return rsassa_sign(MBEDTLS_RSA_PKCS_V15, pri_e, pub_key, mod_n, message, digest_size, sig);
}

bool rsa_pss_sign(const Buffer *pri_e, const Buffer *pub_key, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	return rsassa_sign(MBEDTLS_RSA_PKCS_V21, pri_e, pub_key, mod_n, message, digest_size, sig);
}

static bool rsassa_verify(int padding, const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, const Buffer *sig)
{
	int ret = 0;
	uint8_t digest[DIGEST_SHA512_SIZE] = {0};
	Buffer buf_digest = {.ptr = digest, .size = digest_size};

	mbedtls_rsa_context ctx;
	mbedtls_rsa_init(&ctx);

	mbedtls_rsa_set_padding(&ctx, padding, MBEDTLS_MD_SHA256);

	mbedtls_rsa_import_raw(&ctx, mod_n->ptr, mod_n->size, NULL, 0, NULL, 0, NULL, 0, pub_e->ptr, pub_e->size);
	mbedtls_rsa_complete(&ctx);

	generate_sha(message, &buf_digest);

	if(padding == MBEDTLS_RSA_PKCS_V15)
	{
		ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&ctx, MBEDTLS_MD_SHA256, buf_digest.size, buf_digest.ptr, sig->ptr);
	}
	else
	{
		ret = mbedtls_rsa_rsassa_pss_verify_ext(&ctx, MBEDTLS_MD_SHA256, buf_digest.size, buf_digest.ptr, MBEDTLS_MD_SHA256, buf_digest.size, sig->ptr);
	}

	mbedtls_rsa_free(&ctx);
    return ret == 0 ? true : false;
}

bool rsa_pkcs1_verify(const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, const Buffer *sig)
{
    return rsassa_verify(MBEDTLS_RSA_PKCS_V15, pub_e, mod_n, message, digest_size, sig);
}

bool rsa_pss_verify(const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, const Buffer *sig)
{
	return rsassa_verify(MBEDTLS_RSA_PKCS_V21, pub_e, mod_n, message, digest_size, sig);
}

bool ecdsa_sign(const Buffer *key, const Buffer *message, uint32_t digest_size, Buffer *sig)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_mpi_read_binary(&d, key->ptr, key->size);

	uint8_t digest[DIGEST_SHA512_SIZE] = {0};
	Buffer buf_digest = {.ptr = digest, .size = digest_size};
	generate_sha(message, &buf_digest);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	const char *pers = "ecdsa_pk_sign";

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

	int ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf_digest.ptr, buf_digest.size, mbedtls_ctr_drbg_random, &ctr_drbg);
	if(ret == 0)
	{
		mbedtls_mpi_write_binary(&r, sig->ptr, EC_POINT_SIZE);
		mbedtls_mpi_write_binary(&s, &sig->ptr[EC_POINT_SIZE], EC_POINT_SIZE);
	}

	mbedtls_mpi_free(&d);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecp_group_free(&grp);

	return ret == 0 ? true : false;
}

bool ecdsa_verify(const Buffer *key, const Buffer *message, uint32_t digest_size, const Buffer *sig)
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q;
	mbedtls_mpi r, s;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

	mbedtls_ecp_point_init(&Q);

	mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), key->ptr, EC_POINT_SIZE);
	mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), &key->ptr[EC_POINT_SIZE], EC_POINT_SIZE);
	uint8_t point_z = 0x01;
	mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Z), &point_z, 1);

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_mpi_read_binary(&r, sig->ptr, EC_POINT_SIZE);
	mbedtls_mpi_read_binary(&s, &sig->ptr[EC_POINT_SIZE], EC_POINT_SIZE);

	uint8_t digest[DIGEST_SHA512_SIZE] = {0};
	Buffer buf_digest = {.ptr = digest, .size = digest_size};
	generate_sha(message, &buf_digest);

	int ret = mbedtls_ecdsa_verify(&grp, buf_digest.ptr, buf_digest.size , &Q, & r, &s);

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);

    return ret == 0 ? true : false;
}

