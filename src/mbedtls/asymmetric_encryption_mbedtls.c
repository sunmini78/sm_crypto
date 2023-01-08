#include "sm_asymmetric_encryption.h"

#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static bool rsaes_pk_encrypt(int padding, const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted)
{
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);

	mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	mbedtls_rsa_context * rsa = mbedtls_pk_rsa(ctx);
	mbedtls_rsa_set_padding(rsa, padding, MBEDTLS_MD_SHA256);

	mbedtls_rsa_import_raw(rsa, mod_n->ptr, mod_n->size, NULL, 0, NULL, 0, NULL, 0, pub_e->ptr, pub_e->size);
	mbedtls_rsa_complete(rsa);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	const char *pers = "rsaes_pk_encrypt";

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	int ret = mbedtls_pk_encrypt(&ctx, data->ptr, data->size, encrypted->ptr, &encrypted->size, encrypted->size, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_pk_free(&ctx);
	return ret == 0 ? true : false;
}

bool rsaes_pkcs1_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted)
{
	return rsaes_pk_encrypt(MBEDTLS_RSA_PKCS_V15, data, pub_e, mod_n, encrypted);
}

bool rsaes_oaep_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted)
{
	/* first comparison checks for overflow */
    // if( ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2 )
	return rsaes_pk_encrypt(MBEDTLS_RSA_PKCS_V21, data, pub_e, mod_n, encrypted);
}

static bool rsaes_pk_decrypt(int padding, const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted)
{
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);

	mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	mbedtls_rsa_context * rsa = mbedtls_pk_rsa(ctx);
	mbedtls_rsa_set_padding(rsa, padding, MBEDTLS_MD_SHA256);

	mbedtls_rsa_import_raw(rsa, mod_n->ptr, mod_n->size, NULL, 0, NULL, 0, pri_e->ptr, pri_e->size, pub_e->ptr, pub_e->size);
	mbedtls_rsa_complete(rsa);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	const char *pers = "rsaes_pk_decrypt";

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	int ret = mbedtls_pk_decrypt(&ctx, enc_data->ptr, enc_data->size, decrypted->ptr, &decrypted->size, decrypted->size, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_pk_free(&ctx);

	return ret == 0 ? true : false;
}

bool rsaes_pkcs1_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted)
{
	return rsaes_pk_decrypt(MBEDTLS_RSA_PKCS_V15, enc_data, pri_e, mod_n, pub_e, decrypted);
}

bool rsaes_oaep_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted)
{
	return rsaes_pk_decrypt(MBEDTLS_RSA_PKCS_V21, enc_data, pri_e, mod_n, pub_e, decrypted);
}
