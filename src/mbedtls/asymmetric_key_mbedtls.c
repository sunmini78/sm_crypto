#include "sm_asymmetric_key.h"

#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

bool generate_rsa_key(const uint32_t key_bits, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e)
{
	int ret = 0;
	const int exponent = 65537;
	const char *pers = "rsa_gen_key";

	mbedtls_mpi N, D, E;
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);

	mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx), mbedtls_ctr_drbg_random, &ctr_drbg, key_bits, exponent);

	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
	mbedtls_rsa_export(rsa, &N, NULL, NULL, &D, &E);
	mbedtls_mpi_write_binary(&D, pri_e->ptr, pri_e->size);
	mbedtls_mpi_write_binary(&N, mod_n->ptr, mod_n->size);
	mbedtls_mpi_write_binary(&E, pub_e->ptr, pub_e->size);

	mbedtls_pk_free(&ctx);
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);

	return ret == 0 ? true : false;
}

bool export_rsa_private_key_from_cert(const Buffer *cert, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e)
{
	mbedtls_mpi N, D, E;
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);

	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	mbedtls_pk_parse_key(&ctx, cert->ptr, cert->size, NULL, 0,  NULL, NULL);
	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
	int ret = mbedtls_rsa_export(rsa, &N, NULL, NULL, &D, &E);
	mbedtls_mpi_write_binary(&D, pri_e->ptr, pri_e->size);
	mbedtls_mpi_write_binary(&N, mod_n->ptr, mod_n->size);
	mbedtls_mpi_write_binary(&E, pub_e->ptr, pub_e->size);

	mbedtls_pk_free(&ctx);
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);

	return ret == 0 ? true : false;
}

bool export_rsa_public_key_from_cert(const Buffer *cert, Buffer *mod_n, Buffer *pub_e)
{
	mbedtls_mpi N, E;
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);

	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	mbedtls_pk_parse_public_key(&ctx, cert->ptr, cert->size);

	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
	int ret = mbedtls_rsa_export(rsa, &N, NULL, NULL, NULL, &E);
	mbedtls_mpi_write_binary(&N, mod_n->ptr, mod_n->size);
	mbedtls_mpi_write_binary(&E, pub_e->ptr, pub_e->size);
	mbedtls_pk_free(&ctx);
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);

	return ret == 0 ? true : false;
}

bool generate_rsa_cert(uint32_t key_bits, Buffer *pri_cert, Buffer *pub_cert)
{
	int ret = 0;
	const int exponent = 65537;
	const char *pers = "rsa_gen_key";

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);

	mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx), mbedtls_ctr_drbg_random, &ctr_drbg, key_bits, exponent);

	mbedtls_pk_write_key_pem(&ctx, pri_cert->ptr, pri_cert->size);
	mbedtls_pk_write_pubkey_pem(&ctx, pub_cert->ptr, pub_cert->size);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	mbedtls_pk_free(&ctx);

	return ret == 0 ? true : false;
}

bool generate_ec_cert(Buffer *pri_cert, Buffer *pub_cert)
{
	int ret = 0;
	const char *pers = "ecc_gen_key";

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);

	mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(ctx), mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_pk_write_key_pem(&ctx, pri_cert->ptr, pri_cert->size);
	mbedtls_pk_write_pubkey_pem(&ctx, pub_cert->ptr, pub_cert->size);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	mbedtls_pk_free(&ctx);

	return ret == 0 ? true : false;
}

bool generate_ec_key(Buffer *pri_key, Buffer *pub_key)
{
	bool result = false;
	const char *pers = "ecc_gen_key_pair";

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

	mbedtls_mpi pri_point;
	mbedtls_mpi_init(&pri_point);

	mbedtls_ecp_point pub_point;
	mbedtls_ecp_point_init(&pub_point);

	mbedtls_ecp_gen_keypair(&grp, &pri_point, &pub_point, mbedtls_ctr_drbg_random, &ctr_drbg);

	if(mbedtls_ecp_check_pubkey(&grp, &pub_point) == 0 && mbedtls_ecp_check_privkey(&grp, &pri_point) == 0 )
	{
		mbedtls_mpi_write_binary(&pri_point, pri_key->ptr, pri_key->size);
		mbedtls_mpi_write_binary(&pub_point.MBEDTLS_PRIVATE(X), pub_key->ptr, EC_POINT_SIZE );
		mbedtls_mpi_write_binary(&pub_point.MBEDTLS_PRIVATE(Y), &pub_key->ptr[EC_POINT_SIZE ], EC_POINT_SIZE );

		uint8_t z[EC_POINT_SIZE] = {0};
		mbedtls_mpi_write_binary(&pub_point.MBEDTLS_PRIVATE(Z), z, EC_POINT_SIZE );


		result = true;
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return result;
}

bool export_ec_private_key_from_cert(const Buffer *cert, Buffer* key)
{
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	int ret = mbedtls_pk_parse_key(&ctx, cert->ptr, cert->size, NULL, 0,  NULL, NULL);

	mbedtls_ecp_keypair* keypair = mbedtls_pk_ec(ctx);
	// int ret = mbedtls_ecp_write_key(keypair, key->ptr, key->size);
	mbedtls_mpi_write_binary(&keypair->MBEDTLS_PRIVATE(d), key->ptr, key->size);
	mbedtls_pk_free(&ctx);
	return ret == 0 ? true : false;
}

bool export_ec_public_key_from_cert(const Buffer *cert, Buffer* key)
{
	mbedtls_mpi N, E;
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);

	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	int ret = mbedtls_pk_parse_public_key(&ctx, cert->ptr, cert->size);

	mbedtls_ecp_keypair* keypair = mbedtls_pk_ec(ctx);
	// int ret = mbedtls_ecp_point_write_binary(&keypair->MBEDTLS_PRIVATE(grp), &keypair->MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &key->size, key->ptr, key->size);
	mbedtls_mpi_write_binary(&keypair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), key->ptr, EC_POINT_SIZE );
	mbedtls_mpi_write_binary(&keypair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), &key->ptr[EC_POINT_SIZE ], EC_POINT_SIZE );
	mbedtls_pk_free(&ctx);

	return ret == 0 ? true : false;
}