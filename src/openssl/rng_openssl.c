#include "sm_rng.h"
#include <openssl/rand.h>
// #include <openssl/rsa.h>
// #include <openssl/evp.h>
// #include <openssl/ec.h>
// #include <openssl/bn.h>

// #define EC_POINT_SIZE (32u)

bool generate_random(Buffer *rng)
{
	int rc = RAND_bytes(rng->ptr, rng->size);
	if(rc != 0 && rc != 1)
	{
		return false;
	}

	return true;
}

// static RSA* generate_rsa(const uint32_t key_bits)
// {
// 	BIGNUM* exp = BN_new();
// 	BN_set_word(exp, RSA_F4);

// 	RSA *rsa = RSA_new();
// 	if(rsa != NULL)
// 	{
// 		RSA_generate_key_ex(rsa, key_bits, exp, NULL);
// 	}

// 	BN_free(exp);
// 	return rsa;
// }


// static bool get_ecdsa_public_key(EC_KEY* ec_key, Buffer *pub_key)
// {
// 	BN_CTX* ctx = BN_CTX_new();
// 	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
// 	const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
// 	BIGNUM* x = BN_new();
// 	BIGNUM* y = BN_new();
// 	EC_POINT_get_affine_coordinates(group, public_key, x, y, ctx);
// 	BN_bn2bin(x, pub_key->ptr);
// 	BN_bn2bin(y, &pub_key->ptr[EC_POINT_SIZE]);

// 	BN_CTX_free(ctx);
// 	BN_free(x);
// 	BN_free(y);

// 	return true;
// }
