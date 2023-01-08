#include "sm_rng.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <string.h>

bool generate_random(Buffer *rng)
{
	bool result = true;

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	const char *personalization = "sm_crypto_specific_string";

	mbedtls_ctr_drbg_context ctx;
	mbedtls_ctr_drbg_init(&ctx);
	mbedtls_ctr_drbg_seed( &ctx, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization, strlen( personalization ) );

	int ret = mbedtls_ctr_drbg_random(&ctx, rng->ptr, rng->size);
    if( ret != 0 )
    {
		result = false;
    }

	mbedtls_ctr_drbg_free(&ctx);
	mbedtls_entropy_free(&entropy);

	return result;
}
