#include "sm_symmetric_key.h"

#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

#include "sm_rng.h"

bool generate_blcok_cipher_key(Buffer * key)
{
	return generate_random(key);
}

bool generate_pbkdf2(const Buffer *password, const Buffer *salt, int32_t iterations, Buffer* key)
{
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password->ptr, password->size, salt->ptr, salt->size, iterations, key->size, key->ptr);
    return ret == 0 ? true : false;
}