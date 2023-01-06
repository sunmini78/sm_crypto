#include "sm_symmetric_key.h"

#include <openssl/evp.h>
#include "sm_rng.h"

bool generate_blcok_cipher_key(Buffer * key)
{
	return generate_random(key);
}

bool generate_pbkdf2(const Buffer *password, const Buffer *salt, int32_t iterations, Buffer* key)
{
    int result = PKCS5_PBKDF2_HMAC(password->ptr, password->size, salt->ptr, salt->size, iterations, EVP_sha256(), key->size, key->ptr);
    return result == 1 ? true : false;
}