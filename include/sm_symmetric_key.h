#ifndef SM_SYMMETRIC_KEY_H
#define SM_SYMMETRIC_KEY_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

bool generate_blcok_cipher_key(Buffer * key);
bool generate_pbkdf2(const Buffer *password, const Buffer *salt, int32_t iterations, Buffer* key);

# ifdef __cplusplus
}
# endif
#endif /* SM_ASYMMETRIC_KEY_H */