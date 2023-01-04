#ifndef SM_RNG_H
#define SM_RNG_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

bool generate_random(Buffer *rng);

bool generate_rsa_key(const uint32_t key_bits, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e);
bool generate_ecdsa_key(Buffer *pri_key, Buffer *pub_key);

# ifdef __cplusplus
}
# endif
#endif /* SM_RNG_H */