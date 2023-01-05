#ifndef SM_ASYMMETRIC_KEY_H
#define SM_ASYMMETRIC_KEY_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

bool generate_rsa_cert(uint32_t key_bits, Buffer *pri_key, Buffer *pub_key);
bool generate_ecdsa_cert(Buffer *pri_key, Buffer *pub_key);

bool generate_rsa_key(const uint32_t key_bits, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e);
bool generate_ecdsa_key(Buffer *pri_key, Buffer *pub_key);

bool export_rsa_private_key_from_cert(const Buffer *cert, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e);
bool export_rsa_public_key_from_cert(const Buffer *cert, Buffer *mod_n, Buffer *pub_e);

bool export_ecc_private_key_from_cert(const Buffer *cert, Buffer* key);
bool export_ecc_public_key_from_cert(const Buffer *cert, Buffer* key);

# ifdef __cplusplus
}
# endif
#endif /* SM_ASYMMETRIC_KEY_H */