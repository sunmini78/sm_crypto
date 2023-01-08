
#ifndef SM_SIGNATURE_H
#define SM_SIGNATURE_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

bool rsa_pkcs1_sign(const Buffer *pri_e, const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, Buffer *sig);
bool rsa_pkcs1_verify(const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, const Buffer *sig);

bool rsa_pss_sign(const Buffer *pri_e, const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, Buffer *sig);
bool rsa_pss_verify(const Buffer *pub_e, const Buffer *mod_n, const Buffer *message, uint32_t digest_size, const Buffer *sig);

bool ecdsa_sign(const Buffer *key, const Buffer *message, uint32_t digest_size, Buffer *sig);
bool ecdsa_verify(const Buffer *key, const Buffer *message, uint32_t digest_size, const Buffer *sig);

# ifdef __cplusplus
}
# endif

#endif /* SM_SIGNATURE_H */