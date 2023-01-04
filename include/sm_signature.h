
#ifndef SM_SIGNATURE_H
#define SM_SIGNATURE_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

uint32_t rsa_pkcs1_sign(const Buffer *pri_key, const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig);
uint32_t rsa_pkcs1_verify(const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig);

uint32_t rsa_pss_sign(const Buffer *pri_key, const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig);
uint32_t rsa_pss_verify(const Buffer *pub_key, const Buffer *modN, const Buffer *message, uint32_t digest_size, Buffer *sig);

uint32_t ecdsa_sign(const Buffer *key, const Buffer *message, uint32_t digest_size, Buffer *sig);
uint32_t ecdsa_verify(const Buffer *key, const Buffer *message, uint32_t digest_size, Buffer *sig);

# ifdef __cplusplus
}
# endif

#endif /* SM_SIGNATURE_H */