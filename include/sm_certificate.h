#ifndef SM_CERTIFICATE_H
#define SM_CERTIFICATE_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

bool generate_rsa_cert(uint32_t key_bits, Buffer *pri_key, Buffer *pub_key);
bool generate_ecdsa_cert(Buffer *pri_key, Buffer *pub_key);

# ifdef __cplusplus
}
# endif
#endif /* SM_CERTIFICATE_H */