
#ifndef SM_ASYMMETRIC_ENCRYPTION_H
#define SM_ASYMMETRIC_ENCRYPTION_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

#define AES_KEY_SIZE_128 (16u)
#define AES_KEY_SIZE_192 (24u)
#define AES_KEY_SIZE_256 (32u)

#define AES_BLOCK_SIZE (16u)
#define NIST_SP800_39A_COUNTER_BLOCK (8u)
#define RFC_3896_COUNTER_BLOCK (4u)

bool rsaes_oaep_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted);
bool rsaes_oaep_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted);

bool rsaes_pkcs1_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted);
bool rsaes_pkcs1_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted);

# ifdef __cplusplus
}
# endif
#endif /* SM_ASYMMETRIC_ENCRYPTION_H */