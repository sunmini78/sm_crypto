
#ifndef SM_SYMMETRIC_ENCRYPTION_H
#define SM_SYMMETRIC_ENCRYPTION_H

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

bool aes_cbc_encrypt(const Buffer *key, const Buffer* iv, const Buffer* plain, Buffer* cipher);
bool aes_cbc_decrypt(const Buffer *key, const Buffer* iv, const Buffer* cipher, Buffer* plain);

bool aes_ctr_encrypt(const Buffer *key, const Buffer* iv, uint32_t counter, uint32_t block_size, const Buffer* plain, Buffer* cipher);
bool aes_ctr_decrypt(const Buffer *key, const Buffer* iv, uint32_t counter, uint32_t block_size, const Buffer* cipher, Buffer* plain);

// NONCE 56(7) ~ 104(13)
// AAD 128(16)
// TAG 32(4) ~ 128(16)
bool aes_ccm_encrypt(const Buffer *key, const Buffer* nonce, const Buffer *aad, const Buffer *plain, Buffer *cipher, Buffer* tag);
bool aes_ccm_decrypt(const Buffer *key, const Buffer* nonce, const Buffer *aad, Buffer* tag, const Buffer *cipher, Buffer *plain);

// IV 96(12)
// AAD 128(16)
// TAG 128(16)
bool aes_gcm_encrypt(const Buffer *key, const Buffer* iv, const Buffer *aad, const Buffer* plain, Buffer* cipher, Buffer* tag);
bool aes_gcm_decrypt(const Buffer *key, const Buffer* iv, const Buffer *aad, Buffer* tag, const Buffer* cipher, Buffer* plain);

# ifdef __cplusplus
}
# endif
#endif /* SM_SYMMETRIC_ENCRYPTION_H */