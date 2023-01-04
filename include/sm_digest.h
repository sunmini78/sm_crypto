#ifndef SM_DIGEST_H
#define SM_DIGEST_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

#define DIGEST_SHA1_SIZE (20u)
#define DIGEST_SHA224_SIZE (28u)
#define DIGEST_SHA256_SIZE (32u)
#define DIGEST_SHA384_SIZE (48u)
#define DIGEST_SHA512_SIZE (64u)

bool generate_sha(const Buffer *src, uint8_t *digest, uint32_t digest_size);

# ifdef __cplusplus
}
# endif
#endif /* SM_DIGEST_H */