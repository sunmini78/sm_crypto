#ifndef SM_RNG_H
#define SM_RNG_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>

#include "sm_common.h"

bool generate_random(Buffer *rng);

# ifdef __cplusplus
}
# endif
#endif /* SM_RNG_H */