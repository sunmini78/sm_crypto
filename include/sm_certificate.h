#ifndef SM_CERTIFICATE_H
#define SM_CERTIFICATE_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdbool.h>

#include "sm_common.h"


bool verify_certificate(const Buffer* cert);
bool get_public_key_from_certificate(const Buffer* cert, Buffer* key);
bool get_signature_from_certificate(const Buffer* cert, Buffer* signature);


# ifdef __cplusplus
}
# endif
#endif /* SM_CERTIFICATE_H */