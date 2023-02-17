#ifndef SM_CERTIFICATE_H
#define SM_CERTIFICATE_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdbool.h>

#include "sm_common.h"

typedef enum
{
	CERT_TYPE_PEM = 0,
	CERT_TYPE_DER
} cert_type_t;

bool verify_certificate(const Buffer* cert, cert_type_t type);
bool get_public_key_from_certificate(const Buffer* cert, cert_type_t type, Buffer* key);
bool get_signature_from_certificate(const Buffer* cert, cert_type_t type, Buffer* signature);


# ifdef __cplusplus
}
# endif
#endif /* SM_CERTIFICATE_H */