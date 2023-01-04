
#ifndef SM_COMMON_H
#define SM_COMMON_H

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct
{
    uint8_t* ptr;
    uint32_t size;
} Buffer;

void printLastError(char *msg);
void print_hex(const char* name, const uint8_t* data, size_t data_size);

# ifdef __cplusplus
}
# endif
#endif /* SM_COMMON_H */