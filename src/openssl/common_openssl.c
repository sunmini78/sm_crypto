
#include <openssl/err.h>
#include <stdio.h>

void printLastError(char *msg)
{
	char *err = malloc(130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}

void print_hex(const char* name, const uint8_t* data, size_t data_size)
{
	size_t hex_data_size = (data_size *3 ) + 1;
	char* hex_data = malloc(hex_data_size);
	char* ptr = &hex_data[0];

	size_t count = 0;
	for(size_t i = 0; i < data_size; i++)
	{
		count += 1;
		if(count % 32 == 0)
		{
			ptr += sprintf(ptr, "%02X\n", data[i]);
			count = 0;
		}
		else
		{
			ptr += sprintf(ptr, "%02X ", data[i]);
		}
	}

	printf("%s (size : %zu )\n%s \n", name, data_size, hex_data);
	free(hex_data);

	return;
}
