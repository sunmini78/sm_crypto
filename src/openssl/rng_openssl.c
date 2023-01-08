#include "sm_rng.h"
#include <openssl/rand.h>

bool generate_random(Buffer *rng)
{
	int rc = RAND_bytes(rng->ptr, rng->size);
	if(rc != 0 && rc != 1)
	{
		return false;
	}

	return true;
}
