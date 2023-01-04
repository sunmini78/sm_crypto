

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include <string.h>

#include "sm_asymmetric_encryption.h"

static RSA* convertRSAPrivateKey(const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e)
{
	RSA *rsa = RSA_new();

	if(rsa != NULL)
	{
		BIGNUM* n = BN_bin2bn(mod_n->ptr, mod_n->size, NULL);
		BIGNUM* e = BN_bin2bn(pub_e->ptr, pub_e->size, NULL);
		BIGNUM* d = BN_bin2bn(pri_e->ptr, pri_e->size, NULL);

		if(RSA_set0_key(rsa, n, e, d) == 0)
		{
			RSA_free(rsa);
			rsa = NULL;
		}
	}

	return rsa;
}

static RSA* convertRSAPublicKey(const Buffer *pub_e, const Buffer *mod_n)
{
	RSA *rsa = RSA_new();
	if(rsa != NULL)
	{
		BIGNUM* n = BN_bin2bn(mod_n->ptr, mod_n->size, NULL);
		BIGNUM* e = BN_bin2bn(pub_e->ptr, pub_e->size, NULL);
		if(RSA_set0_key(rsa, n, e, NULL) == 0)
		{
			BN_free(n);
			BN_free(e);
			RSA_free(rsa);
			rsa = NULL;
		}
	}

	return rsa;
}

static RSA* convertPemRSAPrivateKey(const char* key)
{
	RSA* rsa = NULL;
	BIO* keybio = BIO_new_mem_buf(key, strlen(key));
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return rsa;
	}

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	BIO_free(keybio);

	return rsa;
}

static RSA* convertPemRSAPublicKey(const char* key)
{
	RSA* rsa = NULL;
	BIO* keybio = BIO_new_mem_buf(key, strlen(key));
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return rsa;
	}

	rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	BIO_free(keybio);

	return rsa;
}

static bool rsaes_encrypt_pem(const Buffer *data, const char *key, Buffer *encrypted, int padding)
{
	bool result = false;
	RSA* rsa = convertPemRSAPublicKey(key);
	if(rsa != NULL)
	{
		int32_t size = RSA_public_encrypt(data->size, data->ptr, encrypted->ptr, rsa, padding);
		if(size > 0)
		{
			encrypted->size = (uint32_t)size;
			result = true;
		}
		RSA_free(rsa);
	}

	return result;
}

static bool rsaes_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted, int padding)
{
	bool result = false;
	RSA* rsa = convertRSAPublicKey(pub_e, mod_n);
	if(rsa != NULL)
	{
		int32_t size = RSA_public_encrypt(data->size, data->ptr, encrypted->ptr, rsa,  padding);
		if(size > 0)
		{
			encrypted->size = (uint32_t)size;
			result = true;
		}
		RSA_free(rsa);
	}

	return result;
}

static bool rsaes_decrypt_pem(const Buffer *enc_data, const char *key, Buffer *decrypted, int padding)
{
	bool result = false;
	RSA *rsa = convertPemRSAPrivateKey(key);
	if(rsa != NULL)
	{
		int32_t size = RSA_private_decrypt(enc_data->size, enc_data->ptr, decrypted->ptr, rsa, padding);
		if(size > 0)
		{
			decrypted->size = (uint32_t)size;
			result = true;
		}
		RSA_free(rsa);
	}

	return result;
}

static bool rsaes_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted, int padding)
{
	bool result = false;

	RSA *rsa = convertRSAPrivateKey(pri_e, mod_n, pub_e);
	if(rsa != NULL)
	{
		int32_t size = RSA_private_decrypt(enc_data->size, enc_data->ptr, decrypted->ptr, rsa, padding);
		if(size > 0)
		{
			decrypted->size = (uint32_t)size;
			result = true;
		}
		RSA_free(rsa);
	}

	return result;
}

bool rsaes_oaep_encrypt_pem(const Buffer *data, const char *key, Buffer *encrypted)
{
	return rsaes_encrypt_pem(data, key, encrypted, RSA_PKCS1_OAEP_PADDING);
}

bool rsaes_oaep_decrypt_pem(const Buffer *enc_data, const char *key, Buffer *decrypted)
{
	return rsaes_decrypt_pem(enc_data, key, decrypted, RSA_PKCS1_OAEP_PADDING);
}

bool rsaes_pkcs1_encrypt_pem(const Buffer *data, const char *key, Buffer *encrypted)
{
	return rsaes_encrypt_pem(data, key, encrypted, RSA_PKCS1_PADDING);
}

bool rsaes_pkcs1_decrypt_pem(const Buffer *enc_data, const char *key, Buffer *decrypted)
{
	return rsaes_decrypt_pem(enc_data, key, decrypted, RSA_PKCS1_PADDING);
}

bool rsaes_oaep_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted)
{
	return rsaes_encrypt(data, pub_e, mod_n, encrypted, RSA_PKCS1_OAEP_PADDING);
}

bool rsaes_oaep_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted)
{
	return rsaes_decrypt(enc_data, pri_e, mod_n, pub_e, decrypted, RSA_PKCS1_OAEP_PADDING);
}

bool rsaes_pkcs1_encrypt(const Buffer *data, const Buffer *pub_e, const Buffer *mod_n, Buffer *encrypted)
{
	return rsaes_encrypt(data, pub_e, mod_n, encrypted, RSA_PKCS1_PADDING);
}

bool rsaes_pkcs1_decrypt(const Buffer *enc_data, const Buffer *pri_e, const Buffer *mod_n, const Buffer *pub_e, Buffer *decrypted)
{
	return rsaes_decrypt(enc_data, pri_e, mod_n, pub_e, decrypted, RSA_PKCS1_PADDING);
}
