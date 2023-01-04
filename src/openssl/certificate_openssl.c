#include "sm_certificate.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "sm_rng.h"

static RSA* generate_rsa(const uint32_t key_bits)
{
	BIGNUM* exp = BN_new();
	BN_set_word(exp, RSA_F4);

	RSA *rsa = RSA_new();
	if(rsa != NULL)
	{
		RSA_generate_key_ex(rsa, key_bits, exp, NULL);
	}

	BN_free(exp);
	return rsa;
}

bool generate_rsa_cert(uint32_t key_bits, Buffer *pri_key, Buffer *pub_key)
{
	RSA *rsa = generate_rsa(key_bits);
	if(rsa == NULL)
	{
		return false;
	}

	/* To get the C-string PEM form: */
	BIO *pub_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(pub_bio, rsa);

	BIO *pri_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(pri_bio, rsa, NULL, NULL, 0, NULL, NULL);

	int key_size = BIO_pending(pub_bio);
	BIO_read(pub_bio, pub_key->ptr, key_size);
	pub_key->ptr[key_size] = '\0';
	pub_key->size = key_size + 1;

	key_size = BIO_pending(pri_bio);
	BIO_read(pri_bio, pri_key->ptr, key_size);
	pri_key->ptr[key_size] = '\0';
	pri_key->size = key_size + 1;

	BIO_free_all(pri_bio);
	BIO_free_all(pub_bio);
	RSA_free(rsa);
	return true;
}

bool generate_ecdsa_cert(Buffer *pri_key, Buffer *pub_key)
{
	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	/* -------------------------------------------------------- *
	* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
	* ---------------------------------------------------------*/
	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

	if (! (EC_KEY_generate_key(ec_key)))
	{
		return false;
	}

	BIO *pri_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_ECPrivateKey(pri_bio, ec_key, NULL, NULL, 0, NULL, NULL);

	int key_size = BIO_pending(pri_bio);
	BIO_read(pri_bio, pri_key->ptr, key_size);
	pri_key->ptr[key_size] = '\0';
	pri_key->size = key_size + 1;

	BIO *pub_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_EC_PUBKEY(pub_bio, ec_key);

	key_size = BIO_pending(pub_bio);
	BIO_read(pub_bio, pub_key->ptr, key_size);
	pub_key->ptr[key_size] = '\0';
	pub_key->size = key_size + 1;

	BIO_free_all(pri_bio);
	BIO_free_all(pub_bio);
	EC_KEY_free(ec_key);

	return true;
}