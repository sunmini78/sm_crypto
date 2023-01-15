#include "sm_asymmetric_key.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

// #include "sm_rng.h"

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


bool generate_rsa_key(const uint32_t key_bits, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e)
{
    RSA *rsa = generate_rsa(key_bits);

    if(rsa == NULL)
    {
        return false;
    }

	const BIGNUM *d = RSA_get0_d(rsa);
    BN_bn2bin(d, pri_e->ptr);

	const BIGNUM *n = RSA_get0_n(rsa);
    BN_bn2bin(n, mod_n->ptr);

	const BIGNUM *e = RSA_get0_e(rsa);
	pub_e->ptr[0] = 0x00;
    BN_bn2bin(e, &pub_e->ptr[1]);

    RSA_free(rsa);

    return true;
}

bool export_rsa_private_key_from_cert(const Buffer *cert, Buffer *pri_e, Buffer *mod_n, Buffer *pub_e)
{
	RSA* rsa = NULL;
	BIO *bio = BIO_new_mem_buf(cert->ptr, cert->size);
	rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);

	const BIGNUM *d = RSA_get0_d(rsa);
    BN_bn2bin(d, pri_e->ptr);

	const BIGNUM *n = RSA_get0_n(rsa);
	BN_bn2bin(n, mod_n->ptr);

	const BIGNUM *e = RSA_get0_e(rsa);
	pub_e->ptr[0] = 0x00;
    BN_bn2bin(e, &pub_e->ptr[1]);

	BIO_free(bio);
}

bool export_rsa_public_key_from_cert(const Buffer *cert, Buffer *mod_n, Buffer *pub_e)
{
	RSA* rsa = NULL;
	BIO *bio = BIO_new_mem_buf(cert->ptr, cert->size);
	rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);

	const BIGNUM *n = RSA_get0_n(rsa);
	BN_bn2bin(n, mod_n->ptr);

	const BIGNUM *e = RSA_get0_e(rsa);
	pub_e->ptr[0] = 0x00;
    BN_bn2bin(e, &pub_e->ptr[1]);

	BIO_free(bio);
}

bool generate_rsa_cert(uint32_t key_bits, Buffer *pri_cert, Buffer *pub_cert)
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
	BIO_read(pub_bio, pub_cert->ptr, key_size);
	pub_cert->ptr[key_size] = '\0';
	pub_cert->size = key_size + 1;

	key_size = BIO_pending(pri_bio);
	BIO_read(pri_bio, pri_cert->ptr, key_size);
	pri_cert->ptr[key_size] = '\0';
	pri_cert->size = key_size + 1;

	BIO_free_all(pri_bio);
	BIO_free_all(pub_bio);
	RSA_free(rsa);
	return true;
}

bool generate_ec_cert(Buffer *pri_cert, Buffer *pub_cert)
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
	BIO_read(pri_bio, pri_cert->ptr, key_size);
	pri_cert->ptr[key_size] = '\0';
	pri_cert->size = key_size + 1;

	BIO *pub_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_EC_PUBKEY(pub_bio, ec_key);

	key_size = BIO_pending(pub_bio);
	BIO_read(pub_bio, pub_cert->ptr, key_size);
	pub_cert->ptr[key_size] = '\0';
	pub_cert->size = key_size + 1;

	BIO_free_all(pri_bio);
	BIO_free_all(pub_bio);
	EC_KEY_free(ec_key);
	return true;
}

static bool get_ec_public_key(const EC_KEY* ec_key, Buffer *pub_key)
{
	BN_CTX* ctx = BN_CTX_new();
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	EC_POINT_get_affine_coordinates(group, public_key, x, y, ctx);
	BN_bn2bin(x, pub_key->ptr);
	BN_bn2bin(y, &pub_key->ptr[EC_POINT_SIZE]);

	BN_CTX_free(ctx);
	BN_free(x);
	BN_free(y);

	return true;
}

bool generate_ec_key(Buffer *pri_key, Buffer *pub_key)
{
	bool result = true;

	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	/* -------------------------------------------------------- *
	* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
	* ---------------------------------------------------------*/
	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

	if (! (EC_KEY_generate_key(ec_key)))
	{
		result = false;
	}
	else
	{
		const BIGNUM* private_key = EC_KEY_get0_private_key(ec_key);
		BN_bn2bin(private_key, pri_key->ptr);

		get_ec_public_key(ec_key, pub_key);
	}

	EC_KEY_free(ec_key);
    return result;
}


static EC_KEY* get_ec_private_key(const Buffer *key)
{
	BIGNUM* bn = BN_bin2bn(key->ptr, EC_POINT_SIZE, NULL);

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP* grp = EC_KEY_get0_group(ec_key);
    BN_CTX* ctx = BN_CTX_new();

    EC_POINT* pub_key = EC_POINT_new(grp);
    EC_POINT_mul(grp, pub_key, bn, NULL, NULL, ctx);

    EC_KEY_set_public_key(ec_key, pub_key);
    EC_KEY_set_private_key(ec_key, bn);

    EC_POINT_free(pub_key);
    BN_CTX_free(ctx);

    if(EC_KEY_check_key(ec_key) <= 0)
    {
        print_last_error("EC_KEY_check_key faield");
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }

    return ec_key;
}

static EC_POINT* get_ec_point(const Buffer *key)
{
	BN_CTX* ctx = BN_CTX_new();
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	BIGNUM *p_x = BN_bin2bn(key->ptr, EC_POINT_SIZE, NULL);
    BIGNUM* p_y = BN_bin2bn(&key->ptr[EC_POINT_SIZE], EC_POINT_SIZE, NULL);

	EC_POINT* public_key = EC_POINT_new(group);
	EC_POINT_set_affine_coordinates(group, public_key, p_x, p_y, ctx);

	BN_CTX_free(ctx);

	return public_key;
}

bool export_ec_private_key_from_cert(const Buffer *cert, Buffer* key)
{
	EC_KEY* ec_key = NULL;
	BIO *bio = BIO_new_mem_buf(cert->ptr, cert->size);
	ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
	const BIGNUM* private_key = EC_KEY_get0_private_key(ec_key);

	BN_bn2bin(private_key, key->ptr);
	BIO_free(bio);

	return true;
}

bool export_ec_public_key_from_cert(const Buffer *cert, Buffer* key)
{
	EC_KEY* ec_key = NULL;

	BIO *bio = BIO_new_mem_buf(cert->ptr, cert->size);
	ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);

	get_ec_public_key(ec_key, key);

	BIO_free(bio);

	return true;
}

bool generate_ecdh_key(const Buffer * pri_key, const Buffer* peer_pub_key, Buffer* key)
{
	bool result = true;
	EC_KEY* ec_key = get_ec_private_key(pri_key );

	int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
	key->size = (field_size + 7) / 8;

	EC_POINT* pub_key = get_ec_point(peer_pub_key);
	int ret = ECDH_compute_key(key->ptr, key->size, pub_key, ec_key, NULL);
	if(ret <= 0)
	{
		result = false;
	}
	else
	{
		key->size = ret;
	}

	return result;
}