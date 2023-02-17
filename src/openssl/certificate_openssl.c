#include "sm_certificate.h"
#include "sm_asymmetric_key.h"

#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


static X509* get_x509(const Buffer* cert)
{
    BIO* bio = BIO_new_mem_buf(cert->ptr, cert->size);
    X509* x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);

    return x509;
}

bool verify_certificate(const Buffer* cert)
{
    X509* x509 = get_x509(cert);
    EVP_PKEY* pkey = X509_get_pubkey(x509);
    int ret = X509_verify(x509, pkey);
    EVP_PKEY_free(pkey);

    X509_free(x509);

    return ret < 0 ? false : true;
}

static bool get_ec_public_key(const EC_KEY* ec_key, Buffer* pub_key)
{
    BN_CTX* ctx = BN_CTX_new();
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
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

bool get_public_key_from_certificate(const Buffer* cert, Buffer* key)
{
    X509* x509 = get_x509(cert);
    EVP_PKEY* pkey = X509_get_pubkey(x509);
    int32_t key_type = EVP_PKEY_id(pkey);
    switch (key_type)
    {
    case EVP_PKEY_RSA:
    case EVP_PKEY_DSA:
    case EVP_PKEY_DH:
        // not implemented
        return false;
    case EVP_PKEY_EC:
        {
            EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
            get_ec_public_key(eckey, key);
        }
        break;
    default:
        return false;
    }

    EVP_PKEY_free(pkey);
    X509_free(x509);

    return true;
}

bool get_ec_signature(const ASN1_BIT_STRING* ans_sig,  Buffer* signature)
{
    const uint8_t* psig = ans_sig->data;
    ECDSA_SIG* ec_sig = ECDSA_SIG_new();
    d2i_ECDSA_SIG(&ec_sig, &psig, ans_sig->length);

    const BIGNUM* r = ECDSA_SIG_get0_r(ec_sig);
    BN_bn2bin(r, signature->ptr);

    const BIGNUM* s = ECDSA_SIG_get0_s(ec_sig);
    BN_bn2bin(s, &signature->ptr[32]);

    ECDSA_SIG_free(ec_sig);
    return true;
}

bool get_signature_from_certificate(const Buffer* cert, Buffer* signature)
{
    bool result = true;
    X509* x509 = get_x509(cert);
    const ASN1_BIT_STRING* asnSignature;
    const X509_ALGOR* palg;
    X509_get0_signature(&asnSignature, &palg, x509);
    int32_t nid = OBJ_obj2nid(palg->algorithm);

    switch(nid)
    {
    case NID_sha256WithRSAEncryption:
    case NID_sha384WithRSAEncryption:
    case NID_sha512WithRSAEncryption:
        result = false;
        break;
    case NID_ecdsa_with_SHA1:
    case NID_ecdsa_with_SHA224:
    case NID_ecdsa_with_SHA256:
    case NID_ecdsa_with_SHA384:
    case NID_ecdsa_with_SHA512:
        result = get_ec_signature(asnSignature, signature);
        break;
    default:
        result = false;
        break;
    }

    X509_free(x509);

    return result;
}