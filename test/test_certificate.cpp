#include <gtest/gtest.h>

#include <string>
#include <vector>
#include <fstream>

#include "sm_certificate.h"
#include "sm_common.h"

class CertificateTest : public testing::Test
{
protected:
	CertificateTest() = default;
	~CertificateTest() = default;

	void SetUp() override
	{
	}

	void TearDown() override
	{
	}


	std::vector<uint8_t> load_certificate(cert_type_t type)
	{
		std::string file_name = type == CERT_TYPE_PEM ? "../cert/secp256r1/cert.pem" : "../cert/secp256r1/cert.der";
		std::ifstream stream(file_name);
		return std::vector<uint8_t>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
	}
};

TEST_F(CertificateTest, VERIFY_PEM_FORM)
{
	std::vector<uint8_t> cert = load_certificate(CERT_TYPE_PEM);
	Buffer buf_cert = {.ptr = cert.data(), .size = cert.size()};
	bool result = verify_certificate(&buf_cert, CERT_TYPE_PEM);
	ASSERT_EQ(result, true);
}

TEST_F(CertificateTest, VERIFY_DER_FORM)
{
	std::vector<uint8_t> cert = load_certificate(CERT_TYPE_DER);
	Buffer buf_cert = {.ptr = cert.data(), .size = cert.size()};
	bool result = verify_certificate(&buf_cert, CERT_TYPE_DER);
	ASSERT_EQ(result, true);
}


TEST_F(CertificateTest, GET_PUBLIC_KEY_PEM_FORM)
{
	std::vector<uint8_t> cert = load_certificate(CERT_TYPE_PEM);
	Buffer buf_cert = {.ptr = cert.data(), .size = cert.size()};

	std::array<uint8_t, 64> key = {0};
	Buffer buf_key = {.ptr = key.data(), .size = key.size()};
	bool result = get_public_key_from_certificate(&buf_cert, CERT_TYPE_PEM, &buf_key);
	ASSERT_EQ(result, true);
	print_hex("public key", buf_key.ptr, buf_key.size);
}

TEST_F(CertificateTest, GET_PUBLIC_KEY_DER_FORM)
{
	std::vector<uint8_t> cert = load_certificate(CERT_TYPE_DER);
	Buffer buf_cert = {.ptr = cert.data(), .size = cert.size()};

	std::array<uint8_t, 64> key = {0};
	Buffer buf_key = {.ptr = key.data(), .size = key.size()};
	bool result = get_public_key_from_certificate(&buf_cert, CERT_TYPE_DER, &buf_key);
	ASSERT_EQ(result, true);

	print_hex("public key", buf_key.ptr, buf_key.size);
}

TEST_F(CertificateTest, GET_SIGNATURE_PEM_FORM)
{
	std::vector<uint8_t> cert = load_certificate(CERT_TYPE_PEM);
	Buffer buf_cert = {.ptr = cert.data(), .size = cert.size()};

	std::array<uint8_t, 64> sig = {0};
	Buffer buf_sig = {.ptr = sig.data(), .size = sig.size()};

	bool result = get_signature_from_certificate(&buf_cert, CERT_TYPE_PEM, &buf_sig);
	ASSERT_EQ(result, true);

	print_hex("signature", buf_sig.ptr, buf_sig.size);
}

TEST_F(CertificateTest, GET_SIGNATURE_FORM)
{
	std::vector<uint8_t> cert = load_certificate(CERT_TYPE_DER);
	Buffer buf_cert = {.ptr = cert.data(), .size = cert.size()};

	std::array<uint8_t, 64> sig = {0};
	Buffer buf_sig = {.ptr = sig.data(), .size = sig.size()};

	bool result = get_signature_from_certificate(&buf_cert, CERT_TYPE_DER, &buf_sig);
	ASSERT_EQ(result, true);

	print_hex("signature", buf_sig.ptr, buf_sig.size);
}