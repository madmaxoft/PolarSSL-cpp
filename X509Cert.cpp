#include "PolarSSL-cpp.h"
#include <string>
#include "X509Cert.h"
#include "CryptoKey.h"
#include "TlsException.h"





X509Cert::X509Cert(void)
{
	mbedtls_x509_crt_init(&mCert);
}





X509Cert::~X509Cert()
{
	mbedtls_x509_crt_free(&mCert);
}





int X509Cert::parse(const void * aCertContents, size_t aSize)
{
	// mbedTLS requires that PEM-encoded data is passed including the terminating NUL byte,
	// and DER-encoded data is decoded properly even with an extra trailing NUL byte, so we simply add one to everything:
	std::string certContents(static_cast<const char *>(aCertContents), aSize);
	return mbedtls_x509_crt_parse(&mCert, reinterpret_cast<const unsigned char *>(certContents.data()), aSize + 1);
}





X509CertPtr X509Cert::fromPrivateKey(
	std::shared_ptr<CryptoKey> aPrivateKey,
	std::shared_ptr<CryptoKey> aPublicKey,
	const std::string & aSubject
)
{
	try
	{
		X509CertWriter writer;
		auto der = writer
			.setIssuerName(aSubject)
			.setSubjectName(aSubject)
			.setIssuerPrivateKey(aPrivateKey)
			.setSubjectPublicKey(aPublicKey)
			.setValidity("20010101000000", "20301231235959")
			.writeDer();

		auto ret = std::make_shared<X509Cert>();
		auto res = ret->parse(der.data(), der.size());
		if (res != 0)
		{
			throw TlsException("Failed to parse cert", res);
		}
		return ret;
	}
	catch (const TlsException & exc)
	{
		LOG("Failed to create self-signed cert: %s", exc.what());
		return nullptr;
	}
}





////////////////////////////////////////////////////////////////////////////////
// X509CertWriter:

X509CertWriter::X509CertWriter()
{
	mbedtls_x509write_crt_init(&mCtx);
	mbedtls_x509write_crt_set_version(&mCtx, 2);
	mbedtls_x509write_crt_set_md_alg(&mCtx, MBEDTLS_MD_SHA256);
}





X509CertWriter::~X509CertWriter()
{
	mbedtls_x509write_crt_free(&mCtx);
}





X509CertWriter & X509CertWriter::setIssuerPrivateKey(std::shared_ptr<CryptoKey> aPrivateKey)
{
	assert(aPrivateKey != nullptr);
	assert(aPrivateKey->isValid());

	mPrivateKey = aPrivateKey;
	auto privKey = const_cast<mbedtls_pk_context *>(mPrivateKey->operator const mbedtls_pk_context *());
	mbedtls_x509write_crt_set_issuer_key(&mCtx, privKey);
	return *this;
}





X509CertWriter & X509CertWriter::setSubjectPublicKey(std::shared_ptr<CryptoKey> aPublicKey)
{
	assert(aPublicKey != nullptr);
	assert(aPublicKey->isValid());

	mPublicKey = aPublicKey;
	auto pubKey = const_cast<mbedtls_pk_context *>(aPublicKey->operator const mbedtls_pk_context *());
	mbedtls_x509write_crt_set_subject_key(&mCtx, pubKey);
	return *this;
}





X509CertWriter & X509CertWriter::setIssuerName(const std::string & aIssuerName)
{
	int res = mbedtls_x509write_crt_set_issuer_name(&mCtx, aIssuerName.c_str());
	if (res != 0)
	{
		throw TlsException("Failed to set Issuer name", res);
	}
	return *this;
}





X509CertWriter & X509CertWriter::setSubjectName(const std::string & aSubjectName)
{
	int res = mbedtls_x509write_crt_set_subject_name(&mCtx, aSubjectName.c_str());
	if (res != 0)
	{
		throw TlsException("Failed to set Subject name", res);
	}
	return *this;
}





X509CertWriter & X509CertWriter::setValidity(const std::string & aValidFromStr, const std::string & aValidToStr)
{
	assert(aValidFromStr.size() == 14);
	assert(aValidToStr.size() == 14);

	auto res = mbedtls_x509write_crt_set_validity(&mCtx, aValidFromStr.c_str(), aValidToStr.c_str());
	if (res != 0)
	{
		throw TlsException("Failed to set cert validity", res);
	}
	return *this;
}





std::string X509CertWriter::writeDer()
{
	CtrDrbgContext ctrDrbg;
	int res = ctrDrbg.initialize(nullptr, 0);
	if (res != 0)
	{
		throw TlsException("Failed to initialize CtrDrbg", res);
	}
	unsigned char buf[8192];
	memset(buf, 0, sizeof(buf));
	res = mbedtls_x509write_crt_der(&mCtx, buf, sizeof(buf), &mbedtls_ctr_drbg_random, ctrDrbg);
	if (res <= 0)
	{
		throw TlsException("Failed to write certificate DER", res);
	}
	return std::string(reinterpret_cast<const char *>(buf + sizeof(buf) - res), static_cast<size_t>(res));
}
