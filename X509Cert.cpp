#include "PolarSSL-cpp.h"
#include <string>
#include <cstring>
#include "X509Cert.h"
#include "CryptoKey.h"
#include "TlsException.h"
#include "mbedtls/x509_crt.h"





X509Cert::X509Cert():
	mCert(new mbedtls_x509_crt),
	mIsOwned(true)
{
	mbedtls_x509_crt_init(mCert);
}





X509Cert::X509Cert(mbedtls_x509_crt * aCert):
	mCert(aCert),
	mIsOwned(false)
{
}





X509Cert::~X509Cert()
{
	if (mIsOwned)
	{
		mbedtls_x509_crt_free(mCert);
		delete mCert;
	}
}





int X509Cert::parse(const void * aCertContents, size_t aSize)
{
	// mbedTLS requires that PEM-encoded data is passed including the terminating NUL byte,
	// and DER-encoded data is decoded properly even with an extra trailing NUL byte, so we simply add one to everything:
	std::string certContents(static_cast<const char *>(aCertContents), aSize);
	return mbedtls_x509_crt_parse(mCert, reinterpret_cast<const unsigned char *>(certContents.data()), aSize + 1);
}





std::string X509Cert::publicKeyDer()
{
	unsigned char buf[4096];
	auto res = mbedtls_pk_write_pubkey_der(&mCert->pk, buf, sizeof(buf));
	if (res < 0)
	{
		throw TlsException("Failed to write cert's public key to DER", res);
	}
	return std::string(reinterpret_cast<char *>(buf + sizeof(buf) - res), static_cast<size_t>(res));
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
			.setValidity("20200101000000", "20401231235959")
			.setSerialNumber("1")
			.writeDer();

		auto cert = std::make_shared<X509Cert>();
		auto res = cert->parse(der.data(), der.size());
		if (res != 0)
		{
			throw TlsException("Failed to parse cert", res);
		}
		return cert;
	}
	catch (const TlsException & exc)
	{
		LOG("Failed to create self-signed cert: %s", exc.what());
		return nullptr;
	}
}





X509CertPtr X509Cert::fromContext(mbedtls_x509_crt * aContext)
{
	return std::make_shared<X509Cert>(aContext);
}





////////////////////////////////////////////////////////////////////////////////
// X509CertWriter:

X509CertWriter::X509CertWriter():
	mCtx(new mbedtls_x509write_cert)
{
	mbedtls_x509write_crt_init(mCtx.get());
	mbedtls_x509write_crt_set_version(mCtx.get(), MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(mCtx.get(), MBEDTLS_MD_SHA256);
}





X509CertWriter::~X509CertWriter()
{
	mbedtls_x509write_crt_free(mCtx.get());
}





X509CertWriter & X509CertWriter::setIssuerPrivateKey(std::shared_ptr<CryptoKey> aPrivateKey)
{
	assert(aPrivateKey != nullptr);
	assert(aPrivateKey->isValid());

	mPrivateKey = aPrivateKey;
	auto privKey = const_cast<mbedtls_pk_context *>(mPrivateKey->operator const mbedtls_pk_context *());
	mbedtls_x509write_crt_set_issuer_key(mCtx.get(), privKey);
	return *this;
}





X509CertWriter & X509CertWriter::setSubjectPublicKey(std::shared_ptr<CryptoKey> aPublicKey)
{
	assert(aPublicKey != nullptr);
	assert(aPublicKey->isValid());

	mPublicKey = aPublicKey;
	auto pubKey = const_cast<mbedtls_pk_context *>(aPublicKey->operator const mbedtls_pk_context *());
	mbedtls_x509write_crt_set_subject_key(mCtx.get(), pubKey);
	return *this;
}





X509CertWriter & X509CertWriter::setIssuerName(const std::string & aIssuerName)
{
	int res = mbedtls_x509write_crt_set_issuer_name(mCtx.get(), aIssuerName.c_str());
	if (res != 0)
	{
		throw TlsException("Failed to set Issuer name", res);
	}
	return *this;
}





X509CertWriter & X509CertWriter::setSubjectName(const std::string & aSubjectName)
{
	int res = mbedtls_x509write_crt_set_subject_name(mCtx.get(), aSubjectName.c_str());
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

	auto res = mbedtls_x509write_crt_set_validity(mCtx.get(), aValidFromStr.c_str(), aValidToStr.c_str());
	if (res != 0)
	{
		throw TlsException("Failed to set cert validity", res);
	}
	return *this;
}





X509CertWriter & X509CertWriter::setSerialNumber(const std::string & aSerialNumber)
{
	// Parse the serial number:
	mbedtls_mpi serialNumber;
	mbedtls_mpi_init(&serialNumber);
	auto res = mbedtls_mpi_read_string(&serialNumber, 10, aSerialNumber.c_str());
	if (res != 0)
	{
		throw TlsException("Failed to parse the serial number", res);
	}

	// Set the serial number:
	res = mbedtls_x509write_crt_set_serial(mCtx.get(), &serialNumber);
	if (res != 0)
	{
		throw TlsException("Failed to set cert serial number", res);
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
	res = mbedtls_x509write_crt_der(mCtx.get(), buf, sizeof(buf), &mbedtls_ctr_drbg_random, ctrDrbg);
	if (res <= 0)
	{
		throw TlsException("Failed to write certificate DER", res);
	}
	return std::string(reinterpret_cast<const char *>(buf + sizeof(buf) - res), static_cast<size_t>(res));
}
