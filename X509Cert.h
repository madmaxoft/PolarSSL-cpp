#pragma once

#include "PolarSSL-cpp.h"
#include <memory>
#include <string>
#include "mbedtls/x509_crt.h"





// fwd:
class CryptoKey;
class X509Cert;
using X509CertPtr = std::shared_ptr<X509Cert>;





/** Wraps the X509 cert in mbedTLS. */
class X509Cert
{
public:

	X509Cert(void);
	~X509Cert(void);

	/** Parses the certificate chain data into the context.
	The certificate can be DER- or PEM-encoded.
	Returns 0 on succes, or mbedTLS error code on failure. */
	int parse(const void * aCertContents, size_t aSize);

	/** Returns the wrapped MbedTls object, so this class can be used as a direct replacement. */
	operator mbedtls_x509_crt * () { return &mCert; }

	/** Returns a self-signed certificate generated signed with the specified private key.
	Returns a nullptr on failure. */
	static X509CertPtr fromPrivateKey(
		std::shared_ptr<CryptoKey> aPrivateKey,
		std::shared_ptr<CryptoKey> aPublicKey,
		const std::string & aSubject
	);


protected:

	/** The wrapped MbedTls object. */
	mbedtls_x509_crt mCert;
} ;





/** Wraps the X509 certificate writer in mbedTLS.
Follows the Builder pattern. To use, create an instance, then call its modifier functions and finally
call writeDer() or writePem(). */
class X509CertWriter
{
public:
	X509CertWriter();

	virtual ~X509CertWriter();

	/** Sets the private key that is used to sign the certificate (issuer key).
	Returns self (for chaining). */
	X509CertWriter & setIssuerPrivateKey(std::shared_ptr<CryptoKey> aPrivateKey);

	/** Sets the public key contained in the certificate (subject key).
	Returns self (for chaining). */
	X509CertWriter & setSubjectPublicKey(std::shared_ptr<CryptoKey> aPublicKey);

	/** Sets the name of the issuer.
	The name must be in the form "C=XYZ,CN=ABC, ..."
	Throws a TlsException upon failure.
	Returns self (for chaining). */
	X509CertWriter & setIssuerName(const std::string & aIssuerName);

	/** Sets the name of the subject.
	The name must be in the form "C=XYZ,CN=ABC, ..."
	Throws a TlsException upon failure.
	Returns self (for chaining). */
	X509CertWriter & setSubjectName(const std::string & aSubjectName);

	/** Sets the time validity of the certificate.
	The validity strings must be in format "YYYYMMDDhhmmss".
	Throws a TlsException upon failure.
	Returns self (for chaining). */
	X509CertWriter & setValidity(const std::string & aValidFromStr, const std::string & aValidToStr);

	/** Returns the certificate data encoded in DER. */
	std::string writeDer();


protected:

	/** The wrapped mbedTLS object. */
	mbedtls_x509write_cert mCtx;

	/** The private key to be used for signing (issuer key).
	Kept as a shared ptr, so that we enforce object validity for as long as needed for writing. */
	std::shared_ptr<CryptoKey> mPrivateKey;

	/** The public key contained in the certificate (subject key).
	Kept as a shared ptr, so that we enforce object validity for as long as needed for writing. */
	std::shared_ptr<CryptoKey> mPublicKey;
};
