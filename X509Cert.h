#pragma once

#include "PolarSSL-cpp.h"
#include <memory>
#include "mbedtls/x509_crt.h"





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


protected:

	/** The wrapped MbedTls object. */
	mbedtls_x509_crt mCert;
} ;

using X509CertPtr = std::shared_ptr<X509Cert>;
