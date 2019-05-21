#include "PolarSSL-cpp.h"
#include <string>
#include "X509Cert.h"





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




