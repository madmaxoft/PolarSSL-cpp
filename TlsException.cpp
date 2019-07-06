#include "TlsException.h"
#include "mbedtls/error.h"





TlsException::TlsException(const std::string & aErrorText, int aMbedTlsErrorCode):
	Super((aErrorText + " (" + mbedTlsCodeToString(aMbedTlsErrorCode) + ")").c_str()),
	mMbedTlsErrorCode(aMbedTlsErrorCode)
{
}





std::string TlsException::mbedTlsCodeToString(int aMbedTlsErrorCode)
{
	char buf[2048];
	mbedtls_strerror(aMbedTlsErrorCode, buf, sizeof(buf));
	return buf;
}
