#pragma once

#include <stdexcept>
#include <string>





/** Represents an error returned from an mbedTls library call. */
class TlsException:
	public std::runtime_error
{
	using Super = std::runtime_error;

public:
	TlsException(const std::string & aErrorText, int aMbedTlsErrorCode);

	/** Returns the contained mbedTls error code. */
	int mbedTlsErrorCode() const { return mMbedTlsErrorCode; }


protected:

	/** The contained error code. */
	int mMbedTlsErrorCode;

	/** Converts mbedTls error code to its string representation. */
	static std::string mbedTlsCodeToString(int aMbedTlsErrorCode);
};
