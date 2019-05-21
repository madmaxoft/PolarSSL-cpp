#pragma once

#include "PolarSSL-cpp.h"
#include "mbedtls/entropy.h"





/** Wraps the entropy context in mbedTLS. */
class EntropyContext
{
public:

	EntropyContext(void);
	~EntropyContext();

	/** Returns the wrapped MbedTls object. */
	mbedtls_entropy_context * get() { return &mEntropy; }


protected:

	/** The wrapped MbedTls object. */
	mbedtls_entropy_context mEntropy;
} ;
