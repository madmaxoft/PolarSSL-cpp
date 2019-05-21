#pragma once

#include "PolarSSL-cpp.h"
#include <memory>
#include "mbedtls/ctr_drbg.h"





// fwd: EntropyContext.h
class EntropyContext;





/** Wraps the CTR-DRBG implementation in mbedTLS. */
class CtrDrbgContext
{
public:

	/** Constructs the context with a new entropy context. */
	CtrDrbgContext(void);

	/** Constructs the context with the specified entropy context. */
	CtrDrbgContext(const std::shared_ptr<EntropyContext> & a_EntropyContext);

	/** Initializes the context.
	aCustom is optional additional data to use for entropy, nullptr is accepted.
	Returns 0 if successful, mbedTLS error code on failure. */
	int initialize(const void * aCustom, size_t aCustomSize);

	/** Returns true if the object is valid (has been initialized properly) */
	bool isValid(void) const { return mIsValid; }

	/** Returns the wrapped MbedTls object, so this class can be used as a direct replacement. */
	operator mbedtls_ctr_drbg_context * () { return &mCtrDrbg; }


protected:

	/** The entropy source used for generating the random */
	std::shared_ptr<EntropyContext> mEntropyContext;

	/** The random generator context */
	mbedtls_ctr_drbg_context mCtrDrbg;

	/** Set to true if the object is valid (has been initialized properly) */
	bool mIsValid;
} ;
