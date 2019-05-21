#include "PolarSSL-cpp.h"
#include <memory>
#include "CtrDrbgContext.h"
#include "EntropyContext.h"





CtrDrbgContext::CtrDrbgContext(void) :
	mEntropyContext(std::make_shared<EntropyContext>()),
	mIsValid(false)
{
	mbedtls_ctr_drbg_init(&mCtrDrbg);
}





CtrDrbgContext::CtrDrbgContext(const std::shared_ptr<EntropyContext> & a_EntropyContext) :
	mEntropyContext(a_EntropyContext),
	mIsValid(false)
{
	mbedtls_ctr_drbg_init(&mCtrDrbg);
}





int CtrDrbgContext::initialize(const void * aCustom, size_t aCustomSize)
{
	if (mIsValid)
	{
		// Already initialized
		return 0;
	}

	int res = mbedtls_ctr_drbg_seed(&mCtrDrbg, mbedtls_entropy_func, mEntropyContext->get(), static_cast<const unsigned char *>(aCustom), aCustomSize);
	mIsValid = (res == 0);
	return res;
}




