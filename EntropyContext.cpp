#include "PolarSSL-cpp.h"
#include "EntropyContext.h"





EntropyContext::EntropyContext(void)
{
	mbedtls_entropy_init(&mEntropy);
}





EntropyContext::~EntropyContext()
{
	mbedtls_entropy_free(&mEntropy);
}




