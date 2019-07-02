#include "PolarSSL-cpp.h"
#include <memory>
#include <cstring>
#include "AesCfb128Decryptor.h"





AesCfb128Decryptor::AesCfb128Decryptor(void):
	mIsValid(false)
{
	mbedtls_aes_init(&mAes);
}





AesCfb128Decryptor::~AesCfb128Decryptor()
{
	// Clear the leftover in-memory data, so that they can't be accessed by a backdoor
	mbedtls_aes_free(&mAes);
}





void AesCfb128Decryptor::init(const Byte aKey[16], const Byte aIV[16])
{
	ASSERT(!isValid());  // Cannot Init twice

	memcpy(mIV, aIV, 16);
	mbedtls_aes_setkey_enc(&mAes, aKey, 128);
	mIsValid = true;
}





void AesCfb128Decryptor::processData(Byte * aDecryptedOut, const Byte * aEncryptedIn, size_t aLength)
{
	ASSERT(isValid());  // Must Init() first

	mbedtls_aes_crypt_cfb8(&mAes, MBEDTLS_AES_DECRYPT, aLength, mIV, aEncryptedIn, aDecryptedOut);
}





