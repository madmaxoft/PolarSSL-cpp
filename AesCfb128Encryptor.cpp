#include "PolarSSL-cpp.h"
#include <memory>
#include <cstring>
#include "AesCfb128Encryptor.h"





AesCfb128Encryptor::AesCfb128Encryptor(void):
	mIsValid(false)
{
	mbedtls_aes_init(&mAes);
}





AesCfb128Encryptor::~AesCfb128Encryptor()
{
	// Clear the leftover in-memory data, so that they can't be accessed by a backdoor
	mbedtls_aes_free(&mAes);
}





void AesCfb128Encryptor::init(const Byte aKey[16], const Byte aIV[16])
{
	ASSERT(!isValid());  // Cannot Init twice

	memcpy(mIV, aIV, 16);
	mbedtls_aes_setkey_enc(&mAes, aKey, 128);
	mIsValid = true;
}





void AesCfb128Encryptor::processData(Byte * aEncryptedOut, const Byte * aPlainIn, size_t aLength)
{
	ASSERT(isValid());  // Must Init() first

	mbedtls_aes_crypt_cfb8(&mAes, MBEDTLS_AES_ENCRYPT, aLength, mIV, aPlainIn, aEncryptedOut);
}





