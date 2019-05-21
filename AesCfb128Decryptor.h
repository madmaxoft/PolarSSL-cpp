#pragma once

#include "PolarSSL-cpp.h"
#include "mbedtls/aes.h"





/** Decrypts data using the AES / CFB 128 algorithm */
class AesCfb128Decryptor
{
public:

	AesCfb128Decryptor(void);
	~AesCfb128Decryptor();

	/** Initializes the decryptor with the specified Key / IV */
	void init(const Byte aKey[16], const Byte aIV[16]);

	/** Decrypts a_Length bytes of the encrypted data; produces a_Length output bytes */
	void processData(Byte * aDecryptedOut, const Byte * aEncryptedIn, size_t aLength);

	/** Returns true if the object has been initialized with the Key / IV */
	bool isValid(void) const { return mIsValid; }


protected:

	/** The wrapped MbedTls object. */
	mbedtls_aes_context mAes;

	/** The InitialVector, used by the CFB mode decryption */
	Byte mIV[16];

	/** Indicates whether the object has been initialized with the Key / IV */
	bool mIsValid;
} ;





