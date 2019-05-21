#include "PolarSSL-cpp.h"
#include "CryptoKey.h"





CryptoKey::CryptoKey(void)
{
	mbedtls_pk_init(&mPk);
	mCtrDrbg.initialize("rsa_pubkey", 10);
}





CryptoKey::CryptoKey(const std::string & aPublicKeyData)
{
	mbedtls_pk_init(&mPk);
	mCtrDrbg.initialize("rsa_pubkey", 10);
	int res = parsePublic(aPublicKeyData.data(), aPublicKeyData.size());
	if (res != 0)
	{
		LOGWARNING("Failed to parse public key: -0x%x", res);
		ASSERT(!"Cannot parse PubKey");
		return;
	}
}





CryptoKey::CryptoKey(const std::string & aPrivateKeyData, const std::string & aPassword)
{
	mbedtls_pk_init(&mPk);
	mCtrDrbg.initialize("rsa_privkey", 11);
	int res = parsePrivate(aPrivateKeyData.data(), aPrivateKeyData.size(), aPassword);
	if (res != 0)
	{
		LOGWARNING("Failed to parse private key: -0x%x", res);
		ASSERT(!"Cannot parse PrivKey");
		return;
	}
}





CryptoKey::~CryptoKey()
{
	mbedtls_pk_free(&mPk);
}





int CryptoKey::decrypt(const Byte * aEncryptedData, size_t aEncryptedLength, Byte * aDecryptedData, size_t aDecryptedMaxLength)
{
	ASSERT(isValid());

	size_t DecryptedLen = aDecryptedMaxLength;
	int res = mbedtls_pk_decrypt(&mPk,
		aEncryptedData, aEncryptedLength,
		aDecryptedData, &DecryptedLen, aDecryptedMaxLength,
		mbedtls_ctr_drbg_random, mCtrDrbg
	);
	if (res != 0)
	{
		return res;
	}
	return static_cast<int>(DecryptedLen);
}





int CryptoKey::encrypt(const Byte * aPlainData, size_t aPlainLength, Byte * aEncryptedData, size_t aEncryptedMaxLength)
{
	ASSERT(isValid());

	size_t EncryptedLength = aEncryptedMaxLength;
	int res = mbedtls_pk_encrypt(&mPk,
		aPlainData, aPlainLength, aEncryptedData, &EncryptedLength, aEncryptedMaxLength,
		mbedtls_ctr_drbg_random, mCtrDrbg
	);
	if (res != 0)
	{
		return res;
	}
	return static_cast<int>(EncryptedLength);
}





int CryptoKey::parsePublic(const void * aData, size_t aNumBytes)
{
	ASSERT(!isValid());  // Cannot parse a second key

	return mbedtls_pk_parse_public_key(&mPk, static_cast<const unsigned char *>(aData), aNumBytes);
}





int CryptoKey::parsePrivate(const void * aData, size_t aNumBytes, const std::string & aPassword)
{
	ASSERT(!isValid());  // Cannot parse a second key
	// mbedTLS requires that PEM-encoded data is passed including the terminating NUL byte,
	// and DER-encoded data is decoded properly even with an extra trailing NUL byte, so we simply add one to everything:
	std::string keyData(static_cast<const char *>(aData), aNumBytes);

	if (aPassword.empty())
	{
		return mbedtls_pk_parse_key(&mPk, reinterpret_cast<const unsigned char *>(keyData.data()), aNumBytes + 1, nullptr, 0);
	}
	else
	{
		return mbedtls_pk_parse_key(
			&mPk,
			reinterpret_cast<const unsigned char *>(keyData.data()), aNumBytes + 1,
			reinterpret_cast<const unsigned char *>(aPassword.c_str()), aPassword.size()
		);
	}
}





bool CryptoKey::isValid(void) const
{
	return (mbedtls_pk_get_type(&mPk) != MBEDTLS_PK_NONE);
}




