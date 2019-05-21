#pragma once

#include "PolarSSL-cpp.h"
#include <string>
#include "CtrDrbgContext.h"
#include "mbedtls/rsa.h"





/** Encapsulates an RSA private key used in PKI cryptography */
class RsaPrivateKey
{
public:

	/** Creates a new empty object, the key is not assigned */
	RsaPrivateKey(void);

	/** Deep-copies the key from a_Other */
	RsaPrivateKey(const RsaPrivateKey & a_Other);

	~RsaPrivateKey();

	/** Generates a new key within this object, with the specified size in bits.
	Returns true on success, false on failure. */
	bool generate(unsigned a_KeySizeBits = 1024);

	/** Returns the public key part encoded in ASN1 DER encoding */
	std::string getPubKeyDER();

	/** Returns the private key part encoded in ASN1 DER encoding */
	std::string getPrivKeyDER();

	/** Decrypts the data using RSAES-PKCS#1 algorithm.
	Both aEncryptedData and aDecryptedData must be at least <KeySizeBytes> bytes large.
	Returns the number of bytes decrypted, or negative number for error. */
	int decrypt(const Byte * aEncryptedData, size_t aEncryptedLength, Byte * aDecryptedData, size_t aDecryptedMaxLength);

	/** Encrypts the data using RSAES-PKCS#1 algorithm.
	Both aEncryptedData and aDecryptedData must be at least <KeySizeBytes> bytes large.
	Returns the number of bytes decrypted, or negative number for error. */
	int encrypt(const Byte * aPlainData, size_t a_PlainLength, Byte * aEncryptedData, size_t aEncryptedMaxLength);

	/** Returns the wrapped MbedTls object, so this class can be used as a direct replacement. */
	operator mbedtls_rsa_context * () { return &mRsa; }


protected:

	/** The mbedTLS key context */
	mbedtls_rsa_context mRsa;

	/** The random generator used for generating the key and encryption / decryption */
	CtrDrbgContext mCtrDrbg;
} ;

using RsaPrivateKeyPtr = std::shared_ptr<RsaPrivateKey>;
