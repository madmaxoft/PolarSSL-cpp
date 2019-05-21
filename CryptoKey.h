#pragma once

#include "PolarSSL-cpp.h"
#include <string>
#include "CtrDrbgContext.h"
#include "mbedtls/pk.h"





/** Represents a RSA public or private key in mbedTLS */
class CryptoKey
{
public:

	/** Constructs an empty key instance. Before use, it needs to be filled by ParsePublic() or ParsePrivate() */
	CryptoKey(void);

	/** Constructs the public key out of the DER- or PEM-encoded pubkey data */
	CryptoKey(const std::string & aPublicKeyData);

	/** Constructs the private key out of the DER- or PEM-encoded privkey data, with the specified password.
	If a_Password is empty, no password is assumed. */
	CryptoKey(const std::string & aPrivateKeyData, const std::string & aPassword);

	~CryptoKey();

	/** Decrypts the data using the stored public key
	Both aEncryptedData and aDecryptedData must be at least <KeySizeBytes> bytes large.
	Returns the number of bytes decrypted, or negative number for error. */
	int decrypt(const Byte * aEncryptedData, size_t aEncryptedLength, Byte * aDecryptedData, size_t aDecryptedMaxLength);

	/** Encrypts the data using the stored public key
	Both aEncryptedData and aDecryptedData must be at least <KeySizeBytes> bytes large.
	Returns the number of bytes decrypted, or negative number for error. */
	int encrypt(const Byte * aPlainData, size_t aPlainLength, Byte * aEncryptedData, size_t aEncryptedMaxLength);

	/** Parses the specified data into a public key representation.
	The key can be DER- or PEM-encoded.
	Returns 0 on success, mbedTLS error code on failure. */
	int parsePublic(const void * aData, size_t aNumBytes);

	/** Parses the specified data into a private key representation.
	If aPassword is empty, no password is assumed.
	The key can be DER- or PEM-encoded.
	Returns 0 on success, mbedTLS error code on failure. */
	int parsePrivate(const void * aData, size_t aNumBytes, const std::string & aPassword);

	/** Returns true if the contained key is valid. */
	bool isValid(void) const;

	/** Returns the wrapped MbedTls object, so this class can be used as a direct replacement. */
	operator mbedtls_pk_context * () { return &mPk; }


protected:

	/** The MbedTls representation of the key data */
	mbedtls_pk_context mPk;

	/** The random generator used in encryption and decryption */
	CtrDrbgContext mCtrDrbg;
} ;

using CryptoKeyPtr = std::shared_ptr<CryptoKey>;
