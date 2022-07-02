#pragma once

#include "PolarSSL-cpp.h"
#include <memory>
#include <string>





// fwd:
struct mbedtls_ssl_context;
class CtrDrbgContext;
class SslConfig;





/**
Acts as a generic SSL encryptor / decryptor between the two endpoints. The "owner" of this class is expected
to create it, initialize it and then provide the means of reading and writing data through the SSL link.
This is an abstract base class, there are descendants that handle the specific aspects of how the SSL peer
data comes into the system:
	- CallbackSslContext uses callbacks to provide the data
	- (other descendants removed)
Note that this class doesn't provide thread safety, the "owner" is expected to synchronize access, especially
synchronizing between the reads and writes.
*/
class SslContext
{
public:

	/** Creates a new uninitialized context */
	SslContext(void);

	virtual ~SslContext();

	/** Initializes the context for use as a server or client.
	aConfig must not be nullptr and the config must not be changed after this call.
	Returns 0 on success, mbedTLS error on failure. */
	int initialize(std::shared_ptr<const SslConfig> aConfig);

	/** Initializes the context using the default config.
	Returns 0 on success, mbedTLS error on failure. */
	int initialize(bool aIsClient);

	/** Returns true if the object has been initialized properly. */
	bool isValid() const { return mIsValid; }

	/** Sets the SSL peer name expected for this context. Must be called after Initialize().
	aExpectedPeerName is the CommonName that we expect the SSL peer to have in its cert,
	if it is different, the verification will fail. An empty string will disable the CN check. */
	void setExpectedPeerName(const std::string & aExpectedPeerName);

	/** Writes data to be encrypted and sent to the SSL peer. Will perform SSL handshake, if needed.
	Returns the number of bytes actually written, or mbedTLS error code.
	If the return value is MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, the owner should send any
	cached outgoing data to the SSL peer and write any incoming data received from the SSL peer and then call
	this function again with the same parameters (minus the bytes already consumed).
	Note that this may repeat a few times before the data is actually written, mainly due to initial handshake. */
	int writePlain(const void * aData, size_t aNumBytes);

	/** Reads data decrypted from the SSL stream. Will perform SSL handshake, if needed.
	Returns the number of bytes actually read, or mbedTLS error code.
	If the return value is MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, the owner should send any
	cached outgoing data to the SSL peer and write any incoming data received from the SSL peer and then call
	this function again with the same parameters. Note that this may repeat a few times before the data is
	actually read, mainly due to initial handshake. */
	int readPlain(void * aData, size_t aMaxBytes);

	/** Performs the SSL handshake.
	Returns zero on success, mbedTLS error code on failure.
	If the return value is MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, the owner should send any
	cached outgoing data to the SSL peer and write any incoming data received from the SSL peer and then call
	this function again. Note that this may repeat a few times before the handshake is completed. */
	int performHandshake();

	/** Returns true if the SSL handshake has been completed. */
	bool hasHandshaken() const { return mHasHandshaken; }

	/** Notifies the SSL peer that the connection is being closed.
	Returns 0 on success, mbedTLS error code on failure. */
	int notifyClose();


protected:

	/** The wrapped SSL context used by mbedTLS. */
	std::unique_ptr<mbedtls_ssl_context> mSsl;

	/** Configuration of the SSL context. */
	std::shared_ptr<const SslConfig> mConfig;

	/** True if the object has been initialized properly. */
	bool mIsValid;

	/** True if the SSL handshake has been completed. */
	bool mHasHandshaken;


	/** The callback used by mbedTLS when it wants to read encrypted data. */
	static int receiveEncrypted(void * aThis, unsigned char * aBuffer, size_t aNumBytes)
	{
		return (static_cast<SslContext *>(aThis))->receiveEncrypted(aBuffer, aNumBytes);
	}

	/** The callback used by mbedTLS when it wants to write encrypted data. */
	static int sendEncrypted(void * aThis, const unsigned char * aBuffer, size_t aNumBytes)
	{
		return (static_cast<SslContext *>(aThis))->sendEncrypted(aBuffer, aNumBytes);
	}

	/** Called when mbedTLS wants to read encrypted data. */
	virtual int receiveEncrypted(unsigned char * aBuffer, size_t aNumBytes) = 0;

	/** Called when mbedTLS wants to write encrypted data. */
	virtual int sendEncrypted(const unsigned char * aBuffer, size_t aNumBytes) = 0;
} ;




