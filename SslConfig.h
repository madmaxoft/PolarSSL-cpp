#pragma once

#include "PolarSSL-cpp.h"
#include <memory>
#include <vector>
#include "mbedtls/ssl.h"





// fwd:
class CryptoKey;
class CtrDrbgContext;
class X509Cert;

using CryptoKeyPtr = std::shared_ptr<CryptoKey>;
using CtrDrbgContextPtr = std::shared_ptr<CtrDrbgContext>;
using X509CertPtr = std::shared_ptr<X509Cert>;

enum class SslAuthMode
{
	None = 0,      // MBEDTLS_SSL_VERIFY_NONE
	Optional = 1,  // MBEDTLS_SSL_VERIFY_OPTIONAL
	Required = 2,  // MBEDTLS_SSL_VERIFY_REQUIRED
	Unset = 3,     // MBEDTLS_SSL_VERIFY_UNSET
};





/** Stores the configuration for the SSL engine. */
class SslConfig
{
public:

	/** Type of the SSL debug callback. */
	using DebugCallback = void(*)(void * aUserData, int aDebugLevel, const char * aFileName, int aLineNumber, const char * aMessage);

	/** Type of the SSL certificate verify callback. */
	using CertVerifyCallback = int(*)(void * aUserData, mbedtls_x509_crt * aCurrentCert, int aChainDepth, uint32_t * aVerificationFlags);


	SslConfig();
	~SslConfig();

	/** Initialize with mbedTLS default settings. */
	int initDefaults(bool aIsClient);

	/** Set the authorization mode. */
	void setAuthMode(SslAuthMode aAuthMode);

	/** Set the random number generator. */
	void setRng(CtrDrbgContextPtr aCtrDrbg);

	/** Set the debug callback. */
	void setDebugCallback(DebugCallback aCallbackFn, void * aCallbackData);

	/** Set the certificate verify callback. */
	void setVerifyCallback(CertVerifyCallback aCallbackFn, void * aCallbackData);

	/** Set the enabled cipher suites. */
	void setCipherSuites(std::vector<int> aCipherSuites);

	/** Set the certificate to use for connections. */
	void setOwnCert(X509CertPtr aOwnCert, CryptoKeyPtr aOwnCertPrivKey);

	/** Set the trusted certificate authority chain. */
	void setCACerts(X509CertPtr aCACert);

	/** Creates a new config with some sensible defaults on top of mbedTLS basic settings. */
	static std::shared_ptr<SslConfig> makeDefaultConfig(bool aIsClient);

	/** Returns the default config for client connections. */
	static std::shared_ptr<const SslConfig> getDefaultClientConfig();

	/** Returns the default config for server connections. */
	static std::shared_ptr<const SslConfig> getDefaultServerConfig();

	/** Returns the wrapped MbedTls object, so this class can be used as a direct replacement. */
	operator const mbedtls_ssl_config * () const { return &mConfig; }


private:

	mbedtls_ssl_config mConfig;
	CtrDrbgContextPtr mCtrDrbg;
	X509CertPtr mOwnCert;
	CryptoKeyPtr mOwnCertPrivKey;
	X509CertPtr mCACerts;
	std::vector<int> mCipherSuites;
};
