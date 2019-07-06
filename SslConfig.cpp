#include "PolarSSL-cpp.h"
#include <vector>
#include "SslConfig.h"
#include "EntropyContext.h"
#include "CtrDrbgContext.h"
#include "CryptoKey.h"
#include "X509Cert.h"
#include "mbedtls/ssl.h"





// This allows us to debug SSL and certificate problems, but produce way too much output,
// so it's disabled until someone needs it
// #define ENABLE_SSL_DEBUG_MSG


#if defined(_DEBUG) && defined(ENABLE_SSL_DEBUG_MSG)
	#include "mbedtls/debug.h"


	namespace
	{
		void SSLDebugMessage(void * aUserParam, int aLevel, const char * aFilename, int aLineNo, const char * aText)
		{
			if (aLevel > 3)
			{
				// Don't want the trace messages
				return;
			}

			// Remove the terminating LF:
			size_t len = strlen(aText) - 1;
			while ((len > 0) && (aText[len] <= 32))
			{
				len--;
			}
			std::string Text(aText, len + 1);

			LOGD("SSL (%d): %s", aLevel, Text.c_str());
		}





		int SSLVerifyCert(void * aThis, mbedtls_x509_crt * aCrt, int aDepth, uint32_t * aFlags)
		{
			char buf[1024];
			UNUSED(aThis);

			LOG("Verify requested for (Depth %d):", aDepth);
			mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", aCrt);
			LOG("%s", buf);

			uint32_t Flags = *aFlags;
			if ((Flags & MBEDTLS_X509_BADCERT_EXPIRED) != 0)
			{
				LOG(" ! server certificate has expired");
			}

			if ((Flags & MBEDTLS_X509_BADCERT_REVOKED) != 0)
			{
				LOG(" ! server certificate has been revoked");
			}

			if ((Flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0)
			{
				LOG(" ! CN mismatch");
			}

			if ((Flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0)
			{
				LOG(" ! self-signed or not signed by a trusted CA");
			}

			if ((Flags & MBEDTLS_X509_BADCRL_NOT_TRUSTED) != 0)
			{
				LOG(" ! CRL not trusted");
			}

			if ((Flags & MBEDTLS_X509_BADCRL_EXPIRED) != 0)
			{
				LOG(" ! CRL expired");
			}

			if ((Flags & MBEDTLS_X509_BADCERT_OTHER) != 0)
			{
				LOG(" ! other (unknown) flag");
			}

			if (Flags == 0)
			{
				LOG(" This certificate has no flags");
			}

			return 0;
		}
	}
#endif  // defined(_DEBUG) && defined(ENABLE_SSL_DEBUG_MSG)





static int authModeToMbedTlsMode(SslAuthMode aAuthMode)
{
	switch (aAuthMode)
	{
		case SslAuthMode::None:     return MBEDTLS_SSL_VERIFY_NONE;
		case SslAuthMode::Optional: return MBEDTLS_SSL_VERIFY_OPTIONAL;
		case SslAuthMode::Required: return MBEDTLS_SSL_VERIFY_REQUIRED;
		case SslAuthMode::Unset:    return MBEDTLS_SSL_VERIFY_UNSET;
	}
	ASSERT(!"Unsupported SSL auth mode");
	return MBEDTLS_SSL_VERIFY_REQUIRED;  // Default to strict mode
}





////////////////////////////////////////////////////////////////////////////////
// SslConfig:

SslConfig::SslConfig():
	mConfig(new mbedtls_ssl_config)
{
	mbedtls_ssl_config_init(mConfig.get());
}





SslConfig::~SslConfig()
{
	mbedtls_ssl_config_free(mConfig.get());
}





int SslConfig::initDefaults(const bool aIsClient)
{
	return mbedtls_ssl_config_defaults(
		mConfig.get(),
		aIsClient ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	);
}





void SslConfig::setAuthMode(const SslAuthMode aAuthMode)
{
	const int Mode = authModeToMbedTlsMode(aAuthMode);
	mbedtls_ssl_conf_authmode(mConfig.get(), Mode);
}





void SslConfig::setRng(CtrDrbgContextPtr aCtrDrbg)
{
	ASSERT(aCtrDrbg != nullptr);
	mCtrDrbg = std::move(aCtrDrbg);
	mbedtls_ssl_conf_rng(mConfig.get(), mbedtls_ctr_drbg_random, *mCtrDrbg);
}





void SslConfig::setDebugCallback(DebugCallback aCallbackFun, void * aCallbackData)
{
	mbedtls_ssl_conf_dbg(mConfig.get(), aCallbackFun, aCallbackData);
}





void SslConfig::setOwnCert(X509CertPtr aOwnCert, CryptoKeyPtr aOwnCertPrivKey)
{
	ASSERT(aOwnCert != nullptr);
	ASSERT(aOwnCertPrivKey != nullptr);

	// Make sure we have the cert stored for later, mbedTLS only uses the cert later on
	mOwnCert = std::move(aOwnCert);
	mOwnCertPrivKey = std::move(aOwnCertPrivKey);

	// Set into the config:
	mbedtls_ssl_conf_own_cert(mConfig.get(), *mOwnCert, *mOwnCertPrivKey);
}





void SslConfig::setVerifyCallback(CertVerifyCallback aCallbackFun, void * aCallbackData)
{
	mbedtls_ssl_conf_verify(mConfig.get(), aCallbackFun, aCallbackData);
}





void SslConfig::setCipherSuites(std::vector<int> aCipherSuites)
{
	mCipherSuites = std::move(aCipherSuites);
	mCipherSuites.push_back(0);  // Must be null terminated
	mbedtls_ssl_conf_ciphersuites(mConfig.get(), mCipherSuites.data());
}





void SslConfig::setCACerts(X509CertPtr aCACert)
{
	mCACerts = std::move(aCACert);
	mbedtls_ssl_conf_ca_chain(mConfig.get(), *mCACerts, nullptr);
}





std::shared_ptr<SslConfig> SslConfig::makeDefaultConfig(bool aIsClient)
{
	// TODO: Default CA chain and SetAuthMode(eSslAuthMode::Required)
	auto Ret = std::make_shared<SslConfig>();

	Ret->initDefaults(aIsClient);

	{
		auto CtrDrbg = std::make_shared<CtrDrbgContext>();
		CtrDrbg->initialize(nullptr, 0);
		Ret->setRng(std::move(CtrDrbg));
	}

	Ret->setAuthMode(SslAuthMode::None);  // We cannot verify because we don't have a CA chain

	#ifdef _DEBUG
		#ifdef ENABLE_SSL_DEBUG_MSG
			Ret->setDebugCallback(&SSLDebugMessage, nullptr);
			Ret->setVerifyCallback(SSLVerifyCert, nullptr);
			mbedtls_debug_set_threshold(2);
		#endif

		/*
		// Set ciphersuite to the easiest one to decode, so that the connection can be wireshark-decoded:
		Ret->setCipherSuites(
			{
				MBEDTLS_TLS_RSaWITH_RC4_128_MD5,
				MBEDTLS_TLS_RSaWITH_RC4_128_SHA,
				MBEDTLS_TLS_RSaWITH_AES_128_CBC_SHA
			}
		);
		*/
	#endif

	return Ret;
}





std::shared_ptr<const SslConfig> SslConfig::getDefaultClientConfig()
{
	static const std::shared_ptr<const SslConfig> clientConfig = makeDefaultConfig(true);
	return clientConfig;
}





std::shared_ptr<const SslConfig> SslConfig::getDefaultServerConfig()
{
	static const std::shared_ptr<const SslConfig> serverConfig = makeDefaultConfig(false);
	return serverConfig;
}




