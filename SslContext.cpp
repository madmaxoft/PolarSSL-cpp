#include "PolarSSL-cpp.h"
#include "SslContext.h"
#include "SslConfig.h"
#include "mbedtls/ssl.h"





SslContext::SslContext(void) :
	mSsl(new mbedtls_ssl_context),
	mIsValid(false),
	mHasHandshaken(false)
{
	mbedtls_ssl_init(mSsl.get());
}





SslContext::~SslContext()
{
	mbedtls_ssl_free(mSsl.get());
}





int SslContext::initialize(std::shared_ptr<const SslConfig> aConfig)
{
	// Check double-initialization:
	if (mIsValid)
	{
		LOGWARNING("SSL: Double initialization is not supported.");
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;  // There is no return value well-suited for this, reuse this one.
	}

	// Check the Config:
	mConfig = aConfig;
	if (mConfig == nullptr)
	{
		ASSERT(!"Config must not be nullptr");
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	// Apply the configuration to the ssl context
	int res = mbedtls_ssl_setup(mSsl.get(), *mConfig);
	if (res != 0)
	{
		return res;
	}

	// Set the io callbacks
	mbedtls_ssl_set_bio(mSsl.get(), this, sendEncrypted, receiveEncrypted, nullptr);

	mIsValid = true;
	return 0;
}





int SslContext::initialize(bool aIsClient)
{
	if (aIsClient)
	{
		return initialize(SslConfig::getDefaultClientConfig());
	}
	else
	{
		return initialize(SslConfig::getDefaultServerConfig());
	}
}





void SslContext::setExpectedPeerName(const std::string & aExpectedPeerName)
{
	ASSERT(mIsValid);  // Call Initialize() first
	mbedtls_ssl_set_hostname(mSsl.get(), aExpectedPeerName.c_str());
}





int SslContext::writePlain(const void * aData, size_t aNumBytes)
{
	ASSERT(mIsValid);  // Need to call Initialize() first
	if (!mHasHandshaken)
	{
		int res = performHandshake();
		if (res != 0)
		{
			return res;
		}
	}

	return mbedtls_ssl_write(mSsl.get(), static_cast<const unsigned char *>(aData), aNumBytes);
}





int SslContext::readPlain(void * aData, size_t aMaxBytes)
{
	ASSERT(mIsValid);  // Need to call Initialize() first
	if (!mHasHandshaken)
	{
		int res = performHandshake();
		if (res != 0)
		{
			return res;
		}
	}

	return mbedtls_ssl_read(mSsl.get(), static_cast<unsigned char *>(aData), aMaxBytes);
}





int SslContext::performHandshake(void)
{
	ASSERT(mIsValid);  // Need to call Initialize() first
	ASSERT(!mHasHandshaken);  // Must not call twice

	int res = mbedtls_ssl_handshake(mSsl.get());
	if (res == 0)
	{
		mHasHandshaken = true;
	}
	return res;
}





int SslContext::notifyClose(void)
{
	return mbedtls_ssl_close_notify(mSsl.get());
}




