#include "PolarSSL-cpp.h"
#include "SslContext.h"
#include "SslConfig.h"





SslContext::SslContext(void) :
	mIsValid(false),
	mHasHandshaken(false)
{
	mbedtls_ssl_init(&mSsl);
}





SslContext::~SslContext()
{
	mbedtls_ssl_free(&mSsl);
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
	int res = mbedtls_ssl_setup(&mSsl, *mConfig);
	if (res != 0)
	{
		return res;
	}

	// Set the io callbacks
	mbedtls_ssl_set_bio(&mSsl, this, sendEncrypted, receiveEncrypted, nullptr);

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
	mbedtls_ssl_set_hostname(&mSsl, aExpectedPeerName.c_str());
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

	return mbedtls_ssl_write(&mSsl, static_cast<const unsigned char *>(aData), aNumBytes);
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

	return mbedtls_ssl_read(&mSsl, static_cast<unsigned char *>(aData), aMaxBytes);
}





int SslContext::performHandshake(void)
{
	ASSERT(mIsValid);  // Need to call Initialize() first
	ASSERT(!mHasHandshaken);  // Must not call twice

	int res = mbedtls_ssl_handshake(&mSsl);
	if (res == 0)
	{
		mHasHandshaken = true;
	}
	return res;
}





int SslContext::notifyClose(void)
{
	return mbedtls_ssl_close_notify(&mSsl);
}




