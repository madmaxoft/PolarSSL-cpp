#include "PolarSSL-cpp.h"
#include "CallbackSslContext.h"





CallbackSslContext::CallbackSslContext(void) :
	mCallbacks(nullptr)
{
	// Nothing needed, but the constructor needs to exist so
}





CallbackSslContext::CallbackSslContext(CallbackSslContext::DataCallbacks & a_Callbacks) :
	mCallbacks(&a_Callbacks)
{
}





int CallbackSslContext::receiveEncrypted(unsigned char * a_Buffer, size_t a_NumBytes)
{
	if (mCallbacks == nullptr)
	{
		LOGWARNING("SSL: Trying to receive data with no callbacks, aborting.");
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return mCallbacks->receiveEncrypted(a_Buffer, a_NumBytes);
}





int CallbackSslContext::sendEncrypted(const unsigned char * a_Buffer, size_t a_NumBytes)
{
	if (mCallbacks == nullptr)
	{
		LOGWARNING("SSL: Trying to send data with no callbacks, aborting.");
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return mCallbacks->sendEncrypted(a_Buffer, a_NumBytes);
}





