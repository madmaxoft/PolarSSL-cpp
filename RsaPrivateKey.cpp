#include "PolarSSL-cpp.h"
#include "RsaPrivateKey.h"
#include "mbedtls/pk.h"





RsaPrivateKey::RsaPrivateKey(void)
{
	mbedtls_rsa_init(&mRsa, MBEDTLS_RSA_PKCS_V15, 0);
	mCtrDrbg.initialize("RSA", 3);
}





RsaPrivateKey::RsaPrivateKey(const RsaPrivateKey & a_Other)
{
	mbedtls_rsa_init(&mRsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_rsa_copy(&mRsa, &a_Other.mRsa);
	mCtrDrbg.initialize("RSA", 3);
}





RsaPrivateKey::~RsaPrivateKey()
{
	mbedtls_rsa_free(&mRsa);
}





bool RsaPrivateKey::generate(unsigned a_KeySizeBits)
{
	int res = mbedtls_rsa_gen_key(&mRsa, mbedtls_ctr_drbg_random, mCtrDrbg, a_KeySizeBits, 65537);
	if (res != 0)
	{
		LOG("RSA key generation failed: -0x%x", -res);
		return false;
	}

	return true;
}





std::string RsaPrivateKey::getPubKeyDER(void)
{
	// Create a RAII-based pub-key representation:
	class PubKey
	{
	public:
		PubKey(mbedtls_rsa_context * a_Rsa) :
			mIsValid(false)
		{
			mbedtls_pk_init(&mKey);
			if (mbedtls_pk_setup(&mKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
			{
				ASSERT(!"Cannot init PrivKey context");
				return;
			}
			if (mbedtls_rsa_copy(mbedtls_pk_rsa(mKey), a_Rsa) != 0)
			{
				ASSERT(!"Cannot copy RSA to PK context");
				return;
			}
			mIsValid = true;
		}

		~PubKey()
		{
			if (mIsValid)
			{
				mbedtls_pk_free(&mKey);
			}
		}

		operator mbedtls_pk_context * (void) { return &mKey; }

	protected:
		bool mIsValid;
		mbedtls_pk_context mKey;
	} pkCtx(&mRsa);

	unsigned char buf[8000];
	int res = mbedtls_pk_write_pubkey_der(pkCtx, buf, sizeof(buf));
	if (res < 0)
	{
		return std::string();
	}
	return std::string(reinterpret_cast<const char *>(buf + sizeof(buf) - res), static_cast<size_t>(res));
}





std::string RsaPrivateKey::getPrivKeyDER()
{
	// Create a RAII-based priv-key representation:
	class PrivKey
	{
	public:
		PrivKey(mbedtls_rsa_context * a_Rsa) :
			mIsValid(false)
		{
			mbedtls_pk_init(&mKey);
			if (mbedtls_pk_setup(&mKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
			{
				ASSERT(!"Cannot init PrivKey context");
				return;
			}
			if (mbedtls_rsa_copy(mbedtls_pk_rsa(mKey), a_Rsa) != 0)
			{
				ASSERT(!"Cannot copy RSA to PK context");
				return;
			}
			mIsValid = true;
		}

		~PrivKey()
		{
			if (mIsValid)
			{
				mbedtls_pk_free(&mKey);
			}
		}

		operator mbedtls_pk_context * (void) { return &mKey; }

	protected:
		bool mIsValid;
		mbedtls_pk_context mKey;
	} pkCtx(&mRsa);

	unsigned char buf[8000];
	int res = mbedtls_pk_write_key_der(pkCtx, buf, sizeof(buf));
	if (res < 0)
	{
		return std::string();
	}
	return std::string(reinterpret_cast<const char *>(buf + sizeof(buf) - res), static_cast<size_t>(res));
}





int RsaPrivateKey::decrypt(const Byte * aEncryptedData, size_t aEncryptedLength, Byte * aDecryptedData, size_t aDecryptedMaxLength)
{
	if (aEncryptedLength < mRsa.len)
	{
		LOGD("%s: Invalid a_EncryptedLength: got %u, exp at least %u",
			__FUNCTION__, static_cast<unsigned>(aEncryptedLength), static_cast<unsigned>(mRsa.len)
		);
		ASSERT(!"Invalid a_DecryptedMaxLength!");
		return -1;
	}
	if (aDecryptedMaxLength < mRsa.len)
	{
		LOGD("%s: Invalid a_DecryptedMaxLength: got %u, exp at least %u",
			__FUNCTION__, static_cast<unsigned>(aEncryptedLength), static_cast<unsigned>(mRsa.len)
		);
		ASSERT(!"Invalid a_DecryptedMaxLength!");
		return -1;
	}
	size_t DecryptedLength;
	int res = mbedtls_rsa_pkcs1_decrypt(
		&mRsa, mbedtls_ctr_drbg_random, mCtrDrbg, MBEDTLS_RSA_PRIVATE, &DecryptedLength,
		aEncryptedData, aDecryptedData, aDecryptedMaxLength
	);
	if (res != 0)
	{
		return -1;
	}
	return static_cast<int>(DecryptedLength);
}





int RsaPrivateKey::encrypt(const Byte * aPlainData, size_t a_PlainLength, Byte * aEncryptedData, size_t aEncryptedMaxLength)
{
	if (aEncryptedMaxLength < mRsa.len)
	{
		LOGD("%s: Invalid a_EncryptedMaxLength: got %u, exp at least %u",
			__FUNCTION__, static_cast<unsigned>(aEncryptedMaxLength), static_cast<unsigned>(mRsa.len)
		);
		ASSERT(!"Invalid a_DecryptedMaxLength!");
		return -1;
	}
	if (a_PlainLength < mRsa.len)
	{
		LOGD("%s: Invalid a_PlainLength: got %u, exp at least %u",
			__FUNCTION__, static_cast<unsigned>(a_PlainLength), static_cast<unsigned>(mRsa.len)
		);
		ASSERT(!"Invalid a_PlainLength!");
		return -1;
	}
	int res = mbedtls_rsa_pkcs1_encrypt(
		&mRsa, mbedtls_ctr_drbg_random, mCtrDrbg, MBEDTLS_RSA_PRIVATE,
		a_PlainLength, aPlainData, aEncryptedData
	);
	if (res != 0)
	{
		return -1;
	}
	return static_cast<int>(mRsa.len);
}





