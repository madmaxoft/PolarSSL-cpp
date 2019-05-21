#include "PolarSSL-cpp.h"
#include <memory>
#include <string>
#include "Sha1Checksum.h"





/*
// Self-test the hash formatting for known values:
// sha1(Notch) : 4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48
// sha1(jeb_)  : -7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1
// sha1(simon) : 88e16a1019277b15d58faf0541e11910eb756f6

static class Test
{
public:
	Test(void)
	{
		std::string DigestNotch, DigestJeb, DigestSimon;
		Byte Digest[20];
		cSha1Checksum Checksum;
		Checksum.Update((const Byte *)"Notch", 5);
		Checksum.Finalize(Digest);
		cSha1Checksum::DigestToJava(Digest, DigestNotch);
		Checksum.Restart();
		Checksum.Update((const Byte *)"jeb_", 4);
		Checksum.Finalize(Digest);
		cSha1Checksum::DigestToJava(Digest, DigestJeb);
		Checksum.Restart();
		Checksum.Update((const Byte *)"simon", 5);
		Checksum.Finalize(Digest);
		cSha1Checksum::DigestToJava(Digest, DigestSimon);
		printf("Notch: \"%s\"\n", DigestNotch.c_str());
		printf("jeb_:  \"%s\"\n",  DigestJeb.c_str());
		printf("simon: \"%s\"\n", DigestSimon.c_str());
		assert(DigestNotch == "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48");
		assert(DigestJeb   == "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1");
		assert(DigestSimon == "88e16a1019277b15d58faf0541e11910eb756f6");
	}
} test;
*/





////////////////////////////////////////////////////////////////////////////////
// cSha1Checksum:

Sha1Checksum::Sha1Checksum(void) :
	mDoesAcceptInput(true)
{
	mbedtls_sha1_starts(&m_Sha1);
}





void Sha1Checksum::update(const Byte * aData, size_t aLength)
{
	ASSERT(mDoesAcceptInput);  // Not Finalize()-d yet, or Restart()-ed

	mbedtls_sha1_update(&m_Sha1, aData, aLength);
}





void Sha1Checksum::finalize(Sha1Checksum::Checksum & aOutput)
{
	ASSERT(mDoesAcceptInput);  // Not Finalize()-d yet, or Restart()-ed

	mbedtls_sha1_finish(&m_Sha1, aOutput);
	mDoesAcceptInput = false;
}





void Sha1Checksum::digestToJava(const Checksum & a_Digest, std::string & a_Out)
{
	Checksum Digest;
	memcpy(Digest, a_Digest, sizeof(Digest));

	bool IsNegative = (Digest[0] >= 0x80);
	if (IsNegative)
	{
		// Two's complement:
		bool carry = true;  // Add one to the whole number
		for (int i = 19; i >= 0; i--)
		{
			Digest[i] = ~Digest[i];
			if (carry)
			{
				carry = (Digest[i] == 0xff);
				Digest[i]++;
			}
		}
	}
	a_Out.clear();
	a_Out.reserve(40);
	static const char HexChar[] = "0123456789abcdef";
	for (int i = 0; i < 20; i++)
	{
		a_Out.push_back(HexChar[Digest[i] >> 4]);
		a_Out.push_back(HexChar[Digest[i] & 0x0f]);
	}
	while ((a_Out.length() > 0) && (a_Out[0] == '0'))
	{
		a_Out.erase(0, 1);
	}
	if (IsNegative)
	{
		a_Out.insert(0, "-");
	}
}





void Sha1Checksum::restart(void)
{
	mbedtls_sha1_starts(&m_Sha1);
	mDoesAcceptInput = true;
}




