#pragma once

#include "PolarSSL-cpp.h"
#include <string>
#include "mbedtls/sha1.h"





/** Calculates a SHA1 checksum for data stream */
class Sha1Checksum
{

public:

	using Checksum = Byte[20];  // The type used for storing the checksum


	Sha1Checksum(void);

	/** Adds the specified data to the checksum */
	void update(const Byte * aData, size_t aLength);

	/** Calculates and returns the final checksum */
	void finalize(Checksum & aOutput);

	/** Returns true if the object is accepts more input data, false if Finalize()-d (need to Restart()) */
	bool doesAcceptInput(void) const { return mDoesAcceptInput; }

	/** Converts a raw 160-bit SHA1 digest into a Java Hex representation
	According to http://wiki.vg/Protocol_Encryption */
	static void digestToJava(const Checksum & a_Digest, std::string & a_JavaOut);

	/** Clears the current context and starts a new checksum calculation */
	void restart(void);


protected:

	/** The wrapped MbedTls object. */
	mbedtls_sha1_context m_Sha1;

	/** True if the object can accepts more input data, false if finalize()-d (need to restart()) */
	bool mDoesAcceptInput;
} ;




