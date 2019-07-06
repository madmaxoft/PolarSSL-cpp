
set(SRCS
	AesCfb128Decryptor.cpp
	AesCfb128Encryptor.cpp
	CallbackSslContext.cpp
	CtrDrbgContext.cpp
	CryptoKey.cpp
	EntropyContext.cpp
	RsaPrivateKey.cpp
	Sha1Checksum.cpp
	SslConfig.cpp
	SslContext.cpp
	TlsException.cpp
	X509Cert.cpp
)

set(HDRS
	AesCfb128Decryptor.h
	AesCfb128Encryptor.h
	CallbackSslContext.h
	CtrDrbgContext.h
	CryptoKey.h
	EntropyContext.h
	ErrorCodes.h
	PolarSSL-cpp.h
	RsaPrivateKey.h
	Sha1Checksum.h
	SslConfig.h
	SslContext.h
	TlsException.h
	X509Cert.h
)

add_library(PolarSSL-cpp STATIC ${SRCS} ${HDRS})
target_link_libraries(PolarSSL-cpp mbedtls)



# Until MbedTls supports proper per-target include directories, we need to add our own:
# TODO: Get rid of the hard-coded PolarSSL folder
target_include_directories(PolarSSL-cpp PUBLIC ../PolarSSL/include/)

target_include_directories(PolarSSL-cpp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
