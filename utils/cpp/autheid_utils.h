#pragma once
#include <cstdint>
#include <vector>
#include <string>

#if !defined(AUTHEID_BOTAN_AMALGAMATION)
#include <botan/secmem.h>
#else
#include <botan_all.h>
#endif


namespace autheid
{

// secp256k1 secret key
constexpr size_t kPrivateKeySize = 32;

// secp256k1 EC point (compressed)
constexpr size_t kPublicKeySize = 33;

using Bytes = std::vector<uint8_t>;
using SecureBytes = Botan::secure_vector<uint8_t>;

using PublicKey = Bytes;
using PrivateKey = SecureBytes;

PrivateKey generatePrivateKey();
PublicKey getPublicKey(const PrivateKey &privateKey);

Bytes encryptData(const void *data, size_t dataSize, const PublicKey &publicKey);

// Returns empty data if decrypt failed
SecureBytes decryptData(const void *data, size_t dataSize, const PrivateKey &privateKey);

Bytes signData(const void *data, size_t dataSize, const PrivateKey &privateKey);

bool verifyData(const void *data, size_t dataSize, const void *sign, size_t signSize
   , const PublicKey &publicKey);

} // namespace autheid
