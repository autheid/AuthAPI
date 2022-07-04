#include "autheid_utils.h"

#if !defined(AUTHEID_BOTAN_AMALGAMATION)
#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/ecdh.h>
#include <botan/ecies.h>
#include <botan/ecdsa.h>
#endif


namespace autheid
{

namespace  {

const Botan::EC_Group kDomain("secp256k1");

const auto kSignAlg = "EMSA1(SHA-256)";

// Use stream cipher and compressed point to get smaller encrypted size
const Botan::ECIES_System_Params kEciesParams(kDomain,
   "KDF2(SHA-256)", "ChaCha(20)", 32, "HMAC(SHA-256)", 20,
   Botan::PointGFp::COMPRESSED, Botan::ECIES_Flags::NONE);

} // namespace

PrivateKey generatePrivateKey()
{
   Botan::AutoSeeded_RNG rnd;
   return rnd.random_vec(kPrivateKeySize);
}

PublicKey getPublicKey(const PrivateKey &privateKey)
{
   try {
      Botan::AutoSeeded_RNG rnd;

      Botan::BigInt privateKeyValue;
      privateKeyValue.binary_decode(privateKey);
      Botan::ECDH_PrivateKey privateKeyEC(rnd, kDomain, privateKeyValue);
      privateKeyValue.clear();

      Bytes publicKey = privateKeyEC.public_point().encode(Botan::PointGFp::COMPRESSED);
      if (publicKey.size() != kPublicKeySize) {
         return {};
      }

      return publicKey;
   } catch (...){
      return {};
   }
}

Bytes encryptData(const void *data, size_t dataSize, const PublicKey &publicKey)
{
   try {
      Botan::AutoSeeded_RNG rng;

      auto publicKeyDecoded = kDomain.OS2ECP(publicKey);

      Botan::ECIES_Encryptor encrypt(rng, kEciesParams);

      encrypt.set_other_key(publicKeyDecoded);

      Bytes result = encrypt.encrypt(static_cast<const uint8_t*>(data), dataSize, rng);

      return result;
   } catch (...) {
      return {};
   }
}

SecureBytes decryptData(const void *data, size_t dataSize, const PrivateKey &privateKey)
{
   try {
      Botan::AutoSeeded_RNG rng;

      Botan::BigInt privateKeyValue;
      privateKeyValue.binary_decode(privateKey);
      Botan::ECDH_PrivateKey privateKeyDecoded(rng, kDomain, privateKeyValue);
      privateKeyValue.clear();

      Botan::ECIES_Decryptor decryptor(privateKeyDecoded, kEciesParams, rng);

      auto result = decryptor.decrypt(static_cast<const uint8_t*>(data), dataSize);
      return result;

   } catch (const Botan::Decoding_Error& e){
      return {};
   } catch (const std::exception& e) {
      return {};
   }
}

Bytes signData(const void *data, size_t dataSize, const PrivateKey &privateKey, bool derFormat)
{
   try {
      Botan::AutoSeeded_RNG rng;

      Botan::BigInt privateKeyValue;
      privateKeyValue.binary_decode(privateKey);
      Botan::ECDSA_PrivateKey privateKeyDecoded(rng, kDomain, privateKeyValue);
      // Clear data for security
      privateKeyValue.clear();

      Botan::PK_Signer signer(privateKeyDecoded, rng, kSignAlg, derFormat ? Botan::DER_SEQUENCE : Botan::IEEE_1363);
      signer.update(static_cast<const uint8_t*>(data), dataSize);
      Bytes signature = signer.signature(rng);

      return signature;
   } catch (...){
      return {};
   }
}

bool verifyData(const void *data, size_t dataSize, const void *sign, size_t signSize
   , const PublicKey &publicKey, bool derFormat)
{
   try {
      auto publicKeyValue = kDomain.OS2ECP(publicKey);

      Botan::ECDSA_PublicKey publicKeyDecoded(kDomain, publicKeyValue);

      Botan::PK_Verifier verifier(publicKeyDecoded, kSignAlg, derFormat ? Botan::DER_SEQUENCE : Botan::IEEE_1363);
      verifier.update(static_cast<const uint8_t *>(data), dataSize);
      bool result = verifier.check_signature(static_cast<const uint8_t *>(sign), signSize);

      return result;
   } catch (...){
      return false;
   }
}

} // namespace autheid
