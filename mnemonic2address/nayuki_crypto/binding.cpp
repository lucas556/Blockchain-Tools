// binding.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "Sha256.hpp"
#include "Sha512.hpp"
#include "Uint256.hpp"
#include "CurvePoint.hpp"
#include "Utils.hpp"
#include "Keccak256.hpp"

namespace py = pybind11;

PYBIND11_MODULE(nayuki_crypto, m) {
    m.doc() = "Unified cryptographic module using Nayuki's Bitcoin-Cryptography-Library";

    // SHA256 - return raw bytes
    m.def("sha256", [](py::bytes data) {
        std::string raw = data;
        Sha256Hash hash = Sha256::getHash(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        return py::bytes(reinterpret_cast<const char*>(hash.value), Sha256Hash::HASH_LEN);
    });

    // HMAC-SHA512
    m.def("hmac_sha512", [](py::bytes key, py::bytes data) {
        std::string k = key;
        std::string d = data;
        uint8_t out[64];
        Sha512::getHmac(reinterpret_cast<const uint8_t*>(k.data()), k.size(),
                        reinterpret_cast<const uint8_t*>(d.data()), d.size(), out);
        return py::bytes(reinterpret_cast<const char*>(out), 64);
    });

    // secp256k1: private key to compressed public key (33 bytes)
    m.def("private_to_public", [](const std::vector<uint8_t> &privkey_bytes) {
        if (privkey_bytes.size() != 32) throw std::invalid_argument("Private key must be 32 bytes");
        Uint256 priv(privkey_bytes.data());
        CurvePoint pub = CurvePoint::privateExponentToPublicPoint(priv);
        std::vector<uint8_t> out(33);
        pub.toCompressedPoint(out.data());
        return out;
    });


    // Keccak256
    m.def("keccak256", [](py::bytes data) {
        std::string raw = data;
        uint8_t hash[Keccak256::HASH_LEN];
        Keccak256::getHash(reinterpret_cast<const uint8_t*>(raw.data()), raw.size(), hash);
        return py::bytes(reinterpret_cast<const char*>(hash), Keccak256::HASH_LEN);
    });
} 
