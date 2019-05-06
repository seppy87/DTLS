#pragma once

#include <botan/tls_client.h>
#include<botan/tls_server.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include<botan/pkcs8.h>
#include<botan/data_src.h>
#include<botan/datastor.h>
#include<botan/certstor.h>
#include<botan/symkey.h>


#include<iostream>

namespace DTLS {
	enum class DTLSVersion : unsigned int
	{
		DTLS_ANY = 0,
		DTLS_1_0 = 1,
		DTLS_1_2 = 2,
		DTLS_1_3 = 3, // NOT IMPLEMENTED
	};

	enum class DTLSAllowedOption : unsigned int {
		DTLS_ALLOWED_CIPHERS = 1,
		DTLS_ALLOWED_SIGNATURE_HASHES = 2,
		DTLS_ALLOWED_MACS = 3,
		DTLS_ALLOWED_KEY_EXCHANGE_METHODS = 4,
		DTLS_ALLOWED_SIGNATURE_METHODS = 5
	};

	class Policy : public Botan::TLS::Policy
	{
	public:
		Policy(DTLSVersion minimalVersion = DTLSVersion::DTLS_ANY);
		~Policy() = default;

		//overridden Functions
		bool allow_dtls10() const override {
			return this->dtls10_enabled;
		}
		bool allow_dtls12() const override {
			return this->dtls12_enabled;
		}

		std::vector<std::string> allowed_ciphers()const override {
			return this->allowedCiphersVec;
		}
		
		std::vector<std::string> allowed_signature_hashes()const override {
			return this->allowedSignatureHashesVec;
		}

		std::vector<std::string> allowed_macs()const override {
			return this->allowedMacsVec;
		}

		std::vector<std::string> allowed_key_exchange_methods()const override {
			return this->allowedKeyExchangeMethodsVec;
		}

		std::vector<std::string> allowed_signature_methods() const override {
			return this->allowedSignatureMethodsVec;
		}

		bool allow_tls10() const override {
			return false;
		}

		bool allow_tls11() const override {
			return false;
		}

		bool allow_tls12() const override {
			return false;
		}

		bool removeItemAllowedOption(DTLSAllowedOption option, const std::string& key);

		


	private:
		bool dtls10_enabled = false;
		bool dtls12_enabled = false;
		bool dtls13_enabled = false;
		std::vector<std::string> allowedCiphersVec{ "AES-256/OCB(12)","AES-128/OCB(12)","ChaCha20Poly1305","AES-256/GCM","AES-128/GCM","AES-256/CCM","AES-128/CCM","AES-256/CCM(8)","AES-128/CCM(8)","Camellia-256/GCM","Camellia-128/GCM","ARIA-256/GCM", "ARIA-128/GCM", "AES-256", "AES-128","Camellia-256", "Camellia-128", "SEED","3DES" };;
		std::vector<std::string> allowedSignatureHashesVec{ "SHA-512","SHA-384","SHA-256","SHA-1", };
		std::vector<std::string> allowedMacsVec{ "AEAD","SHA-256","SHA-384","SHA-1" };
		std::vector<std::string> allowedKeyExchangeMethodsVec{ "SRP_SHA", "ECDHE_PSK", "DHE_PSK", "PSK", "CECPQ1", "ECDH", "DH", "RSA" };
		std::vector<std::string> allowedSignatureMethodsVec{ "ECDSA","RSA","DSA","IMPLICIT","ANONYMOUS" };
	};
}

