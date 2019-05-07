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
	class ServerCredentials : public Botan::Credentials_Manager
	{
	public:
		ServerCredentials(const std::string& key, const std::string& cert);
		~ServerCredentials() = default;

		//overrridden functions
		std::vector<Botan::X509_Certificate> cert_chain(const std::vector<std::string>& cert_key_types, const std::string& type, const std::string& context) override {
			std::cout << "Type=" << type << '\n';
			std::cout << "Context=" << context << '\n';
			for (auto s : cert_key_types) {
				std::cout << "Key Type=" << s << '\n';
				if (s == "RSA")
					return this->certChain;
			}
			//std::cout << "My Cert = " << certChain[0].to_string();
			//return this->certChain;
			return std::vector<Botan::X509_Certificate>();
		}

		Botan::SymmetricKey psk(const std::string& type, const std::string& context, const std::string& identity) override {
			return Botan::OctetString();
		}

		Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const std::string& type, const std::string& context) noexcept override {
			std::cout << "Type=" << type << '\n';
			return this->m_key.get();
		}

		std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type, const std::string& context) override {
			return std::vector<Botan::Certificate_Store*>();
		}

	private:
		std::unique_ptr<Botan::Private_Key> m_key;
		std::vector<Botan::X509_Certificate> certChain;
	};
}
