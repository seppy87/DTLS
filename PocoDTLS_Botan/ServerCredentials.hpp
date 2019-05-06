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

namespace DTLS {
	class ServerCredentials : public Botan::Credentials_Manager
	{
	public:
		ServerCredentials(const std::string& key, const std::string& cert);
		~ServerCredentials() = default;

		//overrridden functions
		std::vector<Botan::X509_Certificate> cert_chain(const std::vector<std::string>& cert_key_types, const std::string& type, const std::string& context) override {
			return this->certChain;
		}

		Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const std::string& type, const std::string& context) override {
			return this->m_key.get();
		}

	private:
		std::unique_ptr<Botan::Private_Key> m_key;
		std::vector<Botan::X509_Certificate> certChain;
	};
}
