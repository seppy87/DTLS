#pragma once
#include"Client.hpp"
#include<initializer_list>

namespace DTLS {
	class ClientCredentials : public Botan::Credentials_Manager
	{
	public:
		ClientCredentials();
		~ClientCredentials() = default;

		void addCAs(const std::string& path);
		void addCAs(std::initializer_list<std::string> list);
		void addCRL(const std::string& path);
		void addCertChain(const std::string& path);
		void addPrivateKey(const std::string& path);

		//overridden Function
		std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,const std::string& context) override {

			return this->store;
		}

		std::vector<Botan::X509_Certificate> cert_chain(const std::vector<std::string>& cert_key_types, const std::string& type, const std::string& context) override;

		Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const std::string& type, const std::string& context) override;
		

	private:
		Botan::Certificate_Store_In_Memory certstor;
		std::vector<Botan::Certificate_Store*> store;
		std::vector<Botan::X509_Certificate> certChain;
		std::unique_ptr<Botan::Private_Key> m_key;
	};
}

