#include "ClientCredentials.h"

DTLS::ClientCredentials::ClientCredentials() 
{
	this->store.insert(store.end(), &this->certstor);
}

void DTLS::ClientCredentials::addCAs(const std::string& path)
{
	this->certstor.add_certificate(Botan::X509_Certificate(path));
}

void DTLS::ClientCredentials::addCAs(std::initializer_list<std::string> list)
{
	for (auto cert : list) {
		this->certstor.add_certificate(Botan::X509_Certificate(cert));
	}
}

void DTLS::ClientCredentials::addCRL(const std::string& path)
{
	this->certstor.add_crl(Botan::X509_CRL(path));
}

void DTLS::ClientCredentials::addCertChain(const std::string& path)
{
	this->certChain.insert(certChain.end(), Botan::X509_Certificate(path));
}

void DTLS::ClientCredentials::addPrivateKey(const std::string& path)
{
	Botan::DataSource_Stream stream(path);
	this->m_key = Botan::PKCS8::load_key(stream);
}

std::vector<Botan::X509_Certificate> DTLS::ClientCredentials::cert_chain(const std::vector<std::string>& cert_key_types, const std::string& type, const std::string& context)
{
	std::cout << this->certChain[0].to_string() << '\n';
	for (auto keytype : cert_key_types) {
		if(keytype=="RSA")
			return this->certChain;
	}
	return std::vector<Botan::X509_Certificate>();
}

Botan::Private_Key* DTLS::ClientCredentials::private_key_for(const Botan::X509_Certificate& cert, const std::string& type, const std::string& context)
{
	
	return nullptr;
}
