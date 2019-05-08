#include "ServerCredentials.hpp"



DTLS::ServerCredentials::ServerCredentials(const std::string& key, const std::string& cert): certstore("c:\\rsakeys\\ca.crt") {
	Botan::DataSource_Stream src(key);
	this->m_key = Botan::PKCS8::load_key(src);
	this->certChain.insert(this->certChain.end(), Botan::X509_Certificate(cert));
}