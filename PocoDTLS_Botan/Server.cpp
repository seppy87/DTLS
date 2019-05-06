#include "Server.hpp"

DTLS::Server::Server(Poco::Net::SocketAddress sa, Botan::Credentials_Manager* mgr, Botan::TLS::Policy* pol) : Poco::Net::DatagramSocket(sa), session_mgr(rng), creds(mgr), policy(pol)
{
	this->server = std::make_unique<Botan::TLS::Server>(*this, this->session_mgr, *this->creds, *this->policy, this->rng, true);
}

void DTLS::Server::tls_emit_data(const uint8_t data[], size_t size)
{
	this->sendTo(data, size, this->clientAddr);
}

void DTLS::Server::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
{
	std::cout << data << '\n';
}

void DTLS::Server::tls_alert(Botan::TLS::Alert alert)
{
	std::cerr << alert.type_string() << '\n';
}

bool DTLS::Server::tls_session_established(const Botan::TLS::Session& session)
{
	std::cout << &session.session_id()[0] << " Is the Session ID\n";
	return true;
}

void DTLS::Server::startListening()
{
	while (condition) {
		char buffer[4096];
		memset(buffer, 0, sizeof(buffer));
		auto bytes = this->receiveFrom(buffer, sizeof(buffer), this->clientAddr);
		this->server->received_data((uint8_t*)buffer, bytes);
		this->server->send("ACK");
	}
}
