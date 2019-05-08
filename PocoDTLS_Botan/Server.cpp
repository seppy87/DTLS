#include "Server.hpp"

DTLS::Server::Server(Poco::Net::SocketAddress sa, Botan::Credentials_Manager* mgr, Botan::TLS::Policy* pol) : Poco::Net::DatagramSocket(sa,true), session_mgr(rng), creds(mgr), policy(pol)
{
	this->server = std::make_unique<Botan::TLS::Server>(*this, this->session_mgr, *this->creds, *this->policy, this->rng, true);
	this->replyFunction = [&](const std::string & message) {
		this->sendTo(message.c_str(), message.size(), this->clientAddr);
	};
}

void DTLS::Server::setupCallback(DTLSCallback type, std::any foo)
{
	switch (type) {
	case DTLSCallback::DTLS_RECORD_RECEIVED_CALLBACK:
		this->DataReceivedEvent = std::any_cast<DTLSReceivedCallback>(foo);
		return;
	case DTLSCallback::DTLS_ON_ERROR_CALLBACK:
		this->OnErrorEvent = std::any_cast<DTLSErrorCallback>(foo);
		return;
	default:
		std::cerr << "ERROR: SETUP CALLBACK\n";
		return;
	}
}

void DTLS::Server::tls_emit_data(const uint8_t data[], size_t size)
{
	this->sendTo(data, size, this->clientAddr);
}

void DTLS::Server::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
{
	std::cout << "DATA RECEIVED\n";
	//std::cout << data << '\n';
	//this->server->send("ACK");
	if (this->DataReceivedEvent) {
		std::string t = "";
		for (unsigned int i = 0; i < size; i++) {
			t += data[i];
		}
		this->DataReceivedEvent(t, this->replyFunction);
	}
}

void DTLS::Server::tls_alert(Botan::TLS::Alert alert)
{
	std::cerr << alert.type_string() << '\n';
	if (this->OnErrorEvent) {
		this->OnErrorEvent(alert.type_string());
	}
}

bool DTLS::Server::tls_session_established(const Botan::TLS::Session& session)
{
	std::cout << &session.session_id()[0] << " Is the Session ID\n";
	return false;
}

void DTLS::Server::startListening()
{
	uint8_t buffer[4096];
	memset(buffer, 0, sizeof(buffer));
	while (condition) {
		try {
			auto bytes = this->receiveFrom(buffer, sizeof(buffer), this->clientAddr);
			std::cout << "FROM PORT=" << this->clientAddr.port() << '\n';
			try {
				this->server->received_data(buffer, bytes);
				this->sendTo("ACK", sizeof("ACK"), this->clientAddr);
			}
			catch (Botan::Exception & ex) {
				std::cout << ex.what() << '\n';
			}
		}
		catch (Poco::Exception & ex) {
			std::cout << ex.displayText();
		}
		
	}
}
