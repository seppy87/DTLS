#include "Client.hpp"

DTLS::Client::Client(Poco::Net::SocketAddress connectTo, Botan::Credentials_Manager& credentials, Botan::TLS::Policy& policy): mgr(this->rng), creds(credentials), policy(policy), target(connectTo)
{
	this->connect(connectTo);
}

void DTLS::Client::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
{
	if (!this->lastMessage.empty())
			this->lastMessage.clear();
	this->lastMessage = "";
	for (uint16_t i = 0; i < size; i++) {
		this->lastMessage += data[i];
	}
	if (this->DataReceivedEvent)
		this->DataReceivedEvent(this);
}

std::ostream& DTLS::operator<<(std::ostream& os, const DTLS::Client& cl)
{
	os << cl.lastMessage;
	return os;
}

std::istream& DTLS::operator>>(std::istream& is, DTLS::Client& cl)
{
	std::istreambuf_iterator<char> eos;
	std::string s(std::istreambuf_iterator<char>(is), eos);
	cl.client->send(s);
	return is;
}
