#define POCO_STATIC
#include"Policy.hpp"
#include"ServerCredentials.hpp"
#include"Server.hpp"
#include"Client.hpp"
#include"ClientCredentials.h"


void received(const std::string& data, DTLS::DTLSReplyCallback& reply) {
	std::cout << data << '\n';
	reply("ACK");
}

int main(int argc, char **argv) {
	Poco::Net::initializeNetwork();
	if (argc < 2) {
		try {
			DTLS::Policy policy;
			DTLS::ServerCredentials cred("c:\\CATEST\\botan\\private.key", "c:\\CATEST\\botan\\botanserver.crt");
			DTLS::Server server(Poco::Net::SocketAddress("192.168.1.119", 999), &cred, &policy);
			server.setupCallback(DTLS::DTLSCallback::DTLS_RECORD_RECEIVED_CALLBACK, std::make_any<DTLS::DTLSReceivedCallback>(&received));
			server.startListening();
		}
		catch (const Botan::Exception & ex) {
			std::cout << ex.what() << '\n';
		}
	}
	else {
		DTLS::Policy policy;
		DTLS::ClientCredentials creds;
		creds.addCAs("c:\\rsakeys\\CAS\\ca.crt");
		creds.addCertChain("c:\\rsakeys\\client.crt");
		creds.addPrivateKey("c:\\rsakeys\\client.key");
		try {
			DTLS::Client client(Poco::Net::SocketAddress("192.168.1.119", 999), creds, policy);
			client.DTLSConnect();
			client << "HALLO";
	//		std::cout << client;
			
		}
		catch (Botan::Exception & ex) {
			std::cout << ex.what();
		}
	}
	system("pause");
	Poco::Net::uninitializeNetwork();
	return 0;
}