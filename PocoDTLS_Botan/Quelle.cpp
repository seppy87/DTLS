#define POCO_STATIC
#include"Policy.hpp"
#include"ServerCredentials.hpp"
#include"Server.hpp"
#include"Client.hpp"
#include"ClientCredentials.h"




int main(int argc, char **argv) {
	Poco::Net::initializeNetwork();
	if (argc < 2) {
		try {
			DTLS::Policy policy;
			DTLS::ServerCredentials cred("c:\\CATEST\\botan\\private.key", "c:\\CATEST\\botan\\botanserver.crt");
			DTLS::Server server(Poco::Net::SocketAddress("192.168.1.119", 999), &cred, &policy);
			server.startListening();
		}
		catch (const Botan::Exception & ex) {
			std::cout << ex.what() << '\n';
		}
	}
	else {
		DTLS::Policy policy;
		DTLS::ClientCredentials creds;
		creds.addCAs("c:\\rsakeys\\ca.crt");
		creds.addCertChain("c:\\rsakeys\\client.crt");
		creds.addPrivateKey("c:\\rsakeys\\client.key");
		try {
			DTLS::Client client(Poco::Net::SocketAddress("192.168.1.119", 999), creds, policy);
			std::string test("HALLO");
			//client << "HALLO WELT";
			client << "HALLO";
			std::cout << client;
			
		}
		catch (Botan::Exception & ex) {
			std::cout << ex.what();
		}
	}
	system("pause");
	Poco::Net::uninitializeNetwork();
	return 0;
}