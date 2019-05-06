#define POCO_STATIC
#include"Policy.hpp"
#include"ServerCredentials.hpp"
#include"Server.hpp"


int main() {
	Poco::Net::initializeNetwork();
	try {
		DTLS::Policy policy;
		DTLS::ServerCredentials cred("c:\\CATEST\\botan.key", "c:\\CATEST\\example.cert");
		DTLS::Server server(Poco::Net::SocketAddress("192.168.1.119", 999), &cred, &policy);
		server.startListening();
	}
	catch (Botan::Exception & ex) {
		std::cout << ex.what() << '\n';
	}
	system("pause");
	Poco::Net::uninitializeNetwork();
	return 0;
}