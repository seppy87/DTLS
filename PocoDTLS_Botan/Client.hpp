#pragma once
#define POCO_STATIC
#include"Server.hpp"

namespace DTLS {
	using DTLSSimpleCallback = std::function<void(void* sender)>;
	
	class Client : public Botan::TLS::Callbacks, public Poco::Net::DatagramSocket
	{
	public:
		Client(Poco::Net::SocketAddress connectTo, Botan::Credentials_Manager& credentials, Botan::TLS::Policy& policy);
		~Client() = default;

		void DTLSConnect();

		//overridden Functions
		void tls_emit_data(const uint8_t data[], size_t size) override {
			this->sendTo(data, size,this->target);
		}

		void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;

		void tls_alert(Botan::TLS::Alert alert) override {
			std::cerr << alert.type_string()<<'\n';
			if (this->OnErrorEvent)
				this->OnErrorEvent(alert.type_string());
		}

		bool tls_session_established(const Botan::TLS::Session& session) override
		{
			std::cout << "SESSION ESTABLISHED\n";
			// the session with the tls server was established
			// return false to prevent the session from being cached, true to
			// cache the session in the configured session manager
			return false;
		}

		bool isActive() {
			return this->client->is_active();
		}

		bool isClosed() {
			return this->client->is_closed();
		}

	private:
		std::unique_ptr<Botan::TLS::Client> client;
		Botan::AutoSeeded_RNG rng;
		Botan::TLS::Session_Manager_In_Memory mgr;
		Botan::Credentials_Manager creds;
		Botan::TLS::Policy policy;
		Poco::Net::SocketAddress target;
		std::string lastMessage;

		DTLSSimpleCallback DataReceivedEvent;
		DTLSErrorCallback OnErrorEvent;

	public:
		Client& operator<<(const std::string& str);
		friend std::ostream& operator<<(std::ostream& os, const DTLS::Client& cl);
		friend std::istream& operator>>(std::istream& is, DTLS::Client& cl);
			
	};

	std::ostream& operator<<(std::ostream& os, const DTLS::Client& cl);
	std::istream& operator>>(std::istream& is, DTLS::Client& cl);
}

