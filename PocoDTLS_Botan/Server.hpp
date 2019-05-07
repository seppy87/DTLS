#pragma once
#define _WINSOCKAPI_ // stop windows.h including winsock.h
#define POCO_STATIC

#pragma comment(lib,"botan.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

#include <botan/tls_client.h>
#include<botan/tls_server.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include<botan/pkcs8.h>
#include<botan/data_src.h>
#include<botan/datastor.h>
#include<botan/certstor.h>
#include<botan/symkey.h>

#include<Poco/Net/DatagramSocket.h>
#include<Poco/Net/IPAddress.h>
#include<Poco/Net/SocketAddress.h>

#include<iostream>
#include<any>

namespace DTLS {

	enum class DTLSCallback {
		DTLS_RECORD_RECEIVED_CALLBACK = 1,
		DTLS_ON_ERROR_CALLBACK = 2,
	};

	using DTLSReplyCallback = std::function<void(const std::string&)>;
	using DTLSReceivedCallback = std::function<void(const std::string&, DTLSReplyCallback& reply)>;
	using DTLSErrorCallback = std::function<void(const std::string&)>;

	class Server : public Botan::TLS::Callbacks, public Poco::Net::DatagramSocket
	{
	public:
		Server(Poco::Net::SocketAddress sa, Botan::Credentials_Manager* mgr, Botan::TLS::Policy* pol);
		~Server() = default;

		void setupCallback(DTLSCallback type, std::any foo);
		//overridden functions
		void tls_emit_data(const uint8_t data[], size_t size) override;
		void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;
		void tls_alert(Botan::TLS::Alert alert) override;
		bool tls_session_established(const Botan::TLS::Session& session) override;
		/*void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
			const std::vector<std::shared_ptr<Botan::OCSP::Response>>& ocsp_responses,
			const std::vector<Botan::Certificate_Store*>& trusted_roots,
			Botan::Usage_Type usage,
			const std::string& hostname,
			const Botan::TLS::Policy& policy
		) {

		}*/

		//MAIN FUNCTION FOR CLASS
		void startListening();

		void stopServer() {
			this->condition = false;
		}


	private:
		Poco::Net::SocketAddress clientAddr;
		Botan::AutoSeeded_RNG rng;
		Botan::TLS::Session_Manager_In_Memory session_mgr;
		Botan::Credentials_Manager* creds;
		Botan::TLS::Policy* policy;
		std::unique_ptr<Botan::TLS::Server> server;
		bool condition = true;

		//Events
		DTLSReceivedCallback DataReceivedEvent;
		DTLSErrorCallback OnErrorEvent;
		DTLSReplyCallback replyFunction;
	};

}

