#pragma once
#include <mutex>
#include <winsock2.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

#include <thread>
#include <vector>

#include "socket_select.h"

class shadow_tls_server
{
public:
	shadow_tls_server();
	shadow_tls_server(const std::string& shadow_domain);
	~shadow_tls_server();

	int start_server(uint16_t port);
	void shutdown();

	int send(int id, const void* data, const int len);

private:
	struct client_info
	{
		int id;
		SOCKET s;
		HANDLE thread;
		bool handshaked;
		std::vector<uint8_t> data;
		mbedtls_ssl_context	ssl_ctx;

		client_info()
		{
			handshaked = false;
			s = INVALID_SOCKET;
			id = -1;
		}
	};

private:
	void init();
	void listen_routine();
	void client_routine(int id);

private:
	std::string shadow_doamin_;
	SOCKET socket_listen_;

	mbedtls_ctr_drbg_context ctr_drbg_;
	mbedtls_entropy_context entropy_;

	mbedtls_ssl_config srv_ssl_conf_;
	mbedtls_x509_crt ca_crt_;
	mbedtls_x509_crt srv_crt_;
	mbedtls_pk_context srv_pk_ctx_;

	SocketBreaker read_write_breaker_;
	bool shutdown_;
	std::thread listen_thread_;
	std::mutex client_mutex_;
	std::map<int, client_info> clients_;
};


