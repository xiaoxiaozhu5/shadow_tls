#pragma once
#include <string>
#include <winsock2.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>

#include "socket_address.h"
#include "socket_select.h"

class shadow_client
{
public:
	shadow_client();
	shadow_client(int id);
	~shadow_client();

	SOCKET connect(const socket_address& _address, int& _errcode, int32_t _timeout = -1);
	int handshake();
	int send(const void* _buffer, size_t _len, int& _errcode, int _timeout = -1);
	int recv(std::string& _buffer, size_t _max_size, int& _errcode, int _timeout = -1, bool _wait_full_size = false);
	void cancel();

private:
	void init();
	SOCKET connect_impl(const socket_address& _address, int& _errcode, int32_t _timeout/*ms*/);

private:
	int relate_id;
	bool handshaked_;
	SOCKET socket_;
	SOCKET remote_socket_;
	SocketBreaker breaker_;

	mbedtls_ctr_drbg_context ctr_drbg_;
	mbedtls_entropy_context entropy_;

	mbedtls_ssl_context ssl_ctx_;
	mbedtls_x509_crt ca_crt_;
	mbedtls_ssl_config ssl_conf_;
};

