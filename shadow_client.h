#pragma once
#include <string>
#include <winsock2.h>

#include "socket_address.h"
#include "socket_select.h"

class shadow_client
{
public:
	shadow_client();
	shadow_client(SOCKET remote_sock);
	~shadow_client();

	SOCKET connect(const socket_address& _address, int& _errcode, int32_t _timeout = -1);
	int handshake();
	int send(const void* _buffer, size_t _len, int& _errcode, int _timeout = -1);
	int recv(std::string& _buffer, size_t _max_size, int& _errcode, int _timeout = -1, bool _wait_full_size = false);
	void cancel();

private:
	void init();
	SOCKET connect_impl(const socket_address& _address, int& _errcode, int32_t _timeout/*ms*/);
	int stream_data(SOCKET Source, SOCKET Dest);

private:
	SOCKET socket_;
	SOCKET remote_socket_;
	SocketBreaker breaker_;
};

