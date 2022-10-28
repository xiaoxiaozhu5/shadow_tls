#pragma once
#include <mutex>
#include <winsock2.h>

#include <thread>
#include <vector>

#include "socket_select.h"

class shadow_tls_server;

class MShadowServer
{
public:
	virtual ~MShadowServer(){}
	virtual void OnAccept(shadow_tls_server* server, SOCKET sock, const sockaddr_in& addr) = 0;
	virtual void OnError(shadow_tls_server* server, int err) = 0;
};

class shadow_tls_server
{
public:
	friend DWORD WINAPI thread_client(LPVOID lpThreadParameter);
	shadow_tls_server(MShadowServer& observer);
	shadow_tls_server(MShadowServer& observer, const std::string& shadow_domain);
	~shadow_tls_server();

	int start_server(uint16_t port);
	void shutdown();

	int send(int id, const void* data, const int len);

private:
	struct client_info
	{
		int id;
		SOCKET s;
		std::thread thread;
		bool handshaked;
		std::vector<uint8_t> data;

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

	SocketBreaker read_write_breaker_;
	bool shutdown_;
	std::thread listen_thread_;
	std::mutex client_mutex_;
	std::map<int, client_info> clients_;
	MShadowServer& observer_; 
};


