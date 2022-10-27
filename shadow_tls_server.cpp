#include "shadow_tls_server.h"

#include <cstdlib>
#include <functional>
#include <atomic>

#include "bio.h"
#include "shadow_client.h"

#include "debug_helper.h"

#define DEFAULT_SHADOW_DOAMIN "www.google.com:443"

int g_client_id = 0;

DWORD WINAPI thread_client(LPVOID lpThreadParameter)
{
	auto cli = static_cast<shadow_client*>(lpThreadParameter);
	while(true)
	{
		int ret = cli->handshake();
		if (ret == -1)
		{
			debug_log("handshake to shadow domain failed\n");
			return 1;
		}
		break;
	}
	return 0;
}

shadow_tls_server::shadow_tls_server()
	: shadow_doamin_(DEFAULT_SHADOW_DOAMIN)
	  , shutdown_(false)
{
	init();
}

shadow_tls_server::shadow_tls_server(const std::string& shadow_domain)
	: shadow_doamin_(shadow_domain)
	  , shutdown_(false)
{
	init();
}

shadow_tls_server::~shadow_tls_server()
{
	shutdown_ = true;
	listen_thread_.join();
	for (auto th = clients_.begin(); th != clients_.end(); ++th)
	{
		if(th->second.thread.joinable())
			th->second.thread.join();
	}

	{
		std::unique_lock<std::mutex> lock(client_mutex_);
		clients_.clear();
	}
}

int shadow_tls_server::start_server(uint16_t port)
{
	int res = 0;
	do
	{
		if (port <= 0 || port >= 0xffff)
			break;
		socket_listen_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (socket_listen_ == INVALID_SOCKET)
		{
			break;
		}
		SOCKADDR_IN si = {0};
		si.sin_family = AF_INET;
		si.sin_port = ntohs(static_cast<USHORT>(port));
		si.sin_addr.S_un.S_addr = ADDR_ANY;
		res = ::bind(socket_listen_, (sockaddr*)&si, sizeof(si));
		if (res == SOCKET_ERROR)
		{
			break;
		}
		res = listen(socket_listen_, SOMAXCONN);
		if (res == SOCKET_ERROR)
		{
			break;
		}

		listen_thread_ = std::thread(std::bind(&shadow_tls_server::listen_routine, this));
	}
	while (false);
	return res;
}

void shadow_tls_server::shutdown()
{
	shutdown_ = true;
	read_write_breaker_.Break();
}

void shadow_tls_server::init()
{
}

void shadow_tls_server::listen_routine()
{
	int ret = 0;
	while (!shutdown_)
	{
		struct sockaddr_storage sock_addr;
		int len = sizeof(sock_addr);
		SOCKET c = accept(socket_listen_, (sockaddr*)&sock_addr, &len);
		if (c == INVALID_SOCKET)
		{
			debug_log("accept %d\n", WSAGetLastError());
			break;
		}
		g_client_id++;
		debug_log("%d new client %d\n", g_client_id, c);
		client_info client{};
		client.id = g_client_id;
		client.s = c;
		DWORD dwThreadId = 0;
		client.thread = std::thread([&]()
		{
				client_routine(g_client_id);
		});

		std::unique_lock<std::mutex> lock(client_mutex_);
		clients_.insert({g_client_id, std::move(client)});
	}
}

void shadow_tls_server::client_routine(int id)
{
	int ret = 0;
	std::map<int, client_info>::iterator it;

	{
		std::unique_lock<std::mutex> lock(client_mutex_);
		it = clients_.find(id);
		if (it == clients_.end())
			return;
	}

	debug_log("client routine %d begin\n", GetCurrentThreadId());

	routine_context* ctx = new routine_context();
	ctx->type = kContextServer;
	ctx->src_sock = it->second.s;

	while (!shutdown_)
	{
		SocketSelect sel(read_write_breaker_, true);
		sel.PreSelect();
		sel.Read_FD_SET(it->second.s);
		sel.Exception_FD_SET(it->second.s);
		if (!it->second.data.empty())
		{
			sel.Write_FD_SET(it->second.s);
		}

		int retsel = sel.Select(3 * 1000);
		if (retsel < 0)
		{
			break;
		}

		if (sel.IsException())
		{
			continue;
		}

		if (sel.Exception_FD_ISSET(it->second.s))
		{
			continue;
		}

		if (sel.Write_FD_ISSET(it->second.s))
		{
			if(!it->second.handshaked)
			{
				
			}
			int sent = ::send(it->second.s, (const char*)it->second.data.data(), it->second.data.size(), 0);
			if (sent <= 0)
			{
				break;
			}
			it->second.data.clear();
		}

		if (sel.Read_FD_ISSET(it->second.s))
		{
			if (!it->second.handshaked)
			{
				int err;
				shadow_client *cli = new shadow_client(ctx->src_sock);
				SOCKET remote = cli->connect(socket_address(shadow_doamin_.c_str()), err);
				if(remote == INVALID_SOCKET)
				{
					delete cli;
					debug_log("connect tls remote failed\n");
					break;
				}
				ctx->dst_sock = remote;

				if(cli->handshake() < 0)
				{
					delete cli;
					debug_log("handshake failed\n");
					break;
				}
				//DWORD thread_id = 0;
				//HANDLE handle = CreateThread(nullptr, 0, thread_client, cli, 0, &thread_id);
				//if(handle == nullptr)
				//{
				//	break;
				//}
				//WaitForSingleObject(handle, INFINITE);
				it->second.handshaked = true;
			}
			else
			{

			}
		}
	}
	debug_log("client routine %d end\n", GetCurrentThreadId());
}

