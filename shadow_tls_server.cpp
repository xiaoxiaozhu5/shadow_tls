#include "shadow_tls_server.h"

#include <cstdlib>
#include <functional>
#include <atomic>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

#include "bio.h"
#include "shadow_client.h"

#include "debug_helper.h"

#define DEFAULT_SHADOW_DOAMIN "www.google.com:443"

int g_client_id = 0;

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
		WaitForSingleObject((*th).second.thread, INFINITE);
	}

	{
		std::unique_lock<std::mutex> lock(client_mutex_);
		clients_.clear();
	}

	mbedtls_x509_crt_free(&ca_crt_);
	mbedtls_pk_free(&srv_pk_ctx_);
	mbedtls_x509_crt_free(&srv_crt_);
	mbedtls_ssl_config_free(&srv_ssl_conf_);

	mbedtls_ctr_drbg_free(&ctr_drbg_);
	mbedtls_entropy_free(&entropy_);
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
	mbedtls_ctr_drbg_init(&ctr_drbg_);
	mbedtls_entropy_init(&entropy_);

	int res = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, NULL, 0);
	if (0 != res)
	{
		debug_log("drbg init error = %X.\n", res);
		exit(1);
	}
	mbedtls_ssl_config_init(&srv_ssl_conf_);
	mbedtls_x509_crt_init(&ca_crt_);
	mbedtls_x509_crt_init(&srv_crt_);
	mbedtls_pk_init(&srv_pk_ctx_);

	res = mbedtls_ssl_config_defaults(&srv_ssl_conf_, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
	                                  MBEDTLS_SSL_PRESET_DEFAULT);
	if (0 != res)
	{
		debug_log("default conf error = %X.\n", res);
		exit(1);
	}

	mbedtls_ssl_conf_authmode(&srv_ssl_conf_, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&srv_ssl_conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
	mbedtls_ssl_conf_min_version(&srv_ssl_conf_, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
}

void shadow_tls_server::listen_routine()
{
	int ret = 0;
	while (!shutdown_)
	{
		SOCKADDR_IN sock{};
		int len{0};
		SOCKET c = accept(socket_listen_, (sockaddr*)&sock, &len);
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
		client.thread = std::thread([&]()
		{
			client_routine(client.id);
		}).native_handle();

		std::unique_lock<std::mutex> lock(client_mutex_);
		clients_.insert({g_client_id, client});
	}
}

void shadow_tls_server::client_routine(int id)
{
	int ret = 0;
	client_info client;

	{
		std::unique_lock<std::mutex> lock(client_mutex_);
		auto it = clients_.find(id);
		if (it == clients_.end())
			return;
		client = it->second;
	}

	mbedtls_ssl_setup(&client.ssl_ctx, &srv_ssl_conf_);

	routine_context* ctx = new routine_context();
	ctx->type = kContextServer;
	mbedtls_ssl_set_bio(&client.ssl_ctx, ctx, send_routine, recv_routine, nullptr);

	while (!shutdown_)
	{
		SocketSelect sel(read_write_breaker_, true);
		sel.PreSelect();
		sel.Read_FD_SET(client.s);
		sel.Exception_FD_SET(client.s);
		if (!client.data.empty())
		{
			sel.Write_FD_SET(client.s);
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

		if (sel.Exception_FD_ISSET(client.s))
		{
			continue;
		}

		if (sel.Write_FD_ISSET(client.s))
		{
			int sent = ::send(client.s, (const char*)client.data.data(), client.data.size(), 0);
			if (sent <= 0)
			{
				break;
			}
			client.data.clear();
		}

		if (sel.Read_FD_ISSET(client.s))
		{
			if (!client.handshaked)
			{
				int err = 0;
				shadow_client cli(id);
				ret = cli.connect(socket_address(shadow_doamin_.c_str()), err);
				if (ret == -1)
				{
					debug_log("connect to shadow domain failed:%d\n", err);
					break;
				}


				char szTem[MAX_PATH] = {0};
				ret = mbedtls_ssl_handshake(&client.ssl_ctx);
				if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
				{
					ret = 0;
					break;
				}
				if (0 != ret)
				{
					mbedtls_strerror(ret, szTem, sizeof(szTem));
					debug_log(" handshake error=%#X, %s", 0 - ret, szTem);
					break;
				}
				client.handshaked = true;
			}
			//TODO: read data
		}
	}
}
