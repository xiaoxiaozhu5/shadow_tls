#include "shadow_tls_client.h"

#include <functional>

#include "autobuffer.h"

#include "debug_helper.h"


shadow_tls_client::shadow_tls_client(MShadowEvent& event)
	: event_(event)
{
	will_disconnect_ = false;
	mbedtls_ctr_drbg_init(&ctr_drbg_);
	mbedtls_entropy_init(&entropy_);

	int res = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, NULL, 0);
	if (0 != res)
	{
		debug_log("drbg init error = %d.\n", res);
		exit(1);
	}

	mbedtls_net_init(&net_ctx_);
	mbedtls_ssl_init(&ssl_ctx_);
	mbedtls_x509_crt_init(&ca_crt_);
	mbedtls_ssl_config_init(&ssl_conf_);

	res = mbedtls_ssl_config_defaults(&ssl_conf_, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
	                                  MBEDTLS_SSL_PRESET_DEFAULT);
	if (0 != res)
	{
		debug_log("clt conf set default error = %d.\n", res);
		exit(1);
	}

	mbedtls_ssl_conf_authmode(&ssl_conf_, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&ssl_conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
	mbedtls_ssl_conf_min_version(&ssl_conf_, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
}

shadow_tls_client::~shadow_tls_client()
{
	mbedtls_net_free(&net_ctx_);
	mbedtls_x509_crt_free(&ca_crt_);
	mbedtls_ssl_free(&ssl_ctx_);
	mbedtls_ssl_config_free(&ssl_conf_);

	mbedtls_ctr_drbg_free(&ctr_drbg_);
	mbedtls_entropy_free(&entropy_);
}

int shadow_tls_client::connect(const std::string& server, const std::string& shadow_domain)
{
	int res = 0;
	do
	{
		if (!validate_address(server))
		{
			res = MBEDTLS_ERR_SSL_BAD_CONFIG;
			break;
		}
		std::string address, port;
		if (!split_address_to_ip_and_port(server, address, port))
		{
			res = MBEDTLS_ERR_SSL_BAD_CONFIG;
			break;
		}
		debug_log("connect to %s:%s\n", address.c_str(), port.c_str());
		res = mbedtls_net_connect(&net_ctx_, address.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP);
		if (0 != res)
		{
			break;
		}

		res = mbedtls_ssl_setup(&ssl_ctx_, &ssl_conf_);
		if (0 != res)
		{
			break;
		}

		res = mbedtls_ssl_set_hostname(&ssl_ctx_, shadow_domain.c_str());
		if (0 != res)
		{
			break;
		}
		bool hs_failed = false;
		mbedtls_ssl_set_bio(&ssl_ctx_, &net_ctx_, mbedtls_net_send, mbedtls_net_recv, NULL);
		debug_log("start handshake\n");
		while ((res = mbedtls_ssl_handshake(&ssl_ctx_)) != 0)
		{
			if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				hs_failed = true;
				debug_log("mbedtls_ssl_handshake returned -0x%x\n", -res);
				break;
			}
		}
		if (hs_failed)
		{
			break;
		}

		res = 0;
		event_.OnConnect();
		thread_ = std::thread(std::bind(&shadow_tls_client::io_thread, this));
	}
	while (false);
	if (res != 0)
	{
		event_.OnError(res);
	}
	return res;
}

void shadow_tls_client::disconenct()
{
	if (will_disconnect_)
		return;
	will_disconnect_ = true;
}

void shadow_tls_client::write(const void* buf, unsigned int len)
{
	AutoBuffer* tmpbuff = new AutoBuffer;
	tmpbuff->Write(0, buf, len);

	std::unique_lock<std::mutex> lock(write_mutex_);
	lst_buffer_.push_back(tmpbuff);
}

SSIZE_T shadow_tls_client::read(void* buf, unsigned int len)
{
	std::unique_lock<std::mutex> lock(read_disconnect_mutex_);
	if(lst_rv_buffer_.empty())
		return 0;
	AutoBuffer& tmp = *lst_rv_buffer_.front();
	auto read_bytes = tmp.Read(buf, len);
	delete lst_rv_buffer_.front();
	lst_rv_buffer_.pop_front();
	return read_bytes;
}

bool shadow_tls_client::validate_address(const std::string& server)
{
	if (server.find(':') == std::string::npos)
	{
		return false;
	}
	return true;
}

bool shadow_tls_client::split_address_to_ip_and_port(const std::string& server, std::string& address, std::string& port)
{
	auto pos = server.find(':');
	address = server.substr(0, pos);
	port = server.substr(pos + 1);
	return true;
}

void shadow_tls_client::io_thread()
{
	int ret = 0;
	uint32_t flag = MBEDTLS_NET_POLL_READ;
	bool write_again = false, read_again = false;
	while (true)
	{
		{
			std::unique_lock<std::mutex> lock(write_mutex_);
			if (!lst_buffer_.empty()) 
				flag = MBEDTLS_NET_POLL_WRITE;
			else
				flag = MBEDTLS_NET_POLL_READ;
		}
		ret = mbedtls_net_poll(&net_ctx_, flag, 300);
		if (0 == ret)
		{
			if(will_disconnect_)
				break;

			event_.OnDisConnect(false);
			continue;
		}
		if (0 > ret)
		{
			debug_log("mbedtls poll error:%#X\n", -ret);
			break;
		}
		if (ret != flag)
		{
			debug_log("mbedtls poll error:%#X\n", -ret);
			break;
		}

		if(write_again)
		{
			std::unique_lock<std::mutex> lock(write_mutex_);
			AutoBuffer& buf = *lst_buffer_.front();
			size_t len = buf.Length();

			if (buf.Pos() < (off_t)len)
			{
				int send_len = mbedtls_ssl_write(&ssl_ctx_, (const unsigned char*)buf.PosPtr(),
					(size_t)(len - buf.Pos()));
				if (0 == send_len)
				{
					return;
				}
				if (0 > send_len)
				{
					if (ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
						ret != MBEDTLS_ERR_SSL_WANT_READ &&
						ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS &&
						ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
					{
						return;
					}
					else if (MBEDTLS_ERR_SSL_WANT_WRITE == send_len)
					{
						flag = MBEDTLS_NET_POLL_WRITE;
						write_again = true;
						continue;
					}
					else if (MBEDTLS_ERR_SSL_WANT_READ == send_len)
					{
						flag = MBEDTLS_NET_POLL_READ;
						write_again = true;
						continue;
					}
					else
					{
						flag = MBEDTLS_NET_POLL_WRITE;
						write_again = true;
						continue;
					}
				}
				if (0 < send_len)
				{
					buf.Seek(send_len, AutoBuffer::ESeekCur);
					write_again = false;
				}
			}
			else
			{
				delete lst_buffer_.front();
				lst_buffer_.pop_front();
			}
			write_again = false;
			continue;
		}

		if(read_again)
		{
			AutoBuffer* tmp = new AutoBuffer();
			tmp->AllocWrite(4096);
			ret = mbedtls_ssl_read(&ssl_ctx_, (unsigned char*)tmp->Ptr(), tmp->Length());
			if (0 == ret)
			{
				delete tmp;
				return;
			}
			if (0 > ret)
			{
				if (MBEDTLS_ERR_SSL_WANT_READ == ret)
				{
					flag = MBEDTLS_NET_POLL_READ;
					read_again = true;
					continue;
				}
				if (MBEDTLS_ERR_SSL_WANT_WRITE == ret)
				{
					flag = MBEDTLS_NET_POLL_WRITE;
					read_again = true;
				}
				return;
			}
			if (0 < ret)
			{
				std::unique_lock<std::mutex> lock(read_disconnect_mutex_);
				lst_rv_buffer_.push_back(tmp);
			}
			read_again = false;
			continue;
		}

		switch (flag)
		{
		case MBEDTLS_NET_POLL_READ:
			{
				AutoBuffer* tmp = new AutoBuffer();
				tmp->AllocWrite(4096);
				ret = mbedtls_ssl_read(&ssl_ctx_, (unsigned char*)tmp->Ptr(), tmp->Length());
				if(0 == ret)
				{
					delete tmp;
					event_.OnDisConnect(true);
					return;
				}
				if(0 > ret)
				{
					if(MBEDTLS_ERR_SSL_WANT_READ == ret)
					{
						flag = MBEDTLS_NET_POLL_READ;
						read_again = true;
						continue;
					}
					if(MBEDTLS_ERR_SSL_WANT_WRITE == ret)
					{
						flag = MBEDTLS_NET_POLL_WRITE;
						read_again = true;
					}
					return;
				}
				if(0 < ret)
				{
					std::unique_lock<std::mutex> lock(read_disconnect_mutex_);
					lst_rv_buffer_.push_back(tmp);
				}
			}
			break;
		case MBEDTLS_NET_POLL_WRITE:
			{
				std::unique_lock<std::mutex> lock(write_mutex_);
				AutoBuffer& buf = *lst_buffer_.front();
				size_t len = buf.Length();

				if (buf.Pos() < (off_t)len)
				{
					int send_len = mbedtls_ssl_write(&ssl_ctx_, (const unsigned char*)buf.PosPtr(),
					                                 (size_t)(len - buf.Pos()));
					if (0 == send_len)
					{
						event_.OnDisConnect(true);
						return;
					}
					if (0 > send_len)
					{
						if (ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
							ret != MBEDTLS_ERR_SSL_WANT_READ &&
							ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS &&
							ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
						{
							return;
						}
						else if (MBEDTLS_ERR_SSL_WANT_WRITE == send_len)
						{
							flag = MBEDTLS_NET_POLL_WRITE;
							write_again = true;
							continue;
						}
						else if (MBEDTLS_ERR_SSL_WANT_READ == send_len)
						{
							flag = MBEDTLS_NET_POLL_READ;
							write_again = true;
							continue;
						}
						else
						{
							flag = MBEDTLS_NET_POLL_WRITE;
							write_again = true;
							continue;
						}
					}
					if( 0 < send_len)
					{
						buf.Seek(send_len, AutoBuffer::ESeekCur);
						write_again = false;
					}
				}
				else
				{
					delete lst_buffer_.front();
					lst_buffer_.pop_front();
				}
			}
			break;
		}
	}
}

