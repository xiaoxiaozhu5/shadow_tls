#include "shadow_tls_client.h"

#include "debug_helper.h"


shadow_tls_client::shadow_tls_client()
{
	mbedtls_ctr_drbg_init(&ctr_drbg_);
	mbedtls_entropy_init(&entropy_);

	int res = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, NULL, 0);
	if (0 != res)
	{
		debug_log("drbg init error = %d.\n", res);
		exit(1);
	}

	mbedtls_net_context net_ctx_;
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
		if(0 != res)
		{
			break;
		}
		bool hs_failed = false;
		mbedtls_ssl_set_bio(&ssl_ctx_, &net_ctx_, mbedtls_net_send, mbedtls_net_recv, NULL);
		while ((res = mbedtls_ssl_handshake(&ssl_ctx_)) != 0)
		{
			if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				hs_failed = true;
				debug_log("mbedtls_ssl_handshake returned -0x%x\n", -res);
				break;
			}
		}
		if(hs_failed)
		{
			break;
		}

		//TODO: start io thread
	}
	while (false);
	return res;
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
	address = server.substr(0, pos - 1);
	port = server.substr(pos + 1);
	return true;
}
