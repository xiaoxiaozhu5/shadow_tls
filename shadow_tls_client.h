#pragma once

#include <string>

#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>

class shadow_tls_client
{
public:
	shadow_tls_client();
	~shadow_tls_client();

public:
	int connect(const std::string& server, const std::string& shadow_domain);

private:
	bool validate_address(const std::string& server);
	bool split_address_to_ip_and_port(const std::string& server, std::string& address, std::string& port);

private:
	mbedtls_ctr_drbg_context ctr_drbg_;
	mbedtls_entropy_context entropy_;

	mbedtls_net_context net_ctx_;
	mbedtls_ssl_context ssl_ctx_;
	mbedtls_x509_crt ca_crt_;
	mbedtls_ssl_config ssl_conf_;
};

