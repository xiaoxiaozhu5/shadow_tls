#pragma once
#include <basetsd.h>

#include <list>
#include <mutex>
#include <string>
#include <thread>

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>

class AutoBuffer;

class MShadowEvent {
  public:
    virtual ~MShadowEvent() {}

    virtual void OnConnect() = 0;
    virtual void OnDisConnect(bool isremote) = 0;
    virtual void OnError(int errcode) = 0;
};

class shadow_tls_client
{
public:
	shadow_tls_client(MShadowEvent& event);
	~shadow_tls_client();

public:
	int connect(const std::string& server, const std::string& shadow_domain);
	void disconenct();
	void write(const void* buf, unsigned int len);
	SSIZE_T read(void* buf, unsigned int len);

private:
	bool validate_address(const std::string& server);
	bool split_address_to_ip_and_port(const std::string& server, std::string& address, std::string& port);
	void io_thread();

private:
	mbedtls_ctr_drbg_context ctr_drbg_;
	mbedtls_entropy_context entropy_;

	mbedtls_net_context net_ctx_;
	mbedtls_ssl_context ssl_ctx_;
	mbedtls_x509_crt ca_crt_;
	mbedtls_ssl_config ssl_conf_;

	std::mutex write_mutex_;
	std::mutex read_disconnect_mutex_;
	std::list<AutoBuffer*> lst_buffer_;
	std::list<AutoBuffer*> lst_rv_buffer_;
	std::thread thread_;
	bool will_disconnect_;
	MShadowEvent& event_;
};

