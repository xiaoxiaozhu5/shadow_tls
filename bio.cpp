#include "bio.h"

#include <assert.h>

#include "shadow_client.h"
#include "shadow_tls_server.h"

enum RECORD_TYPE : unsigned char
{
    recordTypeChangeCipherSpec = 20,
    recordTypeAlert            = 21,
    recordTypeHandshake        = 22,
    recordTypeApplicationData  = 23,
};

enum RECORD_VERSION : unsigned short
{
    VersionTLS10 = 0x0301,
    VersionTLS11 = 0x0302,
    VersionTLS12 = 0x0303,
    VersionTLS13 = 0x0304,
 
    VersionSSL30 = 0x0300
};

#pragma pack(push, 1)
struct record_layer
{
	RECORD_TYPE content_type;
	RECORD_VERSION version;
	unsigned short len;
};
#pragma pack(pop)


int send_routine(void* ctx, const unsigned char* buf, size_t len)
{
	assert(len >= 5);
	int send_len = 0;
	auto context = static_cast<routine_context*>(ctx);
	auto record = reinterpret_cast<record_layer*>(const_cast<unsigned char*>(buf));
	switch (context->type)
	{
	case kContextServer: 
		send_len = ::send(context->dst_sock, (const char*)buf, len, 0);
		break;
	case KContextClient: 
		send_len = ::send(context->dst_sock, (const char*)buf, len, 0);
		break;
	default: break;
	}
	return send_len;
}

int recv_routine(void* ctx, unsigned char* buf, size_t len)
{
	assert(len >= 5);
	int recv_len = 0;
	auto context = static_cast<routine_context*>(ctx);
	auto record = reinterpret_cast<record_layer*>(buf);
	switch (context->type)
	{
	case kContextServer: 
		recv_len = ::recv(context->dst_sock, (char*)buf, len, 0);
		break;
	case KContextClient: 
		recv_len = ::recv(context->dst_sock, (char*)buf, len, 0);
		break;
	default: break;
	}
	return recv_len;
}
