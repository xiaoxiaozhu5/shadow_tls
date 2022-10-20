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
	auto context = static_cast<routine_context*>(ctx);
	auto record = reinterpret_cast<record_layer*>(const_cast<unsigned char*>(buf));
	switch (context->type)
	{
	case kContextServer: break;
	case KContextClient: break;
	default: break;
	}
}

int recv_routine(void* ctx, unsigned char* buf, size_t len)
{
	assert(len >= 5);
	auto context = static_cast<routine_context*>(ctx);
	auto record = reinterpret_cast<record_layer*>(buf);
	switch (context->type)
	{
	case kContextServer: break;
	case KContextClient: break;
	default: break;
	}
}
