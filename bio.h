#pragma once
#include <winsock2.h>


enum ContextType
{
	kContextServer,
	KContextClient
};

struct routine_context
{
	ContextType type;
	SOCKET src_sock;
	SOCKET dst_sock;
};

int send_routine(void* ctx, const unsigned char* buf, size_t len);
int recv_routine(void* ctx, unsigned char* buf, size_t len);
