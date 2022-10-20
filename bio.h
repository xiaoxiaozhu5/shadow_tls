#pragma once


enum ContextType
{
	kContextServer,
	KContextClient
};

struct routine_context
{
	ContextType type;

};

int send_routine(void* ctx, const unsigned char* buf, size_t len);
int recv_routine(void* ctx, unsigned char* buf, size_t len);
