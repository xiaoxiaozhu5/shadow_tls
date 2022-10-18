#include "debug_helper.h"

#include <windows.h>

#include <cstring>
#include <stdio.h>
#include <stdarg.h>

#define LOG_MAXBUF_SIZE 2048

void debug_helper::debug(const char* file, int line, const char* format, ...)
{
	va_list va;
	va_start(va, format);
	const CHAR* pFileStr = nullptr;
	char szLogBuff[LOG_MAXBUF_SIZE] = { 0 };
	pFileStr = strrchr(file, '\\');
	pFileStr = (pFileStr == NULL) ? file : pFileStr + 1;
	int num_write = snprintf(szLogBuff, LOG_MAXBUF_SIZE - 1, "[%s:%d] ", pFileStr, line);
	vsnprintf(szLogBuff + num_write, LOG_MAXBUF_SIZE - num_write, format, va);
	OutputDebugStringA(szLogBuff);
	va_end(va);
}

void debug_helper::debug_w(const wchar_t* file, int line, const wchar_t* format, ...)
{
	va_list va;
	va_start(va, format);
	const WCHAR* pFileStr = nullptr;
	WCHAR szLogBuff[LOG_MAXBUF_SIZE] = { 0 };
	pFileStr = wcsrchr(file, '\\');
	pFileStr = (pFileStr == NULL) ? file : pFileStr + 1;
	int num_write = swprintf_s(szLogBuff, LOG_MAXBUF_SIZE - 1, L"[%s:%d] ", pFileStr, line);
	vswprintf(szLogBuff + num_write, LOG_MAXBUF_SIZE - num_write, format, va);
	OutputDebugStringW(szLogBuff);
	va_end(va);
}
