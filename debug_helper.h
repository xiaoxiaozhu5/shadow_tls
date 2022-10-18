#pragma once

class debug_helper
{
public:
	static void debug(const char* file, int line, const char* format, ...);
	static void debug_w(const wchar_t* file, int line, const wchar_t* format, ...);
};

#define debug_log(x, ...) debug_helper::debug(__FILE__, __LINE__, x, ##__VA_ARGS__)
#define debug_log_w(x, ...) debug_helper::debug_w(__FILEW__, __LINE__, x, ##__VA_ARGS__)

