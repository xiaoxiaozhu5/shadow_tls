// Tencent is pleased to support the open source community by making Mars available.
// Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.

// Licensed under the MIT License (the "License"); you may not use this file except in 
// compliance with the License. You may obtain a copy of the License at
// http://opensource.org/licenses/MIT

// Unless required by applicable law or agreed to in writing, software distributed under the License is
// distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing permissions and
// limitations under the License.


/*
 * socket_address.cpp
 *
 *  Created on: 2014-12-1
 *      Author: yerungui
 */

#include "socket_address.h"

#include <cstdint>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "debug_helper.h"

#define NS_INADDRSZ 4
typedef unsigned int uint32;
typedef int int32;
typedef unsigned short uint16;  // NOLINT
typedef short int16;  // NOLINT

inline bool IN6_IS_ADDR_NAT64(in6_addr* a6) {
	return a6->s6_words[0] == htons(0x0064) && a6->s6_words[1] == htons(0x0064);
}


#if defined(__linux__) && !defined(AI_DEFAULT)
	#define  AI_DEFAULT (AI_V4MAPPED | AI_ADDRCONFIG)
#endif

static const char kWellKnownNat64Prefix[] = {'6', '4', ':', 'f', 'f', '9', 'b', ':', ':', '\0'};

static int socket_inet_pton4(const char* src, void* dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0')
	{
		const char* pch;

		if ((pch = strchr(digits, ch)) != NULL)
		{
			size_t newNum = *tp * 10 + (pch - digits);

			if (newNum > 255)
				return (0);
			*tp = (unsigned char)newNum;
			if (! saw_digit)
			{
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		}
		else if (ch == '.' && saw_digit)
		{
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		}
		else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

//https://chromium.googlesource.com/external/webrtc/+/edc6e57a92d2b366871f4c2d2e926748326017b9/webrtc/base/win32.cc
// Helper function for inet_pton for IPv6 addresses.
static int socket_inet_pton6(const char* src, void* dst)
{
	// sscanf will pick any other invalid chars up, but it parses 0xnnnn as hex.
	// Check for literal x in the input string.
	const char* readcursor = src;
	char c = *readcursor++;
	while (c)
	{
		if (c == 'x')
		{
			return 0;
		}
		c = *readcursor++;
	}
	readcursor = src;
	struct in6_addr an_addr;
	memset(&an_addr, 0, sizeof(an_addr));
	uint16* addr_cursor = (uint16*)(&an_addr.s6_addr[0]);
	uint16* addr_end = (uint16*)(&an_addr.s6_addr[16]);
	int seencompressed = 0; //false c89 not define bool type
	// Addresses that start with "::" (i.e., a run of initial zeros) or
	// "::ffff:" can potentially be IPv4 mapped or compatibility addresses.
	// These have dotted-style IPv4 addresses on the end (e.g. "::192.168.7.1").
	if (*readcursor == ':' && *(readcursor + 1) == ':' &&
		*(readcursor + 2) != 0)
	{
		// Check for periods, which we'll take as a sign of v4 addresses.
		const char* addrstart = readcursor + 2;
		if (strchr(addrstart, '.'))
		{
			const char* colon = strchr(addrstart, ':');
			if (colon)
			{
				uint16 a_short;
				int bytesread = 0;
				if (sscanf(addrstart, "%hx%n", &a_short, &bytesread) != 1 ||
					a_short != 0xFFFF || bytesread != 4)
				{
					// Colons + periods means has to be ::ffff:a.b.c.d. But it wasn't.
					return 0;
				}
				else
				{
					an_addr.s6_addr[10] = 0xFF;
					an_addr.s6_addr[11] = 0xFF;
					addrstart = colon + 1;
				}
			}
			struct in_addr v4;
			if (socket_inet_pton4(addrstart, &v4.s_addr))
			{
				memcpy(&an_addr.s6_addr[12], &v4, sizeof(v4));
				memcpy(dst, &an_addr, sizeof(an_addr));
				return 1;
			}
			else
			{
				// Invalid v4 address.
				return 0;
			}
		}
	}
	// For addresses without a trailing IPv4 component ('normal' IPv6 addresses).
	while (*readcursor != 0 && addr_cursor < addr_end)
	{
		if (*readcursor == ':')
		{
			if (*(readcursor + 1) == ':')
			{
				if (seencompressed)
				{
					// Can only have one compressed run of zeroes ("::") per address.
					return 0;
				}
				// Hit a compressed run. Count colons to figure out how much of the
				// address is skipped.
				readcursor += 2;
				const char* coloncounter = readcursor;
				int coloncount = 0;
				if (*coloncounter == 0)
				{
					// Special case - trailing ::.
					addr_cursor = addr_end;
				}
				else
				{
					while (*coloncounter)
					{
						if (*coloncounter == ':')
						{
							++coloncount;
						}
						++coloncounter;
					}
					// (coloncount + 1) is the number of shorts left in the address.
					addr_cursor = addr_end - (coloncount + 1);
					seencompressed = 1;
				}
			}
			else
			{
				++readcursor;
			}
		}
		else
		{
			uint16 word;
			int bytesread = 0;
			if (sscanf(readcursor, "%hx%n", &word, &bytesread) != 1)
			{
				return 0;
			}
			else
			{
				*addr_cursor = htons(word);
				++addr_cursor;
				readcursor += bytesread;
				if (*readcursor != ':' && *readcursor != '\0')
				{
					return 0;
				}
			}
		}
	}
	if (*readcursor != '\0' || addr_cursor < addr_end)
	{
		// Catches addresses too short or too long.
		return 0;
	}
	memcpy(dst, &an_addr, sizeof(an_addr));
	return 1;
}

int socket_inet_pton(int af, const char* src, void* dst)
{
	// if (IsWindows7OrGreater()){
	//   return inet_pton(af, src, dst);
	// }

	// for OS below WINDOWS 7
	switch (af)
	{
	case AF_INET:
		return socket_inet_pton4(src, dst);
	case AF_INET6:
		return socket_inet_pton6(src, dst);
	default:
		//xerror("EAFNOSUPPORT");
		return 0;
	}
}

static const char* inet_ntop_v4(const void* src, char* dst, socklen_t size)
{
	const char digits[] = "0123456789";
	int i;
	struct in_addr* addr = (struct in_addr*)src;
	u_long a = ntohl(addr->s_addr);
	const char* orig_dst = dst;

	if (size < 16)
	{
		//xerror("ENOSPC: size = %0", size);
		return NULL;
	}
	for (i = 0; i < 4; ++i)
	{
		int n = (a >> (24 - i * 8)) & 0xFF;
		int non_zerop = 0;

		if (non_zerop || n / 100 > 0)
		{
			*dst++ = digits[n / 100];
			n %= 100;
			non_zerop = 1;
		}
		if (non_zerop || n / 10 > 0)
		{
			*dst++ = digits[n / 10];
			n %= 10;
			non_zerop = 1;
		}
		*dst++ = digits[n];
		if (i != 3)
			*dst++ = '.';
	}
	*dst++ = '\0';
	return orig_dst;
}

// Helper function for inet_ntop for IPv6 addresses.
static const char* inet_ntop_v6(const void* src, char* dst, socklen_t size)
{
	if (size < INET6_ADDRSTRLEN)
	{
		return NULL;
	}
	const uint16* as_shorts =
		reinterpret_cast<const uint16*>(src);
	int runpos[8];
	int current = 1;
	int max = 1;
	int maxpos = -1;
	int run_array_size = sizeof(runpos) / sizeof(runpos[0]);
	// Run over the address marking runs of 0s.
	for (int i = 0; i < run_array_size; ++i)
	{
		if (as_shorts[i] == 0)
		{
			runpos[i] = current;
			if (current > max)
			{
				maxpos = i;
				max = current;
			}
			++current;
		}
		else
		{
			runpos[i] = -1;
			current = 1;
		}
	}
	if (max > 1)
	{
		int tmpmax = maxpos;
		// Run back through, setting -1 for all but the longest run.
		for (int i = run_array_size - 1; i >= 0; i--)
		{
			if (i > tmpmax)
			{
				runpos[i] = -1;
			}
			else if (runpos[i] == -1)
			{
				// We're less than maxpos, we hit a -1, so the 'good' run is done.
				// Setting tmpmax -1 means all remaining positions get set to -1.
				tmpmax = -1;
			}
		}
	}
	char* cursor = dst;
	// Print IPv4 compatible and IPv4 mapped addresses using the IPv4 helper.
	// These addresses have an initial run of either eight zero-bytes followed
	// by 0xFFFF, or an initial run of ten zero-bytes.
	if (runpos[0] == 1 && (maxpos == 5 ||
		(maxpos == 4 && as_shorts[5] == 0xFFFF)))
	{
		*cursor++ = ':';
		*cursor++ = ':';
		if (maxpos == 4)
		{
			cursor += snprintf(cursor, INET6_ADDRSTRLEN - 2, "ffff:");
		}
		const struct in_addr* as_v4 =
			reinterpret_cast<const struct in_addr*>(&(as_shorts[6]));
		inet_ntop_v4(as_v4, cursor,
		             static_cast<socklen_t>(INET6_ADDRSTRLEN - (cursor - dst)));
	}
	else
	{
		for (int i = 0; i < run_array_size; ++i)
		{
			if (runpos[i] == -1)
			{
				cursor += snprintf(cursor,
				                   INET6_ADDRSTRLEN - (cursor - dst),
				                   "%x", ntohs(as_shorts[i]));
				if (i != 7 && runpos[i + 1] != 1)
				{
					*cursor++ = ':';
				}
			}
			else if (runpos[i] == 1)
			{
				// Entered the run; print the colons and skip the run.
				*cursor++ = ':';
				*cursor++ = ':';
				i += (max - 1);
			}
		}
	}
	return dst;
}

const char* socket_inet_ntop(int af, const void* src, char* dst, unsigned int size)
{
	// if (IsWindows7OrGreater()){
	//   return inet_ntop(af, (PVOID)src, dst, size);
	// }

	// for OS below WINDOWS 7
	switch (af)
	{
	case AF_INET:
		return inet_ntop_v4(src, dst, size);
	case AF_INET6:
		return inet_ntop_v6(src, dst, size);
	default:
		//xerror("EAFNOSUPPORT");
		return NULL;
	}
}

socket_address::socket_address(const char* _ip, uint16_t _port)
{
	in6_addr addr6 = IN6ADDR_ANY_INIT;
	in_addr addr4 = {0};

	if (socket_inet_pton(AF_INET, _ip, &addr4))
	{
		sockaddr_in sock_addr = {0};
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_addr = addr4;
		sock_addr.sin_port = htons(_port);

		__init((sockaddr*)&sock_addr);
	}
	else if (socket_inet_pton(AF_INET6, _ip, &addr6))
	{
		sockaddr_in6 sock_addr = {0};
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = addr6;
		sock_addr.sin6_port = htons(_port);

		__init((sockaddr*)&sock_addr);
	}
	else
	{
		sockaddr sock_addr = {0};
		sock_addr.sa_family = AF_UNSPEC;
		__init((sockaddr*)&sock_addr);
	}
}

socket_address::socket_address(const sockaddr_in& _addr)
{
	__init((sockaddr*)&_addr);
}

socket_address::socket_address(const sockaddr_in6& _addr)
{
	__init((sockaddr*)&_addr);
}

socket_address::socket_address(const sockaddr* _addr)
{
	__init(_addr);
}

socket_address::socket_address(const struct in_addr& _in_addr)
{
	sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr = _in_addr;
	__init((sockaddr*)&addr);
}

socket_address::socket_address(const struct in6_addr& _in6_addr)
{
	sockaddr_in6 addr6 = {0};
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = _in6_addr;
	__init((sockaddr*)&addr6);
}

socket_address::socket_address(const char* ipport)
{
	std::vector<std::string> splitted;
	char* pos = strtok((char*)ipport, ":");
	while(pos != nullptr)
	{
		splitted.push_back(pos);
		pos = strtok(nullptr, ":");
	}
	socket_address(splitted[0].c_str(), atoi(splitted[1].c_str()));
}

void socket_address::__init(const sockaddr* _addr)
{
	memset(&addr_, 0, sizeof(addr_));
	memset(ip_, 0, sizeof(ip_));
	memset(url_, 0, sizeof(url_));

	if (AF_INET == _addr->sa_family)
	{
		memcpy(&addr_, _addr, sizeof(sockaddr_in));
		socket_inet_ntop(_asv4()->sin_family, &_asv4()->sin_addr, ip_, sizeof(ip_));
		snprintf(url_, sizeof(url_), "%s:%u", ip_, port());
	}
	else if (AF_INET6 == _addr->sa_family)
	{
		memcpy(&addr_, _addr, sizeof(sockaddr_in6));
		if (IN6_IS_ADDR_NAT64(const_cast<in6_addr*>(&_asv6()->sin6_addr)))
		{
			strncpy(ip_, kWellKnownNat64Prefix, 9);
			sockaddr_in addr = {0};
			addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = _asv6()->sin6_addr.u.Byte[12];
			socket_inet_ntop(_asv6()->sin6_family, &(_asv6()->sin6_addr), ip_ + 9, sizeof(ip_) - 9);
		}
		else
		{
			socket_inet_ntop(_asv6()->sin6_family, &(_asv6()->sin6_addr), ip_, sizeof(ip_));
		}

		snprintf(url_, sizeof(url_), "[%s]:%u", ip_, port());
	}
	else
	{
		addr_.ss_family = AF_UNSPEC;
	}
}

const sockaddr& socket_address::address() const
{
	//if (ELocalIPStack_IPv6==local_ipstack_detect())
	//	return address_fix();
	return (sockaddr&)addr_;
}

socklen_t socket_address::address_length() const
{
	if (AF_INET == addr_.ss_family)
	{
		return sizeof(sockaddr_in);
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		return sizeof(sockaddr_in6);
	}

	return 0;
}

const char* socket_address::url() const
{
	return url_;
}

const char* socket_address::ip() const
{
	if (AF_INET == addr_.ss_family)
	{
		return ip_;
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		if (0 == strncmp("::FFFF:", ip_, 7))
			return ip_ + 7;
		else if (0 == strncmp(kWellKnownNat64Prefix, ip_, 9))
			return ip_ + 9;
		else
			return ip_;
	}

	debug_log("invalid ip family:%d, ip:%s", addr_.ss_family, ip_);
	return "";
}

const char* socket_address::ipv6() const
{
	return ip_;
}

uint16_t socket_address::port() const
{
	if (AF_INET == addr_.ss_family)
	{
		return ntohs(_asv4()->sin_port);
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		return ntohs(_asv6()->sin6_port);
	}

	return 0;
}

bool socket_address::valid() const
{
	return (AF_INET == addr_.ss_family || AF_INET6 == addr_.ss_family);
}

bool socket_address::valid_server_address(bool _allowloopback, bool _ignore_port) const
{
	if (AF_INET == addr_.ss_family)
	{
		uint32_t hostip = ntohl(_asv4()->sin_addr.s_addr);
		return (_ignore_port ? true : 0 != _asv4()->sin_port)
			&& hostip != INADDR_ANY
			&& hostip != INADDR_BROADCAST
			&& hostip != INADDR_NONE
			&& (_allowloopback ? true : hostip != INADDR_LOOPBACK);
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		if (IN6_IS_ADDR_V4MAPPED(&_asv6()->sin6_addr))
		{
			uint32_t hostip = ntohl((*(const uint32_t*)(const void*)(&_asv6()->sin6_addr.s6_addr[12])));
			return (_ignore_port ? true : 0 != _asv6()->sin6_port)
				&& hostip != INADDR_ANY
				&& hostip != INADDR_BROADCAST
				&& hostip != INADDR_NONE
				&& (_allowloopback ? true : hostip != INADDR_LOOPBACK);
		}
		else
		{
			//TODO
			return true;
		}
	}

	return false;
}

bool socket_address::valid_broadcast_address() const
{
	if (AF_INET == addr_.ss_family)
	{
		return 0 != _asv4()->sin_port && INADDR_BROADCAST == ntohl(_asv4()->sin_addr.s_addr);
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		return false;
	}
	return false;
}

bool socket_address::valid_loopback_ip() const
{
	if (AF_INET == addr_.ss_family)
	{
		return INADDR_LOOPBACK == ntohl(_asv4()->sin_addr.s_addr);
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		return false;
	}
	return false;
}

bool socket_address::valid_broadcast_ip() const
{
	if (AF_INET == addr_.ss_family)
	{
		return INADDR_BROADCAST == ntohl(_asv4()->sin_addr.s_addr);
	}
	else if (AF_INET6 == addr_.ss_family)
	{
		return false;
	}
	return false;
}

bool socket_address::isv4mapped_address() const
{
	if (AF_INET6 == addr_.ss_family)
	{
		return IN6_IS_ADDR_V4MAPPED(&(_asv6()->sin6_addr));
	}
	return false;
}

bool socket_address::isv6() const
{
	return AF_INET6 == addr_.ss_family && !isv4mapped_address();
}

bool socket_address::isv4() const
{
	return AF_INET == addr_.ss_family;
}

socket_address socket_address::getsockname(SOCKET _sock)
{
	struct sockaddr_storage addr = {0};
	socklen_t addr_len = sizeof(addr);

	if (0 == ::getsockname(_sock, (sockaddr*)&addr, &addr_len))
	{
		if (AF_INET == addr.ss_family)
		{
			return socket_address((const sockaddr_in&)addr);
		}
		else if (AF_INET6 == addr.ss_family)
		{
			return socket_address((const sockaddr_in6&)addr);
		}
	}

	return socket_address("0.0.0.0", 0);
}

socket_address socket_address::getpeername(SOCKET _sock)
{
	struct sockaddr_storage addr = {0};
	socklen_t addr_len = sizeof(addr);

	if (0 == ::getpeername(_sock, (sockaddr*)&addr, &addr_len))
	{
		if (AF_INET == addr.ss_family)
		{
			return socket_address((const sockaddr_in&)addr);
		}
		else if (AF_INET6 == addr.ss_family)
		{
			return socket_address((const sockaddr_in6&)addr);
		}
		else
		{
			debug_log("invalid famiray %d", addr.ss_family);
		}
	}

	return socket_address("0.0.0.0", 0);
}

const sockaddr_in* socket_address::_asv4() const
{
	return reinterpret_cast<const sockaddr_in*>(&addr_);
}

const sockaddr_in6* socket_address::_asv6() const
{
	return reinterpret_cast<const sockaddr_in6*>(&addr_);
}
