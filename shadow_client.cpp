#include "shadow_client.h"

#include <ws2ipdef.h>
#include <WS2tcpip.h>

#include "bio.h"

#include "debug_helper.h"

#pragma warning(disable: 4996)

typedef SSIZE_T ssize_t;


#define socket_close closesocket
#define socket_errno WSAGetLastError()

#define SOCKET_ERRNO(error) WSA##error
#define IS_NOBLOCK_WRITE_ERRNO(err) ((err) == SOCKET_ERRNO(EWOULDBLOCK))
#define IS_NOBLOCK_READ_ERRNO(err)  ((err) == SOCKET_ERRNO(EWOULDBLOCK))
#define IS_NOBLOCK_CONNECT_ERRNO(err) ((err) == SOCKET_ERRNO(EWOULDBLOCK))
#define IS_NOBLOCK_SEND_ERRNO(err) IS_NOBLOCK_WRITE_ERRNO(err)


int socket_ipv6only(SOCKET _sock, int _only)
{
	return setsockopt(_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&_only, sizeof(_only));
}

int socket_set_nobio(SOCKET fd)
{
	static const int noblock = 1;
	return ioctlsocket(fd, FIONBIO, (u_long*)&noblock);
}

int socket_error(SOCKET sock)
{
	int error = 0;
	socklen_t len = sizeof(error);
	if (0 != getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len))
	{
		error = socket_errno;
	}
	return error;
}

shadow_client::shadow_client()
	: socket_(INVALID_SOCKET)
	, remote_socket_(INVALID_SOCKET)
{
	init();
}

shadow_client::shadow_client(SOCKET remote_sock)
	: socket_(INVALID_SOCKET)
	, remote_socket_(remote_sock)
{
	init();
}

shadow_client::~shadow_client()
{
}

SOCKET shadow_client::connect(const socket_address& _address, int& _errcode,
                              int32_t _timeout/*ms*/)
{
	SOCKET sock = connect_impl(_address, _errcode, _timeout);
	socket_ = sock;
	return sock;
}

int shadow_client::handshake()
{
	int res = 0;
	stream_data(remote_socket_, socket_);
	stream_data(socket_, remote_socket_);
	return 0;
}

int shadow_client::send(const void* _buffer, size_t _len, int& _errcode,
                        int _timeout)
{
	uint64_t start = GetTickCount64();
	int32_t cost_time = 0;
	size_t sent_len = 0;

	SocketSelect sel(breaker_);

	while (true)
	{
		ssize_t nwrite = ::send(socket_, (const char*)_buffer + sent_len, _len - sent_len, 0);
		if (nwrite == 0 || (0 > nwrite && !IS_NOBLOCK_SEND_ERRNO(socket_errno)))
		{
			_errcode = socket_errno;
			return -1;
		}

		if (0 < nwrite) sent_len += nwrite;

		if (sent_len >= _len)
		{
			_errcode = 0;
			return (int)sent_len;
		}

		sel.PreSelect();
		sel.Write_FD_SET(socket_);
		sel.Exception_FD_SET(socket_);
		int ret = (0 <= _timeout)
			          ? (sel.Select((_timeout > cost_time) ? (_timeout - cost_time) : 0))
			          : (sel.Select());
		cost_time = (int32_t)(GetTickCount64() - start);

		if (ret < 0)
		{
			_errcode = sel.Errno();
			return -1;
		}

		if (ret == 0)
		{
			_errcode = SOCKET_ERRNO(ETIMEDOUT);
			return (int)sent_len;
		}

		if (sel.IsException() || sel.IsBreak())
		{
			_errcode = 0;
			return (int)sent_len;
		}

		if (sel.Exception_FD_ISSET(socket_))
		{
			_errcode = socket_error(socket_);
			return -1;
		}

		if (!sel.Write_FD_ISSET(socket_))
		{
			_errcode = socket_error(socket_);
			return -1;
		}
	}
}

int shadow_client::recv(std::string& _buffer, size_t _max_size, int& _errcode,
                        int _timeout, bool _wait_full_size)
{
	uint64_t start = GetTickCount64();
	int32_t cost_time = 0;
	size_t recv_len = 0;

	if (_buffer.capacity() - _buffer.size() < _max_size)
	{
		_buffer.reserve(_buffer.capacity() + _max_size - (_buffer.capacity() - _buffer.size()));
	}

	char* pos = (char*)_buffer.data();

	SocketSelect sel(breaker_);
	while (true)
	{
		ssize_t nrecv = ::recv(socket_, pos, _max_size - recv_len, 0);

		if (0 == nrecv)
		{
			_errcode = 0;
			_buffer.resize(_buffer.size() + recv_len);
			pos += recv_len;

			return (int)recv_len;
		}

		if (0 > nrecv && !IS_NOBLOCK_READ_ERRNO(socket_errno))
		{
			_errcode = socket_errno;
			return -1;
		}

		if (0 < nrecv) recv_len += nrecv;

		if (recv_len >= _max_size)
		{
			_errcode = 0;
			_buffer.resize(_buffer.size() + recv_len);
			pos += recv_len;
			return (int)recv_len;
		}

		if (recv_len > 0 && !_wait_full_size)
		{
			_errcode = 0;
			_buffer.resize(_buffer.size() + recv_len);
			pos += recv_len;
			return (int)recv_len;
		}

		sel.PreSelect();
		sel.Read_FD_SET(socket_);
		sel.Exception_FD_SET(socket_);
		int ret = (0 <= _timeout)
			          ? (sel.Select((_timeout > cost_time) ? (_timeout - cost_time) : 0))
			          : (sel.Select());
		cost_time = (int32_t)(GetTickCount64() - start);

		if (ret < 0)
		{
			_errcode = sel.Errno();
			return -1;
		}

		if (ret == 0)
		{
			_errcode = SOCKET_ERRNO(ETIMEDOUT);
			_buffer.resize(_buffer.size() + recv_len);
			pos += recv_len;
			return (int)recv_len;
		}

		if (sel.IsException() || sel.IsBreak())
		{
			_errcode = sel.Errno();
			_buffer.resize(_buffer.size() + recv_len);
			pos += recv_len;
			return (int)recv_len;
		}

		if (sel.Exception_FD_ISSET(socket_))
		{
			_errcode = socket_error(socket_);
			return -1;
		}

		if (!sel.Read_FD_ISSET(socket_))
		{
			_errcode = socket_error(socket_);
			return -1;
		}
	}
}

void shadow_client::cancel()
{
	breaker_.Break();
}

void shadow_client::init()
{
}

SOCKET shadow_client::connect_impl(const socket_address& _address, int& _errcode, int32_t _timeout)
{
	//socket
	SOCKET sock = socket(_address.address().sa_family, SOCK_STREAM, IPPROTO_TCP);

	if (sock == INVALID_SOCKET)
	{
		_errcode = socket_errno;
		return INVALID_SOCKET;
	}

#ifdef _WIN32
	if (0 != socket_ipv6only(sock, 0)) { debug_log("set ipv6only failed. error %s\n", strerror(socket_errno)); }
#endif

	/*
	int ret = socket_set_nobio(sock);
	if (ret != 0)
	{
		_errcode = socket_errno;
		::socket_close(sock);
		return INVALID_SOCKET;
	}
	*/

	//connect
	int ret = ::connect(sock, &_address.address(), _address.address_length());
	if (ret != 0 && !IS_NOBLOCK_CONNECT_ERRNO(socket_errno))
	{
		_errcode = socket_errno;
		::socket_close(sock);
		return INVALID_SOCKET;
	}

	SocketSelect sel(breaker_);
	sel.PreSelect();
	sel.Write_FD_SET(sock);
	sel.Exception_FD_SET(sock);

	ret = (_timeout >= 0) ? (sel.Select(_timeout)) : (sel.Select());
	if (ret == 0)
	{
		_errcode = SOCKET_ERRNO(ETIMEDOUT);
		::socket_close(sock);
		return INVALID_SOCKET;
	}
	else if (ret < 0)
	{
		_errcode = sel.Errno();
		::socket_close(sock);
		return INVALID_SOCKET;
	}

	if (sel.IsException())
	{
		_errcode = 0;
		::socket_close(sock);
		return INVALID_SOCKET;
	}
	if (sel.IsBreak())
	{
		_errcode = 0;
		::socket_close(sock);
		return INVALID_SOCKET;
	}

	if (sel.Exception_FD_ISSET(sock))
	{
		_errcode = socket_error(sock);
		::socket_close(sock);
		return INVALID_SOCKET;
	}

	if (!sel.Write_FD_ISSET(sock))
	{
		_errcode = socket_error(sock);
		::socket_close(sock);
		return INVALID_SOCKET;
	}
	_errcode = socket_error(sock);
	if (0 != _errcode)
	{
		::socket_close(sock);
		return INVALID_SOCKET;
	}

	return sock;
}

int shadow_client::stream_data(SOCKET Source, SOCKET Dest)
{
	int ret = 0;
	ssize_t len = 0;
	char dataBuffer[4096] = {0};

	do {
		len = ::recv(Source, dataBuffer, sizeof(dataBuffer), 0);
		if (len > 0) {
			debug_log("<<< %zu bytes received\n", len);
			len = ::send(Dest, dataBuffer, len, 0);
			if (len >= 0)
				debug_log(">>> %zu bytes sent\n", len);
		}

		if (len == -1)
			ret = -1;
	} while (len > 0);

	return ret;
}
