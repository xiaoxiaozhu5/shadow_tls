#include "socket_select.h"

#include <WS2tcpip.h>

#include <cassert>

#include "debug_helper.h"

#define socket_errno WSAGetLastError()


#define ASSERT2(exp, fmt, ...) \
    do { \
		if(!(exp)) {            \
			debug_log("%s " fmt, ##exp, __VA_ARGS__); }		\
    }while(false)

static DWORD __SO_RCVTIMEO(SOCKET _sock) {
    DWORD optval = 0;
    int optlen = sizeof(optval);
    ASSERT2(0 == getsockopt(_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&optval, &optlen), "%d, %s\n", WSAGetLastError(), gai_strerror(socket_errno));
    return optval;
}

static void __SO_RCVTIMEO(SOCKET _sock, DWORD _ms) {
    DWORD optval = _ms;
    int optlen = sizeof(optval);
    ASSERT2(0 == setsockopt(_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&optval, optlen), "%d, %s\n", socket_errno, gai_strerror(socket_errno));
}

static BOOL __WOULDBLOCK(SOCKET _sock) {
    DWORD ret = __SO_RCVTIMEO(_sock);

    if (0 == ret) {
        return true;
    }

    return ret & 0x1;
}

static void __WOULDBLOCK(SOCKET _sock, bool _block) {
    DWORD ret = __SO_RCVTIMEO(_sock);

    if (0 == ret) {
        ret =  60 * 1000;
    }

    __SO_RCVTIMEO(_sock, (ret & (~0x1)) + _block);
}

SocketBreaker::SocketBreaker()
    : m_broken(false)
    , m_create_success(true), m_exception(0) {
    ReCreate();
}

SocketBreaker::~SocketBreaker() {
    Close();
}

bool SocketBreaker::IsCreateSuc() const {
    return m_create_success;
}

bool SocketBreaker::ReCreate() {
    m_event = WSACreateEvent();
    m_create_success = WSA_INVALID_EVENT != m_event;
    ASSERT2(m_create_success, "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));
    m_exception = WSAGetLastError();
    m_broken = !m_create_success;
    return m_create_success;
}

bool SocketBreaker::IsBreak() const {
    return m_broken;
}

bool SocketBreaker::Break() {
    std::unique_lock<std::mutex> lock(m_mutex);
    bool ret = WSASetEvent(m_event);
    ASSERT2(ret, "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));
    m_broken = ret;

    if (!ret) m_exception = WSAGetLastError();

    return m_broken;
}

bool SocketBreaker::Clear() {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (!m_broken) return true;

    bool ret = WSAResetEvent(m_event);
    ASSERT2(ret, "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));

    m_broken = !ret;

    if (!ret) m_exception = WSAGetLastError();

    return ret;
}

void SocketBreaker::Close() {
    bool ret = WSACloseEvent(m_event);
    ASSERT2(ret, "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));
    m_exception = WSAGetLastError();
    m_event = WSA_INVALID_EVENT;
    m_broken = true;
}

WSAEVENT SocketBreaker::BreakerFD() const {
    return m_event;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
SocketSelect::SocketSelect(SocketBreaker& _breaker, bool _autoclear)
    : autoclear_(_autoclear), breaker_(_breaker), m_broken(false), errno_(0) {
    // inital FD
    FD_ZERO(&writefd_);

    FD_ZERO(&readfd_);
    FD_ZERO(&exceptionfd_);
}

SocketSelect::~SocketSelect()
{}

void SocketSelect::PreSelect() {
    m_broken = false;
    m_filter_map.clear();
    errno_ = 0;

    FD_ZERO(&writefd_);

    FD_ZERO(&readfd_);
    FD_ZERO(&exceptionfd_);
}

int SocketSelect::Select() {
    return Select(WSA_INFINITE);
}

int SocketSelect::Select(int _msec) {
    assert(-1 <= _msec);

	//create eventarray and socketarray
	WSAEVENT* eventarray = (WSAEVENT*)calloc(m_filter_map.size() + 1, sizeof(WSAEVENT));
    SOCKET* socketarray = (SOCKET*)calloc(m_filter_map.size() + 1, sizeof(SOCKET));
    eventarray[0] = Breaker().BreakerFD();
    socketarray[0] = INVALID_SOCKET;

    int index = 1;

    for (std::map<SOCKET, int>::iterator it = m_filter_map.begin(); it != m_filter_map.end(); ++it) {
        eventarray[index] = WSACreateEvent();
        socketarray[index] = it->first;

        ASSERT2(WSA_INVALID_EVENT != eventarray[index], "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));
        ASSERT2(SOCKET_ERROR != WSAEventSelect(it->first, eventarray[index], it->second), "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));

        ++index;
    }


    // select
    SOCKET maxsocket = INVALID_SOCKET;

    for (std::map<SOCKET, int>::iterator it = m_filter_map.begin(); it != m_filter_map.end(); ++it) {
        maxsocket = maxsocket == INVALID_SOCKET ? it->first : maxsocket;
        maxsocket = it->first > maxsocket ? it->first : maxsocket;

        if (it->second & (FD_READ | FD_ACCEPT | FD_CLOSE)) {
            FD_SET(it->first, &readfd_);
        }

        if (it->second & (FD_WRITE | FD_CONNECT)) {
            FD_SET(it->first, &writefd_);
        }

        if (it->second & (FD_CLOSE)) {
            FD_SET(it->first, &exceptionfd_);
        }
    }

    int ret = 0;
    // check socket first write select
    int new_WOULDBLOCK_count = 0;

    if (INVALID_SOCKET != maxsocket) {
        timeval timeout = {0, 0};
        ret = select(maxsocket + 1, &readfd_, &writefd_, &exceptionfd_, &timeout);

        if (0 > ret) {
            errno_ = WSAGetLastError();
            m_broken = Breaker().m_broken;

            if (autoclear_) Breaker().Clear();

            debug_log("return select, ret=%d\n", ret);
            goto END; //free eventarray and socketarrary
        }

        if (0 < ret) {
            m_broken = Breaker().m_broken;

            if (autoclear_) Breaker().Clear();
            goto END; //free eventarray and socketarrary
        }
    }


    for (std::map<SOCKET, int>::iterator it = m_filter_map.begin(); it != m_filter_map.end(); ++it) {
        if (it->second & (FD_WRITE) && !__WOULDBLOCK(it->first)) {
            FD_SET(it->first, &writefd_);
            __WOULDBLOCK(it->first, true);
            ++new_WOULDBLOCK_count;
            debug_log("socket %d\n", it->first);
        }
    }

    if (0 < new_WOULDBLOCK_count) {
        debug_log("WOULDBLOCK FD_WRITE wait count:%d\n", new_WOULDBLOCK_count);
        m_broken = Breaker().m_broken;

        if (autoclear_) Breaker().Clear();

        ret = new_WOULDBLOCK_count;
		goto END; //free eventarray and socketarrary
    }

    // WSAWaitForMultipleEvents
    ret = WSAWaitForMultipleEvents(m_filter_map.size() + 1, eventarray, FALSE, _msec, FALSE);
    ASSERT2(WSA_WAIT_FAILED != ret, "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));

    if (WSA_WAIT_FAILED == ret) errno_ = WSAGetLastError();

    if (WSA_WAIT_FAILED != ret && WSA_WAIT_TIMEOUT != ret && 0 < ret - WSA_WAIT_EVENT_0) {
        WSANETWORKEVENTS networkevents = {0};
        int event_index = ret;
        ret = WSAEnumNetworkEvents(socketarray[event_index - WSA_WAIT_EVENT_0], eventarray[event_index - WSA_WAIT_EVENT_0], &networkevents);

        if (ret == SOCKET_ERROR)
            errno_ = WSAGetLastError();
        else {
            SOCKET sock = socketarray[event_index - WSA_WAIT_EVENT_0];

            if (networkevents.lNetworkEvents & (FD_WRITE | FD_CONNECT) && 0 != __SO_RCVTIMEO(sock)) {
                debug_log("WOULDBLOCK FD_WRITE notify sock:%d\n", sock);
            }

            if (m_filter_map[sock] & (FD_WRITE | FD_CONNECT) && networkevents.lNetworkEvents & (FD_WRITE | FD_CONNECT)) {
                FD_SET(sock, &writefd_);
                __WOULDBLOCK(sock, false);
				debug_log("FD_WRITE | FD_CONNECT\n");
            }

            if (m_filter_map[sock] & (FD_READ | FD_ACCEPT) && networkevents.lNetworkEvents & (FD_READ | FD_ACCEPT)) {
                FD_SET(sock, &readfd_);
                debug_log("FD_READ | FD_ACCEPT\n");
            }

            if (m_filter_map[sock] & (FD_READ | FD_ACCEPT) && networkevents.lNetworkEvents & FD_CLOSE && networkevents.iErrorCode[FD_CLOSE_BIT] == 0) {
                FD_SET(sock, &readfd_);
                debug_log("FD_READ | FD_ACCEPT\n");
            }

            if (m_filter_map[sock] & (FD_CLOSE)) {
                for (int i = 0; i < FD_MAX_EVENTS; ++i) {
                    if (networkevents.iErrorCode[i] != 0) {
                        debug_log("selector exception, sock %d err %d\n",sock, networkevents.iErrorCode[i]);
                        FD_SET(sock, &exceptionfd_);
                        break;
                    }
                }
            }
        }
	} else {
		debug_log("return WSAWaitForMultipleEvents, ret=%d\n", ret);
	}


    if (ret == WSA_WAIT_FAILED) ret = -1;
    else if (ret == SOCKET_ERROR) ret = -1;
    else if (ret == WSA_WAIT_TIMEOUT)  ret = 0;
    else ret = 1;

    m_broken = Breaker().m_broken;
    
    if (autoclear_) Breaker().Clear();

END:
	//free eventarray and socketarray
    index = 1;

    for (std::map<SOCKET, int>::iterator it = m_filter_map.begin(); it != m_filter_map.end(); ++it) {
        ASSERT2(WSACloseEvent(eventarray[index]), "%d, %s\n", WSAGetLastError(), gai_strerror(WSAGetLastError()));
        ++index;
    }

    free(eventarray);
    free(socketarray);

    return ret;
}

int SocketSelect::Select(int _sec, int _usec) {
    assert(0 <= _sec);
    assert(0 <= _usec);

    return Select(_sec * 1000 + _usec / 1000);
}

void SocketSelect::Read_FD_SET(SOCKET _socket) {
    m_filter_map[_socket] |= (FD_READ | FD_ACCEPT | FD_CLOSE);
}

void SocketSelect::Write_FD_SET(SOCKET _socket) {
    m_filter_map[_socket] |= (FD_WRITE | FD_CONNECT);
}

void SocketSelect::Exception_FD_SET(SOCKET _socket) {
    m_filter_map[_socket] |= (FD_CLOSE);
}

int SocketSelect::Read_FD_ISSET(SOCKET _socket) const {
    return FD_ISSET(_socket, &readfd_);
}

int SocketSelect::Write_FD_ISSET(SOCKET _socket) const {
    return FD_ISSET(_socket, &writefd_);
}

int SocketSelect::Exception_FD_ISSET(SOCKET _socket) const {
    return FD_ISSET(_socket, &exceptionfd_);
}

bool SocketSelect::IsException() const {
    return 0 != breaker_.m_exception;
}

bool SocketSelect::IsBreak() const {
    return m_broken;
}

SocketBreaker& SocketSelect::Breaker() {
    return breaker_;
}

int SocketSelect::Errno() const {
    return errno_;
}

