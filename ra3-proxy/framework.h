#pragma once



#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <tchar.h>

// Boost Library Headers
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/array.hpp>
#include <boost/beast/http.hpp>

#include "Config.hpp"



// Detours Library Headers
#include "detours/detours.h"
#pragma comment(lib, "detours.lib")

//#include "../vendor/Detour/detours.h"

//#if defined(_X86_)
//  #pragma comment(lib, "../vendor/Detour/detours.x86.lib")
//#elif defined(_AMD64_)
//  #pragma comment(lib, "../vendor/Detour/detours.x64.lib")
//#endif



#pragma comment(lib, "ws2_32.lib") //ntohs & htons

// OpenSSL Library
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")


#define PACKET_MAX_LENGTH 8192

#define HEADER_VALUE_LENGTH 4
#define CATEGORY_OFFSET 0
#define TYPE_OFFSET   CATEGORY_OFFSET + HEADER_VALUE_LENGTH
#define LENGTH_OFFSET TYPE_OFFSET + HEADER_VALUE_LENGTH
#define HEADER_LENGTH LENGTH_OFFSET + HEADER_VALUE_LENGTH

enum MessageType {
	msg_fsys,
	msg_subs,
	msg_acct,
	msg_dobj
};
enum MessageClass {
	fsys_Hello = 0x01,
	fsys_Ping = 0x00,
	fsys_MemCheck = 0x00
};