#include "util.h"
#include <iomanip>
#include <sstream>
#include <boost/log/trivial.hpp>

std::wstring toWString(const std::string& s) {
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.length(), nullptr, 0);
    std::wstring buf(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.length(), &buf[0], size);
    return buf;
}

void print_hex(const char* buffer, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(static_cast<unsigned char>(buffer[i])) << " ";
    }
    oss << std::endl;
    BOOST_LOG_TRIVIAL(debug) << "SSL hex: " << oss.str();
    BOOST_LOG_TRIVIAL(debug) << "received: " << std::string(buffer, length);
}

DWORD GetModuleSize(const HANDLE handle)
{
	auto hModule = static_cast<HMODULE>(handle);

	if (!hModule)
		return NULL;

	const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(hModule) + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	const PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = &ntHeader->OptionalHeader;
	return pImageOptionalHeader->SizeOfImage;
}

DWORD GetEntryPointOffset(const HANDLE hHandle)
{
	auto hModule = static_cast<HMODULE>(hHandle);

	if (!hModule)
		return NULL;

	const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(hModule) + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	const PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = &ntHeader->OptionalHeader;
	return pImageOptionalHeader->BaseOfCode;
}
