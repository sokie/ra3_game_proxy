#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>

std::wstring toWString(const std::string& s);
void print_hex(const char* buffer, size_t length);

DWORD GetModuleSize(HANDLE handle);
DWORD GetEntryPointOffset(HANDLE hHandle);
