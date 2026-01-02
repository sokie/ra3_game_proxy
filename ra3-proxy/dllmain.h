/*
Copyright (c) Anthony Beaumont
Modifications by sokie
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

#include "Framework.h"

typedef HINSTANCE(WINAPI* ShellExecuteW_t)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
typedef int (WSAAPI *connect_t)(SOCKET s, const sockaddr*, int namelen);
typedef int (WSAAPI *send_t)(SOCKET s, const char *buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef struct hostent* (WSAAPI *gethostbyname_t)(const char *name);

HINSTANCE WINAPI detourShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd);
int WSAAPI detourConnect(SOCKET s, const sockaddr* name, int namelen);
int WSAAPI detourSend(SOCKET s, const char *buf, int len, int flags);
int WSAAPI detourRecv(SOCKET s, char* buf, int len, int flags);
struct hostent* WSAAPI detourGetHostByName(const char *name);
bool takeDetour(PVOID* ppPointer, PVOID pDetour);
bool setDetoursForSocket();
bool setDetoursForShell();
DWORD WINAPI Main(LPVOID lpReserved);
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
