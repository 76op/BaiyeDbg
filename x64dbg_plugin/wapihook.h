#pragma once
#include <windows.h>

typedef HANDLE(WINAPI *OpenProcessFn)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef BOOL(WINAPI *CloseHandleFn)(HANDLE hObject);

HANDLE WINAPI New_OpenProcess(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwProcessId);

BOOL WINAPI New_CloseHandle(HANDLE hObject);


typedef BOOL(WINAPI *ReadProcessMemoryFn)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
typedef BOOL(WINAPI *WriteProcessMemoryFn)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

// ¶ÁÐ´ÄÚ´æ
typedef BOOL(WINAPI *ReadProcessMemoryFn)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
typedef BOOL(WINAPI *WriteProcessMemoryFn)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

BOOL WINAPI New_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
BOOL WINAPI New_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

class wapihook
{
public:
	wapihook();
	~wapihook();

	void hook_open_process();
	void unhook_open_process();

	void hook_close_handle();
	void unhook_close_handle();

	void hook_read_process_memory();
	void unhook_read_process_memory();

	void hook_write_process_memory();
	void unhook_write_process_memory();

	void hook_all();
	void unhook_all();
};