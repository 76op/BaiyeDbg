#include "wapihook.h"
#include "kernel_msg.h"

#include <detours.h>

kernel_msg *kmsg = nullptr;

static OpenProcessFn Old_OpenProcess = OpenProcess;
HANDLE WINAPI New_OpenProcess(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwProcessId)
{
	return (HANDLE)dwProcessId;
}


static CloseHandleFn Old_CloseHandle = CloseHandle;
BOOL WINAPI New_CloseHandle(HANDLE hObject)
{
	return TRUE;
}


static ReadProcessMemoryFn Old_ReadProcessMemory = ReadProcessMemory;
BOOL WINAPI New_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
	return kmsg->read_vierual_memory((uint32_t)hProcess, (void *)lpBaseAddress, (void *)lpBuffer, nSize, lpNumberOfBytesRead);
}


static WriteProcessMemoryFn Old_WriteProcessMemory = WriteProcessMemory;
BOOL WINAPI New_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
	return kmsg->write_vierual_memory((uint32_t)hProcess, (void *)lpBaseAddress, (void *)lpBuffer, nSize, lpNumberOfBytesWritten);
}


wapihook::wapihook()
{
	kmsg = new kernel_msg;

	hook_all();
}

wapihook::~wapihook()
{
	unhook_all();

	delete kmsg;
}

void wapihook::hook_open_process()
{
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID &)Old_OpenProcess, New_OpenProcess);
	DetourTransactionCommit();
}

void wapihook::unhook_open_process()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID &)Old_OpenProcess, New_OpenProcess);
	DetourTransactionCommit();
}

void wapihook::hook_close_handle()
{
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID &)Old_CloseHandle, New_CloseHandle);
	DetourTransactionCommit();
}

void wapihook::unhook_close_handle()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID &)Old_CloseHandle, New_CloseHandle);
	DetourTransactionCommit();
}

void wapihook::hook_read_process_memory()
{
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID &)Old_ReadProcessMemory, New_ReadProcessMemory);
	DetourTransactionCommit();
}

void wapihook::unhook_read_process_memory()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID &)Old_ReadProcessMemory, New_ReadProcessMemory);
	DetourTransactionCommit();
}

void wapihook::hook_write_process_memory()
{
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID &)Old_WriteProcessMemory, New_WriteProcessMemory);
	DetourTransactionCommit();
}

void wapihook::unhook_write_process_memory()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID &)Old_WriteProcessMemory, New_WriteProcessMemory);
	DetourTransactionCommit();
}

void wapihook::hook_all()
{
	hook_open_process();
	hook_close_handle();

	hook_read_process_memory();
	hook_write_process_memory();
}

void wapihook::unhook_all()
{
	unhook_open_process();
	unhook_close_handle();

	unhook_read_process_memory();
	unhook_write_process_memory();
}