#include "pch.h"
#include "kernel_msg.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <winioctl.h>

#define IO_CTL_START_DEBUG			CTL_CODE(FILE_DEVICE_NULL, 2048, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IO_CTL_HOOK_R3				CTL_CODE(FILE_DEVICE_NULL, 2049, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IO_CTL_ALLOCATE_VM			CTL_CODE(FILE_DEVICE_NULL, 2050, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

const WCHAR *symbolName = L"\\\\.\\NUL";

kernel_msg::kernel_msg()
{
	msg_handle = CreateFileW(symbolName, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);

	if (msg_handle == INVALID_HANDLE_VALUE)
	{
		msg_state = MSG_STATE::OPEN_ERROR;
		return;
	}

	msg_state = MSG_STATE::OPENED;
}

kernel_msg::~kernel_msg()
{
	msg_state = MSG_STATE::CLOSED;

	CloseHandle(msg_handle);
	msg_handle = nullptr;
}

bool kernel_msg::send_message(uint32_t control_code, void *in_buffer, size_t in_size, void *out_bufer, size_t out_size)
{
	if (!is_open()) return false;

	uint32_t done_bytes;
	// IRP_MJ_DEVICE_CONTROL
	return DeviceIoControl(
		msg_handle, control_code,
		in_buffer, in_size, // 发送
		out_bufer, out_size, // 接收，不接收可以填NULL
		(LPDWORD)&done_bytes, 0
	);
}

bool kernel_msg::start_debugger(uint64_t debugger_pid, uint64_t debugee_pid)
{
	DWORD Status = 0;
	add_debugger_t adt = {
		debugger_pid, debugee_pid
	};
	bool ret = send_message(IO_CTL_START_DEBUG, &adt, sizeof(add_debugger_t), nullptr, 0);
	return ret && ((Status & 0x80000000) == 0);
}

bool kernel_msg::hook_r3(uint64_t process_id, void *address, void *fake_page)
{
	DWORD Status = 0;
	hook_r3_t adt = {
		process_id, address, fake_page
	};
	bool ret = send_message(IO_CTL_HOOK_R3, &adt, sizeof(hook_r3_t), nullptr, 0);
	return ret && ((Status & 0x80000000) == 0);
}

bool kernel_msg::allocate_vm(uint64_t process_id, void **address)
{
	DWORD Status = 0;
	allocate_vm_t adt = {
		process_id, nullptr
	};
	bool ret = send_message(IO_CTL_ALLOCATE_VM, &adt, sizeof(hook_r3_t), &adt, sizeof(hook_r3_t));

	*address = adt.base_address;
	
	return ret && ((Status & 0x80000000) == 0);
}