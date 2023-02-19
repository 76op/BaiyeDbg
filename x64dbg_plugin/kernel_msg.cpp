#include "kernel_msg.h"

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


bool kernel_msg::read_vierual_memory(uint32_t pid, void *virtual_address, void *buffer, size_t size, size_t *number_of_bytes)
{
	DWORD Status = 0;
	MEMORY_RW_DESC mem_desc = {
		pid, virtual_address, buffer, size, number_of_bytes, &Status, RW_MODE::READ
	};
	bool ret = send_message(IO_CTL_RW_VM, &mem_desc, sizeof(MEMORY_RW_DESC), nullptr, 0);
	return ret && ((Status & 0x80000000) == 0);
}

bool kernel_msg::write_vierual_memory(uint32_t pid, void *virtual_address, void *buffer, size_t size, size_t *number_of_bytes)
{
	DWORD Status = 0;
	MEMORY_RW_DESC mem_desc = {
		pid, virtual_address, buffer, size, number_of_bytes, &Status, RW_MODE::WRITE
	};
	bool ret = send_message(IO_CTL_RW_VM, &mem_desc, sizeof(MEMORY_RW_DESC), nullptr, 0);
	return ret && ((Status & 0x80000000) == 0);
}
