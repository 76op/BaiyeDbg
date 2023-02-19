#pragma once
#include <windows.h>
#include <cstdint>

#define IO_CTL_RW_VM				CTL_CODE(FILE_DEVICE_NULL, 2051, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

enum class MSG_STATE
{
	NORMAL,
	OPEN_ERROR,
	OPENED,
	CLOSED,
};

enum class RW_MODE
{
	READ,
	WRITE
};

typedef struct _MEMORY_RW_DESC
{
	ULONG64 ProcessId;
	PVOID VirtualAddress;
	PVOID BufferRW;
	SIZE_T Size;
	PSIZE_T NumberOfBytes;
	PDWORD Status;
	RW_MODE Mode;
}MEMORY_RW_DESC, *PMEMORY_RW_DESC;

struct QUOTA_LIMITS_MSG
{
	uint32_t pid;
	void *information;
	uint32_t information_length;
	DWORD *status;
};

struct QUERY_VM_MSG
{
	uint32_t pid;
	void *base_address;
	uint64_t information_class;
	void *information;
	uint32_t information_length;
	size_t *return_length;
	uint32_t *status;
};

struct ALLOCATE_VM_MSG
{
	uint32_t pid;
	void *base_address;
	uint64_t zero_bits;
	size_t *size;
	uint32_t allocation_type;
	uint32_t protect;
	uint32_t *status;
};


class kernel_msg
{
public:
	kernel_msg();
	~kernel_msg();

	bool read_vierual_memory(uint32_t pid, void *virtual_address, void *buffer, size_t size, size_t *number_of_bytes);
	bool write_vierual_memory(uint32_t pid, void *virtual_address, void *buffer, size_t size, size_t *number_of_bytes);


private:
	HANDLE msg_handle = nullptr;
	MSG_STATE msg_state = MSG_STATE::NORMAL;

	bool is_open()
	{
		return msg_state == MSG_STATE::OPENED;
	};

	bool send_message(uint32_t control_code, void *in_buffer, size_t in_size, void *out_bufer, size_t out_size);

};

