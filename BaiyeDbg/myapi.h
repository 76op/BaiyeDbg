#pragma once
#include "_global.h"
#include "nt_kernel.h"
#include <ntifs.h>

enum class RW_MODE
{
	READ,
	WRITE
};

typedef struct _MEMORY_RW_DESC
{
	uint32_t process_id;
	RW_MODE rw_mode;
	void *virtual_address;
	void *buffer;
	size_t buffer_size;
	size_t *number_of_bytes;
	NTSTATUS *status;
}MEMORY_RW_DESC, *PMEMORY_RW_DESC;

struct QUOTA_LIMITS_MSG
{
	uint32_t pid;
	void *info_buffer;
	uint32_t info_length;
	NTSTATUS *status;
};

struct QUERY_VM_MSG
{
	uint32_t pid;
	void *base_address;
	MEMORY_INFORMATION_CLASS info_class;
	void *info_buffer;
	uint32_t info_length;
	size_t *return_length;
	NTSTATUS *status;
};

struct ALLOCATE_VM_MSG
{
	uint32_t pid;
	void **base_address;
	uint64_t zero_bits;
	size_t *size;
	uint32_t allocation_type;
	uint32_t protect;
	NTSTATUS *status;
};

class myapi
{
public:
	// ¶ÁÐ´ÄÚ´æ
	static NTSTATUS read_process_memory(uint32_t process_id, void *virtual_address, void *dst_buffer, size_t buffer_size, size_t *number_of_bytes);
	static NTSTATUS write_process_memory(uint32_t process_id, void *virtual_address, void *src_buffer, size_t buffer_size, size_t *number_of_bytes);
};
