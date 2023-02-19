#pragma once
#include "_global.h"

class memory
{
public:
	static NTSTATUS lock_memory(uint64_t process_id, void *address, size_t size, OUT PMDL *mdl);

	static void unlock_memory(PMDL mdl);
};

