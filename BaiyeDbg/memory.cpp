#include "memory.h"
#include "_kernel_struct.h"

NTSTATUS memory::lock_memory(uint64_t process_id, void *address, size_t size, OUT PMDL *save_mdl)
{
	NTSTATUS Status;

	PEPROCESS_BY Process;
	KAPC_STATE Apc;

	Status = PsLookupProcessByProcessId((PVOID)(process_id), (PEPROCESS *)&Process);
	
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	PMDL mdl = NULL;

	__try
	{
		KeStackAttachProcess((PEPROCESS)Process, &Apc);

		mdl = IoAllocateMdl((PVOID)address, size, FALSE, FALSE, NULL);
		if (mdl)
		{
			__try
			{
				MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
			}
			__except (1)
			{
				IoFreeMdl(mdl);
				Status = STATUS_UNSUCCESSFUL;
				DbgBreakPoint();

				return Status;
			}
		}
	}
	__finally
	{
		KeUnstackDetachProcess(&Apc);
	}

	*save_mdl = mdl;
	Status = STATUS_SUCCESS;

	return Status;
}

void memory::unlock_memory(PMDL mdl)
{
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
}