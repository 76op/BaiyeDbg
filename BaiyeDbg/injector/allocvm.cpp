#include "ntmi.h"

extern "C" 
VOID
FASTCALL
ExAcquirePushLockExclusiveEx(
	PEX_PUSH_LOCK PushLock,
	_In_ ULONG Flags
);

extern "C"
VOID
FASTCALL
ExReleasePushLockExclusiveEx(
	_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
	PEX_PUSH_LOCK PushLock,
	_In_ ULONG Flags
);

NTSTATUS MiAllocateVirtualMemoryForMdlPages(
    IN PMDL Mdl,
    IN OUT PVOID *BaseAddress,
    SIZE_T Size
)
{
	NTSTATUS Status;

	PETHREAD_BY Thread;
	PEPROCESS_BY Process;

	PVOID StartingVa;
	PFN_NUMBER NumberOfPages;
	PVOID EndingAddress;

	PVOID HighestUserAddress;

	PVOID Base = NULL;

	StartingVa = (PVOID)((PCHAR)Mdl->StartVa + Mdl->ByteOffset);
	NumberOfPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(StartingVa, Mdl->ByteCount);

	Thread = (PETHREAD_BY)PsGetCurrentThread();
	Process = (PEPROCESS_BY)PsGetCurrentProcess();

	if ((*BaseAddress) != NULL)
	{
		if (BYTE_OFFSET(*BaseAddress) != 0) {

			//
			// Invalid base address.
			//

			return STATUS_INVALID_ADDRESS;
		}

		EndingAddress = (PVOID)((PCHAR)(*BaseAddress) + ((ULONG_PTR)NumberOfPages * PAGE_SIZE) - 1);

		if (( EndingAddress <= (*BaseAddress) ) || (EndingAddress > MM_HIGHEST_VAD_ADDRESS)) {
			//
			// Invalid region size.
			//

			return STATUS_INVALID_ADDRESS;
		}
	}
	else
	{
		ExAcquirePushLockExclusiveEx((PEX_PUSH_LOCK)&Process->AddressCreationLock, 0);

		if (Process->Flags & PS_PROCESS_FLAGS_VM_DELETED)
		{
			ExReleasePushLockExclusiveEx((PEX_PUSH_LOCK)&Process->AddressCreationLock, 0);
			return STATUS_PROCESS_IS_TERMINATING;
		}


		//
		// 从MmHighestUserAddress开始倒着找可用内存，如果得到的内存是可用的，则从找到的内存接着开始找
		//

		HighestUserAddress = MmHighestUserAddress;

		while (1)
		{
			Status = MiFindEmptyAddressRangeDownTree(Process->VadRoot, Size, HighestUserAddress, PAGE_SIZE, &Base);

			if (!NT_SUCCESS(Status)) {
				ExReleasePushLockExclusiveEx((PEX_PUSH_LOCK)&Process->AddressCreationLock, 0);
				return Status;
			}

			if (!MmIsAddressValid(Base))
			{
				break;
			}

			HighestUserAddress = Base;
		}

		ExReleasePushLockExclusiveEx((PEX_PUSH_LOCK)&Process->AddressCreationLock, 0);
		//EndingAddress = (PVOID)((PCHAR)BaseAddress + ((ULONG_PTR)NumberOfPages * PAGE_SIZE) - 1);
	}

	Status = MiMapPagesForMdl(Mdl, Base, Size);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	*BaseAddress = Base;

	return STATUS_SUCCESS;
}