#include "myapi.h"
#include "_kernel_struct.h"
#include "log.h"

// ¶ÁÐ´ÄÚ´æ
NTSTATUS myapi::read_process_memory(uint32_t process_id, void *virtual_address, void *dst_buffer, size_t buffer_size, size_t *number_of_bytes)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS curr_process;
	PEPROCESS from_process;
	KPROCESSOR_MODE previous_mode;
	size_t bytes_copied = 0;

	uint8_t *virtual_address_max = reinterpret_cast<uint8_t *>(virtual_address) + buffer_size;
	uint8_t *dst_buffer_max = reinterpret_cast<uint8_t *>(dst_buffer) + buffer_size;

	if (virtual_address_max < virtual_address)
		return STATUS_ACCESS_VIOLATION;

	if (dst_buffer_max < dst_buffer)
		return STATUS_ACCESS_VIOLATION;

	if (virtual_address_max > reinterpret_cast<uint8_t *>(0x7FFFFFFEFFFF) || dst_buffer_max > reinterpret_cast<uint8_t *>(0x7FFFFFFEFFFF))
		return STATUS_ACCESS_VIOLATION;

	if (!buffer_size)
	{
		return status;
	}

	curr_process = PsGetCurrentProcess();
	previous_mode = ExGetPreviousMode();

	status = PsLookupProcessByProcessId((HANDLE)process_id, &from_process);
	if (!NT_SUCCESS(status))
	{
		return STATUS_ACCESS_VIOLATION;
	}

	status = MmCopyVirtualMemory(from_process, virtual_address, curr_process, dst_buffer, buffer_size, previous_mode, &bytes_copied);

	ObDereferenceObject(from_process);

	if (ARGUMENT_PRESENT(number_of_bytes)) {
		__try
		{
			*number_of_bytes = bytes_copied;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			NOTHING;
		}
	}

	return status;
}

NTSTATUS myapi::write_process_memory(uint32_t process_id, void *virtual_address, void *src_buffer, size_t buffer_size, size_t *number_of_bytes)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS process;
	PMDL mdl;
	KAPC_STATE apc;

	KPROCESSOR_MODE previos_mode = ExGetPreviousMode();
	size_t number_of_bytes_temp = 0;

	uint8_t *virtual_address_max = reinterpret_cast<uint8_t *>(virtual_address) + buffer_size;
	uint8_t *src_buffer_max = reinterpret_cast<uint8_t *>(src_buffer) + buffer_size;

	if (virtual_address_max < virtual_address)
		return STATUS_ACCESS_VIOLATION;

	if (src_buffer_max < src_buffer)
		return STATUS_ACCESS_VIOLATION;

	if (virtual_address_max > reinterpret_cast<uint8_t *>(0x7FFFFFFEFFFF) || src_buffer_max > reinterpret_cast<uint8_t *>(0x7FFFFFFEFFFF))
		return STATUS_ACCESS_VIOLATION;

	status = PsLookupProcessByProcessId((HANDLE)process_id, &process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const PVOID buffer_temp = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'byrw');

	if (buffer_temp == NULL)
	{
		ObDereferenceObject(process);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlCopyMemory(buffer_temp, src_buffer, buffer_size);

	KeStackAttachProcess(process, &apc);

	if (!MmIsAddressValid(virtual_address))
	{
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*number_of_bytes = number_of_bytes_temp;

		return STATUS_ACCESS_VIOLATION;
	}

	const KIRQL irql = KeRaiseIrqlToDpcLevel();

	mdl = IoAllocateMdl(virtual_address, buffer_size, 0, 0, NULL);
	if (mdl == NULL)
	{
		KeLowerIrql(irql);
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*number_of_bytes = number_of_bytes_temp;

		return STATUS_NO_MEMORY;
	}

	MmBuildMdlForNonPagedPool(mdl);

	__try
	{
		MmProbeAndLockPages(mdl, previos_mode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

#pragma prefast(push)
#pragma prefast(disable:__WARNING_MODIFYING_MDL, "Trust me I'm a scientist")
	const CSHORT OriginalMdlFlags = mdl->MdlFlags;
	mdl->MdlFlags |= MDL_PAGES_LOCKED;
	mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

	PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, previos_mode, MmCached, NULL, FALSE, HighPagePriority);

	if (mapped == NULL)
	{
		mdl->MdlFlags = OriginalMdlFlags;
		IoFreeMdl(mdl);
		KeLowerIrql(irql);
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*number_of_bytes = number_of_bytes_temp;

		return STATUS_NONE_MAPPED;
	}

	__try
	{
#pragma warning(push)
#pragma warning(disable:6386)
		RtlCopyMemory(mapped, buffer_temp, buffer_size);
#pragma warning(pop)

		number_of_bytes_temp = buffer_size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		number_of_bytes_temp = 0;
		status = STATUS_ACCESS_VIOLATION;
	}

	MmUnmapLockedPages(mapped, mdl);
	mdl->MdlFlags = OriginalMdlFlags;
#pragma prefast(pop)

	IoFreeMdl(mdl);

	KeLowerIrql(irql);
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);
	ExFreePool(buffer_temp);
	*number_of_bytes = number_of_bytes_temp;

	return status;
}