#include "comm.h"
#include "log.h"
#include "nt_kernel.h"
#include "debug_system.h"
#include "exception_system.h"
#include "user_system.h"
#include "myapi.h"

#include "injector/ntmi.h"

#include "ce_kernel/IOPLDispatcher.h"

#define MAX_BY(a,b) (((a) > (b)) ? (a) : (b))

static PFAST_IO_DISPATCH FastIoDispatch = NULL;

#define IO_CTL_START_DEBUG			CTL_CODE(FILE_DEVICE_NULL, 2048, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IO_CTL_HOOK_R3				CTL_CODE(FILE_DEVICE_NULL, 2049, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IO_CTL_ALLOCATE_VM			CTL_CODE(FILE_DEVICE_NULL, 2050, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IO_CTL_RW_VM				CTL_CODE(FILE_DEVICE_NULL, 2051, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

struct add_debugger_t
{
	uint64_t debugger_pid;
	uint64_t debugee_pid;
};

struct hook_r3_t
{
	uint64_t process_id;
	void *address;
	void *fake_page;
};

struct allocate_vm_t
{
	uint64_t process_id;
	void *base_address;
};

EXTERN_C BOOLEAN DispatchDeviceControl(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	IN ULONG IoControlCode,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	size_t byte_size = 0;

	// 兼容CE
	if (IsCeCtl(IoControlCode))
	{
		IRP FakeIRP;
		BOOLEAN r;
		PVOID buffer;
		buffer = ExAllocatePool(PagedPool, MAX_BY(InputBufferLength, OutputBufferLength));
		if (!buffer) return false;
		RtlCopyMemory(buffer, InputBuffer, InputBufferLength);

		FakeIRP.AssociatedIrp.SystemBuffer = buffer;
		FakeIRP.Flags = IoControlCode; //(ab)using an unused element

		r = DispatchIoctl(DeviceObject, &FakeIRP) == STATUS_SUCCESS;

		RtlCopyMemory(OutputBuffer, buffer, OutputBufferLength);
		
		ExFreePool(buffer);
		return r;
	}

	if (IoControlCode == IO_CTL_START_DEBUG)
	{
		add_debugger_t *adt = (add_debugger_t *)InputBuffer;
		debug_system::start_debug(adt->debugger_pid, adt->debugee_pid);
	}
	if (IoControlCode == IO_CTL_RW_VM)
	{
		PMEMORY_RW_DESC mrd = (PMEMORY_RW_DESC)InputBuffer;
		if (mrd->rw_mode == RW_MODE::READ)
		{
			status = myapi::read_process_memory(mrd->process_id, mrd->virtual_address, mrd->buffer, mrd->buffer_size, mrd->number_of_bytes);
		}
		else
		{
			status = myapi::write_process_memory(mrd->process_id, mrd->virtual_address, mrd->buffer, mrd->buffer_size, mrd->number_of_bytes);
		}
		*mrd->status = status;
	}
	else if (IoControlCode == IO_CTL_HOOK_R3)
	{
		hook_r3_t *adt = (hook_r3_t *)InputBuffer;
		user_system::hook_r3(adt->process_id, adt->address);
	}
	else if (IoControlCode == IO_CTL_ALLOCATE_VM)
	{
		allocate_vm_t *indata = (allocate_vm_t *)InputBuffer;

		PEPROCESS Process;
		KAPC_STATE Apc;

		PHYSICAL_ADDRESS LowAddress;
		PHYSICAL_ADDRESS HighAddress;
		PHYSICAL_ADDRESS SkipBytes;

		PMDL g_AllocatedMdl = NULL;
		PVOID g_AllocatedAddress = NULL;

		status = PsLookupProcessByProcessId((HANDLE)indata->process_id, &Process);

		if (NT_SUCCESS(status))
		{
			KeStackAttachProcess(Process, &Apc);

			LowAddress.QuadPart = 0;
			HighAddress.QuadPart = -1;
			SkipBytes.QuadPart = PAGE_SIZE;

			SIZE_T Size = 0x1000;

			g_AllocatedMdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, Size, MmWriteCombined, 0);

			if (g_AllocatedMdl == NULL)
			{
				status = STATUS_MEMORY_NOT_ALLOCATED;
				KeUnstackDetachProcess(&Apc);
				ObDereferenceObject(Process);
			}
			else
			{
				PVOID BaseAddress = NULL;
				status = MiAllocateVirtualMemoryForMdlPages(g_AllocatedMdl, &BaseAddress, Size);

				KeUnstackDetachProcess(&Apc);
				ObDereferenceObject(Process);

				allocate_vm_t *outdata = (allocate_vm_t *)OutputBuffer;
				outdata->base_address = BaseAddress;
				byte_size = sizeof(allocate_vm_t);
			}
		}


	}
	
	IoStatus->Status = status;
	IoStatus->Information = byte_size; // 读写了多少字节
	return TRUE;
}

NTSTATUS InitCom()
{
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING DriverName;
	PDRIVER_OBJECT pDriverObj = NULL;
	RtlInitUnicodeString(&DriverName, L"\\Driver\\Null");
	Status = ObReferenceObjectByName(
		&DriverName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID *)&pDriverObj);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	FastIoDispatch = pDriverObj->FastIoDispatch;
	*(PVOID *)&FastIoDispatch->FastIoDeviceControl = DispatchDeviceControl;

	ObDereferenceObject(pDriverObj);

	return Status;
}

VOID UnInitCom()
{
	if (FastIoDispatch) *(PVOID *)&FastIoDispatch->FastIoDeviceControl = 0;
}