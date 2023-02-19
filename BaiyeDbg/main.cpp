#include "log.h"
#include "hooklib.h"
#include "exception_system.h"
#include "debug_system.h"
#include "user_system.h"

#include "comm.h"
#include "ce_kernel/DbkUtil.h"

#include "injector/ntkernels.h"

#include "hv/hv.h"


//hyper_hook_t *hyper_hook1 = nullptr;
//PVOID pNtOpenProcessAddress;
//
//typedef NTSTATUS(*NtOpenProcessFn)(
//	_Out_ PHANDLE ProcessHandle,
//	_In_ ACCESS_MASK DesiredAccess,
//	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
//	_In_opt_ PCLIENT_ID ClientId
//	);
//
//NTSTATUS
//MyOpenProcess(
//	_Out_ PHANDLE ProcessHandle,
//	_In_ ACCESS_MASK DesiredAccess,
//	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
//	_In_opt_ PCLIENT_ID ClientId
//) {
//	//DbgPrint("pNtOpenProcess address: %p\n", pNtOpenProcessAddress);
//	if (hyper_hook1)
//	{
//		NtOpenProcessFn fn = (NtOpenProcessFn)hyper_hook1->bridge();
//		return fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
//	}
//	return STATUS_SUCCESS;
//}
//
//VOID HookNtOpenProcess() {
//	UNICODE_STRING usNtOpenProcess;
//	RtlInitUnicodeString(&usNtOpenProcess, L"NtOpenProcess");
//	pNtOpenProcessAddress = MmGetSystemRoutineAddress(&usNtOpenProcess);
//	if (pNtOpenProcessAddress != NULL) {
//		DbgPrint("pNtOpenProcess address: %p\n", pNtOpenProcessAddress);
//		//ctxNtOpenProcess = hypervisor::hook(pNtOpenProcessAddress, MyOpenProcess);
//
//		hyper_hook1 = hyper::hook(pNtOpenProcessAddress, MyOpenProcess);
//	}
//	else
//	{
//		DbgPrint("Î´ÕÒµ½NtOpenProcessµØÖ·\n");
//	}
//}
//
//VOID UnHookNtOpenProcess() {
//	if (hyper_hook1) hyper::unhook(hyper_hook1);
//}


EXTERN_C VOID DriverUnload(PDRIVER_OBJECT pDriverObject) 
{
	UnInitCom();
	DbkUnInitialize();

	user_system::destory();
	debug_system::destory();
	exception_system::destory();

	hv::stop();
	Log("Devirtualized the system.\n");

	Log("Driver unloaded.\n");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = DriverUnload;

	Log("Driver loaded.\n");

	if (!hv::start()) {
		Log("Failed to virtualize system.\n");
		return STATUS_HV_OPERATION_FAILED;
	}
	Log("Hypervisor started.\n");

	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)(pDriverObject->DriverSection);
	exception_system::initialize(ldr->DllBase, ldr->SizeOfImage);

	debug_system::initialize();
	user_system::initialize();

	if (!KmInit())
	{
		//hv::stop();
		return STATUS_UNSUCCESSFUL;
	}

	DbkInitialize();
	InitCom();

	return STATUS_SUCCESS;
}

struct kernel_ext_t
{
	void *driver_unload;
	uint8_t *invalid_msr_low;

	void *dll_base;
	size_t image_size;
};

//EXTERN_C NTSTATUS DriverEntry(PVOID Arg1, kernel_ext_t *ext_data)
//{
//	ext_data->driver_unload = DriverUnload;
//
//	Log("Driver loaded.\n");
//
//	if (!hv::start()) {
//		Log("Failed to virtualize system.\n");
//		return STATUS_HV_OPERATION_FAILED;
//	}
//
//	Log("Hypervisor started.\n");
//
//	//HookNtOpenProcess();
//	//bhvp_trace("dll_base: %p, image_size: %lld", ext_data->dll_base, ext_data->image_size);
//
//	exception_system::initialize(ext_data->dll_base, ext_data->image_size);
//	/*debug_system::initialize();
//	user_system::initialize();*/
//
//	if (!KmInit())
//	{
//		hv::stop();
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	DbkInitialize();
//	InitCom();
//
//	return STATUS_SUCCESS;
//}