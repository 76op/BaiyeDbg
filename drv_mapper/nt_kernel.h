#pragma once
#include "_global.h"
#include "_kernel_struct.h"
#include "_debug_struct.h"

#include <string>
#include <unordered_map>

/// <summary>
/// 获取所有需要的内核api函数和内核全局变量
/// 一些对应windows版本的工具函数也可以在这里写
/// </summary>
class nt_kernel
{
public:
	nt_kernel();
	~nt_kernel();

	void *api(const std::string fn_name);
	void *member(const std::string mem_name);

	HANDLE get_process_kernel_handle(uint32_t process_id);
private:
	std::unordered_map<std::string, void *> members;
	std::unordered_map<std::string, void *> apis;
	PLDR_DATA_TABLE_ENTRY ntos_module;

	/// <summary>
	/// 获取ntoskrnl模块结构
	/// 这个函数一定会获取到数据，如果不能则找其他方式
	/// </summary>
	void get_ntos_module();

	void *ntos_base();
	uint32_t ntos_size();

	void get_members();
	void get_apis();


	// 全局变量

	/// <summary>
	/// ObpKernelHandleTable
	/// 系统进程(PsInitialSystemProcess)的句柄表
	/// </summary>
	void get_ObpKernelHandleTable();

	void get_ObTypeIndexTable();


	// 函数

	/// <summary>
	/// mm
	/// </summary>
	void get_MmQueryWorkingSetInformation();

	/// <summary>
	/// psquery
	/// </summary>
	void get_PspQueryQuotaLimits();
	void get_PspSetQuotaLimits();

	void get_PsSuspendProcess();
	void get_PsResumeProcess();

	/// <summary>
	/// query vm
	/// </summary>
	void get_NtQueryVirtualMemory();


	void get_PspCheckForInvalidAccessByProtection();

	void get_PsGetNextProcessThread();

	void get_DbgkpWakeTarget();

	void get_PsSynchronizeWithThreadInsertion();

	void get_PsSuspendThread();
	void get_PsResumeThread();

	void get_DbgkpSectionToFileHandle();

	void get_MmGetFileNameForAddress();

	void get_PsCallImageNotifyRoutines();

	void get_PsCaptureExceptionPort();

	void get_DbgkpSendErrorMessage();

	void get_DbgkpSuspendProcess();

	void get_PsThawProcess();

	void get_DbgkpSuppressDbgMsg();

	void get_DbgkpConvertKernelToUserStateChange();

	void get_DbgkpOpenHandles();

	void get_PsQuerySystemDllInfo();

	void get_PsTerminateProcess();

	void get_PsGetNextProcess();

	void get_ObCreateObjectType();

	void get_RtlInsertInvertedFunctionTable();
	void get_RtlRemoveInvertedFunctionTable();

	// 调试相关
	void get_NtDebugActiveProcess();

	void get_DbgkCreateThread();

	void get_DbgkExitThread();

	void get_DbgkExitProcess();

	void get_DbgkMapViewOfSection();
	void get_DbgkUnMapViewOfSection();

	void get_KiDispatchException();

	void get_NtWaitForDebugEvent();

	void get_NtCreateDebugObject();

	void get_DbgkpCloseObject();

	void get_NtDebugContinue();

	void get_DbgkpMarkProcessPeb();

	void get_DbgkClearProcessDebugObject();

	void get_DbgkForwardException();

	void get_ObpRemoveObjectRoutine();

	void get_DbgkpSendApiMessageLpc();
};

#ifdef __cplusplus
extern "C"
{
#endif
	// 到处变量
	extern PLIST_ENTRY PsLoadedModuleList;
	extern POBJECT_TYPE *IoDriverObjectType;

	// 导出函数

	// 拷贝虚拟内存
	NTSTATUS MmCopyVirtualMemory(
		IN PEPROCESS FromProcess,
		IN CONST VOID *FromAddress,
		IN PEPROCESS ToProcess,
		OUT PVOID ToAddress,
		IN SIZE_T BufferSize,
		IN KPROCESSOR_MODE PreviousMode,
		OUT PSIZE_T NumberOfBytesCopied
	);


	PIMAGE_NT_HEADERS RtlImageNtHeader(
		PVOID Base
	);

	NTSTATUS PsReferenceProcessFilePointer(
		IN PEPROCESS_BY PROCESS,
		OUT PFILE_OBJECT *FileObject
	);

	VOID PsSetProcessFaultInformation(
		IN PEPROCESS_BY Process,
		PULONG64 arg2
	);

	VOID ZwFlushInstructionCache(
		__in HANDLE ProcessHandle,
		__in_opt PVOID BaseAddress,
		__in SIZE_T Length
	);

	BOOLEAN KeIsAttachedProcess();

	UINT16 PsWow64GetProcessMachine(PEPROCESS_BY Process);

	NTSTATUS ObCreateObject(
		__in KPROCESSOR_MODE ProbeMode,
		__in POBJECT_TYPE ObjectType,
		__in POBJECT_ATTRIBUTES ObjectAttributes,
		__in KPROCESSOR_MODE OwnershipMode,
		__inout_opt PVOID ParseContext,
		__in ULONG ObjectBodySize,
		__in ULONG PagedPoolCharge,
		__in ULONG NonPagedPoolCharge,
		__out PVOID *Object
	);

	PPEB PsGetProcessPeb(IN PEPROCESS_BY);

	NTKERNELAPI
		NTSTATUS ObReferenceObjectByName(
			IN PUNICODE_STRING ObjectName,
			IN ULONG Attributes,
			IN PACCESS_STATE PassedAccessState OPTIONAL,
			IN ACCESS_MASK DesiredAccess OPTIONAL,
			IN POBJECT_TYPE ObjectType,
			IN KPROCESSOR_MODE AccessMode,
			IN OUT PVOID ParseContext OPTIONAL,
			OUT PVOID *Object
		);

#ifdef __cplusplus
}
#endif

typedef NTSTATUS(*Fn_MmQueryWorkingSetInformation)(
	IN PSIZE_T PeakWorkingSetSize,
	IN PSIZE_T WorkingSetLeafSize,
	IN PSIZE_T WorkingSetLeafPrivateSize,
	IN PSIZE_T MinimumWorkingSetSize,
	IN PSIZE_T MaximumWorkingSetSize,
	IN PULONG HardEnforcementFlags
	);

typedef NTSTATUS(*Fn_PspQueryQuotaLimits)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL,
	IN KPROCESSOR_MODE PreviousMode
	);

typedef NTSTATUS(*Fn_PspSetQuotaLimits)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	IN KPROCESSOR_MODE PreviousMode
	);

typedef NTSTATUS(*Fn_NtQueryVirtualMemory)(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
	);

typedef NTSTATUS(*Fn_PsSuspendProcess)(PEPROCESS Process);
typedef NTSTATUS(*Fn_PsResumeProcess)(PEPROCESS Process);

typedef BOOLEAN(*Fn_PspCheckForInvalidAccessByProtection)(
	IN UCHAR CurrentPreviousMode,
	IN PS_PROTECTION SourceProcessProtection,
	IN PS_PROTECTION TargetProcessProtection
	);

typedef PETHREAD_BY(*Fn_PsGetNextProcessThread)(
	IN PEPROCESS_BY Process,
	IN PETHREAD_BY Thread
	);

typedef VOID(*Fn_DbgkpWakeTarget)(
	IN PDEBUG_EVENT DebugEvent
	);

typedef NTSTATUS(*Fn_PsSynchronizeWithThreadInsertion)(
	IN PETHREAD_BY Thread1,
	IN PETHREAD_BY Thread2
	);

typedef NTSTATUS(*Fn_PsSuspendThread)(
	IN PETHREAD_BY Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

typedef NTSTATUS(*Fn_PsResumeThread)(
	IN PETHREAD_BY Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

typedef HANDLE(*Fn_DbgkpSectionToFileHandle)(
	IN VOID *SectionObject
	);

typedef NTSTATUS(*Fn_MmGetFileNameForAddress)(
	PIMAGE_NT_HEADERS NtHeaders,
	PUNICODE_STRING Name
	);

typedef NTSTATUS(*Fn_PsCallImageNotifyRoutines)(
	IN PUNICODE_STRING FileName,
	IN PVOID ProcessId,
	IN PIMAGE_INFO ImageInfo,
	IN PFILE_OBJECT FileObject
	);

typedef PVOID(*Fn_PsCaptureExceptionPort)(
	IN PEPROCESS_BY Process
	);


typedef NTSTATUS(*Fn_DbgkpSendErrorMessage)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	ULONG64 arg2,
	PDBGKM_APIMSG pm
	);


typedef BOOLEAN(*Fn_DbgkpSuspendProcess)(
	PEPROCESS_BY
	);

typedef VOID(*Fn_PsThawProcess)(
	PEPROCESS_BY Process,
	ULONG64 Flags
	);

typedef ULONG(*Fn_DbgkpSuppressDbgMsg)(
	PTEB Teb
	);


typedef VOID(*Fn_KiDispatchException)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
	);

typedef VOID(*Fn_DbgkpConvertKernelToUserStateChange)(
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PDEBUG_EVENT DebugEvent
	);

typedef VOID(*Fn_DbgkpOpenHandles)(
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PEPROCESS_BY Process,
	PETHREAD_BY Thread
	);

typedef PPS_SYSTEM_DLL_INFO(*Fn_PsQuerySystemDllInfo)(
	IN int Index
	);

typedef NTSTATUS(*Fn_PsTerminateProcess)(
	PEPROCESS_BY Process,
	NTSTATUS ExitStatus
	);

typedef PEPROCESS_BY(*Fn_PsGetNextProcess)(
	PEPROCESS_BY Process
	);

typedef NTSTATUS(*Fn_ObCreateObjectType)(
	__in PUNICODE_STRING TypeName,
	__in POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out POBJECT_TYPE *ObjectType
	);

typedef VOID(*Fn_ObpRemoveObjectRoutine)(
	IN PVOID Object,
	IN BOOLEAN CalledOnWorkerThread
	);


typedef NTSTATUS(*Fn_DbgkpSendApiMessageLpc)(
	PDBGKM_APIMSG ApiMsg,
	PVOID Port,
	BOOLEAN DebugException
	);

typedef VOID (*Fn_RtlInsertInvertedFunctionTable)(
	PVOID ImageBase,
	ULONG SizeOfImage
);

typedef VOID (*Fn_RtlRemoveInvertedFunctionTable)(
	PVOID ImageBase
);