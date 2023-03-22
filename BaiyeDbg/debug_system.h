#pragma once
#include "_global.h"
#include "_kernel_struct.h"
#include "_debug_struct.h"

#include "log.h"

#include "ida_macros.h"

#include "nt_kernel.h"
#include "hooklib.h"

#include <list>


//
// Debugger
//
typedef struct _DEBUGGER_ENTRY
{
	LIST_ENTRY DebuggerList;

	uint64_t DebuggerId;

	// Transfer debug events
	PVOID DebugObject;
}DEBUGGER_ENTRY, *PDEBUGGER_ENTRY;

//
// Debugee
//
typedef struct _DEBUGEE_ENTRY
{
	LIST_ENTRY DebugeeList;

	uint64_t DebugeeId;

	LIST_ENTRY DebuggerList;
}DEBUGEE_ENTRY, *PDEBUGEE_ENTRY;

//
// Debug all data
// Connect debugger and debugee use process id
// A debugee have multi debugger
//
typedef struct _DEBUG_BRIDGE
{
	FAST_MUTEX Mutex;

	LIST_ENTRY DebugeeList;		// struct _DEBUGEE_OBJECT
}DEBUG_BRIDGE, *PDEBUG_BRIDGE;


// TODO: multi debugee
//typedef struct _DEBUG_STATE_LIST
//{
//	LIST_ENTRY List;
//
//	DEBUG_STATE DebugState;
//}DEBUG_STATE_LIST, *PDEBUG_STATE_LIST;


BOOL DbgsiFindDebugeeEntry(uint64_t DebugeeId, OUT PDEBUGEE_ENTRY *outDebugeeEntry);

BOOL DbgsiFindDebugObject(uint64_t DebugeeId, uint64_t DebuggerId, OUT PDEBUG_OBJECT *outDebugObject);

void DbgsInitialize();
void DbgsDestory();

VOID DbgsCreateDebugObject(OUT PDEBUG_OBJECT *DebugObject);
VOID DbgsDestoryDebugObject(uint64_t DebugeeId);

NTSTATUS DbgsStartDebug(uint64_t DebugeeId);
NTSTATUS DbgsStopDebug();



class debug_state
{
public:
	debug_state();
	~debug_state();
	std::list<debug_state_t> dbgk_list;
};

class debug_system
{
public:
	// 初始化相关
	static void initialize();
	static void destory();

public:
	// 与外部通讯时使用
	// 首先调用 start_debug 函数，传入调试进程id与被调试进程id
	static void start_debug(uint64_t debugger_pid, uint64_t debugee_pid);

private:
	// 内核函数
	static nt_kernel *ntkrnl;

	// 调试运行时的状态
	static POBJECT_TYPE DbgkDebugObjectType;
	static FAST_MUTEX DbgkpProcessDebugPortMutex;

	static std::list<debug_state_t> *dbgk_list;
	static bool get_state_by_debugger_pid(uint64_t debugger_pid, debug_state_t **state);
	static bool get_state_by_debugee_pid(uint64_t debugee_pid, debug_state_t **state);

	// 获取和设置被调试进程debugobject
	static PDEBUG_OBJECT get_debug_object(PEPROCESS_BY Process);
	static void set_debug_object(PEPROCESS_BY Process, PDEBUG_OBJECT DebugObject);

	static void init_debug_object_type();

private:
	static void *get_ntfunc(const char *fn_name);

private:
	// hook 相关
	static void hook_all();
	static void unhook_all();

	static hyper_hook_t *hook_NtDebugActiveProcess;
	static hyper_hook_t *hook_DbgkCreateThread;
	static hyper_hook_t *hook_DbgkExitThread;
	static hyper_hook_t *hook_DbgkExitProcess;
	static hyper_hook_t *hook_DbgkMapViewOfSection;
	static hyper_hook_t *hook_DbgkUnMapViewOfSection;
	static hyper_hook_t *hook_KiDispatchException;
	static hyper_hook_t *hook_NtWaitForDebugEvent;
	static hyper_hook_t *hook_NtCreateDebugObject;
	static hyper_hook_t *hook_DbgkpCloseObject;
	static hyper_hook_t *hook_NtDebugContinue;
	static hyper_hook_t *hook_DbgkpMarkProcessPeb;
	static hyper_hook_t *hook_DbgkClearProcessDebugObject;
	static hyper_hook_t *hook_DbgkForwardException;

private:
	// 重写的api
	static NTSTATUS NTAPI New_NtCreateDebugObject(
		OUT PHANDLE DebugObjectHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN ULONG Flags
	);

	static NTSTATUS NTAPI New_NtDebugActiveProcess(
		IN HANDLE DebugeeProcessHandle,
		IN HANDLE DebugObjectHandle
	);

	static NTSTATUS NTAPI New_DbgkpSetProcessDebugObject(
		IN PEPROCESS_BY Process,
		IN PDEBUG_OBJECT DebugObject,
		IN NTSTATUS MsgStatus,
		IN PETHREAD_BY LastThread
	);

	static NTSTATUS NTAPI New_DbgkpPostFakeProcessCreateMessages(
		IN PEPROCESS_BY Process,
		IN PDEBUG_OBJECT DebugObject,
		IN PETHREAD_BY *pLastThread
	);

	static NTSTATUS NTAPI New_DbgkpPostFakeThreadMessages(
		IN PEPROCESS_BY Process,
		IN PDEBUG_OBJECT DebugObject,
		IN PETHREAD_BY StartThread,
		OUT PETHREAD_BY *pFirstThread,
		OUT PETHREAD_BY *pLastThread
	);

	static NTSTATUS NTAPI New_DbgkpPostModuleMessages(
		IN PEPROCESS_BY Process,
		IN PETHREAD_BY Thread,
		IN PDEBUG_OBJECT DebugObject
	);

	static VOID NTAPI New_DbgkCreateThread(
		PETHREAD_BY Thread
	);

	static NTSTATUS NTAPI New_DbgkpQueueMessage(
		IN PEPROCESS_BY Process,
		IN PETHREAD_BY Thread,
		IN OUT PDBGKM_APIMSG ApiMsg,
		IN ULONG Flags,
		IN PDEBUG_OBJECT TargetDebugObject
	);

	static BOOLEAN NTAPI New_DbgkForwardException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN BOOLEAN DebugException,
		IN BOOLEAN SecondChance
	);

	static NTSTATUS NTAPI New_DbgkClearProcessDebugObject(
		IN PEPROCESS_BY Process,
		IN PDEBUG_OBJECT SourceDebugObject
	);

	static NTSTATUS NTAPI New_DbgkpSendApiMessage(
		PEPROCESS_BY Process,
		ULONG Flags,
		PDBGKM_APIMSG ApiMsg
	);

	static NTSTATUS NTAPI New_DbgkExitThread(
		NTSTATUS ExitStatus
	);

	static NTSTATUS NTAPI New_DbgkExitProcess(
		NTSTATUS ExitStatus
	);

	//static DECLSPEC_NORETURN VOID NTAPI New_PspExitThread(IN NTSTATUS ExitStatus);

	static VOID NTAPI New_DbgkMapViewOfSection(
		IN PEPROCESS_BY Process,
		IN PVOID SectionObject,
		IN PVOID SectionBaseAddress
	);

	static VOID NTAPI New_DbgkUnMapViewOfSection(
		IN PEPROCESS_BY Process,
		IN PVOID BaseAddress
	);

	static VOID NTAPI New_KiDispatchException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN PKEXCEPTION_FRAME ExceptionFrame,
		IN PKTRAP_FRAME TrapFrame,
		IN KPROCESSOR_MODE PreviousMode,
		IN BOOLEAN FirstChance
	);

	static NTSTATUS NTAPI New_NtWaitForDebugEvent(
		IN HANDLE DebugObjectHandle,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER Timeout OPTIONAL,
		OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
	);

	static VOID NTAPI New_DbgkSendSystemDllMessages(
		PETHREAD_BY Thread,
		PDEBUG_OBJECT DebugObject,
		PDBGKM_APIMSG ApiMsg
	);

	static VOID NTAPI New_DbgkpCloseObject(
		IN PEPROCESS_BY Process,
		IN PVOID Object,
		IN ULONG_PTR ProcessHandleCount,
		IN ULONG_PTR SystemHandleCount
	);

	static NTSTATUS NTAPI New_NtDebugContinue(
		IN HANDLE DebugObjectHandle,
		IN PCLIENT_ID ClientId,
		IN NTSTATUS ContinueStatus
	);


	static VOID NTAPI New_DbgkpMarkProcessPeb(
		PEPROCESS_BY Process
	);

	static BOOL NTAPI New_DbgkpSuppressDbgMsg(
		PTEB Teb
	);
};