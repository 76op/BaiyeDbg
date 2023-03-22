#pragma once

#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.

#define DEBUG_EVENT_READ            (0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT          (0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE        (0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE         (0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED  (0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND         (0x20)  // Resume thread on continue

//
// Define debug object access types. No security is present on this object.
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
                              DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE  (0x1) // Kill all debuggees on last handle close


//
// Define the debug object thats used to attatch to processes that are being debugged.
//
#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE  (0x2) // Kill all debugged processes on close

#define DEBUG_OBJECT_WOW64_DEBUGGER  (0x4) // Debugger is a x86 process


//
// Valid return values for the PORT_MESSAGE Type file
//

#define LPC_REQUEST             1
#define LPC_REPLY               2
#define LPC_DATAGRAM            3
#define LPC_LOST_REPLY          4
#define LPC_PORT_CLOSED         5
#define LPC_CLIENT_DIED         6
#define LPC_EXCEPTION           7
#define LPC_DEBUG_EVENT         8
#define LPC_ERROR_EVENT         9
#define LPC_CONNECTION_REQUEST 10

//
// DbgKm Apis are from the kernel component (Dbgk) through a process
// debug port.
//

#define DBGKM_MSG_OVERHEAD \
    (FIELD_OFFSET(DBGKM_APIMSG, u.Exception) - sizeof(PORT_MESSAGE))

#define DBGKM_API_MSG_LENGTH(TypeSize) \
    ((sizeof(DBGKM_APIMSG) << 16) | (DBGKM_MSG_OVERHEAD + (TypeSize)))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)

typedef struct _DEBUG_OBJECT {
	//
	// Event thats set when the EventList is populated.
	//
	KEVENT EventsPresent;
	//
	// Mutex to protect the structure
	//
	FAST_MUTEX Mutex;
	//
	// Queue of events waiting for debugger intervention
	//
	LIST_ENTRY EventList;
	//
	// Flags for the object
	//
	ULONG Flags;
} DEBUG_OBJECT, *PDEBUG_OBJECT;


typedef enum _DBGKM_APINUMBER {
	DbgKmExceptionApi,
	DbgKmCreateThreadApi,
	DbgKmCreateProcessApi,
	DbgKmExitThreadApi,
	DbgKmExitProcessApi,
	DbgKmLoadDllApi,
	DbgKmUnloadDllApi,
	DbgKmMaxApiNumber
} DBGKM_APINUMBER;


typedef struct _DBGKM_EXCEPTION32               // 2 elements, 0x54 bytes (sizeof) 
{
	/*0x000*/     struct _EXCEPTION_RECORD32 ExceptionRecord; // 6 elements, 0x50 bytes (sizeof) 
	/*0x050*/     ULONG32      FirstChance;
}DBGKM_EXCEPTION32, *PDBGKM_EXCEPTION32;

typedef struct _DBGKM_EXCEPTION64               // 2 elements, 0xA0 bytes (sizeof) 
{
	/*0x000*/     struct _EXCEPTION_RECORD ExceptionRecord; // 7 elements, 0x98 bytes (sizeof) 
	/*0x098*/     ULONG32      FirstChance;
	/*0x09C*/     UINT8        _PADDING0_[0x4];
}DBGKM_EXCEPTION64, *PDBGKM_EXCEPTION64;

typedef DBGKM_EXCEPTION64 DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
	HANDLE FileHandle;		// 0x0
	PVOID BaseOfDll;		// 0x8
	ULONG DebugInfoFileOffset;	// 0x10
	ULONG DebugInfoSize;	// 0x14
	PVOID NamePointer;		// 0x18
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;



#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			SHORT DataLength;                                               //0x0
			SHORT TotalLength;                                              //0x2
		} s1;                                                               //0x0
		ULONG Length;                                                       //0x0
	} u1;                                                                   //0x0
	union
	{
		struct
		{
			SHORT Type;                                                     //0x4
			SHORT DataInfoOffset;                                           //0x6
		} s2;                                                               //0x4
		ULONG ZeroInit;                                                     //0x4
	} u2;                                                                   //0x4
	union
	{
		struct _CLIENT_ID ClientId;                                         //0x8
		double DoNotUseThisField;                                           //0x8
	};
	ULONG MessageId;                                                        //0x18
	union
	{
		ULONGLONG ClientViewSize;                                           //0x20
		ULONG CallbackId;                                                   //0x20
	};
}PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _DBGKM_APIMSG {
	PORT_MESSAGE h;					// 0x0
	DBGKM_APINUMBER ApiNumber;		// 0x28
	NTSTATUS ReturnedStatus;		// 0x2c
	union {							// 0x30
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} u;
} DBGKM_APIMSG, *PDBGKM_APIMSG;


typedef struct _DEBUG_EVENT {
	LIST_ENTRY EventList;		//	0x0		Queued to event object through this
	KEVENT ContinueEvent;		//	0x10
	CLIENT_ID ClientId;			//	0x28
	PEPROCESS Process;			//	0x38	Waiting process
	PETHREAD Thread;			//	0x40	Waiting thread
	NTSTATUS Status;			//	0x48	Status of operation
	ULONG Flags;				//	0x4C
	PETHREAD BackoutThread;		//	0x50	Backout key for faked messages
	DBGKM_APIMSG ApiMsg;		//	0x58	Message being sent
} DEBUG_EVENT, *PDEBUG_EVENT;

//
//
// DbgSs Apis are from the system service emulation subsystems to the Dbg
// subsystem
//

typedef enum _DBG_STATE {
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_CREATE_THREAD {
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS {
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union {
		DBGKM_EXCEPTION Exception;
		DBGUI_CREATE_THREAD CreateThread;
		DBGUI_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;