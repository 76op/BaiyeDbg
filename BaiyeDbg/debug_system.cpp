#include "debug_system.h"

nt_kernel *debug_system::ntkrnl = nullptr;

POBJECT_TYPE debug_system::DbgkDebugObjectType = nullptr;
FAST_MUTEX debug_system::DbgkpProcessDebugPortMutex = { 0 };

std::list<debug_state_t> *debug_system::dbgk_list = nullptr;

hyper_hook_t *debug_system::hook_NtDebugActiveProcess = nullptr;
hyper_hook_t *debug_system::hook_DbgkCreateThread = nullptr;
hyper_hook_t *debug_system::hook_DbgkExitThread = nullptr;
hyper_hook_t *debug_system::hook_DbgkExitProcess = nullptr;
hyper_hook_t *debug_system::hook_DbgkMapViewOfSection = nullptr;
hyper_hook_t *debug_system::hook_DbgkUnMapViewOfSection = nullptr;
hyper_hook_t *debug_system::hook_KiDispatchException = nullptr;
hyper_hook_t *debug_system::hook_NtWaitForDebugEvent = nullptr;
hyper_hook_t *debug_system::hook_NtCreateDebugObject = nullptr;
hyper_hook_t *debug_system::hook_DbgkpCloseObject = nullptr;
hyper_hook_t *debug_system::hook_NtDebugContinue = nullptr;
hyper_hook_t *debug_system::hook_DbgkpMarkProcessPeb = nullptr;
hyper_hook_t *debug_system::hook_DbgkClearProcessDebugObject = nullptr;
hyper_hook_t *debug_system::hook_DbgkForwardException = nullptr;


void debug_system::initialize()
{
	debug_system::ntkrnl = new nt_kernel;

	dbgk_list = new std::list<debug_state_t>();

	ExInitializeFastMutex(&DbgkpProcessDebugPortMutex);
	debug_system::init_debug_object_type();

	debug_system::hook_all();
}

void debug_system::destory()
{
	debug_system::unhook_all();

	if (dbgk_list)
	{
		if (dbgk_list->size() > 0)
		{
			dbgk_list->clear();
		}
		delete dbgk_list;
	}
	
	//ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

	if (debug_system::ntkrnl) delete debug_system::ntkrnl;
}

void debug_system::start_debug(uint64_t debugger_pid, uint64_t debugee_pid)
{
	debug_state_t ds = {};
	ds.debugger_pid = debugger_pid;
	ds.debugee_pid = debugee_pid;

	dbgk_list->push_back(ds);
}

void *debug_system::get_ntfunc(const char *fn_name)
{
	return ntkrnl->api(fn_name);
}

void New_DbgkpDeleteProcedure(PVOID)
{
	return;
}

void debug_system::init_debug_object_type()
{
	NTSTATUS Status;
	UNICODE_STRING Name;
	OBJECT_TYPE_INITIALIZER oti = { 0 };
	GENERIC_MAPPING GenericMapping = { STANDARD_RIGHTS_READ | DEBUG_READ_EVENT,
									  STANDARD_RIGHTS_WRITE | DEBUG_PROCESS_ASSIGN,
									  STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
									  DEBUG_ALL_ACCESS };

	RtlInitUnicodeString(&Name, L"Baiye");

	Fn_ObCreateObjectType ObCreateObjectType = (Fn_ObCreateObjectType)ntkrnl->api("ObCreateObjectType");

	oti.Length = sizeof(OBJECT_TYPE_INITIALIZER);
	oti.SecurityRequired = TRUE;
	oti.InvalidAttributes = 0;
	oti.PoolType = NonPagedPoolNx;
	oti.ValidAccessMask = DEBUG_ALL_ACCESS;
	oti.GenericMapping = GenericMapping;
	oti.DefaultPagedPoolCharge = 0;
	oti.DefaultNonPagedPoolCharge = 0;
	oti.ObjectTypeFlags |= 8;
	oti.DeleteProcedure = New_DbgkpDeleteProcedure;
	oti.CloseProcedure = New_DbgkpCloseObject;

	Status = ObCreateObjectType(&Name, &oti, NULL, &DbgkDebugObjectType);
	
	if (Status == STATUS_OBJECT_NAME_COLLISION)
	{
		POBJECT_TYPE cObjectType = NULL;
		POBJECT_TYPE *ObTypeIndexTable = (POBJECT_TYPE *)ntkrnl->member("ObTypeIndexTable");

		for (int i = 2; ; i++) {
			if (ObTypeIndexTable[i] == 0)
				break;

			cObjectType = ObTypeIndexTable[i];
			if (RtlCompareUnicodeString(&Name, &cObjectType->Name, TRUE) == 0) {
				DbgkDebugObjectType = cObjectType;
				DbgkDebugObjectType->TypeInfo.DeleteProcedure = New_DbgkpDeleteProcedure;
				DbgkDebugObjectType->TypeInfo.CloseProcedure = New_DbgkpCloseObject;
				break;
			}
		}
	}
}

bool debug_system::get_state_by_debugger_pid(uint64_t debugger_pid, debug_state_t **state)
{
	if (dbgk_list->size() > 0)
	{
		for (debug_state_t &_state : *dbgk_list)
		{
			if (_state.debugger_pid == debugger_pid)
			{
				if (state)
				{
					*state = &_state;
				}
				return true;
			}
		}
	}

	return false;
}

bool debug_system::get_state_by_debugee_pid(uint64_t debugee_pid, debug_state_t **state)
{
	if (dbgk_list->size() > 0)
	{
		for (debug_state_t &_state : *dbgk_list)
		{
			if (_state.debugee_pid == debugee_pid)
			{
				if (state)
				{
					*state = &_state;
				}
				return true;
			}
		}
	}

	return false;
}

PDEBUG_OBJECT debug_system::get_debug_object(PEPROCESS_BY Process)
{
	debug_state_t *state;
	if (get_state_by_debugee_pid(reinterpret_cast<uint64_t>(Process->UniqueProcessId), &state))
	{
		return (PDEBUG_OBJECT)state->debug_object;
	}

	return nullptr;
}

void debug_system::set_debug_object(PEPROCESS_BY Process, PDEBUG_OBJECT DebugObject)
{
	debug_state_t *state;
	if (get_state_by_debugee_pid(reinterpret_cast<uint64_t>(Process->UniqueProcessId), &state))
	{
		state->debug_object = DebugObject;
	}
}

void debug_system::hook_all()
{
	void *pNtCreateDebugObject = ntkrnl->api("NtCreateDebugObject");
	debug_system::hook_NtCreateDebugObject = hyper::hook(pNtCreateDebugObject, debug_system::New_NtCreateDebugObject);

	void *pNtDebugActiveProcess = ntkrnl->api("NtDebugActiveProcess");
	debug_system::hook_NtDebugActiveProcess = hyper::hook(pNtDebugActiveProcess, debug_system::New_NtDebugActiveProcess);

	void *pDbgkCreateThread = ntkrnl->api("DbgkCreateThread");
	debug_system::hook_DbgkCreateThread = hyper::hook(pDbgkCreateThread, debug_system::New_DbgkCreateThread);

	void *pDbgkExitThread = ntkrnl->api("DbgkExitThread");
	debug_system::hook_DbgkExitThread = hyper::hook(pDbgkExitThread, debug_system::New_DbgkExitThread);

	void *pDbgkExitProcess = ntkrnl->api("DbgkExitProcess");
	debug_system::hook_DbgkExitProcess = hyper::hook(pDbgkExitProcess, debug_system::New_DbgkExitProcess);

	void *pDbgkMapViewOfSection = ntkrnl->api("DbgkMapViewOfSection");
	debug_system::hook_DbgkMapViewOfSection = hyper::hook(pDbgkMapViewOfSection, debug_system::New_DbgkMapViewOfSection);

	void *pDbgkUnMapViewOfSection = ntkrnl->api("DbgkUnMapViewOfSection");
	debug_system::hook_DbgkUnMapViewOfSection = hyper::hook(pDbgkUnMapViewOfSection, debug_system::New_DbgkUnMapViewOfSection);

	void *pKiDispatchException = ntkrnl->api("KiDispatchException");
	debug_system::hook_KiDispatchException = hyper::hook(pKiDispatchException, debug_system::New_KiDispatchException);

	void *pNtWaitForDebugEvent = ntkrnl->api("NtWaitForDebugEvent");
	debug_system::hook_NtWaitForDebugEvent = hyper::hook(pNtWaitForDebugEvent, debug_system::New_NtWaitForDebugEvent);

	void *pDbgkpCloseObject = ntkrnl->api("DbgkpCloseObject");
	debug_system::hook_DbgkpCloseObject = hyper::hook(pDbgkpCloseObject, debug_system::New_DbgkpCloseObject);

	void *pNtDebugContinue = ntkrnl->api("NtDebugContinue");
	debug_system::hook_NtDebugContinue = hyper::hook(pNtDebugContinue, debug_system::New_NtDebugContinue);

	void *pDbgkpMarkProcessPeb = ntkrnl->api("DbgkpMarkProcessPeb");
	debug_system::hook_DbgkpMarkProcessPeb = hyper::hook(pDbgkpMarkProcessPeb, debug_system::New_DbgkpMarkProcessPeb);

	//void *pDbgkClearProcessDebugObject = ntkrnl->api("DbgkClearProcessDebugObject");
	//debug_system::hook_DbgkClearProcessDebugObject = hyper::hook(pDbgkClearProcessDebugObject, debug_system::New_DbgkClearProcessDebugObject);

	void *pDbgkForwardException = ntkrnl->api("DbgkForwardException");
	debug_system::hook_DbgkForwardException = hyper::hook(pDbgkForwardException, debug_system::New_DbgkForwardException);
}

void debug_system::unhook_all()
{
	if (debug_system::hook_NtDebugActiveProcess)
		hyper::unhook(debug_system::hook_NtDebugActiveProcess);

	if (debug_system::hook_DbgkCreateThread)
		hyper::unhook(debug_system::hook_DbgkCreateThread);

	if (debug_system::hook_DbgkExitThread)
		hyper::unhook(debug_system::hook_DbgkExitThread);

	if (debug_system::hook_DbgkExitProcess)
		hyper::unhook(debug_system::hook_DbgkExitProcess);

	if (debug_system::hook_DbgkMapViewOfSection)
		hyper::unhook(debug_system::hook_DbgkMapViewOfSection);

	if (debug_system::hook_DbgkUnMapViewOfSection)
		hyper::unhook(debug_system::hook_DbgkUnMapViewOfSection);

	if (debug_system::hook_KiDispatchException)
		hyper::unhook(debug_system::hook_KiDispatchException);

	if (debug_system::hook_NtWaitForDebugEvent)
		hyper::unhook(debug_system::hook_NtWaitForDebugEvent);

	if (debug_system::hook_NtCreateDebugObject)
		hyper::unhook(debug_system::hook_NtCreateDebugObject);

	if (debug_system::hook_DbgkpCloseObject)
		hyper::unhook(debug_system::hook_DbgkpCloseObject);

	if (debug_system::hook_NtDebugContinue)
		hyper::unhook(debug_system::hook_NtDebugContinue);

	if (debug_system::hook_DbgkpMarkProcessPeb)
		hyper::unhook(debug_system::hook_DbgkpMarkProcessPeb);

	if (debug_system::hook_DbgkClearProcessDebugObject)
		hyper::unhook(debug_system::hook_DbgkClearProcessDebugObject);

	if (debug_system::hook_DbgkForwardException)
		hyper::unhook(debug_system::hook_DbgkForwardException);
}

NTSTATUS NTAPI debug_system::New_NtDebugActiveProcess(
	IN HANDLE DebugeeProcessHandle,
	IN HANDLE DebugObjectHandle
)
{
	UCHAR CurrentPreviousMode;

	PEPROCESS_BY DebuggerProcess;	// 调试器进程
	PEPROCESS_BY DebugeeProcess;	// 被调试进程

	PETHREAD_BY Thread;
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PETHREAD_BY LastThread;
	PS_PROTECTION SourceProcessProtection;
	PS_PROTECTION TargetProcessProtection;

	//uint64_t DebuggerProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	//debug_state_t *state = nullptr;
	//if (!debug_system::get_state_by_debugger_pid(DebuggerProcessId, &state))
	//{
	//	Fn_NtDebugActiveProcess NtDebugActiveProcess = (Fn_NtDebugActiveProcess)hook_NtDebugActiveProcess->bridge();
	//	return NtDebugActiveProcess(DebugeeProcessHandle, DebugObjectHandle);
	//}

	Thread = (PETHREAD_BY)PsGetCurrentThread();
	CurrentPreviousMode = ExGetPreviousMode();

	// 获取被调试进程对象
	uint64_t DebuggerProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	debug_state_t *state = nullptr;
	debug_system::get_state_by_debugger_pid(DebuggerProcessId, &state);

	Status = PsLookupProcessByProcessId((HANDLE)state->debugee_pid, (PEPROCESS *)&DebugeeProcess);

	if (NT_SUCCESS(Status))
	{
		DebuggerProcess = (PEPROCESS_BY)Thread->Tcb.ApcState.Process;
		if (DebugeeProcess == DebuggerProcess || (PEPROCESS)DebugeeProcess == PsInitialSystemProcess)
		{
			ObfDereferenceObject(DebugeeProcess);
			return STATUS_ACCESS_DENIED;
		}

		Log("[NtDebugActiveProcess] 调试器: %s, 被调试进程: %s", DebuggerProcess->ImageFileName, DebugeeProcess->ImageFileName);

		SourceProcessProtection = DebuggerProcess->Protection;
		TargetProcessProtection = DebugeeProcess->Protection;

		// TODO
		Fn_PspCheckForInvalidAccessByProtection PspCheckForInvalidAccessByProtection = (Fn_PspCheckForInvalidAccessByProtection)ntkrnl->api("PspCheckForInvalidAccessByProtection");
		if (PspCheckForInvalidAccessByProtection(CurrentPreviousMode, SourceProcessProtection, TargetProcessProtection))
		{
			ObfDereferenceObject(DebugeeProcess);
			return STATUS_PROCESS_IS_PROTECTED;
		}

		// VslpEnterIumSecureMode 这里有个判断，因为没有原型，所以先不加

		if ((DebugeeProcess->Pcb.SecureState & 1) == 0)
		{
			// 是否非32位进程
			if (DebuggerProcess->WoW64Process == NULL || DebugeeProcess->WoW64Process != NULL)
			{
				Status = ObReferenceObjectByHandle(
					DebugObjectHandle,
					DEBUG_PROCESS_ASSIGN,
					debug_system::DbgkDebugObjectType,
					CurrentPreviousMode,
					(PVOID *)&DebugObject,
					NULL);

				if (NT_SUCCESS(Status))
				{
					PEX_RUNDOWN_REF ref = &DebugeeProcess->RundownProtect;
					if (ExAcquireRundownProtection(ref))
					{
						//
						// Post the fake process create messages etc.
						//

						//DbgkpPostFakeProcessCreateMessagesProc DbgkpPostFakeProcessCreateMessages = GetDbgkpPostFakeProcessCreateMessagesProc();
						//Status = DbgkpPostFakeProcessCreateMessages(DebugeeProcess, DebugObject, &LastThread);
						Status = debug_system::New_DbgkpPostFakeProcessCreateMessages(DebugeeProcess, DebugObject, &LastThread);

						//
						// Set the debug port. If this fails it will remove any faked messages.
						//
						Status = debug_system::New_DbgkpSetProcessDebugObject((PEPROCESS_BY)DebugeeProcess, DebugObject, Status, LastThread);
						ExReleaseRundownProtection(ref);
					}
					else
					{
						Status = STATUS_PROCESS_IS_TERMINATING;
					}
					ObfDereferenceObject(DebugObject);
				}
			}
			else {
				Status = STATUS_NOT_SUPPORTED;
			}
		}

		ObfDereferenceObject(DebugeeProcess);
	}
	return Status;
}

NTSTATUS NTAPI debug_system::New_DbgkpSetProcessDebugObject(
	IN PEPROCESS_BY Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD_BY LastThread
)
{
	PETHREAD_BY ThisThread; // r13		v3
	NTSTATUS Status; // edi		v4
	//register PVOID varPEProcess; // rsi	v6
	PETHREAD_BY Thread = NULL; // r15	v8
	PLIST_ENTRY Entry; // r15	v9
	PDEBUG_EVENT DebugEvent; // rbx	v11
	PETHREAD_BY FirstThread = NULL; // [rsp+38h] [rbp-28h]	BugCheckParameter2
	LIST_ENTRY TempList; // [rsp+48h] [rbp-18h]		P
	BOOLEAN First; // [rsp+A8h] [rbp+48h]		v28
	BOOLEAN GlobalHeld; // [rsp+B0h] [rbp+50h]	v29

	ThisThread = (PETHREAD_BY)PsGetCurrentThread();

	InitializeListHead(&TempList);
	First = TRUE;
	Status = MsgStatus;
	GlobalHeld = FALSE;
	//varPEProcess = argPEProcess;
	if (NT_SUCCESS(MsgStatus)) {
		//vLastThread = vLastThreadTemp;
		Status = STATUS_SUCCESS;
	}
	else {
		//vLastThread = NULL;
		//vLastThreadTemp = NULL;
		LastThread = NULL;
		Status = MsgStatus;
	}

	if (NT_SUCCESS(Status))
	{
		ExAcquireFastMutex(&debug_system::DbgkpProcessDebugPortMutex);
		while (1)
		{
			GlobalHeld = TRUE;

			//if (StoreGetDebugPort(Process) != NULL) {	// get debug port
			//	Status = STATUS_PORT_ALREADY_SET;
			//	break;
			//}
			if (debug_system::get_debug_object(Process) != NULL)
			{
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}

			//*(PULONG_PTR)((PUCHAR)argPEProcess + 0x420) = (ULONG_PTR)DebugObject;	// set debug port
			// 这判断是否是dnf进程
			//StoreSetDebugPort(Process, DebugObject);
			debug_system::set_debug_object(Process, DebugObject);

			ObfReferenceObjectWithTag(LastThread, POOL_TAG);
			//Thread = PsGetNextProcessThread(varPEProcess, LastThread);
			Fn_PsGetNextProcessThread PsGetNextProcessThread = (Fn_PsGetNextProcessThread)ntkrnl->api("PsGetNextProcessThread");
			Thread = PsGetNextProcessThread(Process, LastThread);

			if (Thread != NULL) {
				//PULONG64 debugPort = (PULONG64)((PUCHAR)argPEProcess + 0x420);
				//*debugPort = 0;		// set debug port
				// 判断是否是dnf进程
				//StoreSetDebugPort(Process, NULL);
				debug_system::set_debug_object(Process, NULL);

				ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
				GlobalHeld = FALSE;
				ObfDereferenceObject(LastThread);
				// 为所有线程发送假的创建消息
				// Status = DbgkpPostFakeThreadMessages(varPEProcess, DebugObject, Thread, &FirstThread, &LastThread);
				//DbgkpPostFakeThreadMessagesProc tempcallDbgkpPostFakeThreadMessagesProc = GetDbgkpPostFakeThreadMessagesProc();
				Status = debug_system::New_DbgkpPostFakeThreadMessages(Process, DebugObject, Thread, &FirstThread, &LastThread);
				if (!NT_SUCCESS(Status))
				{
					LastThread = NULL;
					break; // goto LABEL_10;
				}
				if (FirstThread != NULL)
					ObfDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	//
	// Lock the debug object so we can check its deleted status
	//
	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// We must not propagate a debug port thats got no handles left.
	//

	if (NT_SUCCESS(Status))
	{
		if (DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING)
		{
			//*((PUCHAR)varPEProcess + 0x420) = NULL;
			//PULONG64* debugPort = (PULONG64*)((PUCHAR)argPEProcess + 0x420);
			//*debugPort = NULL;		// set debug port
			//StoreSetDebugPort(Process, NULL);
			debug_system::set_debug_object(Process, NULL);
			Status = STATUS_DEBUGGER_INACTIVE;
		}
		else
		{
			// get Process Flags
			// TODO 下面这行可能会被检测，注释掉
			//PS_SET_BITS(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObfReferenceObject(DebugObject);
		}
	}

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {
		//v10 = Status;
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;
		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) != 0 && (PETHREAD_BY)DebugEvent->BackoutThread == ThisThread) {

			Thread = (PETHREAD_BY)DebugEvent->Thread;		// 获取DeubgEvent的0x40为Thread

			//
			// If the thread has not been inserted by CreateThread yet then don't
			// create a handle. We skip system threads here also
			//
			if (NT_SUCCESS(Status))
			{
				if ((DebugObject->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0)
				{
					PS_SET_BITS(&Thread->CrossThreadFlags, PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					if (First)
					{
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PS_SET_BITS(&Thread->CrossThreadFlags, PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
				}
			}
			else
			{
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;

				ExReleaseRundownProtection(&Thread->RundownProtect);
			}
		}
	} // for end

	ExReleaseFastMutex(&DebugObject->Mutex);
	if (GlobalHeld)
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
	if (LastThread)
		ObfDereferenceObject(LastThread);

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		//DbgkpWakeTarget(DebugEvent);
		Fn_DbgkpWakeTarget DbgkpWakeTarget = (Fn_DbgkpWakeTarget)ntkrnl->api("DbgkpWakeTarget");
		DbgkpWakeTarget(DebugEvent);
	}

	if (NT_SUCCESS(Status)) {
		//DbgkpMarkProcessPeb(varPEProcess);

		//DbgkpMarkProcessPebProc DbgkpMarkProcessPeb = GetDbgkpMarkProcessPebProc();
		//DbgkpMarkProcessPeb(Process);

		New_DbgkpMarkProcessPeb(Process);
	}
	return Status;
}


NTSTATUS NTAPI debug_system::New_DbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS_BY Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD_BY *pLastThread
)
{
	NTSTATUS Status;
	KAPC_STATE ApcState;
	PETHREAD_BY Thread;
	PETHREAD_BY LastThread;

	//
	// Attach to the process so we can touch its address space
	//
	KeStackAttachProcess((PEPROCESS)Process, &ApcState);

	Status = debug_system::New_DbgkpPostFakeThreadMessages(
		Process,
		DebugObject,
		NULL,
		&Thread,
		&LastThread);

	if (NT_SUCCESS(Status)) {
		Status = debug_system::New_DbgkpPostModuleMessages(Process, Thread, DebugObject);
		
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(LastThread);
			LastThread = NULL;
		}
		ObDereferenceObject(Thread);
	}
	else {
		LastThread = NULL;
	}

	KeUnstackDetachProcess(&ApcState);

	*pLastThread = LastThread;

	return Status;
}

NTSTATUS NTAPI debug_system::New_DbgkpPostFakeThreadMessages(
	IN PEPROCESS_BY Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD_BY StartThread,
	OUT PETHREAD_BY *pFirstThread,
	OUT PETHREAD_BY *pLastThread
)
{
	NTSTATUS Status;
	PETHREAD_BY Thread, FirstThread, LastThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	NTSTATUS Status1;

	LastThread = FirstThread = NULL;

	Status = STATUS_UNSUCCESSFUL;

	Fn_PsGetNextProcessThread PsGetNextProcessThread = (Fn_PsGetNextProcessThread)get_ntfunc("PsGetNextProcessThread");

	if (StartThread != NULL)
	{
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(FirstThread);
	}
	else
	{
		StartThread = PsGetNextProcessThread(Process, NULL);
		First = TRUE;
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = PsGetNextProcessThread(Process, Thread)) 
	{

		Flags = DEBUG_EVENT_NOWAIT;

		//
		// Keep a track ont he last thread we have seen.
		// We use this as a starting point for new threads after we
		// really attach so we can pick up any new threads.
		//
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
		LastThread = Thread;
		ObReferenceObject(LastThread);

		// 是否是系统线程
		if ((Thread->Tcb.MiscFlags & 0x400) == 0)
		{
			Fn_PsSynchronizeWithThreadInsertion PsSynchronizeWithThreadInsertion = (Fn_PsSynchronizeWithThreadInsertion)get_ntfunc("PsSynchronizeWithThreadInsertion");

			if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD
				|| (PsSynchronizeWithThreadInsertion(StartThread, Thread), Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD))
			{

				//
				// Acquire rundown protection of the thread.
				// This stops the thread exiting so we know it can't send
				// it's termination message
				//
				if (ExAcquireRundownProtection(&Thread->RundownProtect)) {
					Flags |= DEBUG_EVENT_RELEASE;

					//
					// Suspend the thread if we can for the debugger
					// We don't suspend terminating threads as we will not be giving details
					// of these to the debugger.
					//

					Fn_PsSuspendThread PsSuspendThread = (Fn_PsSuspendThread)get_ntfunc("PsSuspendThread");
					Status1 = PsSuspendThread(Thread, NULL);
					if (NT_SUCCESS(Status1)) {
						Flags |= DEBUG_EVENT_SUSPEND;
					}

				}
				else
				{
					//
					// Rundown protection failed for this thread.
					// This means the thread is exiting. We will mark this thread
					// later so it doesn't sent a thread termination message.
					// We can't do this now because this attach might fail.
					//
					Flags |= DEBUG_EVENT_PROTECT_FAILED;
				}

				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				if (First && (Flags & DEBUG_EVENT_PROTECT_FAILED) == 0) {
					IsFirstThread = TRUE;
				}
				else {
					IsFirstThread = FALSE;
				}

				if (IsFirstThread)
				{
					ApiMsg.ApiNumber = DbgKmCreateProcessApi;
					if (Process->SectionObject != NULL)  // system process doesn't have one of these!
					{

						Fn_DbgkpSectionToFileHandle DbgkpSectionToFileHandle = (Fn_DbgkpSectionToFileHandle)get_ntfunc("DbgkpSectionToFileHandle");
						ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
					}
					else
					{
						ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
					}

					ApiMsg.u.CreateProcessInfo.BaseOfImage = Process->SectionBaseAddress;

					KAPC_STATE Apc;
					KeStackAttachProcess((PKPROCESS)Process, &Apc);

					__try
					{
						NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
						if (NtHeaders)
						{
							ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; // Filling this in breaks MSDEV!
	//                        (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
							ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
							ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
						}
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
						ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
						ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
					}

					KeUnstackDetachProcess(&Apc);
				}
				else
				{
					ApiMsg.ApiNumber = DbgKmCreateThreadApi;
					ApiMsg.u.CreateThread.StartAddress = Thread->Win32StartAddress;
				}

				Status = debug_system::New_DbgkpQueueMessage(
					Process,
					Thread,
					&ApiMsg,
					Flags,
					DebugObject);

				Fn_PsResumeThread PsResumeThread = (Fn_PsResumeThread)get_ntfunc("PsResumeThread");

				if (!NT_SUCCESS(Status)) {
					if (Flags & DEBUG_EVENT_SUSPEND) {
						PsResumeThread(Thread, NULL);
					}
					if (Flags & DEBUG_EVENT_RELEASE) {
						ExReleaseRundownProtection(&Thread->RundownProtect);
					}
					if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
						ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
					}
					ObfDereferenceObject(Thread);
					break;
				}
				else if (IsFirstThread)
				{
					First = FALSE;
					ObReferenceObject(Thread);
					FirstThread = Thread;

					//DbgkSendSystemDllMessagesFn DbgkSendSystemDllMessages = GetDbgkSendSystemDllMessagesFn();
					//DbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
					New_DbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
				}
			}
		}

	}


	if (!NT_SUCCESS(Status)) {
		if (FirstThread) {
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	return Status;
}


NTSTATUS NTAPI debug_system::New_DbgkpPostModuleMessages(
	IN PEPROCESS_BY Process,
	IN PETHREAD_BY Thread,
	IN PDEBUG_OBJECT DebugObject
)
{
	PPEB_BY Peb = Process->Peb;
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY LdrHead, LdrNext;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DBGKM_APIMSG ApiMsg;
	ULONG i;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING Name;
	PIMAGE_NT_HEADERS NtHeaders;
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	if (Peb == NULL) {
		return STATUS_SUCCESS;
	}

	__try {
		Ldr = Peb->Ldr;

		LdrHead = &Ldr->InLoadOrderModuleList;

		ProbeForRead(LdrHead, sizeof(LIST_ENTRY), sizeof(UCHAR));
		for (LdrNext = LdrHead->Flink, i = 0;
			LdrNext != LdrHead && i < 500;	// DbgkpMaxModuleMsgs ->500<-
			LdrNext = LdrNext->Flink, i++) {

			//
			// First image got send with process create message
			//
			if (i > 0) {
				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				LdrEntry = CONTAINING_RECORD(LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForRead(LdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(UCHAR));

				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;
				ApiMsg.u.LoadDll.NamePointer = NULL;

				ProbeForRead(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

				NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders) {
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}

				Fn_MmGetFileNameForAddress MmGetFileNameForAddress = (Fn_MmGetFileNameForAddress)get_ntfunc("MmGetFileNameForAddress");
				Status = MmGetFileNameForAddress(NtHeaders, &Name);

				if (NT_SUCCESS(Status)) {
					InitializeObjectAttributes(&oa,
						&Name,
						OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						NULL,
						NULL);

					Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
						GENERIC_READ | SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_SYNCHRONOUS_IO_NONALERT);

					if (!NT_SUCCESS(Status)) {
						ApiMsg.u.LoadDll.FileHandle = NULL;
					}
					ExFreePool(Name.Buffer);
				}

				if (DebugObject)
				{
					Status = New_DbgkpQueueMessage(
						Process,
						Thread,
						&ApiMsg,
						DEBUG_EVENT_NOWAIT,
						DebugObject);
				}
				else
				{
					New_DbgkpSendApiMessage(
						Process,
						DEBUG_EVENT_READ | DEBUG_EVENT_NOWAIT,
						&ApiMsg);

					Status = STATUS_UNSUCCESSFUL;
				}

				if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
					ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
				}

			}
			ProbeForRead(LdrNext, sizeof(LIST_ENTRY), sizeof(UCHAR));
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	}

#if defined(_WIN64)
	if (Process->WoW64Process != NULL && Process->WoW64Process->Peb != NULL) {
		PPEB32_BY Peb32;
		PPEB_LDR_DATA32 Ldr32;
		PLIST_ENTRY32 LdrHead32, LdrNext32;
		PLDR_DATA_TABLE_ENTRY32 LdrEntry32;
		PWCHAR pSys;

		Peb32 = (PPEB32_BY)Process->WoW64Process->Peb;

		__try {
			Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);

			LdrHead32 = (PLIST_ENTRY32)&Ldr32->InLoadOrderModuleList;

			ProbeForRead(LdrHead32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink), i = 0;
				LdrNext32 != LdrHead32 && i < 500;
				LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink), i++) {

				if (i > 0) {
					RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

					LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					ProbeForRead(LdrEntry32, sizeof(LDR_DATA_TABLE_ENTRY32), sizeof(UCHAR));

					ApiMsg.ApiNumber = DbgKmLoadDllApi;
					ApiMsg.u.LoadDll.BaseOfDll = (PVOID)UlongToPtr(LdrEntry32->DllBase);
					ApiMsg.u.LoadDll.NamePointer = NULL;

					ProbeForRead(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

					NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
					if (NtHeaders) {
						ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
						ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
					}

					Fn_MmGetFileNameForAddress MmGetFileNameForAddress = (Fn_MmGetFileNameForAddress)get_ntfunc("MmGetFileNameForAddress");
					Status = MmGetFileNameForAddress(NtHeaders, &Name);

					if (NT_SUCCESS(Status)) {

						InitializeObjectAttributes(&oa,
							&Name,
							OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							NULL,
							NULL);

						Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
							GENERIC_READ | SYNCHRONIZE,
							&oa,
							&iosb,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							FILE_SYNCHRONOUS_IO_NONALERT);

						if (!NT_SUCCESS(Status)) {
							ApiMsg.u.LoadDll.FileHandle = NULL;
						}
						ExFreePool(Name.Buffer);
					}

					if (DebugObject)
					{
						Status = New_DbgkpQueueMessage(Process,
							Thread,
							&ApiMsg,
							DEBUG_EVENT_NOWAIT,
							DebugObject);
					}
					else
					{
						New_DbgkpSendApiMessage(
							Process,
							DEBUG_EVENT_READ | DEBUG_EVENT_NOWAIT,
							&ApiMsg);

						Status = STATUS_UNSUCCESSFUL;
					}

					if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
						ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
					}
				}

				ProbeForRead(LdrNext32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			}

		} __except(EXCEPTION_EXECUTE_HANDLER) {
		}
	}

#endif
	return STATUS_SUCCESS;
}

ULONG64 MyPsWow64GetProcessNtdllType(PEPROCESS_BY Process)
{
	EWOW64PROCESS *Wow64Process;
	ULONG64 NtdllType;

	NtdllType = 0;

	Wow64Process = Process->WoW64Process;
	if (Wow64Process)
		NtdllType = Wow64Process->NtdllType;

	return NtdllType;
}

VOID NTAPI debug_system::New_DbgkCreateThread(
	PETHREAD_BY Thread
)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	PEPROCESS_BY Process;
	PDBGKM_LOAD_DLL LoadDllArgs;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	PIMAGE_NT_HEADERS NtHeaders;
	PTEB Teb;
	LONG OldFlags;

	PFILE_OBJECT FileObject;

#if defined(_WIN64)
	PVOID Wow64Process;
#endif

	Process = (PEPROCESS_BY)Thread->Tcb.ApcState.Process;

#if defined(_WIN64)
	Wow64Process = Process->WoW64Process;
#endif

	OldFlags = PS_TEST_SET_BITS(&Process->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);

	Fn_PsCallImageNotifyRoutines PsCallImageNotifyRoutines = (Fn_PsCallImageNotifyRoutines)get_ntfunc("PsCallImageNotifyRoutines");
	
	if (!_bittest(&OldFlags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_PROCESS_EXITING | PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES))
	{
		//TODO 这里不通知，先看看有没有问题

		/*PULONG PspNotifyEnableMask = GetPspNotifyEnableMask();
		PUINT16 PerfGlobalGroupMask = GetPerfGlobalGroupMask();*/
		ULONG PspNotifyEnableMask = 1;
		ULONG PerfGlobalGroupMask = 4;

		if (PspNotifyEnableMask & 1 || PerfGlobalGroupMask & 4) 
		{
			IMAGE_INFO_EX ImageInfoEx = { 0 };
			PUNICODE_STRING UnicodeFileName;
			POBJECT_NAME_INFORMATION FileNameInfo;

			//
			// notification of main .exe
			//
			ImageInfoEx.ImageInfo.Properties = 0;
			ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
			ImageInfoEx.ImageInfo.ImageBase = Process->SectionBaseAddress;
			ImageInfoEx.ImageInfo.ImageSize = 0;

			__try 
			{

				NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);

				if (NtHeaders) {
#if defined(_WIN64)
					if (Wow64Process != NULL) {
						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, SizeOfImage);
					}
					else {
#endif
						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
#if defined(_WIN64)
					}
#endif
				}
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				ImageInfoEx.ImageInfo.ImageSize = 0;
			}
			ImageInfoEx.ImageInfo.ImageSelector = 0;
			ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

			//Status = SeLocateProcessImageName(Process, &UnicodeFileName);
			//if (!NT_SUCCESS(Status))
			//{
			//	UnicodeFileName = NULL;
			//}

			PsReferenceProcessFilePointer(Process, &FileObject);

			ImageInfoEx.FileObject = FileObject;

			PsCallImageNotifyRoutines(
				&Process->SeAuditProcessCreationInfo.ImageFileName->Name,
				Process,
				&ImageInfoEx.ImageInfo,
				FileObject
			);

			//PsCallImageNotifyRoutines(
			//	Process->SeAuditProcessCreationInfo.ImageFileName,
			//	Process->UniqueProcessId,
			//	&ImageInfoEx.ImageInfo,
			//	FileObject
			//);

			//if (UnicodeFileName)
			//{
			//	ExFreePool(UnicodeFileName);
			//}

			ObfDereferenceObject(FileObject);

			int index = 0;
			for (index = 0; ; ++index)
			{
				if (index >= 6)
					break;

				Fn_PsQuerySystemDllInfo PsQuerySystemDllInfo = (Fn_PsQuerySystemDllInfo)debug_system::get_ntfunc("PsQuerySystemDllInfo");
				PPS_SYSTEM_DLL_INFO SystemDllInfo = PsQuerySystemDllInfo(index);

				if (SystemDllInfo && (index <= 0 || SystemDllInfo->MachineType && Wow64Process != NULL && index == MyPsWow64GetProcessNtdllType(Process)))
				{

					//
					// and of ntdll.dll
					//
					ImageInfoEx.ImageInfo.Properties = 0;
					ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
					ImageInfoEx.ImageInfo.ImageBase = SystemDllInfo->ImageBase;
					ImageInfoEx.ImageInfo.ImageSize = 0;

					__try 
					{
						NtHeaders = RtlImageNtHeader(SystemDllInfo->ImageBase);

						if (NtHeaders) {
#if defined(_WIN64)
							if (Wow64Process != NULL) {
								ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, SizeOfImage);
							}
							else {
#endif
								ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
#if defined(_WIN64)
							}
#endif
						}
					} 
					__except(EXCEPTION_EXECUTE_HANDLER) {
						ImageInfoEx.ImageInfo.ImageSize = 0;
					}
					ImageInfoEx.ImageInfo.ImageSelector = 0;
					ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

					PPS_SYSTEM_DLL SystemDll = CONTAINING_RECORD(SystemDllInfo, PS_SYSTEM_DLL, SystemDllInfo);

					Fn_PspReferenceSystemDll PspReferenceSystemDll = (Fn_PspReferenceSystemDll)debug_system::get_ntfunc("PspReferenceSystemDll");
					PSECTION Section = PspReferenceSystemDll(&SystemDll->SectionObjectFastRef);

					Fn_MiSectionControlArea MiSectionControlArea = (Fn_MiSectionControlArea)debug_system::get_ntfunc("MiSectionControlArea");
					PCONTROL_AREA ControlArea = MiSectionControlArea(Section);

					Fn_MiReferenceControlAreaFile MiReferenceControlAreaFile = (Fn_MiReferenceControlAreaFile)debug_system::get_ntfunc("MiReferenceControlAreaFile");
					FileObject = MiReferenceControlAreaFile(ControlArea);

					if (FileObject != NULL)
					{
						Fn_ObFastDereferenceObject ObFastDereferenceObject = (Fn_ObFastDereferenceObject)debug_system::get_ntfunc("ObFastDereferenceObject");
						ObFastDereferenceObject(
							&SystemDll->SectionObjectFastRef,
							Section
						);
					}

					PsCallImageNotifyRoutines(&SystemDllInfo->Ntdll32Path, Process, &ImageInfoEx.ImageInfo, FileObject);

					ObfDereferenceObject(FileObject);

				}
			}
		}
	}

	//Port = Process->DebugPort;
	Port = debug_system::get_debug_object(Process);

	if (Port == NULL) {
		return;
	}

	//
	// Make sure we only get one create process message
	//

	if ((OldFlags & PS_PROCESS_FLAGS_CREATE_REPORTED) == 0) {

		//
		// This is a create process
		//

		CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
		CreateThreadArgs->SubSystemKey = 0;

		CreateProcessArgs = &m.u.CreateProcessInfo;
		CreateProcessArgs->SubSystemKey = 0;

		Fn_DbgkpSectionToFileHandle DbgkpSectionToFileHandle = (Fn_DbgkpSectionToFileHandle)get_ntfunc("DbgkpSectionToFileHandle");
		CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);

		CreateProcessArgs->BaseOfImage = Process->SectionBaseAddress;
		CreateThreadArgs->StartAddress = NULL;
		CreateProcessArgs->DebugInfoFileOffset = 0;
		CreateProcessArgs->DebugInfoSize = 0;


		__try 
		{

			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);

			if (NtHeaders) {

#if defined(_WIN64)
				if (Wow64Process != NULL) {
					CreateThreadArgs->StartAddress = UlongToPtr(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, ImageBase) +
						DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, AddressOfEntryPoint));
				}
				else {
#endif
					CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) +
						DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));
#if defined(_WIN64)
				}
#endif

				//
				// The following fields are safe for Wow64 as the offsets
				// are the same for a PE32+ as a PE32 header.
				//

				CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			CreateThreadArgs->StartAddress = NULL;
			CreateProcessArgs->DebugInfoFileOffset = 0;
			CreateProcessArgs->DebugInfoSize = 0;
		}

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));

		//DbgkpSendApiMessageProc DbgkpSendApiMessage0 = GetDbgkpSendApiMessageProc();
		New_DbgkpSendApiMessage(Process, FALSE, &m);

		if (CreateProcessArgs->FileHandle != NULL) {
			ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
		}

		//DbgkSendSystemDllMessages(NULL, NULL, &m);
		New_DbgkSendSystemDllMessages(NULL, NULL, &m);

		if (Thread->SameThreadPassiveFlags & PS_CROSS_THREAD_FLAGS_SYSTEM)
		{
			New_DbgkpPostModuleMessages(Process, Thread, NULL);
		}
	}
	else
	{
		CreateThreadArgs = &m.u.CreateThread;
		CreateThreadArgs->SubSystemKey = 0;
		CreateThreadArgs->StartAddress = Thread->Win32StartAddress;

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));

		New_DbgkpSendApiMessage(Process, TRUE, &m);
	}
}


NTSTATUS NTAPI debug_system::New_DbgkpQueueMessage(
	IN PEPROCESS_BY Process,
	IN PETHREAD_BY Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)
{
	DEBUG_EVENT StaticDebugEvent; // rbx		v5
	NTSTATUS Status; // ebx
	PDEBUG_EVENT DebugEvent; // rax
	PDEBUG_OBJECT DebugObject = NULL;	// v5
	ULONG ThreadCrossThreadFlags;

	if (Flags & DEBUG_EVENT_NOWAIT)
	{
		//DebugEvent = ExAllocatePoolWithQuotaTag(520, 0x168, 0x45676244);
		DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag(NonPagedPoolNx, sizeof(DEBUG_EVENT), POOL_TAG);
		if (DebugEvent == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObfReferenceObject(Process);
		ObfReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();

		DebugObject = TargetDebugObject;
	}
	else
	{
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

		DebugObject = debug_system::get_debug_object(Process);

		ThreadCrossThreadFlags = Thread->CrossThreadFlags;

		//
		// See if this create message has already been sent.
		//
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (ThreadCrossThreadFlags & PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION) {
				DebugObject = NULL;
			}
		}

		if (ApiMsg->ApiNumber == DbgKmLoadDllApi) {
			if (ThreadCrossThreadFlags & Flags & PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION) {
				DebugObject = NULL;
			}
		}

		//
		// See if this exit message is for a thread that never had a create
		//
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (SLOBYTE(ThreadCrossThreadFlags) < 0) {
				DebugObject = NULL;
			}
		}

		KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	}

	// TODO
	DebugEvent->Process = (PEPROCESS)Process;
	DebugEvent->Thread = (PETHREAD)Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL)
	{
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		//
		// We must not use a debug port thats got no handles left.
		//
		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then don't use this object.
		//
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			//
			// Set the event to say there is an unread event in the object
			//
			if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		KeReleaseGuardedMutex(&DebugObject->Mutex);
	}

	if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
		KeReleaseGuardedMutex(&DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObfDereferenceObject(Process);
			ObfDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}

BOOLEAN NTAPI debug_system::New_DbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance
)
{
	PEPROCESS_BY Process;
	PVOID Port;
	ULONG64 v21;
	DBGKM_APIMSG m;
	PDBGKM_EXCEPTION args;
	NTSTATUS st = STATUS_SUCCESS;
	BOOLEAN LpcPort;

	//char image_name[18] = { 0 };
	//memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	//Log("DbgkForwardException, Process: %s, ExceptionCode: %x\r\n", image_name, ExceptionRecord->ExceptionCode);

	args = &m.u.Exception;

	//
	// Initialize the debug LPC message with default information.
	//
	DBGKM_FORMAT_API_MSG(m, DbgKmExceptionApi, sizeof(*args));

	Process = (PEPROCESS_BY)PsGetCurrentProcess();

	if (SecondChance)
	{
		v21 = 1;
		PsSetProcessFaultInformation(Process, &v21);
	}

	if (DebugException) {
		/*if (PsApiGetThreadCrossThreadFlags(KeGetCurrentThread()) & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
			Port = NULL;
		}
		else
		{
			Port = PsApiGetProcessDebugPort(Process);
		}*/

		Port = debug_system::get_debug_object(Process);
		LpcPort = FALSE;
	}
	else {
		Fn_PsCaptureExceptionPort PsCaptureExceptionPort = (Fn_PsCaptureExceptionPort)ntkrnl->api("PsCaptureExceptionPort");
		Port = PsCaptureExceptionPort(Process);
		m.h.u2.ZeroInit = LPC_EXCEPTION;
		LpcPort = TRUE;
	}

	//
	// If the destination LPC port address is NULL, then return FALSE.
	//
	if (Port == NULL && DebugException)
		return FALSE;

	//
	// Fill in the remainder of the debug LPC message.
	//
	args->ExceptionRecord = *ExceptionRecord;
	args->FirstChance = !SecondChance;

	//
	// Send the debug message to the destination LPC port.
	//
	if (LpcPort) {
		if (Port != NULL)
		{
			Fn_DbgkpSendApiMessageLpc DbgkpSendApiMessageLpc = (Fn_DbgkpSendApiMessageLpc)ntkrnl->api("DbgkpSendApiMessageLpc");
			st = DbgkpSendApiMessageLpc(&m, Port, DebugException);
			ObfDereferenceObject(Port);
		}

		m.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
	}
	else
	{
		st = New_DbgkpSendApiMessage(Process, DebugException, &m);
	}

	//
	// If the send was not successful, then return a FALSE indicating that
	// the port did not handle the exception. Otherwise, if the debug port
	// is specified, then look at the return status in the message.
	//
	if (!NT_SUCCESS(st))
		return FALSE;

	if (m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED) {
		if (!DebugException)
		{
			Fn_DbgkpSendErrorMessage DbgkpSendErrorMessage = (Fn_DbgkpSendErrorMessage)ntkrnl->api("DbgkpSendErrorMessage");
			st = DbgkpSendErrorMessage(ExceptionRecord, 2, &m);
			st = STATUS_UNSUCCESSFUL;
			return NT_SUCCESS(st);
		}
		return FALSE;
	}
	return NT_SUCCESS(st);
}


NTSTATUS NTAPI debug_system::New_DbgkClearProcessDebugObject(
	IN PEPROCESS_BY Process,
	IN PDEBUG_OBJECT SourceDebugObject
)
{
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;

	ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

	
	DebugObject = debug_system::get_debug_object(Process);
	if (DebugObject == NULL || (DebugObject != SourceDebugObject && SourceDebugObject != NULL)) {
		DebugObject = NULL;
		Status = STATUS_PORT_NOT_SET;
	}
	else {
		debug_system::set_debug_object(Process, nullptr);
		Status = STATUS_SUCCESS;
	}
	ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

	if (NT_SUCCESS(Status)) {
		New_DbgkpMarkProcessPeb(Process);
	}

	//
	// Remove any events for this process and wake up the threads.
	//
	if (DebugObject) {
		//
		// Remove any events and queue them to a temporary queue
		//
		InitializeListHead(&TempList);

		ExAcquireFastMutex(&DebugObject->Mutex);
		for (Entry = DebugObject->EventList.Flink;
			Entry != &DebugObject->EventList;
			) {

			DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
			Entry = Entry->Flink;
			if (DebugEvent->Process == (PEPROCESS)Process) {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}
		}
		ExReleaseFastMutex(&DebugObject->Mutex);

		ObDereferenceObject(DebugObject);

		//
		// Wake up all the removed threads.
		//
		while (!IsListEmpty(&TempList)) {
			Entry = RemoveHeadList(&TempList);
			DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
			DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
			//DbgkpWakeTarget(DebugEvent);
			Fn_DbgkpWakeTarget DbgkpWakeTarget = (Fn_DbgkpWakeTarget)ntkrnl->api("DbgkpWakeTarget");
			DbgkpWakeTarget(DebugEvent);
		}
	}

	return Status;
}


NTSTATUS NTAPI debug_system::New_DbgkpSendApiMessage(
	PEPROCESS_BY Process,
	ULONG Flags,
	PDBGKM_APIMSG ApiMsg
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN SuspendProcess;
	PETHREAD_BY Thread;

	Thread = (PETHREAD_BY)PsGetCurrentThread();

	// TODO 这里不发送etw事件
	//PUINT16 PerfGlobalGroupMask = GetPerfGlobalGroupMask();
	//EtwTraceDebuggerEventFn EtwTraceDebuggerEvent = GetEtwTraceDebuggerEventFn();
	//if (*PerfGlobalGroupMask & 0x400000)
	//	EtwTraceDebuggerEvent(Thread->Tcb.ApcState.Process, KeGetCurrentThread(), 1);

	do {
		SuspendProcess = FALSE;

		if ((PEPROCESS)Process == Thread->Tcb.ApcState.Process && (Flags & 1))
		{
			Fn_DbgkpSuspendProcess DbgkpSuspendProcess = (Fn_DbgkpSuspendProcess)ntkrnl->api("DbgkpSuspendProcess");
			SuspendProcess = DbgkpSuspendProcess(Process);
		}

		ApiMsg->ReturnedStatus = STATUS_PENDING;

		Status = New_DbgkpQueueMessage(
			Process, 
			(PETHREAD_BY)PsGetCurrentThread(), 
			ApiMsg, 
			(Flags & DEBUG_EVENT_NOWAIT) != 0 ? 0x40 : 0, 
			NULL
		);

		//Status = DbgkpQueueMessage(
		//	Process, 
		//	PsGetCurrentThread(), 
		//	ApiMsg, 
		//	(Flags & DEBUG_EVENT_NOWAIT) != 0 ? 0x40 : 0, 
		//	NULL);

		ZwFlushInstructionCache((HANDLE)-1, NULL, 0);

		if (SuspendProcess) {
			Fn_PsThawProcess PsThawProcess = (Fn_PsThawProcess)ntkrnl->api("PsThawProcess");
			PsThawProcess(Process, 0);
			KeLeaveCriticalRegion();
		}
	} while (NT_SUCCESS(Status) && ApiMsg->ReturnedStatus == DBG_REPLY_LATER);

	return Status;
}

NTSTATUS NTAPI debug_system::New_DbgkExitThread(
	NTSTATUS ExitStatus
)
{
	PVOID DebugPort;
	DBGKM_APIMSG m;
	PDBGKM_EXIT_THREAD args;
	PEPROCESS_BY Process;
	PETHREAD_BY Thread;

	NTSTATUS Status = STATUS_SUCCESS;
	
	Thread = (PETHREAD_BY)PsGetCurrentThread();
	Process = (PEPROCESS_BY)PsGetCurrentProcess();

	//if (!(Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG))
	//{
	//}

	//DebugPort = Process->DebugPort;
	DebugPort = debug_system::get_debug_object(Process);
	if (DebugPort)
	{
		if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD)
		{
			args = &m.u.ExitThread;
			args->ExitStatus = ExitStatus;

			DBGKM_FORMAT_API_MSG(m, DbgKmExitThreadApi, sizeof(*args));

			Status = New_DbgkpSendApiMessage(Process, TRUE, &m);
		}
	}

	return Status;
}

NTSTATUS NTAPI debug_system::New_DbgkExitProcess(
	NTSTATUS ExitStatus
)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_EXIT_PROCESS args;
	PEPROCESS_BY Process;
	PETHREAD_BY Thread;

	NTSTATUS Status = STATUS_SUCCESS;

	Thread = (PETHREAD_BY)PsGetCurrentThread();
	Process = (PEPROCESS_BY)Thread->Tcb.ApcState.Process;

	/*if (!(Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG))
	{
	}*/
	//Port = Process->DebugPort;
	Port = debug_system::get_debug_object(Process);
	if (Port)
	{
		if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD)
		{
			//
			// this ensures that other timed lockers of the process will bail
			// since this call is done while holding the process lock, and lock duration
			// is controlled by debugger
			//

			KeQuerySystemTime(&Process->ExitTime);

			args = &m.u.ExitProcess;
			args->ExitStatus = ExitStatus;

			DBGKM_FORMAT_API_MSG(m, DbgKmExitProcessApi, sizeof(*args));

			Status = New_DbgkpSendApiMessage(Process, FALSE, &m);
			//Status = DbgkpSendApiMessage(Process, FALSE, &m);
		}
	}

	return Status;
}


VOID NTAPI debug_system::New_DbgkMapViewOfSection(
	IN PEPROCESS_BY Process,
	IN PVOID SectionObject,
	IN PVOID SectionBaseAddress
)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_LOAD_DLL LoadDllArgs;
	PIMAGE_NT_HEADERS NtHeaders;
	PETHREAD_BY Thread;
	PTEB Teb;

	NTSTATUS Status = STATUS_SUCCESS;

	//Fn_DbgkMapViewOfSection DbgkMapViewOfSection = (Fn_DbgkMapViewOfSection)hook_DbgkMapViewOfSection->bridge();
	//DbgkMapViewOfSection(Process, SectionObject, SectionBaseAddress);
	//// 如果该`被调试进程`没有注册，则不向自定义的DebugObject发送事件，直接返回
	//uint64_t DebugeeProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	//if (!debug_system::get_state_by_debugee_pid(DebugeeProcessId, nullptr))
	//{
	//	return;
	//}

	Thread = (PETHREAD_BY)PsGetCurrentThread();

	if (Thread->Tcb.PreviousMode == KernelMode && Process->Pcb.SecureState == 0) {
		return;
	}

	//if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
	//	Port = NULL;
	//}
	//else {
	//	Port = Process->DebugPort;
	//}

	//Port = Process->DebugPort;
	Port = debug_system::get_debug_object(Process);

	if (!Port) {
		return;
	}

	char image_name[18] = { 0 };
	memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	Log("[DbgkMapViewOfSection] Send debug message, current process: %s\r\n", image_name);

	if (Thread->Tcb.MiscFlags & 0x400 || KeIsAttachedProcess())
		Teb = NULL;
	else
		Teb = (PTEB)Thread->Tcb.Teb;

	// TODO
	//Fn_DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg = (Fn_DbgkpSuppressDbgMsg)get_ntfunc("get_DbgkpSuppressDbgMsg");
	if (Teb == NULL || (PEPROCESS)Process != Thread->Tcb.Process || debug_system::New_DbgkpSuppressDbgMsg(Teb) == 0)
	{
		Fn_DbgkpSectionToFileHandle DbgkpSectionToFileHandle = (Fn_DbgkpSectionToFileHandle)get_ntfunc("DbgkpSectionToFileHandle");

		LoadDllArgs = &m.u.LoadDll;
		LoadDllArgs->FileHandle = DbgkpSectionToFileHandle(SectionObject);
		LoadDllArgs->BaseOfDll = SectionBaseAddress;
		LoadDllArgs->DebugInfoFileOffset = 0;
		LoadDllArgs->DebugInfoSize = 0;


		__try {
			NtHeaders = RtlImageNtHeader(SectionBaseAddress);

			if (NtHeaders != NULL) {
				LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		} 
		__except(EXCEPTION_EXECUTE_HANDLER) {
			LoadDllArgs->DebugInfoFileOffset = 0;
			LoadDllArgs->DebugInfoSize = 0;
			LoadDllArgs->NamePointer = NULL;
		}

		DBGKM_FORMAT_API_MSG(m, DbgKmLoadDllApi, sizeof(*LoadDllArgs));

		New_DbgkpSendApiMessage(Process, TRUE, &m);

		if (LoadDllArgs->FileHandle != NULL) {
			ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
		}
	}
}

VOID NTAPI debug_system::New_DbgkUnMapViewOfSection(
	IN PEPROCESS_BY Process,
	IN PVOID BaseAddress
)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_UNLOAD_DLL UnloadDllArgs;
	PTEB Teb;
	PETHREAD_BY Thread;

	//Fn_DbgkUnMapViewOfSection DbgkUnMapViewOfSection = (Fn_DbgkUnMapViewOfSection)hook_DbgkUnMapViewOfSection->bridge();
	//DbgkUnMapViewOfSection(Process, BaseAddress);
	//// 如果该`被调试进程`没有注册，则不向自定义的DebugObject发送事件，直接返回
	//uint64_t DebugeeProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	//if (!debug_system::get_state_by_debugee_pid(DebugeeProcessId, nullptr))
	//{
	//	return;
	//}

	Thread = (PETHREAD_BY)PsGetCurrentThread();

	if (Thread->Tcb.PreviousMode == KernelMode) {
		return;
	}

	/*if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
		Port = NULL;
	}
	else {
		Port = PsGetCurrentProcess()->DebugPort;
	}*/

	//Port = Process->DebugPort;
	Port = debug_system::get_debug_object(Process);

	if (!Port) {
		return;
	}

	char image_name[18] = { 0 };
	memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	Log("[DbgkUnMapViewOfSection] Send debug message, current process: %s\r\n", image_name);

	if (Thread->Tcb.MiscFlags & 0x400 || KeIsAttachedProcess())
		Teb = NULL;
	else
		Teb = (PTEB)Thread->Tcb.Teb;

	// TODO
	//Fn_DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg = (Fn_DbgkpSuppressDbgMsg)ntkrnl->api("DbgkpSuppressDbgMsg");
	if (Teb == NULL || (PEPROCESS)Process != Thread->Tcb.Process || debug_system::New_DbgkpSuppressDbgMsg(Teb) == 0)
	{
		UnloadDllArgs = &m.u.UnloadDll;
		UnloadDllArgs->BaseAddress = BaseAddress;

		DBGKM_FORMAT_API_MSG(m, DbgKmUnloadDllApi, sizeof(*UnloadDllArgs));

		New_DbgkpSendApiMessage(Process, TRUE, &m);
	}
}

VOID NTAPI debug_system::New_KiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
)
{

	if (PreviousMode == KernelMode)
	{
	}
	else
	{

		/*ULONG NumberParameters = ExceptionRecord->NumberParameters + 4;
		PVOID Dst = ((PUCHAR)ExceptionRecord) + (size_t)NumberParameters * 8;
		ULONG64 Size1 = ((ULONG64)ExceptionRecord) - (ULONG64)Dst + 0x98;

		memset(&ExceptionRecord->ExceptionInformation[ExceptionRecord->NumberParameters], 0, (size_t)-8 * ((size_t)ExceptionRecord->NumberParameters + 4) + 0x98);*/

		//用户模式也有一次进入KiDebugRoutine的机会.

		if (ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT || 
			ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		{
			HANDLE pid = PsGetCurrentProcessId();
			if (debug_system::get_state_by_debugee_pid(uint64_t(pid), nullptr))
			{
				//User
				if (New_DbgkForwardException(ExceptionRecord, TRUE, FALSE))
				{
					return; //如果调试器处理成功 直接返回 不继续处理了 仅只给一次机会.
				}
			}
		}

	}
	
	if (debug_system::hook_KiDispatchException)
	{
		Fn_KiDispatchException KiDispatchException = (Fn_KiDispatchException)hook_KiDispatchException->bridge();
		if (!KiDispatchException)
		{
			DbgBreakPoint();//必死无疑
		}

		//失败或正常进入 则再次执行
		return KiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
	}
	else
	{
		DbgBreakPoint();
	}
}

int ExSystemExceptionFilter()
{
	return(ExGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH
		);
}

NTSTATUS NTAPI debug_system::New_NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
)
{
	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	LARGE_INTEGER Tmo = { 0 };
	LARGE_INTEGER StartTime = { 0 };
	DBGUI_WAIT_STATE_CHANGE tWaitStateChange;
	PEPROCESS_BY Process;
	PETHREAD_BY Thread;
	PLIST_ENTRY Entry, Entry2;
	PDEBUG_EVENT DebugEvent, DebugEvent2;
	BOOLEAN GotEvent;

	memset(&tWaitStateChange, 0, sizeof(DBGUI_WAIT_STATE_CHANGE));

	char image_name[18] = { 0 };
	memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	Log("[NtWaitForDebugEvent] current process: %s\r\n", image_name);

	PreviousMode = ExGetPreviousMode();

	__try 
	{
		if (ARGUMENT_PRESENT(Timeout)) {
			if (PreviousMode != KernelMode) {
				ProbeForRead(Timeout, sizeof(*Timeout), sizeof(UCHAR));
			}
			Tmo = *Timeout;
			Timeout = &Tmo;
			KeQuerySystemTime(&StartTime);
		}
		if (PreviousMode != KernelMode) {
			ProbeForWrite(WaitStateChange, sizeof(*WaitStateChange), sizeof(UCHAR));
		}

	} 
	__except(ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}


	Status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		DEBUG_READ_EVENT,
		DbgkDebugObjectType,
		PreviousMode,
		(PVOID *)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Process = NULL;
	Thread = NULL;

	while (1) {
		Status = KeWaitForSingleObject(
			&DebugObject->EventsPresent,
			Executive,
			PreviousMode,
			Alertable,
			Timeout);
		if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT || Status == STATUS_ALERTED || Status == STATUS_USER_APC) {
			break;
		}

		GotEvent = FALSE;

		DebugEvent = NULL;

		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then return an error.
		//
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {

			for (Entry = DebugObject->EventList.Flink;
				Entry != &DebugObject->EventList;
				Entry = Entry->Flink)
			{

				DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

				//
				// If this event has not been given back to the user yet and is not
				// inactive then pass it back.
				// We check to see if we have any other outstanding messages for this
				// thread as this confuses VC. You can only get multiple events
				// for the same thread for the attach faked messages.
				//
				if ((DebugEvent->Flags & (DEBUG_EVENT_READ | DEBUG_EVENT_INACTIVE)) == 0) {
					GotEvent = TRUE;
					for (Entry2 = DebugObject->EventList.Flink;
						Entry2 != Entry;
						Entry2 = Entry2->Flink) {

						DebugEvent2 = CONTAINING_RECORD(Entry2, DEBUG_EVENT, EventList);

						if (DebugEvent->ClientId.UniqueProcess == DebugEvent2->ClientId.UniqueProcess) {
							//
							// This event has the same process as an earlier event. Mark it as inactive.
							//
							DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
							DebugEvent->BackoutThread = NULL;
							GotEvent = FALSE;
							break;
						}
					}
					if (GotEvent) {
						break;
					}
				}
			}

			if (GotEvent) {
				Process = (PEPROCESS_BY)DebugEvent->Process;
				Thread = (PETHREAD_BY)DebugEvent->Thread;
				ObReferenceObject(Thread);
				ObReferenceObject(Process);

				Fn_DbgkpConvertKernelToUserStateChange DbgkpConvertKernelToUserStateChange = (Fn_DbgkpConvertKernelToUserStateChange)get_ntfunc("DbgkpConvertKernelToUserStateChange");
				DbgkpConvertKernelToUserStateChange(&tWaitStateChange, DebugEvent);

				DebugEvent->Flags |= DEBUG_EVENT_READ;
			}
			else {
				//
				// No unread events there. Clear the event.
				//
				KeClearEvent(&DebugObject->EventsPresent);
			}
			Status = STATUS_SUCCESS;

		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);

		if (NT_SUCCESS(Status)) {
			//
			// If we woke up and found nothing
			//
			if (GotEvent == FALSE)
			{
				//
				// If timeout is a delta time then adjust it for the wait so far.
				//
				if (Tmo.QuadPart < 0) {
					LARGE_INTEGER NewTime;
					KeQuerySystemTime(&NewTime);
					Tmo.QuadPart = Tmo.QuadPart + (NewTime.QuadPart - StartTime.QuadPart);
					StartTime = NewTime;
					if (Tmo.QuadPart >= 0) {
						Status = STATUS_TIMEOUT;
						break;
					}
				}
			}
			else
			{
				//
				// Fixup needed handles. The caller could have guessed the thread id etc by now and made the target thread
				// continue. This isn't a problem as we won't do anything damaging to the system in this case. The caller
				// won't get the correct results but they set out to break us.
				//

				Fn_DbgkpOpenHandles DbgkpOpenHandles = (Fn_DbgkpOpenHandles)get_ntfunc("DbgkpOpenHandles");
				DbgkpOpenHandles(&tWaitStateChange, Process, Thread);
				ObDereferenceObject(Thread);
				ObDereferenceObject(Process);
				break;
			}
		}
		else {
			break;
		}
	}

	ObDereferenceObject(DebugObject);

	__try {
		*WaitStateChange = tWaitStateChange;
	} 
	__except(ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		Status = GetExceptionCode();
	}
	return Status;
}

VOID NTAPI debug_system::New_DbgkSendSystemDllMessages(
	PETHREAD_BY Thread,
	PDEBUG_OBJECT DebugObject,
	PDBGKM_APIMSG ApiMsg
)
{
	PEPROCESS_BY Process = NULL;
	PDBGKM_LOAD_DLL LoadDllArgs = NULL;
	PVOID ImageBase = NULL;
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	PTEB Teb = NULL;

	BOOLEAN IsStackAttach;

	NTSTATUS Status;

	KAPC_STATE ApcState = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

#if defined(_WIN64)
	PVOID Wow64Process;
#endif

	if (Thread)
		Process = (PEPROCESS_BY)Thread->Tcb.ApcState.Process;
	else
		Process = (PEPROCESS_BY)KeGetCurrentThread()->ApcState.Process;

#if defined(_WIN64)
	Wow64Process = Process->WoW64Process;
#endif

	LoadDllArgs = &ApiMsg->u.LoadDll;

	for (int i = 0; i < 6; ++i)
	{
		Fn_PsQuerySystemDllInfo PsQuerySystemDllInfo = (Fn_PsQuerySystemDllInfo)get_ntfunc("PsQuerySystemDllInfo");
		PPS_SYSTEM_DLL_INFO SystemDllInfo = PsQuerySystemDllInfo(i);

		if (SystemDllInfo && (i <= 0 || SystemDllInfo->MachineType && Wow64Process && i == MyPsWow64GetProcessNtdllType(Process)))
		{
			memset(LoadDllArgs, 0, sizeof(DBGKM_LOAD_DLL));

			ImageBase = SystemDllInfo->ImageBase;
			LoadDllArgs->BaseOfDll = ImageBase;

			if (Thread && i)
			{
				IsStackAttach = TRUE;
				KeStackAttachProcess((PEPROCESS)Process, &ApcState);
			}
			else
			{
				IsStackAttach = FALSE;
			}

			NtHeaders = RtlImageNtHeader(ImageBase);

			if (NtHeaders)
			{
				LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}

			if (Thread == NULL)
			{
				LONG MiscFlags = KeGetCurrentThread()->MiscFlags;
				if (_bittest(&MiscFlags, 0xa) || KeIsAttachedProcess())
					Teb = NULL;
				else
					Teb = (PTEB)KeGetCurrentThread()->Teb;

				if (Teb)
				{

					__try
					{
						RtlStringCbCopyW(Teb->StaticUnicodeBuffer, 0x20A, (const wchar_t *)SystemDllInfo->Reserved2);
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						if (IsStackAttach)
							KeUnstackDetachProcess(&ApcState);
						continue;
					}

					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					LoadDllArgs->NamePointer = Teb->NtTib.ArbitraryUserPointer;
				}
			}

			if (IsStackAttach)
				KeUnstackDetachProcess(&ApcState);

			InitializeObjectAttributes(
				&oa,
				&SystemDllInfo->Ntdll32Path,
				OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			Status = ZwOpenFile(
				&LoadDllArgs->FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&oa,
				&IoStatusBlock,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_SYNCHRONOUS_IO_NONALERT);

			if (!NT_SUCCESS(Status))
			{
				LoadDllArgs->FileHandle = NULL;
			}

			DBGKM_FORMAT_API_MSG(*ApiMsg, DbgKmLoadDllApi, sizeof(*LoadDllArgs));

			if (Thread)
			{
				Status = New_DbgkpQueueMessage(Process, Thread, ApiMsg, 2, DebugObject);
				if (!NT_SUCCESS(Status) && LoadDllArgs->FileHandle)
				{
					ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
				}
			}
			else
			{
				New_DbgkpSendApiMessage(Process, 3, ApiMsg);

				if (LoadDllArgs->FileHandle)
				{
					ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
				}

				if (Teb)
				{
					Teb->NtTib.ArbitraryUserPointer = 0;
				}
			}
		}
	}
}

FORCEINLINE
VOID
ProbeForWriteHandle(
	IN PHANDLE Address
)

{

	if (Address >= (HANDLE *const)MM_USER_PROBE_ADDRESS) {
		Address = (HANDLE *const)MM_USER_PROBE_ADDRESS;
	}

	*((volatile HANDLE *)Address) = *Address;
	return;
}

NTSTATUS NTAPI debug_system::New_NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
)
{
	NTSTATUS Status;
	HANDLE Handle;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;

	char image_name[18] = { 0 };
	memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	Log("[NtCreateDebugObject] current process: %s\r\n", image_name);

	//uint64_t DebuggerProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	//debug_state_t *state = nullptr;
	//if (!debug_system::get_state_by_debugger_pid(DebuggerProcessId, &state))
	//{
	//	Fn_NtCreateDebugObject NtCreateDebugObject = (Fn_NtCreateDebugObject)hook_NtCreateDebugObject->bridge();
	//	return NtCreateDebugObject(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);
	//}

	//
	// Get previous processor mode and probe output arguments if necessary.
	// Zero the handle for error paths.
	//
	PreviousMode = ExGetPreviousMode();

	__try
	{
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle(DebugObjectHandle);
		}
		*DebugObjectHandle = NULL;
	}
	__except (ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}

	//
	// Create a new debug object and initialize it.
	//

	Status = ObCreateObject(
		PreviousMode,
		debug_system::DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID *)&DebugObject);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}

	if (((PEPROCESS_BY)PsGetCurrentProcess())->WoW64Process != NULL)
	{
		DebugObject->Flags |= 4;
	}

	//
	// Insert the object into the handle table
	//
	Status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	__try {
		*DebugObjectHandle = Handle;
	} 
	__except(ExSystemExceptionFilter()) {
		//
		// The caller changed the page protection or deleted the memory for the handle.
		// No point closing the handle as process rundown will do that and we don't know its still the same handle
		//
		Status = GetExceptionCode();
	}

	return Status;
}

VOID NTAPI debug_system::New_DbgkpCloseObject(
	IN PEPROCESS_BY Process,
	IN PVOID Object,
	IN ULONG_PTR ProcessHandleCount,
	IN ULONG_PTR SystemHandleCount
)
{
	PDEBUG_OBJECT DebugObject = (PDEBUG_OBJECT)Object;
	PDEBUG_EVENT DebugEvent;
	PLIST_ENTRY ListPtr;
	BOOLEAN Deref;

	UNREFERENCED_PARAMETER(ProcessHandleCount);

	//
	// If this isn't the last handle then do nothing.
	//
	if (SystemHandleCount > 1) {
		return;
	}

	Fn_PsTerminateProcess PsTerminateProcess = (Fn_PsTerminateProcess)ntkrnl->api("PsTerminateProcess");
	Fn_DbgkpWakeTarget DbgkpWakeTarget = (Fn_DbgkpWakeTarget)ntkrnl->api("DbgkpWakeTarget");
	Fn_PsGetNextProcess PsGetNextProcess = (Fn_PsGetNextProcess)ntkrnl->api("PsGetNextProcess");

	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// Mark this object as going away and wake up any processes that are waiting.
	//
	DebugObject->Flags |= DEBUG_OBJECT_DELETE_PENDING;

	//
	// Remove any events and queue them to a temporary queue
	//
	ListPtr = DebugObject->EventList.Flink;
	InitializeListHead(&DebugObject->EventList);

	ExReleaseFastMutex(&DebugObject->Mutex);

	//
	// Wake anyone waiting. They need to leave this object alone now as its deleting
	//
	KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);

	//
	// Loop over all processes and remove the debug port from any that still have it.
	// Debug port propagation was disabled by setting the delete pending flag above so we only have to do this
	// once. No more refs can appear now.
	//
	for (Process = PsGetNextProcess(NULL);
		Process != NULL;
		Process = PsGetNextProcess(Process)) {

		if (Process->DebugPort == DebugObject) {
			Deref = FALSE;
			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			if (Process->DebugPort == DebugObject) {
				Process->DebugPort = NULL;
				Deref = TRUE;
			}

			ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

			if (Deref) {
				New_DbgkpMarkProcessPeb(Process);

				//
				// If the caller wanted process deletion on debugger dying (old interface) then kill off the process.
				//
				if (DebugObject->Flags & DEBUG_OBJECT_KILL_ON_CLOSE) {
					PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
				}
				ObDereferenceObject(DebugObject);
			}
		}
	}

	//
	// Wake up all the removed threads.
	//
	while (ListPtr != &DebugObject->EventList) {
		DebugEvent = CONTAINING_RECORD(ListPtr, DEBUG_EVENT, EventList);
		ListPtr = ListPtr->Flink;
		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}
}

NTSTATUS NTAPI debug_system::New_NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus
)
{
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent, FoundDebugEvent;
	KPROCESSOR_MODE PreviousMode;
	CLIENT_ID Clid;
	PLIST_ENTRY Entry;
	BOOLEAN GotEvent;

	char image_name[18] = { 0 };
	memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	Log("[NtDebugContinue] current process: %s\r\n", image_name);

	PreviousMode = ExGetPreviousMode();

	__try
	{
		if (PreviousMode != KernelMode) {
			ProbeForRead(ClientId, sizeof(*ClientId), sizeof(UCHAR));
		}
		Clid = *ClientId;
	}
	__except(ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}

	switch (ContinueStatus) {
	case DBG_EXCEPTION_HANDLED:
	case DBG_EXCEPTION_NOT_HANDLED:
	case DBG_REPLY_LATER:
	case DBG_TERMINATE_THREAD:
	case DBG_TERMINATE_PROCESS:
	case DBG_CONTINUE:
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	Status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		DEBUG_READ_EVENT,
		debug_system::DbgkDebugObjectType,
		PreviousMode,
		(PVOID *)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	GotEvent = FALSE;
	FoundDebugEvent = NULL;

	ExAcquireFastMutex(&DebugObject->Mutex);

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		Entry = Entry->Flink) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

		//
		// Make sure the client ID matches and that the debugger saw all the events.
		// We don't allow the caller to start a thread that it never saw a message for.
		//
		if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess)
		{
			if (!GotEvent)
			{
				if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread && (DebugEvent->Flags & DEBUG_EVENT_READ) != 0)
				{
					RemoveEntryList(Entry);
					FoundDebugEvent = DebugEvent;
					GotEvent = TRUE;
				}
			}
			else
			{
				//
				// VC breaks if it sees more than one event at a time
				// for the same process.
				//
				DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
				break;
			}
		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	ObDereferenceObject(DebugObject);

	Fn_DbgkpWakeTarget DbgkpWakeTarget = (Fn_DbgkpWakeTarget)get_ntfunc("DbgkpWakeTarget");
	//PUINT16 PerfGlobalGroupMask = GetPerfGlobalGroupMask();
	//EtwTraceDebuggerEventFn EtwTraceDebuggerEvent = GetEtwTraceDebuggerEventFn();

	if (GotEvent) {
		// TODO
		//if (*PerfGlobalGroupMask & 0x400000)
		//	EtwTraceDebuggerEvent(FoundDebugEvent->Process, FoundDebugEvent->Thread, 2);

		FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
		FoundDebugEvent->Status = STATUS_SUCCESS;
		DbgkpWakeTarget(FoundDebugEvent);
	}
	else {
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}

VOID NTAPI debug_system::New_DbgkpMarkProcessPeb(
	PEPROCESS_BY Process
)
{
	KAPC_STATE ApcState;

	//
	// Acquire process rundown protection as we are about to look at the processes address space
	//
	if (ExAcquireRundownProtection(&Process->RundownProtect)) 
	{
		if (PsGetProcessPeb(Process) != NULL) {
			KeStackAttachProcess((PEPROCESS)Process, &ApcState);

			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			__try {
				PPEB Peb = PsGetProcessPeb(Process);
				PBOOLEAN BeingDebugged = &Peb->BeingDebugged;

				PDEBUG_OBJECT Port = debug_system::get_debug_object(Process);
				// 这里修改被调试进程的PEB，会被3环的反调试检测到，所以不修改
				// 导致的另一个问题就是，调试器不触发系统断点，所以HOOK 3环被调试进程的系统断点函数
				//*BeingDebugged = (BOOLEAN)(Port != NULL ? TRUE : FALSE);
			} 
			__except(EXCEPTION_EXECUTE_HANDLER) {
			}

			ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

			KeUnstackDetachProcess(&ApcState);

		}
		ExReleaseRundownProtection(&Process->RundownProtect);
	}
}

BOOL NTAPI debug_system::New_DbgkpSuppressDbgMsg(
	PTEB Teb
)
{
	_TEB *v1; // rdx
	PEWOW64PROCESS v2; // rcx
	__int16 v3; // ax
	BOOL v5; // [rsp+0h] [rbp-18h]

	PEPROCESS_BY Process = (PEPROCESS_BY)KeGetCurrentThread()->ApcState.Process;

	v1 = Teb;
	v5 = 0;
	if (SLOBYTE(Teb->SameTebFlags) >= 0)
	{
		if (Process->WoW64Process)
		{
			v2 = Process->WoW64Process;
			if (v2)
			{
				v3 = v2->Machine;
				if (v3 == 0x14C || v3 == 0x1C4)
					v5 = SBYTE2(v1[1].BStoreLimit) < 0;
			}
		}
	}
	else
	{
		v5 = 1;
	}
	return v5;
}


debug_state::debug_state()
{
}

debug_state::~debug_state()
{
}