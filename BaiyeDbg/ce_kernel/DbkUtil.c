#include "DbkUtil.h"

#include "DBKFunc.h"
#include <ntifs.h>
#include <windef.h>
#include "DBKDrvr.h"

#include "deepkernel.h"
#include "processlist.h"
#include "memscan.h"
#include "threads.h"
#include "vmxhelper.h"
#include "debugger.h"
#include "vmxoffload.h"

#include "IOPLDispatcher.h"
#include "interruptHook.h"
#include "ultimap.h"
#include "ultimap2.h"
#include "noexceptions.h"

#include "ultimap2\apic.h"

typedef NTSTATUS(*PSRCTNR)(__in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
PSRCTNR PsRemoveCreateThreadNotifyRoutine2;

typedef NTSTATUS(*PSRLINR)(__in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
PSRLINR PsRemoveLoadImageNotifyRoutine2;

EXTERN_C VOID DbkInitialize()
{
	NTSTATUS        ntStatus;
	PVOID           BufDriverString = NULL, BufProcessEventString = NULL, BufThreadEventString = NULL;
	UNICODE_STRING  uszDriverString;

	UNICODE_STRING  uszProcessEventString;
	UNICODE_STRING	uszThreadEventString;
	PDEVICE_OBJECT  pDeviceObject = 0;
	HANDLE reg = 0;
	OBJECT_ATTRIBUTES oa;

	UNICODE_STRING temp;
	char wbuf[100];
	WORD this_cs, this_ss, this_ds, this_es, this_fs, this_gs;
	ULONG cr4reg;

	criticalSection csTest;

	HANDLE Ultimap2Handle;


	KernelCodeStepping = 0;
	KernelWritesIgnoreWP = 0;



	this_cs = getCS();
	this_ss = getSS();
	this_ds = getDS();
	this_es = getES();
	this_fs = getFS();
	this_gs = getGS();

	temp.Buffer = (PWCH)wbuf;
	temp.Length = 0;
	temp.MaximumLength = 100;


	loadedbydbvm = FALSE;

	ntStatus = STATUS_SUCCESS;


	//Processlist init
#ifndef CETC
	ProcessEventCount = 0;
	ExInitializeResourceLite(&ProcesslistR);
#endif

	CreateProcessNotifyRoutineEnabled = FALSE;

	//threadlist init
	ThreadEventCount = 0;

	processlist = NULL;

#ifndef AMD64
	//determine if PAE is used
	cr4reg = (ULONG)getCR4();

	if ((cr4reg & 0x20) == 0x20)
	{
		PTESize = 8; //pae
		PAGE_SIZE_LARGE = 0x200000;
		MAX_PDE_POS = 0xC0604000;
		MAX_PTE_POS = 0xC07FFFF8;


	}
	else
	{
		PTESize = 4;
		PAGE_SIZE_LARGE = 0x400000;
		MAX_PDE_POS = 0xC0301000;
		MAX_PTE_POS = 0xC03FFFFC;
	}
#else
	PTESize = 8; //pae
	PAGE_SIZE_LARGE = 0x200000;
	//base was 0xfffff68000000000ULL

	//to 
	MAX_PTE_POS = 0xFFFFF6FFFFFFFFF8ULL; // base + 0x7FFFFFFFF8
	MAX_PDE_POS = 0xFFFFF6FB7FFFFFF8ULL; // base + 0x7B7FFFFFF8
#endif

	//hideme(DriverObject); //ok, for those that see this, enabling this WILL fuck up try except routines, even in usermode you'll get a blue sreen

	// Return success (don't do the devicestring, I need it for unload)
	DbgPrint("Cleaning up initialization buffers\n");
	if (BufDriverString)
	{
		ExFreePool(BufDriverString);
		BufDriverString = NULL;
	}

	if (BufProcessEventString)
	{
		ExFreePool(BufProcessEventString);
		BufProcessEventString = NULL;
	}

	if (BufThreadEventString)
	{
		ExFreePool(BufThreadEventString);
		BufThreadEventString = NULL;
	}

	if (reg)
	{
		ZwClose(reg);
		reg = 0;
	}

	//fetch cpu info
	{
		DWORD r[4];
		DWORD a;

		__cpuid(r, 0);
		DbgPrint("cpuid.0: r[1]=%x", r[1]);
		if (r[1] == 0x756e6547) //GenuineIntel
		{
			__cpuid(r, 1);

			a = r[0];

			cpu_stepping = a & 0xf;
			cpu_model = (a >> 4) & 0xf;
			cpu_familyID = (a >> 8) & 0xf;
			cpu_type = (a >> 12) & 0x3;
			cpu_ext_modelID = (a >> 16) & 0xf;
			cpu_ext_familyID = (a >> 20) & 0xff;

			cpu_model = cpu_model + (cpu_ext_modelID << 4);
			cpu_familyID = cpu_familyID + (cpu_ext_familyID << 4);

			vmx_init_dovmcall(1);
			setup_APIC_BASE(); //for ultimap
		}
		else
		{
			DbgPrint("Not an intel cpu");
			if (r[1] == 0x68747541)
			{
				DbgPrint("This is an AMD\n");
				vmx_init_dovmcall(0);
			}
		}
	}


	RtlInitUnicodeString(&temp, L"PsSuspendProcess");
	PsSuspendProcess = (PSSUSPENDPROCESS)MmGetSystemRoutineAddress(&temp);

	RtlInitUnicodeString(&temp, L"PsResumeProcess");
	PsResumeProcess = (PSSUSPENDPROCESS)MmGetSystemRoutineAddress(&temp);


	return STATUS_SUCCESS;
}

EXTERN_C VOID DbkUnInitialize()
{
	ultimap_disable();
	DisableUltimap2();
	UnregisterUltimapPMI();

	clean_APIC_BASE();

	NoExceptions_Cleanup();

	if ((CreateProcessNotifyRoutineEnabled) || (ImageNotifyRoutineLoaded))
	{
		PVOID x;
		UNICODE_STRING temp;

		RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
		PsRemoveCreateThreadNotifyRoutine2 = (PSRCTNR)MmGetSystemRoutineAddress(&temp);

		RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
		PsRemoveLoadImageNotifyRoutine2 = (PSRLINR)MmGetSystemRoutineAddress(&temp);

		RtlInitUnicodeString(&temp, L"ObOpenObjectByName");
		x = MmGetSystemRoutineAddress(&temp);

		DbgPrint("ObOpenObjectByName=%p\n", x);


		if ((PsRemoveCreateThreadNotifyRoutine2) && (PsRemoveLoadImageNotifyRoutine2))
		{
			DbgPrint("Stopping processwatch\n");

			if (CreateProcessNotifyRoutineEnabled)
			{
				DbgPrint("Removing process watch");
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
				PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, TRUE);
#else
				PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
#endif


				DbgPrint("Removing thread watch");
				PsRemoveCreateThreadNotifyRoutine2(CreateThreadNotifyRoutine);
			}

			if (ImageNotifyRoutineLoaded)
				PsRemoveLoadImageNotifyRoutine2(LoadImageNotifyRoutine);
		}
		else return;  //leave now!!!!!		
	}


	//IoDeleteDevice(DriverObject->DeviceObject);

#ifdef CETC
#ifndef CETC_RELEASE
	UnloadCETC(); //not possible in the final build
#endif
#endif

#ifndef CETC_RELEASE
	/*DbgPrint("DeviceString=%S\n",uszDeviceString.Buffer);
	{
		NTSTATUS r = IoDeleteSymbolicLink(&uszDeviceString);
		DbgPrint("IoDeleteSymbolicLink: %x\n", r);
	}
	ExFreePool(BufDeviceString);*/
#endif

	CleanProcessList();

	ExDeleteResourceLite(&ProcesslistR);

	RtlZeroMemory(&ProcesslistR, sizeof(ProcesslistR));

#if (NTDDI_VERSION >= NTDDI_VISTA)
	if (DRMHandle)
	{
		DbgPrint("Unregistering DRM handle");
		ObUnRegisterCallbacks(DRMHandle);
		DRMHandle = NULL;
	}
#endif
}