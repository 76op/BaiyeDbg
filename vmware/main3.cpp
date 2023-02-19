#include <ntddk.h>
#include <intrin.h>
#include <cstdint>

typedef struct _cr4
{
	union
	{
		uint64_t flags;

		struct
		{
			uint64_t virtual_mode_extensions : 1;
			uint64_t protected_mode_virtual_interrupts : 1;
			uint64_t timestamp_disable : 1;
			uint64_t debugging_extensions : 1;
			uint64_t page_size_extensions : 1;
			uint64_t physical_address_extension : 1;
			uint64_t machine_check_enable : 1;
			uint64_t page_global_enable : 1;
			uint64_t performance_monitoring_counter_enable : 1;
			uint64_t os_fxsave_fxrstor_support : 1;
			uint64_t os_xmm_exception_support : 1;
			uint64_t usermode_instruction_prevention : 1;
			uint64_t reserved_1 : 1;
			uint64_t vmx_enable : 1;
			uint64_t smx_enable : 1;
			uint64_t reserved_2 : 1;
			uint64_t fsgsbase_enable : 1;
			uint64_t pcid_enable : 1;
			uint64_t os_xsave : 1;
			uint64_t reserved_3 : 1;
			uint64_t smep_enable : 1;
			uint64_t smap_enable : 1;
			uint64_t protection_key_enable : 1;
		};
	};
}cr4_t;

#ifdef DBG 
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"#%d [BaiyeVT]: " format "\n", KeGetCurrentProcessorNumberEx(0), ##__VA_ARGS__)
#else
#define Log(format, ...)
#endif // DBG 

EXTERN_C void DriverUnload5(PDRIVER_OBJECT object)
{
	return;
}

#define MSR_IA32_TSX_CTRL		0x00000122

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT object, PUNICODE_STRING path)
{
	object->DriverUnload = DriverUnload5;

	/*
	__try
	{
		uint64_t tsx = __readmsr(MSR_IA32_TSX_CTRL);
		Log("tsx_value: 0x%llx.", tsx);

		tsx &= ~0b11;
		
		__try
		{
			__writemsr(MSR_IA32_TSX_CTRL, tsx);
			Log("__writemsr(MSR_IA32_TSX_CTRL)³É¹¦");
		}
		__except(1)
		{
			Log("__writemsr(MSR_IA32_TSX_CTRL)Ê§°Ü");
		}
	}
	__except (1)
	{
		Log("__readmsr(MSR_IA32_TSX_CTRL)Ê§°Ü");
	}*/

	size_t size = 0x1000 * 1024 * 200; // 800mb
	PHYSICAL_ADDRESS start = { 0 }, end = { -1ull };
	PMDL mdl = MmAllocatePagesForMdlEx(start, end, start, size, MmCached, 0);
	void *address = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

	if (!address)
	{
		DbgBreakPoint();
	}

	PPFN_NUMBER PfnArray = MmGetMdlPfnArray(mdl);
	SIZE_T CountOfPfn = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));
	PHYSICAL_ADDRESS MdlPhyAddress = MmGetPhysicalAddress(address);
	
	DbgBreakPoint();

	MmUnmapLockedPages(address, mdl);
	MmFreePagesFromMdl(mdl);
	return 0;
}