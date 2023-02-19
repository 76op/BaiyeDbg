#include <ntddk.h>
#include <intrin.h>
#include "_debug_struct.h"
#include <cstdint>

#ifdef DBG 
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"#%d [BaiyeVT]: " format "\n", KeGetCurrentProcessorNumberEx(0), ##__VA_ARGS__)
#else
#define Log(format, ...)
#endif // DBG 

#define MSR_IA32_FEATURE_CONTROL 		    0x03a

extern "C" void asm_sgdt(void *ptr);
extern "C" int vm_detect();
//extern "C" void asm_pg_single_step();
extern "C" void asm_pg_KiErrata361Present();
extern "C" void asm_xbegin();

typedef struct {
	unsigned Lock : 1;
	unsigned reversed0 : 31;
	unsigned reversed1 : 32;
} ia32_feature_control_t;

typedef struct _cr4
{
	union
	{
		ULONG64 flags;

		struct
		{
			ULONG64 virtual_mode_extensions : 1;
			ULONG64 protected_mode_virtual_interrupts : 1;
			ULONG64 timestamp_disable : 1;
			ULONG64 debugging_extensions : 1;
			ULONG64 page_size_extensions : 1;
			ULONG64 physical_address_extension : 1;
			ULONG64 machine_check_enable : 1;
			ULONG64 page_global_enable : 1;
			ULONG64 performance_monitoring_counter_enable : 1;
			ULONG64 os_fxsave_fxrstor_support : 1;
			ULONG64 os_xmm_exception_support : 1;
			ULONG64 usermode_instruction_prevention : 1;
			ULONG64 reserved_1 : 1;
			ULONG64 vmx_enable : 1;
			ULONG64 smx_enable : 1;
			ULONG64 reserved_2 : 1;
			ULONG64 fsgsbase_enable : 1;
			ULONG64 pcid_enable : 1;
			ULONG64 os_xsave : 1;
			ULONG64 reserved_3 : 1;
			ULONG64 smep_enable : 1;
			ULONG64 smap_enable : 1;
			ULONG64 protection_key_enable : 1;
		};
	};
}cr4_t;

typedef struct _DBGKM_APIMSG1 {
	PORT_MESSAGE h;					// 0x0
	DBGKM_APINUMBER ApiNumber;		// 0x40
	NTSTATUS ReturnedStatus;		// 0x44
	DBGKM_EXCEPTION Exception;
} DBGKM_APIMSG1, *PDBGKM_APIMSG1;


#define MSR_LOW_L	0
#define MSR_LOW_HI	0x1fff

#define MSR_HIGH_L	0xc0000000
#define MSR_HIGH_HI	0xc0001fff

#define MSR_HV_L	0x40000000
#define MSR_HV_HI	0x40001fff

static PVOID mapping_address = NULL;

EXTERN_C VOID DriverUnload1(PDRIVER_OBJECT pDriverObject)
{
	//MmFreeMappingAddress(mapping_address, 'byvv');
}

EXTERN_C NTSTATUS DriverEntry1(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = DriverUnload1;

	mapping_address = MmAllocateMappingAddress(PAGE_SIZE, 'byvv');

	return STATUS_SUCCESS;
}

#define MSR_IA32_TSX_CTRL		0x00000122

EXTERN_C NTSTATUS DriverEntry2(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = DriverUnload1;

	/*Log("low-----------");
	for (int i = MSR_LOW_L; i <= MSR_LOW_HI; i++)
	{
		__try
		{
			auto msr_value = __readmsr(i);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Log("无效msr: 0x%x", i);
		}
	}

	Log("high-----------");
	for (int i = MSR_HIGH_L; i <= MSR_HIGH_HI; i++)
	{
		__try
		{
			auto msr_value = __readmsr(i);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Log("无效msr: 0x%x", i);
		}
	}

	Log("hv-----------");
	for (int i = MSR_HV_L; i <= MSR_HV_HI; i++)
	{
		__try
		{
			auto msr_value = __readmsr(i);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Log("无效msr: 0x%x", i);
		}
	}*/

	//auto msr_value = __readmsr(MSR_IA32_FEATURE_CONTROL);

	//__try
	//{
	//	auto msr_value = __readmsr(0x10000);
	//	Log("在虚拟机");
	//}
	//__except (EXCEPTION_EXECUTE_HANDLER)
	//{
	//	Log("不在虚拟机");
	//}

	//__try
	//{
	//	__writemsr(0x10000, 0);
	//	Log("__writemsr detected");
	//}
	//__except (1)
	//{
	//	Log("__writemsr pass");
	//}

	//ia32_feature_control_t msr = reinterpret_cast<ia32_feature_control_t &>(msr_value);
	//if (msr.Lock != 1)
	//{
	//	Log("BIOS未开启VT");
	//}

	//cr4_t cr4 = { __readcr4() };
	//if (cr4.vmx_enable == 0) 
	//{
	//	Log("cr4未开启VT");
	//}

	//Log("%d", sizeof(DBGKM_APIMSG2));

	//DBGKM_APIMSG m;
	//PDBGKM_EXCEPTION args;
	//args = &m.u.Exception;
	//DBGKM_FORMAT_API_MSG(m, DbgKmExceptionApi, sizeof(*args));
	//Log("%llx", m.h.u1.Length);

	//UINT64 XCR0 = _xgetbv(0);

	//__try {

	//	//
	//	// Clear the bit 0 of XCR0 to cause a #GP(0)!
	//	//
	//	_xsetbv(0, XCR0 & ~1);

	//}
	//__except (EXCEPTION_EXECUTE_HANDLER) {

	//	//
	//	// If we get here, the host has properly handled XSETBV and injected a
	//	// #GP(0) into the guest.
	//	//
	//	Log("1337!");
	//}

	//if (vm_detect())
	//{
	//	Log("LBR pass");
	//}
	//else
	//{
	//	Log("LBR detected");
	//}

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

	//__try
	//{
	//	cr4_t cr4 = { __readcr4() };
	//	cr4.reserved_1 = 1;
	//	__writecr4(cr4.flags);

	//	Log("cr4-reverse detected");
	//}
	//__except (1)
	//{
	//	Log("cr4-reverse pass");
	//}

	ULONG64 tsx_ctrl;

	__try
	{
		tsx_ctrl = __readmsr(MSR_IA32_TSX_CTRL);
		Log("tsx_ctrl. %llx", tsx_ctrl);
	}
	__except (1)
	{
		Log("tsx_ctrl, error");
	}

	__try
	{
		__writemsr(MSR_IA32_TSX_CTRL, tsx_ctrl);

		Log("write MSR_IA32_TSX_CTRL pass");
	}
	__except (1)
	{
		Log("write MSR_IA32_TSX_CTRL error");
	}

	__try
	{
		asm_xbegin();

		Log("xbegin pass");
	}
	__except (1)
	{
		Log("xbegin error");
	}

	return STATUS_SUCCESS;
}