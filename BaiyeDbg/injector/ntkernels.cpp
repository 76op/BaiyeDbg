#include "mmsearch.h"
#include "ntkernels.h"

NTKRNL_FUNCTIONS ntfuncs;
NTNRKL_MEMBERS ntmembers;

BOOLEAN KmInit()
{
	//
	// Init Variables
	//

	KvInitNtosModule();

	//
	// Init Functions
	//

	if (!KfInitMiFindEmptyAddressRange())
	{
		return FALSE;
	}

	if (!KfInitMmAccessFault())
		return FALSE;
}

VOID KvInitNtosModule()
{
	PLIST_ENTRY current_list = PsLoadedModuleList;
	PLIST_ENTRY next_list;

	for (next_list = current_list->Flink;
		next_list != current_list;
		next_list = next_list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY_INJ module = CONTAINING_RECORD(next_list, LDR_DATA_TABLE_ENTRY_INJ, InLoadOrderLinks);

		UNICODE_STRING usNtos;
		RtlInitUnicodeString(&usNtos, L"ntoskrnl.exe");

		if (RtlCompareUnicodeString(&usNtos, &module->BaseDllName, TRUE) == 0)
		{
			ntmembers.NtosModule = module;
			goto _found;
		}
	}
	ntmembers.NtosModule = (PLDR_DATA_TABLE_ENTRY_INJ)PsLoadedModuleList;

_found:
	ntmembers.NtosModuleBase = ntmembers.NtosModule->DllBase;
	ntmembers.NtosModuleSize = ntmembers.NtosModule->SizeOfImage;
	return;
}

BOOLEAN KfInitMiFindEmptyAddressRange()
{
	UINT8 Pattern[] = {
		0x48, 0x89, 0x5C, 0x24, 0xCC,                       // mov     [rsp+arg_0], rbx
		0x4C, 0x89, 0x4C, 0x24, 0xCC,                       // mov     [rsp+arg_18], r9
		0x4C, 0x89, 0x44, 0x24, 0xCC,                       // mov     [rsp+arg_10], r8
		0x55,                                               // push    rbp
		0x56,                                               // push    rsi
		0x57,                                               // push    rdi
		0x41, 0x54,                                         // push    r12
		0x41, 0x55,                                         // push    r13
		0x41, 0x56,                                         // push    r14
		0x41, 0x57,                                         // push    r15
		0x48, 0x83, 0xEC, 0xCC,                             // sub     rsp, 40h
		0x4C, 0x8B, 0xA4, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,     // mov     r12, [rsp+78h+arg_28]
		0x49, 0x8B, 0xF1,                                   // mov     rsi, r9
		0x4C, 0x8B, 0xBC, 0x24, 0xCC, 0xCC, 0xCC, 0xCC      // mov     r15, [rsp+78h+arg_20]
	};
	
	PVOID FoundAddress[3] = { 0 };
	SIZE_T MaxFoundSize = 3;
	
	if (MmsSerch(0xcc,
		(PUINT8)ntmembers.NtosModuleBase,
		ntmembers.NtosModuleSize,
		Pattern, sizeof(Pattern),
		FoundAddress, &MaxFoundSize))
	{
		if (MaxFoundSize > 0)
		{
			ntfuncs.MiFindEmptyAddressRange = (Fn_MiFindEmptyAddressRange)FoundAddress[0];
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN KfInitMmAccessFault()
{
	UINT8 Pattern[] = {
		0x4C, 0x8B, 0xDC,                                       // mov     r11, rsp
		0x53,                                                   // push    rbx
		0x56,                                                   // push    rsi
		0x57,                                                   // push    rdi
		0x41, 0x54,                                             // push    r12
		0x41, 0x56,                                             // push    r14
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,               // sub     rsp, 170h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,               // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                       // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,         // mov     [rsp+198h+var_48], rax
		0x45, 0x33, 0xE4                                        // xor     r12d, r12d
	};

	PVOID FoundAddress[3] = { 0 };
	SIZE_T MaxFoundSize = 3;

	if (MmsSerch(0xcc,
		(PUINT8)ntmembers.NtosModuleBase,
		ntmembers.NtosModuleSize,
		Pattern, sizeof(Pattern),
		FoundAddress, &MaxFoundSize))
	{
		if (MaxFoundSize > 0)
		{
			ntfuncs.MmAccessFault = (Fn_MmAccessFault)FoundAddress[0];
			return TRUE;
		}
	}

	return FALSE;
}