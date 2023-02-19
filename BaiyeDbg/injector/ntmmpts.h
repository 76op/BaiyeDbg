#pragma once
//
// Memory Page Table Support
//

#ifndef __PAGE_TABLE_H__
#define __PAGE_TABLE_H__

#include <ntifs.h>

typedef struct _MMPTS_BASE
{
	ULONG64 PxeSelfMappingIndex;
	ULONG64 PxeBase;
	ULONG64 PpeBase;
	ULONG64 PdeBase;
	ULONG64 PteBase;
}MMPTS_BASE, *PMMPTS_BASE;

BOOLEAN PtsInitializePtBase(IN BOOLEAN IsRandom, IN ULONG_PTR Cr3, OUT PMMPTS_BASE PtBase);

PVOID PtsAddressOfPte(IN PMMPTS_BASE PtBase, PVOID VirtualAddress);
PVOID PtsAddressOfPde(IN PMMPTS_BASE PtBase, PVOID VirtualAddress);
PVOID PtsAddressOfPpe(IN PMMPTS_BASE PtBase, PVOID VirtualAddress);
PVOID PtsAddressOfPxe(IN PMMPTS_BASE PtBase, PVOID VirtualAddress);



#endif // !__PAGE_TABLE_H__
