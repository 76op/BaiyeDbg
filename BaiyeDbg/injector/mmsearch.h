#pragma once
//
// Memory Search
//

#ifndef __MMSEARCH_H__
#define __MMSEARCH_H__

#include <ntifs.h>

BOOLEAN MmsCompare(UINT8 Wildcard, PUINT8 Buffer1, PUINT8 Buffer2, SIZE_T CompareSize);

//
// Example:
//
//	UINT8 Pattern[10] = {
//		0x48, 0x89, 0x5C, 0x24, 0xCC,                   // mov     [rsp+arg_0], rbx
//		0x48, 0x89, 0x74, 0x24, 0xCC                    // mov     [rsp+arg_8], rsi
//	};
//	
//	PVOID FoundAddress[3] = { 0 };
//	SIZE_T MaxFoundSize = 3;
//	
//	if (MmsSerch(0xcc,
//		NtosModuleBase,
//		NtosModuleSize,
//		Pattern, 10,
//		FoundAddress, &MaxFoundSize))
//	{
//	}
//

BOOLEAN MmsSerch(
	UINT8			Wildcard, 
	const PUINT8	ScanStart,
	SIZE_T			ScanSize, 
	const PUINT8	Pattern,
	SIZE_T			PatternSize, 
	IN OUT PVOID	*FoundAddress, 
	IN OUT SIZE_T	*MaxFoundSize);

#endif // !__MMSEARCH_H__
