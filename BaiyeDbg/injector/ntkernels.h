#pragma once
//
// Nt Kernel Member Support
// Find undocumention functions and members
//

//#ifndef __NTKERNELS_H__
//#define __NTKERNELS_H__

#include <ntifs.h>
#include "ntstructs.h"

typedef struct _LDR_DATA_TABLE_ENTRY_INJ                         // 59 elements, 0x120 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)   
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)   
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)   
	/*0x030*/     VOID *DllBase;
	/*0x038*/     VOID *EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)   
	/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)   
	union                                                    // 3 elements, 0x4 bytes (sizeof)    
	{
		/*0x068*/         UINT8        FlagGroup[4];
		/*0x068*/         ULONG32      Flags;
		struct                                               // 28 elements, 0x4 bytes (sizeof)   
		{
			/*0x068*/             ULONG32      PackagedBinary : 1;                 // 0 BitPosition                     
			/*0x068*/             ULONG32      MarkedForRemoval : 1;               // 1 BitPosition                     
			/*0x068*/             ULONG32      ImageDll : 1;                       // 2 BitPosition                     
			/*0x068*/             ULONG32      LoadNotificationsSent : 1;          // 3 BitPosition                     
			/*0x068*/             ULONG32      TelemetryEntryProcessed : 1;        // 4 BitPosition                     
			/*0x068*/             ULONG32      ProcessStaticImport : 1;            // 5 BitPosition                     
			/*0x068*/             ULONG32      InLegacyLists : 1;                  // 6 BitPosition                     
			/*0x068*/             ULONG32      InIndexes : 1;                      // 7 BitPosition                     
			/*0x068*/             ULONG32      ShimDll : 1;                        // 8 BitPosition                     
			/*0x068*/             ULONG32      InExceptionTable : 1;               // 9 BitPosition                     
			/*0x068*/             ULONG32      ReservedFlags1 : 2;                 // 10 BitPosition                    
			/*0x068*/             ULONG32      LoadInProgress : 1;                 // 12 BitPosition                    
			/*0x068*/             ULONG32      LoadConfigProcessed : 1;            // 13 BitPosition                    
			/*0x068*/             ULONG32      EntryProcessed : 1;                 // 14 BitPosition                    
			/*0x068*/             ULONG32      ProtectDelayLoad : 1;               // 15 BitPosition                    
			/*0x068*/             ULONG32      ReservedFlags3 : 2;                 // 16 BitPosition                    
			/*0x068*/             ULONG32      DontCallForThreads : 1;             // 18 BitPosition                    
			/*0x068*/             ULONG32      ProcessAttachCalled : 1;            // 19 BitPosition                    
			/*0x068*/             ULONG32      ProcessAttachFailed : 1;            // 20 BitPosition                    
			/*0x068*/             ULONG32      CorDeferredValidate : 1;            // 21 BitPosition                    
			/*0x068*/             ULONG32      CorImage : 1;                       // 22 BitPosition                    
			/*0x068*/             ULONG32      DontRelocate : 1;                   // 23 BitPosition                    
			/*0x068*/             ULONG32      CorILOnly : 1;                      // 24 BitPosition                    
			/*0x068*/             ULONG32      ChpeImage : 1;                      // 25 BitPosition                    
			/*0x068*/             ULONG32      ReservedFlags5 : 2;                 // 26 BitPosition                    
			/*0x068*/             ULONG32      Redirected : 1;                     // 28 BitPosition                    
			/*0x068*/             ULONG32      ReservedFlags6 : 2;                 // 29 BitPosition                    
			/*0x068*/             ULONG32      CompatDatabaseProcessed : 1;        // 31 BitPosition                    
		};
	};
	/*0x06C*/     UINT16       ObsoleteLoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	/*0x070*/     struct _LIST_ENTRY HashLinks;                            // 2 elements, 0x10 bytes (sizeof)   
	/*0x080*/     ULONG32      TimeDateStamp;
	/*0x084*/     UINT8        _PADDING1_[0x4];
	/*0x088*/     struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
	/*0x090*/     VOID *Lock;
	/*0x098*/     struct _LDR_DDAG_NODE *DdagNode;
	/*0x0A0*/     struct _LIST_ENTRY NodeModuleLink;                       // 2 elements, 0x10 bytes (sizeof)   
	/*0x0B0*/     struct _LDRP_LOAD_CONTEXT *LoadContext;
	/*0x0B8*/     VOID *ParentDllBase;
	/*0x0C0*/     VOID *SwitchBackContext;
	/*0x0C8*/     struct _RTL_BALANCED_NODE BaseAddressIndexNode;          // 6 elements, 0x18 bytes (sizeof)   
	/*0x0E0*/     struct _RTL_BALANCED_NODE MappingInfoIndexNode;          // 6 elements, 0x18 bytes (sizeof)   
	/*0x0F8*/     UINT64       OriginalBase;
	/*0x100*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)    
	/*0x108*/     ULONG32      BaseNameHashValue;
	/*0x10C*/     enum _LDR_DLL_LOAD_REASON LoadReason;
	/*0x110*/     ULONG32      ImplicitPathOptions;
	/*0x114*/     ULONG32      ReferenceCount;
	/*0x118*/     ULONG32      DependentLoadFlags;
	/*0x11C*/     UINT8        SigningLevel;
	/*0x11D*/     UINT8        _PADDING2_[0x3];
}LDR_DATA_TABLE_ENTRY_INJ, *PLDR_DATA_TABLE_ENTRY_INJ;

//
// Kernel Functions Prototype
//

typedef NTSTATUS(*Fn_MiFindEmptyAddressRange)(
	IN SIZE_T SizeOfRange,
	IN ULONG_PTR Alignment,
	IN ULONG_PTR HighestVadAddress,
	IN ULONG Priority,
	IN ULONG QuickCheck,
	IN PVOID *Base,
	int *Unknown1
	);

typedef NTSTATUS(*Fn_MmAccessFault)(
	IN ULONG_PTR FaultStatus,
	IN PVOID VirtualAddress,
	IN KPROCESSOR_MODE PreviousMode,
	IN PVOID TrapInformation
	);

//
// kernel Export Variables
//
extern "C" PLIST_ENTRY PsLoadedModuleList;

typedef struct _NTKRNL_FUNCTIONS
{
	Fn_MiFindEmptyAddressRange MiFindEmptyAddressRange;
	Fn_MmAccessFault MmAccessFault;
}NTKRNL_FUNCTIONS;

extern NTKRNL_FUNCTIONS ntfuncs;

typedef struct _NTNRKL_MEMBERS
{
	PLDR_DATA_TABLE_ENTRY_INJ NtosModule;
	PVOID NtosModuleBase;
	SIZE_T NtosModuleSize;
}NTNRKL_MEMBERS;

extern NTNRKL_MEMBERS ntmembers;

// Kernel Members Init
BOOLEAN KmInit();

//
// Find Kernel Variables
//

VOID KvInitNtosModule();

//
// Find Kernel Functions
//

BOOLEAN KfInitMiFindEmptyAddressRange();

BOOLEAN KfInitMmAccessFault();

//#endif // !__NTKERNELS_H__
