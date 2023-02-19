#pragma once
#include "_global.h"

#define VOID void
#define STDCALL __stdcall
#define CDECL __cdecl
#define THISCALL __thiscall
#define NEAR 
#define FAR

typedef VOID(NEAR CDECL FUNCT_011D_2820_DumpProcedure) (VOID *, struct _OBJECT_DUMP_CONTROL *);
typedef LONG32(NEAR CDECL FUNCT_0115_2828_OpenProcedure) (enum _OB_OPEN_REASON, CHAR, struct _EPROCESS *, VOID *, ULONG32 *, ULONG32);
typedef VOID(NEAR CDECL FUNCT_011D_2836_CloseProcedure) (struct _EPROCESS *, VOID *, UINT64, UINT64);
typedef VOID(NEAR CDECL FUNCT_011D_059F_Free_InterfaceReference_InterfaceDereference_WorkerRoutine_Callback_DevicePowerRequired_DevicePowerNotRequired_DeleteCallback_Uninitialize_ClearLocalUnitError_EndOfInterrupt_InitializeController_DeleteProcedure_ReleaseFromLazyWrite_ReleaseFromReadAhead_CleanupProcedure_HalLocateHiberRanges_HalDpReplaceTarget_HalDpReplaceEnd_DisableCallback) (VOID *);
typedef LONG32(NEAR CDECL FUNCT_0115_283C_ParseProcedure) (VOID *, VOID *, struct _ACCESS_STATE *, CHAR, ULONG32, struct _UNICODE_STRING *, struct _UNICODE_STRING *, VOID *, struct _SECURITY_QUALITY_OF_SERVICE *, VOID **);
typedef LONG32(NEAR CDECL FUNCT_0115_2848_ParseProcedureEx) (VOID *, VOID *, struct _ACCESS_STATE *, CHAR, ULONG32, struct _UNICODE_STRING *, struct _UNICODE_STRING *, VOID *, struct _SECURITY_QUALITY_OF_SERVICE *, struct _OB_EXTENDED_PARSE_PARAMETERS *, VOID **);
typedef LONG32(NEAR CDECL FUNCT_0115_285A_SecurityProcedure) (VOID *, enum _SECURITY_OPERATION_CODE, ULONG32 *, VOID *, ULONG32 *, VOID **, enum _POOL_TYPE, struct _GENERIC_MAPPING *, CHAR);
typedef LONG32(NEAR CDECL FUNCT_0115_286B_QueryNameProcedure) (VOID *, UINT8, struct _OBJECT_NAME_INFORMATION *, ULONG32, ULONG32 *, CHAR);
typedef UINT8(NEAR CDECL FUNCT_0116_2873_OkayToCloseProcedure) (struct _EPROCESS *, VOID *, VOID *, CHAR);
typedef VOID(NEAR CDECL FUNCT_011D_122D_PostProcessInitRoutine_FastEndOfInterrupt_EndOfInterrupt_HalHaltSystem_KdCheckPowerButton_HalResumeProcessorFromIdle_HalSaveAndDisableHvEnlightenment_HalRestoreHvEnlightenment_HalPciMarkHiberPhase_HalClockTimerInitialize_HalClockTimerStop_HalTimerWatchdogStart_HalTimerWatchdogResetCountdown_HalTimerWatchdogStop_HalAcpiLateRestore_HalInitPlatformDebugTriggers_DispatchAddress_FinishRoutine) ();

#define TYPE32(x)   ULONG
#define TYPE64(x)   ULONGLONG

#define PS_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBitsDiscardReturn (Flags, Flag)

#define PS_TEST_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBits (Flags, Flag)

#define PS_CLEAR_BITS(Flags, Flag) \
    RtlInterlockedClearBitsDiscardReturn (Flags, Flag)

#define PS_TEST_CLEAR_BITS(Flags, Flag) \
    RtlInterlockedClearBits (Flags, Flag)

#define PS_SET_CLEAR_BITS(Flags, sFlag, cFlag) \
    RtlInterlockedSetClearBits (Flags, sFlag, cFlag)

#define PS_TEST_ALL_BITS_SET(Flags, Bits) \
    ((Flags&(Bits)) == (Bits))

#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
            ((hdrs)->OptionalHeader.##field)

// begin_ntosp
#define OBJECT_TO_OBJECT_HEADER( o ) \
    CONTAINING_RECORD( (o), OBJECT_HEADER, Body )
// end_ntosp

typedef struct _KAFFINITY_EX // 4 elements, 0xA8 bytes (sizeof) 
{
	/*0x000*/     UINT16       Count;
	/*0x002*/     UINT16       Size;
	/*0x004*/     ULONG32      Reserved;
	/*0x008*/     UINT64       Bitmap[20];
}KAFFINITY_EX, *PKAFFINITY_EX;

typedef union _KEXECUTE_OPTIONS                           // 10 elements, 0x1 bytes (sizeof) 
{
	struct                                                // 8 elements, 0x1 bytes (sizeof)  
	{
		/*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                   
		/*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                   
		/*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                   
		/*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                   
		/*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                   
		/*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                   
		/*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                   
		/*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                   
	};
	/*0x000*/     UINT8        ExecuteOptions;
	/*0x000*/     UINT8        ExecuteOptionsNV;
}KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef union _KSTACK_COUNT           // 3 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     LONG32       Value;
	struct                            // 2 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
		/*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
	};
}KSTACK_COUNT, *PKSTACK_COUNT;

typedef struct _KPROCESS                            // 54 elements, 0x438 bytes (sizeof) 
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;               // 59 elements, 0x18 bytes (sizeof)  
	/*0x018*/     struct _LIST_ENTRY ProfileListHead;             // 2 elements, 0x10 bytes (sizeof)   
	/*0x028*/     UINT64       DirectoryTableBase;
	/*0x030*/     struct _LIST_ENTRY ThreadListHead;              // 2 elements, 0x10 bytes (sizeof)   
	/*0x040*/     ULONG32      ProcessLock;
	/*0x044*/     ULONG32      ProcessTimerDelay;
	/*0x048*/     UINT64       DeepFreezeStartTime;
	/*0x050*/     struct _KAFFINITY_EX Affinity;                  // 4 elements, 0xA8 bytes (sizeof)   
	/*0x0F8*/     UINT64       AffinityPadding[12];
	/*0x158*/     struct _LIST_ENTRY ReadyListHead;               // 2 elements, 0x10 bytes (sizeof)   
	/*0x168*/     struct _SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x8 bytes (sizeof)    
	/*0x170*/     struct _KAFFINITY_EX ActiveProcessors;          // 4 elements, 0xA8 bytes (sizeof)   
	/*0x218*/     UINT64       ActiveProcessorsPadding[12];
	union                                           // 2 elements, 0x4 bytes (sizeof)    
	{
		struct                                      // 10 elements, 0x4 bytes (sizeof)   
		{
			/*0x278*/             ULONG32      AutoAlignment : 1;         // 0 BitPosition                     
			/*0x278*/             ULONG32      DisableBoost : 1;          // 1 BitPosition                     
			/*0x278*/             ULONG32      DisableQuantum : 1;        // 2 BitPosition                     
			/*0x278*/             ULONG32      DeepFreeze : 1;            // 3 BitPosition                     
			/*0x278*/             ULONG32      TimerVirtualization : 1;   // 4 BitPosition                     
			/*0x278*/             ULONG32      CheckStackExtents : 1;     // 5 BitPosition                     
			/*0x278*/             ULONG32      CacheIsolationEnabled : 1; // 6 BitPosition                     
			/*0x278*/             ULONG32      PpmPolicy : 3;             // 7 BitPosition                     
			/*0x278*/             ULONG32      VaSpaceDeleted : 1;        // 10 BitPosition                    
			/*0x278*/             ULONG32      ReservedFlags : 21;        // 11 BitPosition                    
		};
		/*0x278*/         LONG32       ProcessFlags;
	};
	/*0x27C*/     ULONG32      ActiveGroupsMask;
	/*0x280*/     CHAR         BasePriority;
	/*0x281*/     CHAR         QuantumReset;
	/*0x282*/     CHAR         Visited;
	/*0x283*/     union _KEXECUTE_OPTIONS Flags;                  // 10 elements, 0x1 bytes (sizeof)   
	/*0x284*/     UINT16       ThreadSeed[20];
	/*0x2AC*/     UINT16       ThreadSeedPadding[12];
	/*0x2C4*/     UINT16       IdealProcessor[20];
	/*0x2EC*/     UINT16       IdealProcessorPadding[12];
	/*0x304*/     UINT16       IdealNode[20];
	/*0x32C*/     UINT16       IdealNodePadding[12];
	/*0x344*/     UINT16       IdealGlobalNode;
	/*0x346*/     UINT16       Spare1;
	/*0x348*/     union _KSTACK_COUNT StackCount;                 // 3 elements, 0x4 bytes (sizeof)    
	/*0x34C*/     UINT8        _PADDING0_[0x4];
	/*0x350*/     struct _LIST_ENTRY ProcessListEntry;            // 2 elements, 0x10 bytes (sizeof)   
	/*0x360*/     UINT64       CycleTime;
	/*0x368*/     UINT64       ContextSwitches;
	/*0x370*/     struct _KSCHEDULING_GROUP *SchedulingGroup;
	/*0x378*/     ULONG32      FreezeCount;
	/*0x37C*/     ULONG32      KernelTime;
	/*0x380*/     ULONG32      UserTime;
	/*0x384*/     ULONG32      ReadyTime;
	/*0x388*/     UINT64       UserDirectoryTableBase;
	/*0x390*/     UINT8        AddressPolicy;
	/*0x391*/     UINT8        Spare2[71];
	/*0x3D8*/     VOID *InstrumentationCallback;
	/*0x3E0*/     UINT64		SecureState;             // 2 elements, 0x8 bytes (sizeof)    
	/*0x3E8*/     UINT64       KernelWaitTime;
	/*0x3F0*/     UINT64       UserWaitTime;
	/*0x3F8*/     UINT64       EndPadding[8];
}KPROCESS, *PKPROCESS;

typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof) 
{
	union                                    // 3 elements, 0x8 bytes (sizeof) 
	{
		struct                               // 5 elements, 0x8 bytes (sizeof) 
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                  
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                  
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                  
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                  
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                  
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID *Ptr;
	};
}EX_PUSH_LOCK_BY, *PEX_PUSH_LOCK_BY;

typedef struct _EX_FAST_REF      // 3 elements, 0x8 bytes (sizeof) 
{
	union                        // 3 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         VOID *Object;
		/*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition                  
		/*0x000*/         UINT64       Value;
	};
}EX_FAST_REF, *PEX_FAST_REF;

typedef struct _RTL_AVL_TREE         // 1 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_BALANCED_NODE *Root;
}RTL_AVL_TREE, *PRTL_AVL_TREE;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO      // 1 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     struct _OBJECT_NAME_INFORMATION *ImageFileName;
}SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _MMSUPPORT_FLAGS                         // 17 elements, 0x4 bytes (sizeof) 
{
	union                                               // 2 elements, 0x2 bytes (sizeof)  
	{
		struct                                          // 2 elements, 0x2 bytes (sizeof)  
		{
			struct                                      // 4 elements, 0x1 bytes (sizeof)  
			{
				/*0x000*/                 UINT8        WorkingSetType : 3;        // 0 BitPosition                   
				/*0x000*/                 UINT8        Reserved0 : 3;             // 3 BitPosition                   
				/*0x000*/                 UINT8        MaximumWorkingSetHard : 1; // 6 BitPosition                   
				/*0x000*/                 UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition                   
			};
			struct                                      // 4 elements, 0x1 bytes (sizeof)  
			{
				/*0x001*/                 UINT8        SessionMaster : 1;         // 0 BitPosition                   
				/*0x001*/                 UINT8        TrimmerState : 2;          // 1 BitPosition                   
				/*0x001*/                 UINT8        Reserved : 1;              // 3 BitPosition                   
				/*0x001*/                 UINT8        PageStealers : 4;          // 4 BitPosition                   
			};
		};
		/*0x000*/         UINT16       u1;
	};
	/*0x002*/     UINT8        MemoryPriority;
	union                                               // 2 elements, 0x1 bytes (sizeof)  
	{
		struct                                          // 6 elements, 0x1 bytes (sizeof)  
		{
			/*0x003*/             UINT8        WsleDeleted : 1;               // 0 BitPosition                   
			/*0x003*/             UINT8        SvmEnabled : 1;                // 1 BitPosition                   
			/*0x003*/             UINT8        ForceAge : 1;                  // 2 BitPosition                   
			/*0x003*/             UINT8        ForceTrim : 1;                 // 3 BitPosition                   
			/*0x003*/             UINT8        NewMaximum : 1;                // 4 BitPosition                   
			/*0x003*/             UINT8        CommitReleaseState : 2;        // 5 BitPosition                   
		};
		/*0x003*/         UINT8        u2;
	};
}MMSUPPORT_FLAGS, *PMMSUPPORT_FLAGS;

typedef struct _MMSUPPORT_INSTANCE               // 19 elements, 0xC0 bytes (sizeof) 
{
	/*0x000*/     ULONG32      NextPageColor;
	/*0x004*/     ULONG32      PageFaultCount;
	/*0x008*/     UINT64       TrimmedPageCount;
	/*0x010*/     struct _MMWSL_INSTANCE *VmWorkingSetList;
	/*0x018*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x10 bytes (sizeof)  
	/*0x028*/     UINT64       AgeDistribution[8];
	/*0x068*/     struct _KGATE *ExitOutswapGate;
	/*0x070*/     UINT64       MinimumWorkingSetSize;
	/*0x078*/     UINT64       WorkingSetLeafSize;
	/*0x080*/     UINT64       WorkingSetLeafPrivateSize;
	/*0x088*/     UINT64       WorkingSetSize;
	/*0x090*/     UINT64       WorkingSetPrivateSize;
	/*0x098*/     UINT64       MaximumWorkingSetSize;
	/*0x0A0*/     UINT64       PeakWorkingSetSize;
	/*0x0A8*/     ULONG32      HardFaultCount;
	/*0x0AC*/     UINT16       LastTrimStamp;
	/*0x0AE*/     UINT16       PartitionId;
	/*0x0B0*/     UINT64       SelfmapLock;
	/*0x0B8*/     struct _MMSUPPORT_FLAGS Flags;               // 17 elements, 0x4 bytes (sizeof)  
	/*0x0BC*/     UINT8        _PADDING0_[0x4];
}MMSUPPORT_INSTANCE, *PMMSUPPORT_INSTANCE;

typedef struct _MMSUPPORT_SHARED            // 11 elements, 0x80 bytes (sizeof) 
{
	/*0x000*/     LONG32       WorkingSetLock;
	/*0x004*/     LONG32       GoodCitizenWaiting;
	/*0x008*/     UINT64       ReleasedCommitDebt;
	/*0x010*/     UINT64       ResetPagesRepurposedCount;
	/*0x018*/     VOID *WsSwapSupport;
	/*0x020*/     VOID *CommitReleaseContext;
	/*0x028*/     VOID *AccessLog;
	/*0x030*/     UINT64       ChargedWslePages;
	/*0x038*/     UINT64       ActualWslePages;
	/*0x040*/     UINT64       WorkingSetCoreLock;
	/*0x048*/     VOID *ShadowMapping;
	/*0x050*/     UINT8        _PADDING0_[0x30];
}MMSUPPORT_SHARED, *PMMSUPPORT_SHARED;

typedef struct _MMSUPPORT_FULL           // 2 elements, 0x140 bytes (sizeof) 
{
	/*0x000*/     struct _MMSUPPORT_INSTANCE Instance; // 19 elements, 0xC0 bytes (sizeof) 
	/*0x0C0*/     struct _MMSUPPORT_SHARED Shared;     // 11 elements, 0x80 bytes (sizeof) 
}MMSUPPORT_FULL, *PMMSUPPORT_FULL;

typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     struct _EX_PUSH_LOCK Lock;        // 7 elements, 0x8 bytes (sizeof)  
	/*0x008*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     UINT64       PagedPoolQuotaCache;
}ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT;

typedef struct _PS_PROTECTION        // 4 elements, 0x1 bytes (sizeof) 
{
	union                            // 2 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        Level;
		struct                       // 3 elements, 0x1 bytes (sizeof) 
		{
			/*0x000*/             UINT8        Type : 3;   // 0 BitPosition                  
			/*0x000*/             UINT8        Audit : 1;  // 3 BitPosition                  
			/*0x000*/             UINT8        Signer : 4; // 4 BitPosition                  
		};
	};
}PS_PROTECTION, *PPS_PROTECTION;

typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES // 7 elements, 0x8 bytes (sizeof) 
{
	struct                                       // 6 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         UINT64       DelayMs : 30;               // 0 BitPosition                  
		/*0x000*/         UINT64       CoalescingWindowMs : 30;    // 30 BitPosition                 
		/*0x000*/         UINT64       Reserved : 1;               // 60 BitPosition                 
		/*0x000*/         UINT64       NewTimerWheel : 1;          // 61 BitPosition                 
		/*0x000*/         UINT64       Retry : 1;                  // 62 BitPosition                 
		/*0x000*/         UINT64       Locked : 1;                 // 63 BitPosition                 
	};
	/*0x000*/     UINT64       All;
}PS_INTERLOCKED_TIMER_DELAY_VALUES, *PPS_INTERLOCKED_TIMER_DELAY_VALUES;

typedef struct _JOBOBJECT_WAKE_FILTER // 2 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     ULONG32      HighEdgeFilter;
	/*0x004*/     ULONG32      LowEdgeFilter;
}JOBOBJECT_WAKE_FILTER, *PJOBOBJECT_WAKE_FILTER;

typedef struct _PS_PROCESS_WAKE_INFORMATION   // 4 elements, 0x30 bytes (sizeof) 
{
	/*0x000*/     UINT64       NotificationChannel;
	/*0x008*/     ULONG32      WakeCounters[7];
	/*0x024*/     struct _JOBOBJECT_WAKE_FILTER WakeFilter; // 2 elements, 0x8 bytes (sizeof)  
	/*0x02C*/     ULONG32      NoWakeCounter;
}PS_PROCESS_WAKE_INFORMATION, *PPS_PROCESS_WAKE_INFORMATION;

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_AVL_TREE Tree;                     // 1 elements, 0x8 bytes (sizeof)  
	/*0x008*/     struct _EX_PUSH_LOCK Lock;                     // 7 elements, 0x8 bytes (sizeof)  
}PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, *PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES;

typedef struct _EWOW64PROCESS        // 3 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     VOID *Peb;
	/*0x008*/     UINT16       Machine;
	/*0x00A*/     UINT8        _PADDING0_[0x2];
	/*0x00C*/     enum _SYSTEM_DLL_TYPE NtdllType;
}EWOW64PROCESS, *PEWOW64PROCESS;

typedef struct _EPROCESS                                                           // 235 elements, 0xA40 bytes (sizeof) 
{
	/*0x000*/     struct _KPROCESS Pcb;                                                          // 54 elements, 0x438 bytes (sizeof)  
	/*0x438*/     struct _EX_PUSH_LOCK ProcessLock;                                              // 7 elements, 0x8 bytes (sizeof)     
	/*0x440*/     VOID *UniqueProcessId;
	/*0x448*/     struct _LIST_ENTRY ActiveProcessLinks;                                         // 2 elements, 0x10 bytes (sizeof)    
	/*0x458*/     struct _EX_RUNDOWN_REF RundownProtect;                                         // 2 elements, 0x8 bytes (sizeof)     
	union                                                                          // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x460*/         ULONG32      Flags2;
		struct                                                                     // 28 elements, 0x4 bytes (sizeof)    
		{
			/*0x460*/             ULONG32      JobNotReallyActive : 1;                                   // 0 BitPosition                      
			/*0x460*/             ULONG32      AccountingFolded : 1;                                     // 1 BitPosition                      
			/*0x460*/             ULONG32      NewProcessReported : 1;                                   // 2 BitPosition                      
			/*0x460*/             ULONG32      ExitProcessReported : 1;                                  // 3 BitPosition                      
			/*0x460*/             ULONG32      ReportCommitChanges : 1;                                  // 4 BitPosition                      
			/*0x460*/             ULONG32      LastReportMemory : 1;                                     // 5 BitPosition                      
			/*0x460*/             ULONG32      ForceWakeCharge : 1;                                      // 6 BitPosition                      
			/*0x460*/             ULONG32      CrossSessionCreate : 1;                                   // 7 BitPosition                      
			/*0x460*/             ULONG32      NeedsHandleRundown : 1;                                   // 8 BitPosition                      
			/*0x460*/             ULONG32      RefTraceEnabled : 1;                                      // 9 BitPosition                      
			/*0x460*/             ULONG32      PicoCreated : 1;                                          // 10 BitPosition                     
			/*0x460*/             ULONG32      EmptyJobEvaluated : 1;                                    // 11 BitPosition                     
			/*0x460*/             ULONG32      DefaultPagePriority : 3;                                  // 12 BitPosition                     
			/*0x460*/             ULONG32      PrimaryTokenFrozen : 1;                                   // 15 BitPosition                     
			/*0x460*/             ULONG32      ProcessVerifierTarget : 1;                                // 16 BitPosition                     
			/*0x460*/             ULONG32      RestrictSetThreadContext : 1;                             // 17 BitPosition                     
			/*0x460*/             ULONG32      AffinityPermanent : 1;                                    // 18 BitPosition                     
			/*0x460*/             ULONG32      AffinityUpdateEnable : 1;                                 // 19 BitPosition                     
			/*0x460*/             ULONG32      PropagateNode : 1;                                        // 20 BitPosition                     
			/*0x460*/             ULONG32      ExplicitAffinity : 1;                                     // 21 BitPosition                     
			/*0x460*/             ULONG32      ProcessExecutionState : 2;                                // 22 BitPosition                     
			/*0x460*/             ULONG32      EnableReadVmLogging : 1;                                  // 24 BitPosition                     
			/*0x460*/             ULONG32      EnableWriteVmLogging : 1;                                 // 25 BitPosition                     
			/*0x460*/             ULONG32      FatalAccessTerminationRequested : 1;                      // 26 BitPosition                     
			/*0x460*/             ULONG32      DisableSystemAllowedCpuSet : 1;                           // 27 BitPosition                     
			/*0x460*/             ULONG32      ProcessStateChangeRequest : 2;                            // 28 BitPosition                     
			/*0x460*/             ULONG32      ProcessStateChangeInProgress : 1;                         // 30 BitPosition                     
			/*0x460*/             ULONG32      InPrivate : 1;                                            // 31 BitPosition                     
		};
	};
	union                                                                          // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x464*/         ULONG32      Flags;
		struct                                                                     // 29 elements, 0x4 bytes (sizeof)    
		{
			/*0x464*/             ULONG32      CreateReported : 1;                                       // 0 BitPosition                      
			/*0x464*/             ULONG32      NoDebugInherit : 1;                                       // 1 BitPosition                      
			/*0x464*/             ULONG32      ProcessExiting : 1;                                       // 2 BitPosition                      
			/*0x464*/             ULONG32      ProcessDelete : 1;                                        // 3 BitPosition                      
			/*0x464*/             ULONG32      ManageExecutableMemoryWrites : 1;                         // 4 BitPosition                      
			/*0x464*/             ULONG32      VmDeleted : 1;                                            // 5 BitPosition                      
			/*0x464*/             ULONG32      OutswapEnabled : 1;                                       // 6 BitPosition                      
			/*0x464*/             ULONG32      Outswapped : 1;                                           // 7 BitPosition                      
			/*0x464*/             ULONG32      FailFastOnCommitFail : 1;                                 // 8 BitPosition                      
			/*0x464*/             ULONG32      Wow64VaSpace4Gb : 1;                                      // 9 BitPosition                      
			/*0x464*/             ULONG32      AddressSpaceInitialized : 2;                              // 10 BitPosition                     
			/*0x464*/             ULONG32      SetTimerResolution : 1;                                   // 12 BitPosition                     
			/*0x464*/             ULONG32      BreakOnTermination : 1;                                   // 13 BitPosition                     
			/*0x464*/             ULONG32      DeprioritizeViews : 1;                                    // 14 BitPosition                     
			/*0x464*/             ULONG32      WriteWatch : 1;                                           // 15 BitPosition                     
			/*0x464*/             ULONG32      ProcessInSession : 1;                                     // 16 BitPosition                     
			/*0x464*/             ULONG32      OverrideAddressSpace : 1;                                 // 17 BitPosition                     
			/*0x464*/             ULONG32      HasAddressSpace : 1;                                      // 18 BitPosition                     
			/*0x464*/             ULONG32      LaunchPrefetched : 1;                                     // 19 BitPosition                     
			/*0x464*/             ULONG32      Background : 1;                                           // 20 BitPosition                     
			/*0x464*/             ULONG32      VmTopDown : 1;                                            // 21 BitPosition                     
			/*0x464*/             ULONG32      ImageNotifyDone : 1;                                      // 22 BitPosition                     
			/*0x464*/             ULONG32      PdeUpdateNeeded : 1;                                      // 23 BitPosition                     
			/*0x464*/             ULONG32      VdmAllowed : 1;                                           // 24 BitPosition                     
			/*0x464*/             ULONG32      ProcessRundown : 1;                                       // 25 BitPosition                     
			/*0x464*/             ULONG32      ProcessInserted : 1;                                      // 26 BitPosition                     
			/*0x464*/             ULONG32      DefaultIoPriority : 3;                                    // 27 BitPosition                     
			/*0x464*/             ULONG32      ProcessSelfDelete : 1;                                    // 30 BitPosition                     
			/*0x464*/             ULONG32      SetTimerResolutionLink : 1;                               // 31 BitPosition                     
		};
	};
	/*0x468*/     union _LARGE_INTEGER CreateTime;                                               // 4 elements, 0x8 bytes (sizeof)     
	/*0x470*/     UINT64       ProcessQuotaUsage[2];
	/*0x480*/     UINT64       ProcessQuotaPeak[2];
	/*0x490*/     UINT64       PeakVirtualSize;
	/*0x498*/     UINT64       VirtualSize;
	/*0x4A0*/     struct _LIST_ENTRY SessionProcessLinks;                                        // 2 elements, 0x10 bytes (sizeof)    
	union                                                                          // 3 elements, 0x8 bytes (sizeof)     
	{
		/*0x4B0*/         VOID *ExceptionPortData;
		/*0x4B0*/         UINT64       ExceptionPortValue;
		/*0x4B0*/         UINT64       ExceptionPortState : 3;                                       // 0 BitPosition                      
	};
	/*0x4B8*/     struct _EX_FAST_REF Token;                                                     // 3 elements, 0x8 bytes (sizeof)     
	/*0x4C0*/     UINT64       MmReserved;
	/*0x4C8*/     struct _EX_PUSH_LOCK AddressCreationLock;                                      // 7 elements, 0x8 bytes (sizeof)     
	/*0x4D0*/     struct _EX_PUSH_LOCK PageTableCommitmentLock;                                  // 7 elements, 0x8 bytes (sizeof)     
	/*0x4D8*/     struct _ETHREAD *RotateInProgress;
	/*0x4E0*/     struct _ETHREAD *ForkInProgress;
	/*0x4E8*/     struct _EJOB *CommitChargeJob;
	/*0x4F0*/     struct _RTL_AVL_TREE CloneRoot;                                                // 1 elements, 0x8 bytes (sizeof)     
	/*0x4F8*/     UINT64       NumberOfPrivatePages;
	/*0x500*/     UINT64       NumberOfLockedPages;
	/*0x508*/     VOID *Win32Process;
	/*0x510*/     struct _EJOB *Job;
	/*0x518*/     VOID *SectionObject;
	/*0x520*/     VOID *SectionBaseAddress;
	/*0x528*/     ULONG32      Cookie;
	/*0x52C*/     UINT8        _PADDING0_[0x4];
	/*0x530*/     struct _PAGEFAULT_HISTORY *WorkingSetWatch;
	/*0x538*/     VOID *Win32WindowStation;
	/*0x540*/     VOID *InheritedFromUniqueProcessId;
	/*0x548*/     UINT64       OwnerProcessId;
	/*0x550*/     struct _PEB *Peb;
	/*0x558*/     struct _MM_SESSION_SPACE *Session;
	/*0x560*/     VOID *Spare1;
	/*0x568*/     struct _EPROCESS_QUOTA_BLOCK *QuotaBlock;
	/*0x570*/     struct _HANDLE_TABLE *ObjectTable;
	/*0x578*/     VOID *DebugPort;
	/*0x580*/     struct _EWOW64PROCESS *WoW64Process;
	/*0x588*/     VOID *DeviceMap;
	/*0x590*/     VOID *EtwDataSource;
	/*0x598*/     UINT64       PageDirectoryPte;
	/*0x5A0*/     struct _FILE_OBJECT *ImageFilePointer;
	/*0x5A8*/     UINT8        ImageFileName[15];
	/*0x5B7*/     UINT8        PriorityClass;
	/*0x5B8*/     VOID *SecurityPort;
	/*0x5C0*/     struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;             // 1 elements, 0x8 bytes (sizeof)     
	/*0x5C8*/     struct _LIST_ENTRY JobLinks;                                                   // 2 elements, 0x10 bytes (sizeof)    
	/*0x5D8*/     VOID *HighestUserAddress;
	/*0x5E0*/     struct _LIST_ENTRY ThreadListHead;                                             // 2 elements, 0x10 bytes (sizeof)    
	/*0x5F0*/     ULONG32      ActiveThreads;
	/*0x5F4*/     ULONG32      ImagePathHash;
	/*0x5F8*/     ULONG32      DefaultHardErrorProcessing;
	/*0x5FC*/     LONG32       LastThreadExitStatus;
	/*0x600*/     struct _EX_FAST_REF PrefetchTrace;                                             // 3 elements, 0x8 bytes (sizeof)     
	/*0x608*/     VOID *LockedPagesList;
	/*0x610*/     union _LARGE_INTEGER ReadOperationCount;                                       // 4 elements, 0x8 bytes (sizeof)     
	/*0x618*/     union _LARGE_INTEGER WriteOperationCount;                                      // 4 elements, 0x8 bytes (sizeof)     
	/*0x620*/     union _LARGE_INTEGER OtherOperationCount;                                      // 4 elements, 0x8 bytes (sizeof)     
	/*0x628*/     union _LARGE_INTEGER ReadTransferCount;                                        // 4 elements, 0x8 bytes (sizeof)     
	/*0x630*/     union _LARGE_INTEGER WriteTransferCount;                                       // 4 elements, 0x8 bytes (sizeof)     
	/*0x638*/     union _LARGE_INTEGER OtherTransferCount;                                       // 4 elements, 0x8 bytes (sizeof)     
	/*0x640*/     UINT64       CommitChargeLimit;
	/*0x648*/     UINT64       CommitCharge;
	/*0x650*/     UINT64       CommitChargePeak;
	/*0x658*/     UINT8        _PADDING1_[0x28];
	/*0x680*/     struct _MMSUPPORT_FULL Vm;                                                     // 2 elements, 0x140 bytes (sizeof)   
	/*0x7C0*/     struct _LIST_ENTRY MmProcessLinks;                                             // 2 elements, 0x10 bytes (sizeof)    
	/*0x7D0*/     ULONG32      ModifiedPageCount;
	/*0x7D4*/     LONG32       ExitStatus;
	/*0x7D8*/     struct _RTL_AVL_TREE VadRoot;                                                  // 1 elements, 0x8 bytes (sizeof)     
	/*0x7E0*/     VOID *VadHint;
	/*0x7E8*/     UINT64       VadCount;
	/*0x7F0*/     UINT64       VadPhysicalPages;
	/*0x7F8*/     UINT64       VadPhysicalPagesLimit;
	/*0x800*/     struct _ALPC_PROCESS_CONTEXT AlpcContext;                                      // 3 elements, 0x20 bytes (sizeof)    
	/*0x820*/     struct _LIST_ENTRY TimerResolutionLink;                                        // 2 elements, 0x10 bytes (sizeof)    
	/*0x830*/     struct _PO_DIAG_STACK_RECORD *TimerResolutionStackRecord;
	/*0x838*/     ULONG32      RequestedTimerResolution;
	/*0x83C*/     ULONG32      SmallestTimerResolution;
	/*0x840*/     union _LARGE_INTEGER ExitTime;                                                 // 4 elements, 0x8 bytes (sizeof)     
	/*0x848*/     struct _INVERTED_FUNCTION_TABLE *InvertedFunctionTable;
	/*0x850*/     struct _EX_PUSH_LOCK InvertedFunctionTableLock;                                // 7 elements, 0x8 bytes (sizeof)     
	/*0x858*/     ULONG32      ActiveThreadsHighWatermark;
	/*0x85C*/     ULONG32      LargePrivateVadCount;
	/*0x860*/     struct _EX_PUSH_LOCK ThreadListLock;                                           // 7 elements, 0x8 bytes (sizeof)     
	/*0x868*/     VOID *WnfContext;
	/*0x870*/     struct _EJOB *ServerSilo;
	/*0x878*/     UINT8        SignatureLevel;
	/*0x879*/     UINT8        SectionSignatureLevel;
	/*0x87A*/     struct _PS_PROTECTION Protection;                                              // 4 elements, 0x1 bytes (sizeof)     
	struct                                                                         // 3 elements, 0x1 bytes (sizeof)     
	{
		/*0x87B*/         UINT8        HangCount : 3;                                                // 0 BitPosition                      
		/*0x87B*/         UINT8        GhostCount : 3;                                               // 3 BitPosition                      
		/*0x87B*/         UINT8        PrefilterException : 1;                                       // 6 BitPosition                      
	};
	union                                                                          // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x87C*/         ULONG32      Flags3;
		struct                                                                     // 28 elements, 0x4 bytes (sizeof)    
		{
			/*0x87C*/             ULONG32      Minimal : 1;                                              // 0 BitPosition                      
			/*0x87C*/             ULONG32      ReplacingPageRoot : 1;                                    // 1 BitPosition                      
			/*0x87C*/             ULONG32      Crashed : 1;                                              // 2 BitPosition                      
			/*0x87C*/             ULONG32      JobVadsAreTracked : 1;                                    // 3 BitPosition                      
			/*0x87C*/             ULONG32      VadTrackingDisabled : 1;                                  // 4 BitPosition                      
			/*0x87C*/             ULONG32      AuxiliaryProcess : 1;                                     // 5 BitPosition                      
			/*0x87C*/             ULONG32      SubsystemProcess : 1;                                     // 6 BitPosition                      
			/*0x87C*/             ULONG32      IndirectCpuSets : 1;                                      // 7 BitPosition                      
			/*0x87C*/             ULONG32      RelinquishedCommit : 1;                                   // 8 BitPosition                      
			/*0x87C*/             ULONG32      HighGraphicsPriority : 1;                                 // 9 BitPosition                      
			/*0x87C*/             ULONG32      CommitFailLogged : 1;                                     // 10 BitPosition                     
			/*0x87C*/             ULONG32      ReserveFailLogged : 1;                                    // 11 BitPosition                     
			/*0x87C*/             ULONG32      SystemProcess : 1;                                        // 12 BitPosition                     
			/*0x87C*/             ULONG32      HideImageBaseAddresses : 1;                               // 13 BitPosition                     
			/*0x87C*/             ULONG32      AddressPolicyFrozen : 1;                                  // 14 BitPosition                     
			/*0x87C*/             ULONG32      ProcessFirstResume : 1;                                   // 15 BitPosition                     
			/*0x87C*/             ULONG32      ForegroundExternal : 1;                                   // 16 BitPosition                     
			/*0x87C*/             ULONG32      ForegroundSystem : 1;                                     // 17 BitPosition                     
			/*0x87C*/             ULONG32      HighMemoryPriority : 1;                                   // 18 BitPosition                     
			/*0x87C*/             ULONG32      EnableProcessSuspendResumeLogging : 1;                    // 19 BitPosition                     
			/*0x87C*/             ULONG32      EnableThreadSuspendResumeLogging : 1;                     // 20 BitPosition                     
			/*0x87C*/             ULONG32      SecurityDomainChanged : 1;                                // 21 BitPosition                     
			/*0x87C*/             ULONG32      SecurityFreezeComplete : 1;                               // 22 BitPosition                     
			/*0x87C*/             ULONG32      VmProcessorHost : 1;                                      // 23 BitPosition                     
			/*0x87C*/             ULONG32      VmProcessorHostTransition : 1;                            // 24 BitPosition                     
			/*0x87C*/             ULONG32      AltSyscall : 1;                                           // 25 BitPosition                     
			/*0x87C*/             ULONG32      TimerResolutionIgnore : 1;                                // 26 BitPosition                     
			/*0x87C*/             ULONG32      DisallowUserTerminate : 1;                                // 27 BitPosition                     
		};
	};
	/*0x880*/     LONG32       DeviceAsid;
	/*0x884*/     UINT8        _PADDING2_[0x4];
	/*0x888*/     VOID *SvmData;
	/*0x890*/     struct _EX_PUSH_LOCK SvmProcessLock;                                           // 7 elements, 0x8 bytes (sizeof)     
	/*0x898*/     UINT64       SvmLock;
	/*0x8A0*/     struct _LIST_ENTRY SvmProcessDeviceListHead;                                   // 2 elements, 0x10 bytes (sizeof)    
	/*0x8B0*/     UINT64       LastFreezeInterruptTime;
	/*0x8B8*/     struct _PROCESS_DISK_COUNTERS *DiskCounters;
	/*0x8C0*/     VOID *PicoContext;
	/*0x8C8*/     VOID *EnclaveTable;
	/*0x8D0*/     UINT64       EnclaveNumber;
	/*0x8D8*/     struct _EX_PUSH_LOCK EnclaveLock;                                              // 7 elements, 0x8 bytes (sizeof)     
	/*0x8E0*/     ULONG32      HighPriorityFaultsAllowed;
	/*0x8E4*/     UINT8        _PADDING3_[0x4];
	/*0x8E8*/     struct _PO_PROCESS_ENERGY_CONTEXT *EnergyContext;
	/*0x8F0*/     VOID *VmContext;
	/*0x8F8*/     UINT64       SequenceNumber;
	/*0x900*/     UINT64       CreateInterruptTime;
	/*0x908*/     UINT64       CreateUnbiasedInterruptTime;
	/*0x910*/     UINT64       TotalUnbiasedFrozenTime;
	/*0x918*/     UINT64       LastAppStateUpdateTime;
	struct                                                                         // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x920*/         UINT64       LastAppStateUptime : 61;                                      // 0 BitPosition                      
		/*0x920*/         UINT64       LastAppState : 3;                                             // 61 BitPosition                     
	};
	/*0x928*/     UINT64       SharedCommitCharge;
	/*0x930*/     struct _EX_PUSH_LOCK SharedCommitLock;                                         // 7 elements, 0x8 bytes (sizeof)     
	/*0x938*/     struct _LIST_ENTRY SharedCommitLinks;                                          // 2 elements, 0x10 bytes (sizeof)    
	union                                                                          // 2 elements, 0x10 bytes (sizeof)    
	{
		struct                                                                     // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x948*/             UINT64       AllowedCpuSets;
			/*0x950*/             UINT64       DefaultCpuSets;
		};
		struct                                                                     // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x948*/             UINT64 *AllowedCpuSetsIndirect;
			/*0x950*/             UINT64 *DefaultCpuSetsIndirect;
		};
	};
	/*0x958*/     VOID *DiskIoAttribution;
	/*0x960*/     VOID *DxgProcess;
	/*0x968*/     ULONG32      Win32KFilterSet;
	/*0x96C*/     UINT8        _PADDING4_[0x4];
	/*0x970*/     union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;                    // 7 elements, 0x8 bytes (sizeof)     
	/*0x978*/     ULONG32      KTimerSets;
	/*0x97C*/     ULONG32      KTimer2Sets;
	/*0x980*/     ULONG32      ThreadTimerSets;
	/*0x984*/     UINT8        _PADDING5_[0x4];
	/*0x988*/     UINT64       VirtualTimerListLock;
	/*0x990*/     struct _LIST_ENTRY VirtualTimerListHead;                                       // 2 elements, 0x10 bytes (sizeof)    
	union                                                                          // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x9A0*/         struct _WNF_STATE_NAME WakeChannel;                                        // 1 elements, 0x8 bytes (sizeof)     
		/*0x9A0*/         struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                              // 4 elements, 0x30 bytes (sizeof)    
	};
	union                                                                          // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x9D0*/         ULONG32      MitigationFlags;
		/*0x9D0*/         ULONG32 MitigationFlagsValues;                             // 32 elements, 0x4 bytes (sizeof)    
	};
	union                                                                          // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x9D4*/         ULONG32      MitigationFlags2;
		/*0x9D4*/         ULONG32 MitigationFlags2Values;                            // 32 elements, 0x4 bytes (sizeof)    
	};
	/*0x9D8*/     VOID *PartitionObject;
	/*0x9E0*/     UINT64       SecurityDomain;
	/*0x9E8*/     UINT64       ParentSecurityDomain;
	/*0x9F0*/     VOID *CoverageSamplerContext;
	/*0x9F8*/     VOID *MmHotPatchContext;
	/*0xA00*/     struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                         // 1 elements, 0x8 bytes (sizeof)     
	/*0xA08*/     struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                         // 7 elements, 0x8 bytes (sizeof)     
	/*0xA10*/     struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; // 2 elements, 0x10 bytes (sizeof)    
	/*0xA20*/     ULONG32      DisabledComponentFlags;
	/*0xA24*/     UINT8        _PADDING6_[0x4];
	/*0xA28*/     ULONG32 *PathRedirectionHashes;
	/*0xA30*/     UINT8        _PADDING7_[0x10];
}EPROCESS_BY, *PEPROCESS_BY;


typedef union _KWAIT_STATUS_REGISTER // 7 elements, 0x1 bytes (sizeof) 
{
	/*0x000*/     UINT8        Flags;
	struct                           // 6 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        State : 3;      // 0 BitPosition                  
		/*0x000*/         UINT8        Affinity : 1;   // 3 BitPosition                  
		/*0x000*/         UINT8        Priority : 1;   // 4 BitPosition                  
		/*0x000*/         UINT8        Apc : 1;        // 5 BitPosition                  
		/*0x000*/         UINT8        UserApc : 1;    // 6 BitPosition                  
		/*0x000*/         UINT8        Alert : 1;      // 7 BitPosition                  
	};
}KWAIT_STATUS_REGISTER, *PKWAIT_STATUS_REGISTER;

typedef struct _KTHREAD                                                        // 204 elements, 0x430 bytes (sizeof) 
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;                                          // 59 elements, 0x18 bytes (sizeof)   
	/*0x018*/     VOID *SListFaultAddress;
	/*0x020*/     UINT64       QuantumTarget;
	/*0x028*/     VOID *InitialStack;
	/*0x030*/     VOID *StackLimit;
	/*0x038*/     VOID *StackBase;
	/*0x040*/     UINT64       ThreadLock;
	/*0x048*/     UINT64       CycleTime;
	/*0x050*/     ULONG32      CurrentRunTime;
	/*0x054*/     ULONG32      ExpectedRunTime;
	/*0x058*/     VOID *KernelStack;
	/*0x060*/     struct _XSAVE_FORMAT *StateSaveArea;
	/*0x068*/     struct _KSCHEDULING_GROUP *SchedulingGroup;
	/*0x070*/     union _KWAIT_STATUS_REGISTER WaitRegister;                                 // 7 elements, 0x1 bytes (sizeof)     
	/*0x071*/     UINT8        Running;
	/*0x072*/     UINT8        Alerted[2];
	union                                                                      // 2 elements, 0x4 bytes (sizeof)     
	{
		struct                                                                 // 23 elements, 0x4 bytes (sizeof)    
		{
			/*0x074*/             ULONG32      AutoBoostActive : 1;                                  // 0 BitPosition                      
			/*0x074*/             ULONG32      ReadyTransition : 1;                                  // 1 BitPosition                      
			/*0x074*/             ULONG32      WaitNext : 1;                                         // 2 BitPosition                      
			/*0x074*/             ULONG32      SystemAffinityActive : 1;                             // 3 BitPosition                      
			/*0x074*/             ULONG32      Alertable : 1;                                        // 4 BitPosition                      
			/*0x074*/             ULONG32      UserStackWalkActive : 1;                              // 5 BitPosition                      
			/*0x074*/             ULONG32      ApcInterruptRequest : 1;                              // 6 BitPosition                      
			/*0x074*/             ULONG32      QuantumEndMigrate : 1;                                // 7 BitPosition                      
			/*0x074*/             ULONG32      UmsDirectedSwitchEnable : 1;                          // 8 BitPosition                      
			/*0x074*/             ULONG32      TimerActive : 1;                                      // 9 BitPosition                      
			/*0x074*/             ULONG32      SystemThread : 1;                                     // 10 BitPosition                     
			/*0x074*/             ULONG32      ProcessDetachActive : 1;                              // 11 BitPosition                     
			/*0x074*/             ULONG32      CalloutActive : 1;                                    // 12 BitPosition                     
			/*0x074*/             ULONG32      ScbReadyQueue : 1;                                    // 13 BitPosition                     
			/*0x074*/             ULONG32      ApcQueueable : 1;                                     // 14 BitPosition                     
			/*0x074*/             ULONG32      ReservedStackInUse : 1;                               // 15 BitPosition                     
			/*0x074*/             ULONG32      UmsPerformingSyscall : 1;                             // 16 BitPosition                     
			/*0x074*/             ULONG32      TimerSuspended : 1;                                   // 17 BitPosition                     
			/*0x074*/             ULONG32      SuspendedWaitMode : 1;                                // 18 BitPosition                     
			/*0x074*/             ULONG32      SuspendSchedulerApcWait : 1;                          // 19 BitPosition                     
			/*0x074*/             ULONG32      CetUserShadowStack : 1;                               // 20 BitPosition                     
			/*0x074*/             ULONG32      BypassProcessFreeze : 1;                              // 21 BitPosition                     
			/*0x074*/             ULONG32      Reserved : 10;                                        // 22 BitPosition                     
		};
		/*0x074*/         LONG32       MiscFlags;
	};
	union                                                                      // 2 elements, 0x4 bytes (sizeof)     
	{
		struct                                                                 // 23 elements, 0x4 bytes (sizeof)    
		{
			/*0x078*/             ULONG32      ThreadFlagsSpare : 2;                                 // 0 BitPosition                      
			/*0x078*/             ULONG32      AutoAlignment : 1;                                    // 2 BitPosition                      
			/*0x078*/             ULONG32      DisableBoost : 1;                                     // 3 BitPosition                      
			/*0x078*/             ULONG32      AlertedByThreadId : 1;                                // 4 BitPosition                      
			/*0x078*/             ULONG32      QuantumDonation : 1;                                  // 5 BitPosition                      
			/*0x078*/             ULONG32      EnableStackSwap : 1;                                  // 6 BitPosition                      
			/*0x078*/             ULONG32      GuiThread : 1;                                        // 7 BitPosition                      
			/*0x078*/             ULONG32      DisableQuantum : 1;                                   // 8 BitPosition                      
			/*0x078*/             ULONG32      ChargeOnlySchedulingGroup : 1;                        // 9 BitPosition                      
			/*0x078*/             ULONG32      DeferPreemption : 1;                                  // 10 BitPosition                     
			/*0x078*/             ULONG32      QueueDeferPreemption : 1;                             // 11 BitPosition                     
			/*0x078*/             ULONG32      ForceDeferSchedule : 1;                               // 12 BitPosition                     
			/*0x078*/             ULONG32      SharedReadyQueueAffinity : 1;                         // 13 BitPosition                     
			/*0x078*/             ULONG32      FreezeCount : 1;                                      // 14 BitPosition                     
			/*0x078*/             ULONG32      TerminationApcRequest : 1;                            // 15 BitPosition                     
			/*0x078*/             ULONG32      AutoBoostEntriesExhausted : 1;                        // 16 BitPosition                     
			/*0x078*/             ULONG32      KernelStackResident : 1;                              // 17 BitPosition                     
			/*0x078*/             ULONG32      TerminateRequestReason : 2;                           // 18 BitPosition                     
			/*0x078*/             ULONG32      ProcessStackCountDecremented : 1;                     // 20 BitPosition                     
			/*0x078*/             ULONG32      RestrictedGuiThread : 1;                              // 21 BitPosition                     
			/*0x078*/             ULONG32      VpBackingThread : 1;                                  // 22 BitPosition                     
			/*0x078*/             ULONG32      ThreadFlagsSpare2 : 1;                                // 23 BitPosition                     
			/*0x078*/             ULONG32      EtwStackTraceApcInserted : 8;                         // 24 BitPosition                     
		};
		/*0x078*/         LONG32       ThreadFlags;
	};
	/*0x07C*/     UINT8        Tag;
	/*0x07D*/     UINT8        SystemHeteroCpuPolicy;
	struct                                                                     // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x07E*/         UINT8        UserHeteroCpuPolicy : 7;                                  // 0 BitPosition                      
		/*0x07E*/         UINT8        ExplicitSystemHeteroCpuPolicy : 1;                        // 7 BitPosition                      
	};
	union                                                                      // 2 elements, 0x1 bytes (sizeof)     
	{
		struct                                                                 // 2 elements, 0x1 bytes (sizeof)     
		{
			/*0x07F*/             UINT8        RunningNonRetpolineCode : 1;                          // 0 BitPosition                      
			/*0x07F*/             UINT8        SpecCtrlSpare : 7;                                    // 1 BitPosition                      
		};
		/*0x07F*/         UINT8        SpecCtrl;
	};
	/*0x080*/     ULONG32      SystemCallNumber;
	/*0x084*/     ULONG32      ReadyTime;
	/*0x088*/     VOID *FirstArgument;
	/*0x090*/     struct _KTRAP_FRAME *TrapFrame;
	union                                                                      // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x098*/         struct _KAPC_STATE ApcState;                                           // 9 elements, 0x30 bytes (sizeof)    
		struct                                                                 // 3 elements, 0x30 bytes (sizeof)    
		{
			/*0x098*/             UINT8        ApcStateFill[43];
			/*0x0C3*/             CHAR         Priority;
			/*0x0C4*/             ULONG32      UserIdealProcessor;
		};
	};
	/*0x0C8*/     INT64        WaitStatus;
	/*0x0D0*/     struct _KWAIT_BLOCK *WaitBlockList;
	union                                                                      // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x0D8*/         struct _LIST_ENTRY WaitListEntry;                                      // 2 elements, 0x10 bytes (sizeof)    
		/*0x0D8*/         struct _SINGLE_LIST_ENTRY SwapListEntry;                               // 1 elements, 0x8 bytes (sizeof)     
	};
	/*0x0E8*/     struct _DISPATCHER_HEADER *Queue;
	/*0x0F0*/     VOID *Teb;
	/*0x0F8*/     UINT64       RelativeTimerBias;
	/*0x100*/     struct _KTIMER Timer;                                                      // 7 elements, 0x40 bytes (sizeof)    
	union                                                                      // 9 elements, 0xC0 bytes (sizeof)    
	{
		/*0x140*/         struct _KWAIT_BLOCK WaitBlock[4];
		struct                                                                 // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill4[20];
			/*0x154*/             ULONG32      ContextSwitches;
			/*0x158*/             UINT8        _PADDING0_[0xA8];
		};
		struct                                                                 // 5 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill5[68];
			/*0x184*/             UINT8        State;
			/*0x185*/             CHAR         Spare13;
			/*0x186*/             UINT8        WaitIrql;
			/*0x187*/             CHAR         WaitMode;
			/*0x188*/             UINT8        _PADDING1_[0x78];
		};
		struct                                                                 // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill6[116];
			/*0x1B4*/             ULONG32      WaitTime;
			/*0x1B8*/             UINT8        _PADDING2_[0x48];
		};
		struct                                                                 // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill7[164];
			union                                                              // 2 elements, 0x4 bytes (sizeof)     
			{
				struct                                                         // 2 elements, 0x4 bytes (sizeof)     
				{
					/*0x1E4*/                     INT16        KernelApcDisable;
					/*0x1E6*/                     INT16        SpecialApcDisable;
				};
				/*0x1E4*/                 ULONG32      CombinedApcDisable;
			};
		};
		struct                                                                 // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill8[40];
			/*0x168*/             struct _KTHREAD_COUNTERS *ThreadCounters;
			/*0x170*/             UINT8        _PADDING3_[0x90];
		};
		struct                                                                 // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill9[88];
			/*0x198*/             struct _XSTATE_SAVE *XStateSave;
			/*0x1A0*/             UINT8        _PADDING4_[0x60];
		};
		struct                                                                 // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill10[136];
			/*0x1C8*/             VOID *Win32Thread;
			/*0x1D0*/             UINT8        _PADDING5_[0x30];
		};
		struct                                                                 // 3 elements, 0xC0 bytes (sizeof)    
		{
			/*0x140*/             UINT8        WaitBlockFill11[176];
			/*0x1F0*/             struct _UMS_CONTROL_BLOCK *Ucb;
			/*0x1F8*/             struct _KUMS_CONTEXT_HEADER *Uch;
		};
	};
	union                                                                      // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x200*/         LONG32       ThreadFlags2;
		struct                                                                 // 2 elements, 0x4 bytes (sizeof)     
		{
			/*0x200*/             ULONG32      BamQosLevel : 8;                                      // 0 BitPosition                      
			/*0x200*/             ULONG32      ThreadFlags2Reserved : 24;                            // 8 BitPosition                      
		};
	};
	/*0x204*/     ULONG32      Spare21;
	/*0x208*/     struct _LIST_ENTRY QueueListEntry;                                         // 2 elements, 0x10 bytes (sizeof)    
	union                                                                      // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x218*/         ULONG32      NextProcessor;
		struct                                                                 // 2 elements, 0x4 bytes (sizeof)     
		{
			/*0x218*/             ULONG32      NextProcessorNumber : 31;                             // 0 BitPosition                      
			/*0x218*/             ULONG32      SharedReadyQueue : 1;                                 // 31 BitPosition                     
		};
	};
	/*0x21C*/     LONG32       QueuePriority;
	/*0x220*/     struct _KPROCESS *Process;
	union                                                                      // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x228*/         struct _GROUP_AFFINITY UserAffinity;                                   // 3 elements, 0x10 bytes (sizeof)    
		struct                                                                 // 7 elements, 0x10 bytes (sizeof)    
		{
			/*0x228*/             UINT8        UserAffinityFill[10];
			/*0x232*/             CHAR         PreviousMode;
			/*0x233*/             CHAR         BasePriority;
			union                                                              // 2 elements, 0x1 bytes (sizeof)     
			{
				/*0x234*/                 CHAR         PriorityDecrement;
				struct                                                         // 2 elements, 0x1 bytes (sizeof)     
				{
					/*0x234*/                     UINT8        ForegroundBoost : 4;                          // 0 BitPosition                      
					/*0x234*/                     UINT8        UnusualBoost : 4;                             // 4 BitPosition                      
				};
			};
			/*0x235*/             UINT8        Preempted;
			/*0x236*/             UINT8        AdjustReason;
			/*0x237*/             CHAR         AdjustIncrement;
		};
	};
	/*0x238*/     UINT64       AffinityVersion;
	union                                                                      // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x240*/         struct _GROUP_AFFINITY Affinity;                                       // 3 elements, 0x10 bytes (sizeof)    
		struct                                                                 // 4 elements, 0x10 bytes (sizeof)    
		{
			/*0x240*/             UINT8        AffinityFill[10];
			/*0x24A*/             UINT8        ApcStateIndex;
			/*0x24B*/             UINT8        WaitBlockCount;
			/*0x24C*/             ULONG32      IdealProcessor;
		};
	};
	/*0x250*/     UINT64       NpxState;
	union                                                                      // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x258*/         struct _KAPC_STATE SavedApcState;                                      // 9 elements, 0x30 bytes (sizeof)    
		struct                                                                 // 5 elements, 0x30 bytes (sizeof)    
		{
			/*0x258*/             UINT8        SavedApcStateFill[43];
			/*0x283*/             UINT8        WaitReason;
			/*0x284*/             CHAR         SuspendCount;
			/*0x285*/             CHAR         Saturation;
			/*0x286*/             UINT16       SListFaultCount;
		};
	};
	union                                                                      // 7 elements, 0x58 bytes (sizeof)    
	{
		/*0x288*/         struct _KAPC SchedulerApc;                                             // 17 elements, 0x58 bytes (sizeof)   
		struct                                                                 // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x288*/             UINT8        SchedulerApcFill0[1];
			/*0x289*/             UINT8        ResourceIndex;
			/*0x28A*/             UINT8        _PADDING6_[0x56];
		};
		struct                                                                 // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x288*/             UINT8        SchedulerApcFill1[3];
			/*0x28B*/             UINT8        QuantumReset;
			/*0x28C*/             UINT8        _PADDING7_[0x54];
		};
		struct                                                                 // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x288*/             UINT8        SchedulerApcFill2[4];
			/*0x28C*/             ULONG32      KernelTime;
			/*0x290*/             UINT8        _PADDING8_[0x50];
		};
		struct                                                                 // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x288*/             UINT8        SchedulerApcFill3[64];
			/*0x2C8*/             struct _KPRCB *WaitPrcb;
			/*0x2D0*/             UINT8        _PADDING9_[0x10];
		};
		struct                                                                 // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x288*/             UINT8        SchedulerApcFill4[72];
			/*0x2D0*/             VOID *LegoData;
			/*0x2D8*/             UINT8        _PADDING10_[0x8];
		};
		struct                                                                 // 3 elements, 0x58 bytes (sizeof)    
		{
			/*0x288*/             UINT8        SchedulerApcFill5[83];
			/*0x2DB*/             UINT8        CallbackNestingLevel;
			/*0x2DC*/             ULONG32      UserTime;
		};
	};
	/*0x2E0*/     struct _KEVENT SuspendEvent;                                               // 1 elements, 0x18 bytes (sizeof)    
	/*0x2F8*/     struct _LIST_ENTRY ThreadListEntry;                                        // 2 elements, 0x10 bytes (sizeof)    
	/*0x308*/     struct _LIST_ENTRY MutantListHead;                                         // 2 elements, 0x10 bytes (sizeof)    
	/*0x318*/     UINT8        AbEntrySummary;
	/*0x319*/     UINT8        AbWaitEntryCount;
	/*0x31A*/     UINT8        AbAllocationRegionCount;
	/*0x31B*/     CHAR         SystemPriority;
	/*0x31C*/     ULONG32      SecureThreadCookie;
	/*0x320*/     struct _KLOCK_ENTRY *LockEntries;
	/*0x328*/     struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                            // 1 elements, 0x8 bytes (sizeof)     
	/*0x330*/     struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                               // 1 elements, 0x8 bytes (sizeof)     
	/*0x338*/     UINT8        PriorityFloorCounts[16];
	/*0x348*/     UINT8        PriorityFloorCountsReserved[16];
	/*0x358*/     ULONG32      PriorityFloorSummary;
	/*0x35C*/     LONG32       AbCompletedIoBoostCount;
	/*0x360*/     LONG32       AbCompletedIoQoSBoostCount;
	/*0x364*/     INT16        KeReferenceCount;
	/*0x366*/     UINT8        AbOrphanedEntrySummary;
	/*0x367*/     UINT8        AbOwnedEntryCount;
	/*0x368*/     ULONG32      ForegroundLossTime;
	/*0x36C*/     UINT8        _PADDING11_[0x4];
	union                                                                      // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x370*/         struct _LIST_ENTRY GlobalForegroundListEntry;                          // 2 elements, 0x10 bytes (sizeof)    
		struct                                                                 // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x370*/             struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;             // 1 elements, 0x8 bytes (sizeof)     
			/*0x378*/             UINT64       InGlobalForegroundList;
		};
	};
	/*0x380*/     INT64        ReadOperationCount;
	/*0x388*/     INT64        WriteOperationCount;
	/*0x390*/     INT64        OtherOperationCount;
	/*0x398*/     INT64        ReadTransferCount;
	/*0x3A0*/     INT64        WriteTransferCount;
	/*0x3A8*/     INT64        OtherTransferCount;
	/*0x3B0*/     struct _KSCB *QueuedScb;
	/*0x3B8*/     ULONG32      ThreadTimerDelay;
	union                                                                      // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x3BC*/         LONG32       ThreadFlags3;
		struct                                                                 // 3 elements, 0x4 bytes (sizeof)     
		{
			/*0x3BC*/             ULONG32      ThreadFlags3Reserved : 8;                             // 0 BitPosition                      
			/*0x3BC*/             ULONG32      PpmPolicy : 2;                                        // 8 BitPosition                      
			/*0x3BC*/             ULONG32      ThreadFlags3Reserved2 : 22;                           // 10 BitPosition                     
		};
	};
	/*0x3C0*/     UINT64       TracingPrivate[1];
	/*0x3C8*/     VOID *SchedulerAssist;
	/*0x3D0*/     VOID *AbWaitObject;
	/*0x3D8*/     ULONG32      ReservedPreviousReadyTimeValue;
	/*0x3DC*/     UINT8        _PADDING12_[0x4];
	/*0x3E0*/     UINT64       KernelWaitTime;
	/*0x3E8*/     UINT64       UserWaitTime;
	union                                                                      // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x3F0*/         struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;              // 2 elements, 0x10 bytes (sizeof)    
		struct                                                                 // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x3F0*/             struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; // 1 elements, 0x8 bytes (sizeof)     
			/*0x3F8*/             UINT64       InGlobalUpdateVpThreadPriorityList;
		};
	};
	/*0x400*/     LONG32       SchedulerAssistPriorityFloor;
	/*0x404*/     ULONG32      Spare28;
	/*0x408*/     UINT64       EndPadding[5];
}KTHREAD, *PKTHREAD;

typedef union _PS_CLIENT_SECURITY_CONTEXT    // 4 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       ImpersonationData;
	/*0x000*/     VOID *ImpersonationToken;
	struct                                   // 2 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         UINT64       ImpersonationLevel : 2; // 0 BitPosition                  
		/*0x000*/         UINT64       EffectiveOnly : 1;      // 2 BitPosition                  
	};
}PS_CLIENT_SECURITY_CONTEXT, *PPS_CLIENT_SECURITY_CONTEXT;

typedef struct _PS_PROPERTY_SET  // 2 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY ListHead; // 2 elements, 0x10 bytes (sizeof) 
	/*0x010*/     UINT64       Lock;
}PS_PROPERTY_SET, *PPS_PROPERTY_SET;

typedef struct _KLOCK_ENTRY_LOCK_STATE              // 8 elements, 0x10 bytes (sizeof) 
{
	union                                           // 2 elements, 0x8 bytes (sizeof)  
	{
		struct                                      // 4 elements, 0x8 bytes (sizeof)  
		{
			/*0x000*/             UINT64       CrossThreadReleasable : 1; // 0 BitPosition                   
			/*0x000*/             UINT64       Busy : 1;                  // 1 BitPosition                   
			/*0x000*/             UINT64       Reserved : 61;             // 2 BitPosition                   
			/*0x000*/             UINT64       InTree : 1;                // 63 BitPosition                  
		};
		/*0x000*/         VOID *LockState;
	};
	union                                           // 2 elements, 0x8 bytes (sizeof)  
	{
		/*0x008*/         VOID *SessionState;
		struct                                      // 2 elements, 0x8 bytes (sizeof)  
		{
			/*0x008*/             ULONG32      SessionId;
			/*0x00C*/             ULONG32      SessionPad;
		};
	};
}KLOCK_ENTRY_LOCK_STATE, *PKLOCK_ENTRY_LOCK_STATE;

typedef struct _RTL_RB_TREE             // 3 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_BALANCED_NODE *Root;
	union                               // 2 elements, 0x8 bytes (sizeof)  
	{
		/*0x008*/         UINT8        Encoded : 1;       // 0 BitPosition                   
		/*0x008*/         struct _RTL_BALANCED_NODE *Min;
	};
}RTL_RB_TREE, *PRTL_RB_TREE;

typedef union _KLOCK_ENTRY_BOOST_BITMAP               // 8 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      AllFields;
	struct                                            // 4 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      AllBoosts : 17;                  // 0 BitPosition                  
		/*0x000*/         ULONG32      Reserved : 15;                   // 17 BitPosition                 
		/*0x000*/         UINT16       CpuBoostsBitmap : 15;            // 0 BitPosition                  
		/*0x000*/         UINT16       IoBoost : 1;                     // 15 BitPosition                 
	};
	struct                                            // 3 elements, 0x2 bytes (sizeof) 
	{
		/*0x002*/         UINT16       IoQoSBoost : 1;                  // 0 BitPosition                  
		/*0x002*/         UINT16       IoNormalPriorityWaiterCount : 8; // 1 BitPosition                  
		/*0x002*/         UINT16       IoQoSWaiterCount : 7;            // 9 BitPosition                  
	};
}KLOCK_ENTRY_BOOST_BITMAP, *PKLOCK_ENTRY_BOOST_BITMAP;

typedef struct _KLOCK_ENTRY                                // 31 elements, 0x60 bytes (sizeof) 
{
	union                                                  // 2 elements, 0x18 bytes (sizeof)  
	{
		/*0x000*/         struct _RTL_BALANCED_NODE TreeNode;                // 6 elements, 0x18 bytes (sizeof)  
		/*0x000*/         struct _SINGLE_LIST_ENTRY FreeListEntry;           // 1 elements, 0x8 bytes (sizeof)   
	};
	union                                                  // 3 elements, 0x4 bytes (sizeof)   
	{
		/*0x018*/         ULONG32      EntryFlags;
		struct                                             // 4 elements, 0x4 bytes (sizeof)   
		{
			/*0x018*/             UINT8        EntryOffset;
			union                                          // 2 elements, 0x1 bytes (sizeof)   
			{
				/*0x019*/                 UINT8        ThreadLocalFlags;
				struct                                     // 2 elements, 0x1 bytes (sizeof)   
				{
					/*0x019*/                     UINT8        WaitingBit : 1;           // 0 BitPosition                    
					/*0x019*/                     UINT8        Spare0 : 7;               // 1 BitPosition                    
				};
			};
			union                                          // 2 elements, 0x1 bytes (sizeof)   
			{
				/*0x01A*/                 UINT8        AcquiredByte;
				/*0x01A*/                 UINT8        AcquiredBit : 1;              // 0 BitPosition                    
			};
			union                                          // 2 elements, 0x1 bytes (sizeof)   
			{
				/*0x01B*/                 UINT8        CrossThreadFlags;
				struct                                     // 4 elements, 0x1 bytes (sizeof)   
				{
					/*0x01B*/                     UINT8        HeadNodeBit : 1;          // 0 BitPosition                    
					/*0x01B*/                     UINT8        IoPriorityBit : 1;        // 1 BitPosition                    
					/*0x01B*/                     UINT8        IoQoSWaiter : 1;          // 2 BitPosition                    
					/*0x01B*/                     UINT8        Spare1 : 5;               // 3 BitPosition                    
				};
			};
		};
		struct                                             // 2 elements, 0x4 bytes (sizeof)   
		{
			/*0x018*/             ULONG32      StaticState : 8;                  // 0 BitPosition                    
			/*0x018*/             ULONG32      AllFlags : 24;                    // 8 BitPosition                    
		};
	};
	/*0x01C*/     ULONG32      SpareFlags;
	union                                                  // 3 elements, 0x10 bytes (sizeof)  
	{
		/*0x020*/         struct _KLOCK_ENTRY_LOCK_STATE LockState;          // 8 elements, 0x10 bytes (sizeof)  
		/*0x020*/         VOID *LockUnsafe;
		struct                                             // 4 elements, 0x10 bytes (sizeof)  
		{
			/*0x020*/             UINT8        CrossThreadReleasableAndBusyByte;
			/*0x021*/             UINT8        Reserved[6];
			/*0x027*/             UINT8        InTreeByte;
			union                                          // 2 elements, 0x8 bytes (sizeof)   
			{
				/*0x028*/                 VOID *SessionState;
				struct                                     // 2 elements, 0x8 bytes (sizeof)   
				{
					/*0x028*/                     ULONG32      SessionId;
					/*0x02C*/                     ULONG32      SessionPad;
				};
			};
		};
	};
	union                                                  // 2 elements, 0x20 bytes (sizeof)  
	{
		struct                                             // 2 elements, 0x20 bytes (sizeof)  
		{
			/*0x030*/             struct _RTL_RB_TREE OwnerTree;                 // 3 elements, 0x10 bytes (sizeof)  
			/*0x040*/             struct _RTL_RB_TREE WaiterTree;                // 3 elements, 0x10 bytes (sizeof)  
		};
		/*0x030*/         CHAR         CpuPriorityKey;
	};
	/*0x050*/     UINT64       EntryLock;
	/*0x058*/     union _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;           // 8 elements, 0x4 bytes (sizeof)   
	/*0x05C*/     ULONG32      SparePad;
}KLOCK_ENTRY, *PKLOCK_ENTRY;

typedef struct _ETHREAD                                               // 120 elements, 0x898 bytes (sizeof) 
{
	/*0x000*/     struct _KTHREAD Tcb;                                              // 204 elements, 0x430 bytes (sizeof) 
	/*0x430*/     union _LARGE_INTEGER CreateTime;                                  // 4 elements, 0x8 bytes (sizeof)     
	union                                                             // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x438*/         union _LARGE_INTEGER ExitTime;                                // 4 elements, 0x8 bytes (sizeof)     
		/*0x438*/         struct _LIST_ENTRY KeyedWaitChain;                            // 2 elements, 0x10 bytes (sizeof)    
	};
	union                                                             // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x448*/         struct _LIST_ENTRY PostBlockList;                             // 2 elements, 0x10 bytes (sizeof)    
		struct                                                        // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x448*/             VOID *ForwardLinkShadow;
			/*0x450*/             VOID *StartAddress;
		};
	};
	union                                                             // 3 elements, 0x8 bytes (sizeof)     
	{
		/*0x458*/         struct _TERMINATION_PORT *TerminationPort;
		/*0x458*/         struct _ETHREAD *ReaperLink;
		/*0x458*/         VOID *KeyedWaitValue;
	};
	/*0x460*/     UINT64       ActiveTimerListLock;
	/*0x468*/     struct _LIST_ENTRY ActiveTimerListHead;                           // 2 elements, 0x10 bytes (sizeof)    
	/*0x478*/     struct _CLIENT_ID Cid;                                            // 2 elements, 0x10 bytes (sizeof)    
	union                                                             // 2 elements, 0x20 bytes (sizeof)    
	{
		/*0x488*/         struct _KSEMAPHORE KeyedWaitSemaphore;                        // 2 elements, 0x20 bytes (sizeof)    
		/*0x488*/         struct _KSEMAPHORE AlpcWaitSemaphore;                         // 2 elements, 0x20 bytes (sizeof)    
	};
	/*0x4A8*/     union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                 // 4 elements, 0x8 bytes (sizeof)     
	/*0x4B0*/     struct _LIST_ENTRY IrpList;                                       // 2 elements, 0x10 bytes (sizeof)    
	/*0x4C0*/     UINT64       TopLevelIrp;
	/*0x4C8*/     struct _DEVICE_OBJECT *DeviceToVerify;
	/*0x4D0*/     VOID *Win32StartAddress;
	/*0x4D8*/     VOID *ChargeOnlySession;
	/*0x4E0*/     VOID *LegacyPowerObject;
	/*0x4E8*/     struct _LIST_ENTRY ThreadListEntry;                               // 2 elements, 0x10 bytes (sizeof)    
	/*0x4F8*/     struct _EX_RUNDOWN_REF RundownProtect;                            // 2 elements, 0x8 bytes (sizeof)     
	/*0x500*/     struct _EX_PUSH_LOCK ThreadLock;                                  // 7 elements, 0x8 bytes (sizeof)     
	/*0x508*/     ULONG32      ReadClusterSize;
	/*0x50C*/     LONG32       MmLockOrdering;
	union                                                             // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x510*/         ULONG32      CrossThreadFlags;
		struct                                                        // 21 elements, 0x4 bytes (sizeof)    
		{
			/*0x510*/             ULONG32      Terminated : 1;                              // 0 BitPosition                      
			/*0x510*/             ULONG32      ThreadInserted : 1;                          // 1 BitPosition                      
			/*0x510*/             ULONG32      HideFromDebugger : 1;                        // 2 BitPosition                      
			/*0x510*/             ULONG32      ActiveImpersonationInfo : 1;                 // 3 BitPosition                      
			/*0x510*/             ULONG32      HardErrorsAreDisabled : 1;                   // 4 BitPosition                      
			/*0x510*/             ULONG32      BreakOnTermination : 1;                      // 5 BitPosition                      
			/*0x510*/             ULONG32      SkipCreationMsg : 1;                         // 6 BitPosition                      
			/*0x510*/             ULONG32      SkipTerminationMsg : 1;                      // 7 BitPosition                      
			/*0x510*/             ULONG32      CopyTokenOnOpen : 1;                         // 8 BitPosition                      
			/*0x510*/             ULONG32      ThreadIoPriority : 3;                        // 9 BitPosition                      
			/*0x510*/             ULONG32      ThreadPagePriority : 3;                      // 12 BitPosition                     
			/*0x510*/             ULONG32      RundownFail : 1;                             // 15 BitPosition                     
			/*0x510*/             ULONG32      UmsForceQueueTermination : 1;                // 16 BitPosition                     
			/*0x510*/             ULONG32      IndirectCpuSets : 1;                         // 17 BitPosition                     
			/*0x510*/             ULONG32      DisableDynamicCodeOptOut : 1;                // 18 BitPosition                     
			/*0x510*/             ULONG32      ExplicitCaseSensitivity : 1;                 // 19 BitPosition                     
			/*0x510*/             ULONG32      PicoNotifyExit : 1;                          // 20 BitPosition                     
			/*0x510*/             ULONG32      DbgWerUserReportActive : 1;                  // 21 BitPosition                     
			/*0x510*/             ULONG32      ForcedSelfTrimActive : 1;                    // 22 BitPosition                     
			/*0x510*/             ULONG32      SamplingCoverage : 1;                        // 23 BitPosition                     
			/*0x510*/             ULONG32      ReservedCrossThreadFlags : 8;                // 24 BitPosition                     
		};
	};
	union                                                             // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x514*/         ULONG32      SameThreadPassiveFlags;
		struct                                                        // 12 elements, 0x4 bytes (sizeof)    
		{
			/*0x514*/             ULONG32      ActiveExWorker : 1;                          // 0 BitPosition                      
			/*0x514*/             ULONG32      MemoryMaker : 1;                             // 1 BitPosition                      
			/*0x514*/             ULONG32      StoreLockThread : 2;                         // 2 BitPosition                      
			/*0x514*/             ULONG32      ClonedThread : 1;                            // 4 BitPosition                      
			/*0x514*/             ULONG32      KeyedEventInUse : 1;                         // 5 BitPosition                      
			/*0x514*/             ULONG32      SelfTerminate : 1;                           // 6 BitPosition                      
			/*0x514*/             ULONG32      RespectIoPriority : 1;                       // 7 BitPosition                      
			/*0x514*/             ULONG32      ActivePageLists : 1;                         // 8 BitPosition                      
			/*0x514*/             ULONG32      SecureContext : 1;                           // 9 BitPosition                      
			/*0x514*/             ULONG32      ZeroPageThread : 1;                          // 10 BitPosition                     
			/*0x514*/             ULONG32      WorkloadClass : 1;                           // 11 BitPosition                     
			/*0x514*/             ULONG32      ReservedSameThreadPassiveFlags : 20;         // 12 BitPosition                     
		};
	};
	union                                                             // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x518*/         ULONG32      SameThreadApcFlags;
		struct                                                        // 2 elements, 0x4 bytes (sizeof)     
		{
			struct                                                    // 8 elements, 0x1 bytes (sizeof)     
			{
				/*0x518*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;    // 0 BitPosition                      
				/*0x518*/                 UINT8        OwnsProcessAddressSpaceShared : 1;       // 1 BitPosition                      
				/*0x518*/                 UINT8        HardFaultBehavior : 1;                   // 2 BitPosition                      
				/*0x518*/                 UINT8        StartAddressInvalid : 1;                 // 3 BitPosition                      
				/*0x518*/                 UINT8        EtwCalloutActive : 1;                    // 4 BitPosition                      
				/*0x518*/                 UINT8        SuppressSymbolLoad : 1;                  // 5 BitPosition                      
				/*0x518*/                 UINT8        Prefetching : 1;                         // 6 BitPosition                      
				/*0x518*/                 UINT8        OwnsVadExclusive : 1;                    // 7 BitPosition                      
			};
			struct                                                    // 5 elements, 0x1 bytes (sizeof)     
			{
				/*0x519*/                 UINT8        SystemPagePriorityActive : 1;            // 0 BitPosition                      
				/*0x519*/                 UINT8        SystemPagePriority : 3;                  // 1 BitPosition                      
				/*0x519*/                 UINT8        AllowUserWritesToExecutableMemory : 1;   // 4 BitPosition                      
				/*0x519*/                 UINT8        AllowKernelWritesToExecutableMemory : 1; // 5 BitPosition                      
				/*0x519*/                 UINT8        OwnsVadShared : 1;                       // 6 BitPosition                      
			};
		};
	};
	/*0x51C*/     UINT8        CacheManagerActive;
	/*0x51D*/     UINT8        DisablePageFaultClustering;
	/*0x51E*/     UINT8        ActiveFaultCount;
	/*0x51F*/     UINT8        LockOrderState;
	/*0x520*/     ULONG32      PerformanceCountLowReserved;
	/*0x524*/     LONG32       PerformanceCountHighReserved;
	/*0x528*/     UINT64       AlpcMessageId;
	union                                                             // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x530*/         VOID *AlpcMessage;
		/*0x530*/         ULONG32      AlpcReceiveAttributeSet;
	};
	/*0x538*/     struct _LIST_ENTRY AlpcWaitListEntry;                             // 2 elements, 0x10 bytes (sizeof)    
	/*0x548*/     LONG32       ExitStatus;
	/*0x54C*/     ULONG32      CacheManagerCount;
	/*0x550*/     ULONG32      IoBoostCount;
	/*0x554*/     ULONG32      IoQoSBoostCount;
	/*0x558*/     ULONG32      IoQoSThrottleCount;
	/*0x55C*/     ULONG32      KernelStackReference;
	/*0x560*/     struct _LIST_ENTRY BoostList;                                     // 2 elements, 0x10 bytes (sizeof)    
	/*0x570*/     struct _LIST_ENTRY DeboostList;                                   // 2 elements, 0x10 bytes (sizeof)    
	/*0x580*/     UINT64       BoostListLock;
	/*0x588*/     UINT64       IrpListLock;
	/*0x590*/     VOID *ReservedForSynchTracking;
	/*0x598*/     struct _SINGLE_LIST_ENTRY CmCallbackListHead;                     // 1 elements, 0x8 bytes (sizeof)     
	/*0x5A0*/     struct _GUID *ActivityId;
	/*0x5A8*/     struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                 // 1 elements, 0x8 bytes (sizeof)     
	/*0x5B0*/     VOID *VerifierContext;
	/*0x5B8*/     VOID *AdjustedClientToken;
	/*0x5C0*/     VOID *WorkOnBehalfThread;
	/*0x5C8*/     struct _PS_PROPERTY_SET PropertySet;                              // 2 elements, 0x18 bytes (sizeof)    
	/*0x5E0*/     VOID *PicoContext;
	/*0x5E8*/     UINT64       UserFsBase;
	/*0x5F0*/     UINT64       UserGsBase;
	/*0x5F8*/     struct _THREAD_ENERGY_VALUES *EnergyValues;
	union                                                             // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x600*/         UINT64       SelectedCpuSets;
		/*0x600*/         UINT64 *SelectedCpuSetsIndirect;
	};
	/*0x608*/     struct _EJOB *Silo;
	/*0x610*/     struct _UNICODE_STRING *ThreadName;
	/*0x618*/     struct _CONTEXT *SetContextState;
	/*0x620*/     ULONG32      LastExpectedRunTime;
	/*0x624*/     ULONG32      HeapData;
	/*0x628*/     struct _LIST_ENTRY OwnerEntryListHead;                            // 2 elements, 0x10 bytes (sizeof)    
	/*0x638*/     UINT64       DisownedOwnerEntryListLock;
	/*0x640*/     struct _LIST_ENTRY DisownedOwnerEntryListHead;                    // 2 elements, 0x10 bytes (sizeof)    
	/*0x650*/     struct _KLOCK_ENTRY LockEntries[6];
	/*0x890*/     VOID *CmDbgInfo;
}ETHREAD_BY, *PETHREAD_BY;

typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                                                                                                                                                                                                                                     // 32 elements, 0x78 bytes (sizeof) 
{
	/*0x000*/     UINT16       Length;
	union                                                                                                                                                                                                                                                                                                                                                                                   // 2 elements, 0x2 bytes (sizeof)   
	{
		/*0x002*/         UINT16       ObjectTypeFlags;
		struct                                                                                                                                                                                                                                                                                                                                                                              // 2 elements, 0x2 bytes (sizeof)   
		{
			struct                                                                                                                                                                                                                                                                                                                                                                          // 8 elements, 0x1 bytes (sizeof)   
			{
				/*0x002*/                 UINT8        CaseInsensitive : 1;                                                                                                                                                                                                                                                                                                                                           // 0 BitPosition                    
				/*0x002*/                 UINT8        UnnamedObjectsOnly : 1;                                                                                                                                                                                                                                                                                                                                        // 1 BitPosition                    
				/*0x002*/                 UINT8        UseDefaultObject : 1;                                                                                                                                                                                                                                                                                                                                          // 2 BitPosition                    
				/*0x002*/                 UINT8        SecurityRequired : 1;                                                                                                                                                                                                                                                                                                                                          // 3 BitPosition                    
				/*0x002*/                 UINT8        MaintainHandleCount : 1;                                                                                                                                                                                                                                                                                                                                       // 4 BitPosition                    
				/*0x002*/                 UINT8        MaintainTypeList : 1;                                                                                                                                                                                                                                                                                                                                          // 5 BitPosition                    
				/*0x002*/                 UINT8        SupportsObjectCallbacks : 1;                                                                                                                                                                                                                                                                                                                                   // 6 BitPosition                    
				/*0x002*/                 UINT8        CacheAligned : 1;                                                                                                                                                                                                                                                                                                                                              // 7 BitPosition                    
			};
			struct                                                                                                                                                                                                                                                                                                                                                                          // 2 elements, 0x1 bytes (sizeof)   
			{
				/*0x003*/                 UINT8        UseExtendedParameters : 1;                                                                                                                                                                                                                                                                                                                                     // 0 BitPosition                    
				/*0x003*/                 UINT8        Reserved : 7;                                                                                                                                                                                                                                                                                                                                                  // 1 BitPosition                    
			};
		};
	};
	/*0x004*/     ULONG32      ObjectTypeCode;
	/*0x008*/     ULONG32      InvalidAttributes;
	/*0x00C*/     struct _GENERIC_MAPPING GenericMapping;                                                                                                                                                                                                                                                                                                                                                 // 4 elements, 0x10 bytes (sizeof)  
	/*0x01C*/     ULONG32      ValidAccessMask;
	/*0x020*/     ULONG32      RetainAccess;
	/*0x024*/     enum _POOL_TYPE PoolType;
	/*0x028*/     ULONG32      DefaultPagedPoolCharge;
	/*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
	/*0x030*/     FUNCT_011D_2820_DumpProcedure *DumpProcedure;
	/*0x038*/     FUNCT_0115_2828_OpenProcedure *OpenProcedure;
	/*0x040*/     FUNCT_011D_2836_CloseProcedure *CloseProcedure;
	/*0x048*/     FUNCT_011D_059F_Free_InterfaceReference_InterfaceDereference_WorkerRoutine_Callback_DevicePowerRequired_DevicePowerNotRequired_DeleteCallback_Uninitialize_ClearLocalUnitError_EndOfInterrupt_InitializeController_DeleteProcedure_ReleaseFromLazyWrite_ReleaseFromReadAhead_CleanupProcedure_HalLocateHiberRanges_HalDpReplaceTarget_HalDpReplaceEnd_DisableCallback *DeleteProcedure;
	union                                                                                                                                                                                                                                                                                                                                                                                   // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x050*/         FUNCT_0115_283C_ParseProcedure *ParseProcedure;
		/*0x050*/         FUNCT_0115_2848_ParseProcedureEx *ParseProcedureEx;
	};
	/*0x058*/     FUNCT_0115_285A_SecurityProcedure *SecurityProcedure;
	/*0x060*/     FUNCT_0115_286B_QueryNameProcedure *QueryNameProcedure;
	/*0x068*/     FUNCT_0116_2873_OkayToCloseProcedure *OkayToCloseProcedure;
	/*0x070*/     ULONG32      WaitObjectFlagMask;
	/*0x074*/     UINT16       WaitObjectFlagOffset;
	/*0x076*/     UINT16       WaitObjectPointerOffset;
}OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE                   // 12 elements, 0xD8 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)  
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)  
	/*0x020*/     VOID *DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x029*/     UINT8        _PADDING0_[0x3];
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x03C*/     UINT8        _PADDING1_[0x4];
	/*0x040*/     struct _OBJECT_TYPE_INITIALIZER TypeInfo; // 32 elements, 0x78 bytes (sizeof) 
	/*0x0B8*/     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)   
	/*0x0C0*/     ULONG32      Key;
	/*0x0C4*/     UINT8        _PADDING2_[0x4];
	/*0x0C8*/     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)  
}OBJECT_TYPE, *POBJECT_TYPE;


//
	// Flags for cross thread access. Use interlocked operations
	// via PS_SET_BITS etc.
	//

	//
	// Used to signify that the delete APC has been queued or the
	// thread has called PspExitThread itself.
	//

#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL

//
// Thread create failed
//

#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL

//
// Debugger isn't shown this thread
//

#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL

//
// Thread is impersonating
//

#define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL

//
// This is a system thread
//

#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL

//
// Hard errors are disabled for this thread
//

#define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL

//
// We should break in when this thread is terminated
//

#define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL

//
// This thread should skip sending its create thread message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL

//
// This thread should skip sending its final thread termination message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL

#define PS_SET_BITS(Flags, Flag) \
                    RtlInterlockedSetBitsDiscardReturn (Flags, Flag)



typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	union
	{
		UINT8        FlagGroup[4];
		ULONG32      Flags;
		struct
		{
			ULONG32      PackagedBinary : 1;
			ULONG32      MarkedForRemoval : 1;
			ULONG32      ImageDll : 1;
			ULONG32      LoadNotificationsSent : 1;
			ULONG32      TelemetryEntryProcessed : 1;
			ULONG32      ProcessStaticImport : 1;
			ULONG32      InLegacyLists : 1;
			ULONG32      InIndexes : 1;
			ULONG32      ShimDll : 1;
			ULONG32      InExceptionTable : 1;
			ULONG32      ReservedFlags1 : 2;
			ULONG32      LoadInProgress : 1;
			ULONG32      LoadConfigProcessed : 1;
			ULONG32      EntryProcessed : 1;
			ULONG32      ProtectDelayLoad : 1;
			ULONG32      ReservedFlags3 : 2;
			ULONG32      DontCallForThreads : 1;
			ULONG32      ProcessAttachCalled : 1;
			ULONG32      ProcessAttachFailed : 1;
			ULONG32      CorDeferredValidate : 1;
			ULONG32      CorImage : 1;
			ULONG32      DontRelocate : 1;
			ULONG32      CorILOnly : 1;
			ULONG32      ReservedFlags5 : 3;
			ULONG32      Redirected : 1;
			ULONG32      ReservedFlags6 : 2;
			ULONG32      CompatDatabaseProcessed : 1;
		};
	};
	UINT16       ObsoleteLoadCount;
	UINT16       TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG32      TimeDateStamp;
	UINT8        _PADDING1_[0x4];
	ULONG EntryPointActivationContext;
	ULONG Lock;
	ULONG DdagNode;
	LIST_ENTRY32 NodeModuleLink;
	ULONG LoadContext;
	ULONG ParentDllBase;
	ULONG SwitchBackContext;
}LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _KWAIT_CHAIN_ENTRY // 3 elements, 0x30 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY ListEntry; // 2 elements, 0x10 bytes (sizeof) 
	/*0x010*/     struct _KTHREAD *Thread;
	/*0x018*/     struct _KEVENT Event;         // 1 elements, 0x18 bytes (sizeof) 
}KWAIT_CHAIN_ENTRY, *PKWAIT_CHAIN_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY                         // 59 elements, 0x120 bytes (sizeof) 
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
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed
#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)
#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27
#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //



//
// Process Specific Access Rights
//

//#define PROCESS_CREATE_THREAD     (0x0002)  // winnt
//#define PROCESS_SET_SESSIONID     (0x0004)  // winnt
//#define PROCESS_VM_OPERATION      (0x0008)  // winnt
//#define PROCESS_VM_READ           (0x0010)  // winnt
//#define PROCESS_VM_WRITE          (0x0020)  // winnt
//// begin_ntddk begin_wdm begin_ntifs
//#define PROCESS_DUP_HANDLE        (0x0040)  // winnt
//// end_ntddk end_wdm end_ntifs
//#define PROCESS_CREATE_PROCESS    (0x0080)  // winnt
//#define PROCESS_SET_QUOTA         (0x0100)  // winnt
//#define PROCESS_SET_INFORMATION   (0x0200)  // winnt
//#define PROCESS_QUERY_INFORMATION (0x0400)  // winnt
#define PROCESS_SET_PORT          (0x0800)
//#define PROCESS_SUSPEND_RESUME    (0x0800)  // winnt

// begin_winnt begin_ntddk begin_wdm begin_ntifs
//#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
//                                   0xFFF)


//
// Get Current Prototypes
//
#define THREAD_TO_PROCESS(Thread) ((Thread)->ThreadsProcess)
#define IS_SYSTEM_THREAD(Thread)  (((Thread)->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SYSTEM) != 0)



typedef struct _PS_SYSTEM_DLL_INFO {

	//
	// Flags.
	// Initialized statically.
	// 

	USHORT        Flags;        // 0x0

	//
	// Machine type of this WoW64 NTDLL.
	// Initialized statically.
	// Examples:
	//   - IMAGE_FILE_MACHINE_I386
	//   - IMAGE_FILE_MACHINE_ARMNT
	//

	USHORT        MachineType;  // 0x2

	//
	// Unused, always 0.
	//

	ULONG         Reserved1;    // 0x4

	//
	// Path to the WoW64 NTDLL.
	// Initialized statically.
	// Examples:
	//   - "\\SystemRoot\\SysWOW64\\ntdll.dll"
	//   - "\\SystemRoot\\SysArm32\\ntdll.dll"
	//

	UNICODE_STRING Ntdll32Path; // 0x8

	//
	// Image base of the DLL.
	// Initialized at runtime by PspMapSystemDll.
	// Equivalent of:
	//      RtlImageNtHeader(BaseAddress)->
	//          OptionalHeader.ImageBase;
	//

	PVOID         ImageBase;    // 0x18

	//
	// Contains DLL name (such as "ntdll.dll" or
	// "ntdll32.dll") before runtime initialization.
	// Initialized at runtime by MmMapViewOfSectionEx,
	// called from PspMapSystemDll.
	//

	union {                     // 0x20
		PVOID       BaseAddress;
		PWCHAR      DllName;
	};

	//
	// Unused, always 0.
	//

	PVOID         Reserved2;    // 0x28

	//
	// Section relocation information.
	//

	PVOID         SectionRelocationInformation; // 0x30

	//
	// Unused, always 0.
	//

	PVOID         Reserved3;    // 0x30

} PS_SYSTEM_DLL_INFO, *PPS_SYSTEM_DLL_INFO;

typedef struct _PS_SYSTEM_DLL {

	//
	// _SECTION* object of the DLL.
	// Initialized at runtime by PspLocateSystemDll.
	//

	union {     // 0x0
		EX_FAST_REF SectionObjectFastRef;
		PVOID       SectionObject;
	};

	//
	// Push lock.
	//

	EX_PUSH_LOCK  PushLock;     // 0x8

	//
	// System DLL information.
	// This part is returned by PsQuerySystemDllInfo.
	//

	PS_SYSTEM_DLL_INFO SystemDllInfo;   // 0x10

} PS_SYSTEM_DLL, *PPS_SYSTEM_DLL;


typedef struct _MMSECTION_FLAGS                        // 27 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT32       BeingDeleted : 1;                     // 0 BitPosition                   
	/*0x000*/     UINT32       BeingCreated : 1;                     // 1 BitPosition                   
	/*0x000*/     UINT32       BeingPurged : 1;                      // 2 BitPosition                   
	/*0x000*/     UINT32       NoModifiedWriting : 1;                // 3 BitPosition                   
	/*0x000*/     UINT32       FailAllIo : 1;                        // 4 BitPosition                   
	/*0x000*/     UINT32       Image : 1;                            // 5 BitPosition                   
	/*0x000*/     UINT32       Based : 1;                            // 6 BitPosition                   
	/*0x000*/     UINT32       File : 1;                             // 7 BitPosition                   
	/*0x000*/     UINT32       AttemptingDelete : 1;                 // 8 BitPosition                   
	/*0x000*/     UINT32       PrefetchCreated : 1;                  // 9 BitPosition                   
	/*0x000*/     UINT32       PhysicalMemory : 1;                   // 10 BitPosition                  
	/*0x000*/     UINT32       ImageControlAreaOnRemovableMedia : 1; // 11 BitPosition                  
	/*0x000*/     UINT32       Reserve : 1;                          // 12 BitPosition                  
	/*0x000*/     UINT32       Commit : 1;                           // 13 BitPosition                  
	/*0x000*/     UINT32       NoChange : 1;                         // 14 BitPosition                  
	/*0x000*/     UINT32       WasPurged : 1;                        // 15 BitPosition                  
	/*0x000*/     UINT32       UserReference : 1;                    // 16 BitPosition                  
	/*0x000*/     UINT32       GlobalMemory : 1;                     // 17 BitPosition                  
	/*0x000*/     UINT32       DeleteOnClose : 1;                    // 18 BitPosition                  
	/*0x000*/     UINT32       FilePointerNull : 1;                  // 19 BitPosition                  
	/*0x000*/     UINT32       PreferredNode : 6;                    // 20 BitPosition                  
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;             // 26 BitPosition                  
	/*0x000*/     UINT32       UserWritable : 1;                     // 27 BitPosition                  
	/*0x000*/     UINT32       SystemVaAllocated : 1;                // 28 BitPosition                  
	/*0x000*/     UINT32       PreferredFsCompressionBoundary : 1;   // 29 BitPosition                  
	/*0x000*/     UINT32       UsingFileExtents : 1;                 // 30 BitPosition                  
	/*0x000*/     UINT32       PageSize64K : 1;                      // 31 BitPosition                  
}MMSECTION_FLAGS, *PMMSECTION_FLAGS;

typedef struct _SECTION                             // 9 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_BALANCED_NODE SectionNode;          // 6 elements, 0x18 bytes (sizeof) 
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
	union                                           // 4 elements, 0x8 bytes (sizeof)  
	{
		/*0x028*/         struct _CONTROL_AREA *ControlArea;
		/*0x028*/         struct _FILE_OBJECT *FileObject;
		struct                                      // 2 elements, 0x8 bytes (sizeof)  
		{
			/*0x028*/             UINT64       RemoteImageFileObject : 1; // 0 BitPosition                   
			/*0x028*/             UINT64       RemoteDataFileObject : 1;  // 1 BitPosition                   
		};
	}u1;
	/*0x030*/     UINT64       SizeOfSection;
	union                                           // 2 elements, 0x4 bytes (sizeof)  
	{
		/*0x038*/         ULONG32      LongFlags;
		/*0x038*/         struct _MMSECTION_FLAGS Flags;              // 27 elements, 0x4 bytes (sizeof) 
	}u;
	struct                                          // 3 elements, 0x4 bytes (sizeof)  
	{
		/*0x03C*/         ULONG32      InitialPageProtection : 12;    // 0 BitPosition                   
		/*0x03C*/         ULONG32      SessionId : 19;                // 12 BitPosition                  
		/*0x03C*/         ULONG32      NoValidationNeeded : 1;        // 31 BitPosition                  
	};
}SECTION, *PSECTION;

typedef struct _MMSECTION_FLAGS2          // 2 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      PartitionId : 10;        // 0 BitPosition                  
	/*0x000*/     ULONG32      NumberOfChildViews : 22; // 10 BitPosition                 
}MMSECTION_FLAGS2, *PMMSECTION_FLAGS2;

typedef struct _CONTROL_AREA                                      // 16 elements, 0x80 bytes (sizeof) 
{
	/*0x000*/     struct _SEGMENT *Segment;
	/*0x008*/     struct _LIST_ENTRY ListHead;                                  // 2 elements, 0x10 bytes (sizeof)  
	/*0x018*/     UINT64       NumberOfSectionReferences;
	/*0x020*/     UINT64       NumberOfPfnReferences;
	/*0x028*/     UINT64       NumberOfMappedViews;
	/*0x030*/     UINT64       NumberOfUserReferences;
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x038*/         ULONG32      LongFlags;
		/*0x038*/         struct _MMSECTION_FLAGS Flags;                            // 27 elements, 0x4 bytes (sizeof)  
	}u;
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x03C*/         ULONG32      LongFlags;
		/*0x03C*/         struct _MMSECTION_FLAGS2 Flags;                           // 2 elements, 0x4 bytes (sizeof)   
	}u1;
	/*0x040*/     struct _EX_FAST_REF FilePointer;                              // 3 elements, 0x8 bytes (sizeof)   
	/*0x048*/     LONG32       ControlAreaLock;
	/*0x04C*/     ULONG32      ModifiedWriteCount;
	/*0x050*/     struct _MI_CONTROL_AREA_WAIT_BLOCK *WaitList;
	union                                                         // 1 elements, 0x10 bytes (sizeof)  
	{
		struct                                                    // 13 elements, 0x10 bytes (sizeof) 
		{
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x058*/                 ULONG32      NumberOfSystemCacheViews;
				/*0x058*/                 ULONG32      ImageRelocationStartBit;
			};
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x05C*/                 LONG32       WritableUserReferences;
				struct                                            // 7 elements, 0x4 bytes (sizeof)   
				{
					/*0x05C*/                     ULONG32      ImageRelocationSizeIn64k : 16;   // 0 BitPosition                    
					/*0x05C*/                     ULONG32      Unused : 9;                      // 16 BitPosition                   
					/*0x05C*/                     ULONG32      SystemImage : 1;                 // 25 BitPosition                   
					/*0x05C*/                     ULONG32      StrongCode : 2;                  // 26 BitPosition                   
					/*0x05C*/                     ULONG32      CantMove : 1;                    // 28 BitPosition                   
					/*0x05C*/                     ULONG32      BitMap : 2;                      // 29 BitPosition                   
					/*0x05C*/                     ULONG32      ImageActive : 1;                 // 31 BitPosition                   
				};
			};
			union                                                 // 3 elements, 0x8 bytes (sizeof)   
			{
				/*0x060*/                 ULONG32      FlushInProgressCount;
				/*0x060*/                 ULONG32      NumberOfSubsections;
				/*0x060*/                 struct _MI_IMAGE_SECURITY_REFERENCE *SeImageStub;
			};
		}e2;
	}u2;
	/*0x068*/     struct _EX_PUSH_LOCK FileObjectLock;                          // 7 elements, 0x8 bytes (sizeof)   
	/*0x070*/     UINT64       LockedPages;
	union                                                         // 3 elements, 0x8 bytes (sizeof)   
	{
		struct                                                    // 2 elements, 0x8 bytes (sizeof)   
		{
			/*0x078*/             UINT64       IoAttributionContext : 61;               // 0 BitPosition                    
			/*0x078*/             UINT64       Spare : 3;                               // 61 BitPosition                   
		};
		/*0x078*/         UINT64       SpareImage;
	}u3;
}CONTROL_AREA, *PCONTROL_AREA;


typedef struct _HANDLE_TABLE_FREE_LIST               // 5 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _EX_PUSH_LOCK FreeListLock;               // 7 elements, 0x8 bytes (sizeof)  
	/*0x008*/     union _HANDLE_TABLE_ENTRY *FirstFreeHandleEntry;
	/*0x010*/     union _HANDLE_TABLE_ENTRY *LastFreeHandleEntry;
	/*0x018*/     LONG32       HandleCount;
	/*0x01C*/     ULONG32      HighWaterMark;
	/*0x020*/     UINT8        _PADDING0_[0x20];
}HANDLE_TABLE_FREE_LIST, *PHANDLE_TABLE_FREE_LIST;

typedef struct _HANDLE_TABLE                                       // 17 elements, 0x80 bytes (sizeof) 
{
	/*0x000*/     ULONG32      NextHandleNeedingPool;
	/*0x004*/     LONG32       ExtraInfoPages;
	/*0x008*/     UINT64       TableCode;
	/*0x010*/     struct _EPROCESS *QuotaProcess;
	/*0x018*/     struct _LIST_ENTRY HandleTableList;                            // 2 elements, 0x10 bytes (sizeof)  
	/*0x028*/     ULONG32      UniqueProcessId;
	union                                                          // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x02C*/         ULONG32      Flags;
		struct                                                     // 5 elements, 0x1 bytes (sizeof)   
		{
			/*0x02C*/             UINT8        StrictFIFO : 1;                           // 0 BitPosition                    
			/*0x02C*/             UINT8        EnableHandleExceptions : 1;               // 1 BitPosition                    
			/*0x02C*/             UINT8        Rundown : 1;                              // 2 BitPosition                    
			/*0x02C*/             UINT8        Duplicated : 1;                           // 3 BitPosition                    
			/*0x02C*/             UINT8        RaiseUMExceptionOnInvalidHandleClose : 1; // 4 BitPosition                    
		};
	};
	/*0x030*/     struct _EX_PUSH_LOCK HandleContentionEvent;                    // 7 elements, 0x8 bytes (sizeof)   
	/*0x038*/     struct _EX_PUSH_LOCK HandleTableLock;                          // 7 elements, 0x8 bytes (sizeof)   
	union                                                          // 2 elements, 0x40 bytes (sizeof)  
	{
		/*0x040*/         struct _HANDLE_TABLE_FREE_LIST FreeLists[1];
		struct                                                     // 2 elements, 0x40 bytes (sizeof)  
		{
			/*0x040*/             UINT8        ActualEntry[32];
			/*0x060*/             struct _HANDLE_TRACE_DEBUG_INFO *DebugInfo;
			/*0x068*/             UINT8        _PADDING0_[0x18];
		};
	};
}HANDLE_TABLE, *PHANDLE_TABLE;


#define MM_WORKING_SET_MAX_HARD_ENABLE      0x1
#define MM_WORKING_SET_MAX_HARD_DISABLE     0x2
#define MM_WORKING_SET_MIN_HARD_ENABLE      0x4
#define MM_WORKING_SET_MIN_HARD_DISABLE     0x8


#define KERNEL_HANDLE_MASK ((ULONG_PTR)((LONG)0x80000000))



typedef struct _PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID *SsHandle;
	/*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof) 
	/*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof) 
	/*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof) 
	/*0x040*/     VOID *EntryInProgress;
	/*0x048*/     UINT8        ShutdownInProgress;
	/*0x049*/     UINT8        _PADDING1_[0x7];
	/*0x050*/     VOID *ShutdownThreadId;
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB                                                                                                                                                                                                                                                                                                                                                                                                                                 // 115 elements, 0x7C8 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                                                                                                                                                                                                                                                                                                                                                                                                           // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x003*/         UINT8        BitField;
		struct                                                                                                                                                                                                                                                                                                                                                                                                                                      // 8 elements, 0x1 bytes (sizeof)     
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;                                                                                                                                                                                                                                                                                                                                                                                                   // 0 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcess : 1;                                                                                                                                                                                                                                                                                                                                                                                                    // 1 BitPosition                      
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;                                                                                                                                                                                                                                                                                                                                                                                           // 2 BitPosition                      
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1;                                                                                                                                                                                                                                                                                                                                                                                          // 3 BitPosition                      
			/*0x003*/             UINT8        IsPackagedProcess : 1;                                                                                                                                                                                                                                                                                                                                                                                                     // 4 BitPosition                      
			/*0x003*/             UINT8        IsAppContainer : 1;                                                                                                                                                                                                                                                                                                                                                                                                        // 5 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcessLight : 1;                                                                                                                                                                                                                                                                                                                                                                                               // 6 BitPosition                      
			/*0x003*/             UINT8        IsLongPathAwareProcess : 1;                                                                                                                                                                                                                                                                                                                                                                                                // 7 BitPosition                      
		};
	};
	/*0x004*/     UINT8        Padding0[4];
	/*0x008*/     VOID *Mutant;
	/*0x010*/     VOID *ImageBaseAddress;
	/*0x018*/     struct _PEB_LDR_DATA *Ldr;
	/*0x020*/     struct _RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
	/*0x028*/     VOID *SubSystemData;
	/*0x030*/     VOID *ProcessHeap;
	/*0x038*/     struct _RTL_CRITICAL_SECTION *FastPebLock;
	/*0x040*/     union _SLIST_HEADER *AtlThunkSListPtr;
	/*0x048*/     VOID *IFEOKey;
	union                                                                                                                                                                                                                                                                                                                                                                                                                                           // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct                                                                                                                                                                                                                                                                                                                                                                                                                                      // 9 elements, 0x4 bytes (sizeof)     
		{
			/*0x050*/             ULONG32      ProcessInJob : 1;                                                                                                                                                                                                                                                                                                                                                                                                          // 0 BitPosition                      
			/*0x050*/             ULONG32      ProcessInitializing : 1;                                                                                                                                                                                                                                                                                                                                                                                                   // 1 BitPosition                      
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;                                                                                                                                                                                                                                                                                                                                                                                                       // 2 BitPosition                      
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;                                                                                                                                                                                                                                                                                                                                                                                                       // 3 BitPosition                      
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;                                                                                                                                                                                                                                                                                                                                                                                                       // 4 BitPosition                      
			/*0x050*/             ULONG32      ProcessPreviouslyThrottled : 1;                                                                                                                                                                                                                                                                                                                                                                                            // 5 BitPosition                      
			/*0x050*/             ULONG32      ProcessCurrentlyThrottled : 1;                                                                                                                                                                                                                                                                                                                                                                                             // 6 BitPosition                      
			/*0x050*/             ULONG32      ProcessImagesHotPatched : 1;                                                                                                                                                                                                                                                                                                                                                                                               // 7 BitPosition                      
			/*0x050*/             ULONG32      ReservedBits0 : 24;                                                                                                                                                                                                                                                                                                                                                                                                        // 8 BitPosition                      
		};
	};
	/*0x054*/     UINT8        Padding1[4];
	union                                                                                                                                                                                                                                                                                                                                                                                                                                           // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x058*/         VOID *KernelCallbackTable;
		/*0x058*/         VOID *UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved;
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     VOID *ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        Padding2[4];
	/*0x078*/     VOID *TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     VOID *ReadOnlySharedMemoryBase;
	/*0x090*/     VOID *SharedData;
	/*0x098*/     VOID **ReadOnlyStaticServerData;
	/*0x0A0*/     VOID *AnsiCodePageData;
	/*0x0A8*/     VOID *OemCodePageData;
	/*0x0B0*/     VOID *UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     union _LARGE_INTEGER CriticalSectionTimeout;                                                                                                                                                                                                                                                                                                                                                                                                    // 4 elements, 0x8 bytes (sizeof)     
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     VOID **ProcessHeaps;
	/*0x0F8*/     VOID *GdiSharedHandleTable;
	/*0x100*/     VOID *ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        Padding3[4];
	/*0x110*/     struct _RTL_CRITICAL_SECTION *LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        Padding4[4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     FUNCT_011D_122D_PostProcessInitRoutine_FastEndOfInterrupt_EndOfInterrupt_HalHaltSystem_KdCheckPowerButton_HalResumeProcessorFromIdle_HalSaveAndDisableHvEnlightenment_HalRestoreHvEnlightenment_HalPciMarkHiberPhase_HalClockTimerInitialize_HalClockTimerStop_HalTimerWatchdogStart_HalTimerWatchdogResetCountdown_HalTimerWatchdogStop_HalAcpiLateRestore_HalInitPlatformDebugTriggers_DispatchAddress_FinishRoutine *PostProcessInitRoutine;
	/*0x238*/     VOID *TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        Padding5[4];
	/*0x2C8*/     union _ULARGE_INTEGER AppCompatFlags;                                                                                                                                                                                                                                                                                                                                                                                                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x2D0*/     union _ULARGE_INTEGER AppCompatFlagsUser;                                                                                                                                                                                                                                                                                                                                                                                                       // 4 elements, 0x8 bytes (sizeof)     
	/*0x2D8*/     VOID *pShimData;
	/*0x2E0*/     VOID *AppCompatInfo;
	/*0x2E8*/     struct _UNICODE_STRING CSDVersion;                                                                                                                                                                                                                                                                                                                                                                                                              // 3 elements, 0x10 bytes (sizeof)    
	/*0x2F8*/     struct _ACTIVATION_CONTEXT_DATA *ActivationContextData;
	/*0x300*/     struct _ASSEMBLY_STORAGE_MAP *ProcessAssemblyStorageMap;
	/*0x308*/     struct _ACTIVATION_CONTEXT_DATA *SystemDefaultActivationContextData;
	/*0x310*/     struct _ASSEMBLY_STORAGE_MAP *SystemAssemblyStorageMap;
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     VOID *SparePointers[4];
	/*0x340*/     ULONG32      SpareUlongs[5];
	/*0x354*/     UINT8        _PADDING0_[0x4];
	/*0x358*/     VOID *WerRegistrationData;
	/*0x360*/     VOID *WerShipAssertPtr;
	/*0x368*/     VOID *pUnused;
	/*0x370*/     VOID *pImageHeaderHash;
	union                                                                                                                                                                                                                                                                                                                                                                                                                                           // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x378*/         ULONG32      TracingFlags;
		struct                                                                                                                                                                                                                                                                                                                                                                                                                                      // 4 elements, 0x4 bytes (sizeof)     
		{
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;                                                                                                                                                                                                                                                                                                                                                                                                    // 0 BitPosition                      
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;                                                                                                                                                                                                                                                                                                                                                                                                 // 1 BitPosition                      
			/*0x378*/             ULONG32      LibLoaderTracingEnabled : 1;                                                                                                                                                                                                                                                                                                                                                                                               // 2 BitPosition                      
			/*0x378*/             ULONG32      SpareTracingBits : 29;                                                                                                                                                                                                                                                                                                                                                                                                     // 3 BitPosition                      
		};
	};
	/*0x37C*/     UINT8        Padding6[4];
	/*0x380*/     UINT64       CsrServerReadOnlySharedMemoryBase;
	/*0x388*/     UINT64       TppWorkerpListLock;
	/*0x390*/     struct _LIST_ENTRY TppWorkerpList;                                                                                                                                                                                                                                                                                                                                                                                                              // 2 elements, 0x10 bytes (sizeof)    
	/*0x3A0*/     VOID *WaitOnAddressHashTable[128];
	/*0x7A0*/     VOID *TelemetryCoverageHeader;
	/*0x7A8*/     ULONG32      CloudFileFlags;
	/*0x7AC*/     ULONG32      CloudFileDiagFlags;
	/*0x7B0*/     CHAR         PlaceholderCompatibilityMode;
	/*0x7B1*/     CHAR         PlaceholderCompatibilityModeReserved[7];
	/*0x7B8*/     struct _LEAP_SECOND_DATA *LeapSecondData;
	union                                                                                                                                                                                                                                                                                                                                                                                                                                           // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x7C0*/         ULONG32      LeapSecondFlags;
		struct                                                                                                                                                                                                                                                                                                                                                                                                                                      // 2 elements, 0x4 bytes (sizeof)     
		{
			/*0x7C0*/             ULONG32      SixtySecondEnabled : 1;                                                                                                                                                                                                                                                                                                                                                                                                    // 0 BitPosition                      
			/*0x7C0*/             ULONG32      Reserved : 31;                                                                                                                                                                                                                                                                                                                                                                                                             // 1 BitPosition                      
		};
	};
	/*0x7C4*/     ULONG32      NtGlobalFlag2;
}PEB_BY, *PPEB_BY;

typedef struct _PEB32                                      // 108 elements, 0x480 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                  // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x003*/         UINT8        BitField;
		struct                                             // 8 elements, 0x1 bytes (sizeof)     
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition                      
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 2 BitPosition                      
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 3 BitPosition                      
			/*0x003*/             UINT8        IsPackagedProcess : 1;            // 4 BitPosition                      
			/*0x003*/             UINT8        IsAppContainer : 1;               // 5 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcessLight : 1;      // 6 BitPosition                      
			/*0x003*/             UINT8        IsLongPathAwareProcess : 1;       // 7 BitPosition                      
		};
	};
	/*0x004*/     ULONG32      Mutant;
	/*0x008*/     ULONG32      ImageBaseAddress;
	/*0x00C*/     ULONG32      Ldr;
	/*0x010*/     ULONG32      ProcessParameters;
	/*0x014*/     ULONG32      SubSystemData;
	/*0x018*/     ULONG32      ProcessHeap;
	/*0x01C*/     ULONG32      FastPebLock;
	/*0x020*/     ULONG32      AtlThunkSListPtr;
	/*0x024*/     ULONG32      IFEOKey;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x028*/         ULONG32      CrossProcessFlags;
		struct                                             // 9 elements, 0x4 bytes (sizeof)     
		{
			/*0x028*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition                      
			/*0x028*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition                      
			/*0x028*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition                      
			/*0x028*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition                      
			/*0x028*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition                      
			/*0x028*/             ULONG32      ProcessPreviouslyThrottled : 1;   // 5 BitPosition                      
			/*0x028*/             ULONG32      ProcessCurrentlyThrottled : 1;    // 6 BitPosition                      
			/*0x028*/             ULONG32      ProcessImagesHotPatched : 1;      // 7 BitPosition                      
			/*0x028*/             ULONG32      ReservedBits0 : 24;               // 8 BitPosition                      
		};
	};
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x02C*/         ULONG32      KernelCallbackTable;
		/*0x02C*/         ULONG32      UserSharedInfoPtr;
	};
	/*0x030*/     ULONG32      SystemReserved;
	/*0x034*/     ULONG32      AtlThunkSListPtr32;
	/*0x038*/     ULONG32      ApiSetMap;
	/*0x03C*/     ULONG32      TlsExpansionCounter;
	/*0x040*/     ULONG32      TlsBitmap;
	/*0x044*/     ULONG32      TlsBitmapBits[2];
	/*0x04C*/     ULONG32      ReadOnlySharedMemoryBase;
	/*0x050*/     ULONG32      SharedData;
	/*0x054*/     ULONG32      ReadOnlyStaticServerData;
	/*0x058*/     ULONG32      AnsiCodePageData;
	/*0x05C*/     ULONG32      OemCodePageData;
	/*0x060*/     ULONG32      UnicodeCaseTableData;
	/*0x064*/     ULONG32      NumberOfProcessors;
	/*0x068*/     ULONG32      NtGlobalFlag;
	/*0x06C*/     UINT8        _PADDING0_[0x4];
	/*0x070*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)     
	/*0x078*/     ULONG32      HeapSegmentReserve;
	/*0x07C*/     ULONG32      HeapSegmentCommit;
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;
	/*0x088*/     ULONG32      NumberOfHeaps;
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;
	/*0x090*/     ULONG32      ProcessHeaps;
	/*0x094*/     ULONG32      GdiSharedHandleTable;
	/*0x098*/     ULONG32      ProcessStarterHelper;
	/*0x09C*/     ULONG32      GdiDCAttributeList;
	/*0x0A0*/     ULONG32      LoaderLock;
	/*0x0A4*/     ULONG32      OSMajorVersion;
	/*0x0A8*/     ULONG32      OSMinorVersion;
	/*0x0AC*/     UINT16       OSBuildNumber;
	/*0x0AE*/     UINT16       OSCSDVersion;
	/*0x0B0*/     ULONG32      OSPlatformId;
	/*0x0B4*/     ULONG32      ImageSubsystem;
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x0C0*/     ULONG32      ActiveProcessAffinityMask;
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];
	/*0x14C*/     ULONG32      PostProcessInitRoutine;
	/*0x150*/     ULONG32      TlsExpansionBitmap;
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x1D4*/     ULONG32      SessionId;
	/*0x1D8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E8*/     ULONG32      pShimData;
	/*0x1EC*/     ULONG32      AppCompatInfo;
	/*0x1F0*/     struct _STRING32 CSDVersion;                           // 3 elements, 0x8 bytes (sizeof)     
	/*0x1F8*/     ULONG32      ActivationContextData;
	/*0x1FC*/     ULONG32      ProcessAssemblyStorageMap;
	/*0x200*/     ULONG32      SystemDefaultActivationContextData;
	/*0x204*/     ULONG32      SystemAssemblyStorageMap;
	/*0x208*/     ULONG32      MinimumStackCommit;
	/*0x20C*/     ULONG32      SparePointers[4];
	/*0x21C*/     ULONG32      SpareUlongs[5];
	/*0x230*/     ULONG32      WerRegistrationData;
	/*0x234*/     ULONG32      WerShipAssertPtr;
	/*0x238*/     ULONG32      pUnused;
	/*0x23C*/     ULONG32      pImageHeaderHash;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x240*/         ULONG32      TracingFlags;
		struct                                             // 4 elements, 0x4 bytes (sizeof)     
		{
			/*0x240*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition                      
			/*0x240*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition                      
			/*0x240*/             ULONG32      LibLoaderTracingEnabled : 1;      // 2 BitPosition                      
			/*0x240*/             ULONG32      SpareTracingBits : 29;            // 3 BitPosition                      
		};
	};
	/*0x248*/     UINT64       CsrServerReadOnlySharedMemoryBase;
	/*0x250*/     ULONG32      TppWorkerpListLock;
	/*0x254*/     LIST_ENTRY32 TppWorkerpList;                   // 2 elements, 0x8 bytes (sizeof)     
	/*0x25C*/     ULONG32      WaitOnAddressHashTable[128];
	/*0x45C*/     ULONG32      TelemetryCoverageHeader;
	/*0x460*/     ULONG32      CloudFileFlags;
	/*0x464*/     ULONG32      CloudFileDiagFlags;
	/*0x468*/     CHAR         PlaceholderCompatibilityMode;
	/*0x469*/     CHAR         PlaceholderCompatibilityModeReserved[7];
	/*0x470*/     ULONG32      LeapSecondData;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x474*/         ULONG32      LeapSecondFlags;
		struct                                             // 2 elements, 0x4 bytes (sizeof)     
		{
			/*0x474*/             ULONG32      SixtySecondEnabled : 1;           // 0 BitPosition                      
			/*0x474*/             ULONG32      Reserved : 31;                    // 1 BitPosition                      
		};
	};
	/*0x478*/     ULONG32      NtGlobalFlag2;
	/*0x47C*/     UINT8        _PADDING1_[0x4];
}PEB32_BY, *PPEB32_BY;


typedef struct _PEB_LDR_DATA32                            // 9 elements, 0x58 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     ULONG32 SsHandle;
	/*0x00c*/     struct LIST_ENTRY32 InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof) 
	/*0x010*/     struct LIST_ENTRY32 InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof) 
	/*0x014*/     struct LIST_ENTRY32 InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     TYPE32(PVOID) EntryInProgress;
	UINT8        ShutdownInProgress;
	UINT8        _PADDING1_[0x7];
	TYPE32(PVOID) ShutdownThreadId;
}PEB_LDR_DATA32, *PPEB_LDR_DATA32;


typedef struct _ACTIVATION_CONTEXT_STACK                     // 5 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *ActiveFrame;
	/*0x008*/     struct _LIST_ENTRY FrameListCache;                       // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     ULONG32      Flags;
	/*0x01C*/     ULONG32      NextCookieSequenceNumber;
	/*0x020*/     ULONG32      StackId;
	/*0x024*/     UINT8        _PADDING0_[0x4];
}ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH                 // 4 elements, 0x4E8 bytes (sizeof) 
{
	struct                                    // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x000*/         ULONG32      Offset : 31;             // 0 BitPosition                    
		/*0x000*/         ULONG32      HasRenderingCommand : 1; // 31 BitPosition                   
	};
	/*0x008*/     UINT64       HDC;
	/*0x010*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB                                                  // 127 elements, 0x1838 bytes (sizeof) 
{
	/*0x000*/      struct _NT_TIB NtTib;                                            // 8 elements, 0x38 bytes (sizeof)     
	/*0x038*/      VOID *EnvironmentPointer;
	/*0x040*/      struct _CLIENT_ID ClientId;                                      // 2 elements, 0x10 bytes (sizeof)     
	/*0x050*/      VOID *ActiveRpcHandle;
	/*0x058*/      VOID *ThreadLocalStoragePointer;
	/*0x060*/      struct _PEB *ProcessEnvironmentBlock;
	/*0x068*/      ULONG32      LastErrorValue;
	/*0x06C*/      ULONG32      CountOfOwnedCriticalSections;
	/*0x070*/      VOID *CsrClientThread;
	/*0x078*/      VOID *Win32ThreadInfo;
	/*0x080*/      ULONG32      User32Reserved[26];
	/*0x0E8*/      ULONG32      UserReserved[5];
	/*0x0FC*/      UINT8        _PADDING0_[0x4];
	/*0x100*/      VOID *WOW32Reserved;
	/*0x108*/      ULONG32      CurrentLocale;
	/*0x10C*/      ULONG32      FpSoftwareStatusRegister;
	/*0x110*/      VOID *ReservedForDebuggerInstrumentation[16];
	/*0x190*/      VOID *SystemReserved1[30];
	/*0x280*/      CHAR         PlaceholderCompatibilityMode;
	/*0x281*/      UINT8        PlaceholderHydrationAlwaysExplicit;
	/*0x282*/      CHAR         PlaceholderReserved[10];
	/*0x28C*/      ULONG32      ProxiedProcessId;
	/*0x290*/      struct _ACTIVATION_CONTEXT_STACK _ActivationStack;               // 5 elements, 0x28 bytes (sizeof)     
	/*0x2B8*/      UINT8        WorkingOnBehalfTicket[8];
	/*0x2C0*/      LONG32       ExceptionCode;
	/*0x2C4*/      UINT8        Padding0[4];
	/*0x2C8*/      struct _ACTIVATION_CONTEXT_STACK *ActivationContextStackPointer;
	/*0x2D0*/      UINT64       InstrumentationCallbackSp;
	/*0x2D8*/      UINT64       InstrumentationCallbackPreviousPc;
	/*0x2E0*/      UINT64       InstrumentationCallbackPreviousSp;
	/*0x2E8*/      ULONG32      TxFsContext;
	/*0x2EC*/      UINT8        InstrumentationCallbackDisabled;
	/*0x2ED*/      UINT8        UnalignedLoadStoreExceptions;
	/*0x2EE*/      UINT8        Padding1[2];
	/*0x2F0*/      struct _GDI_TEB_BATCH GdiTebBatch;                               // 4 elements, 0x4E8 bytes (sizeof)    
	/*0x7D8*/      struct _CLIENT_ID RealClientId;                                  // 2 elements, 0x10 bytes (sizeof)     
	/*0x7E8*/      VOID *GdiCachedProcessHandle;
	/*0x7F0*/      ULONG32      GdiClientPID;
	/*0x7F4*/      ULONG32      GdiClientTID;
	/*0x7F8*/      VOID *GdiThreadLocalInfo;
	/*0x800*/      UINT64       Win32ClientInfo[62];
	/*0x9F0*/      VOID *glDispatchTable[233];
	/*0x1138*/     UINT64       glReserved1[29];
	/*0x1220*/     VOID *glReserved2;
	/*0x1228*/     VOID *glSectionInfo;
	/*0x1230*/     VOID *glSection;
	/*0x1238*/     VOID *glTable;
	/*0x1240*/     VOID *glCurrentRC;
	/*0x1248*/     VOID *glContext;
	/*0x1250*/     ULONG32      LastStatusValue;
	/*0x1254*/     UINT8        Padding2[4];
	/*0x1258*/     struct _UNICODE_STRING StaticUnicodeString;                      // 3 elements, 0x10 bytes (sizeof)     
	/*0x1268*/     WCHAR        StaticUnicodeBuffer[261];
	/*0x1472*/     UINT8        Padding3[6];
	/*0x1478*/     VOID *DeallocationStack;
	/*0x1480*/     VOID *TlsSlots[64];
	/*0x1680*/     struct _LIST_ENTRY TlsLinks;                                     // 2 elements, 0x10 bytes (sizeof)     
	/*0x1690*/     VOID *Vdm;
	/*0x1698*/     VOID *ReservedForNtRpc;
	/*0x16A0*/     VOID *DbgSsReserved[2];
	/*0x16B0*/     ULONG32      HardErrorMode;
	/*0x16B4*/     UINT8        Padding4[4];
	/*0x16B8*/     VOID *Instrumentation[11];
	/*0x1710*/     struct _GUID ActivityId;                                         // 4 elements, 0x10 bytes (sizeof)     
	/*0x1720*/     VOID *SubProcessTag;
	/*0x1728*/     VOID *PerflibData;
	/*0x1730*/     VOID *EtwTraceData;
	/*0x1738*/     VOID *WinSockData;
	/*0x1740*/     ULONG32      GdiBatchCount;
	union                                                            // 3 elements, 0x4 bytes (sizeof)      
	{
		/*0x1744*/         struct _PROCESSOR_NUMBER CurrentIdealProcessor;              // 3 elements, 0x4 bytes (sizeof)      
		/*0x1744*/         ULONG32      IdealProcessorValue;
		struct                                                       // 4 elements, 0x4 bytes (sizeof)      
		{
			/*0x1744*/             UINT8        ReservedPad0;
			/*0x1745*/             UINT8        ReservedPad1;
			/*0x1746*/             UINT8        ReservedPad2;
			/*0x1747*/             UINT8        IdealProcessor;
		};
	};
	/*0x1748*/     ULONG32      GuaranteedStackBytes;
	/*0x174C*/     UINT8        Padding5[4];
	/*0x1750*/     VOID *ReservedForPerf;
	/*0x1758*/     VOID *ReservedForOle;
	/*0x1760*/     ULONG32      WaitingOnLoaderLock;
	/*0x1764*/     UINT8        Padding6[4];
	/*0x1768*/     VOID *SavedPriorityState;
	/*0x1770*/     UINT64       ReservedForCodeCoverage;
	/*0x1778*/     VOID *ThreadPoolData;
	/*0x1780*/     VOID **TlsExpansionSlots;
	/*0x1788*/     VOID *DeallocationBStore;
	/*0x1790*/     VOID *BStoreLimit;
	/*0x1798*/     ULONG32      MuiGeneration;
	/*0x179C*/     ULONG32      IsImpersonating;
	/*0x17A0*/     VOID *NlsCache;
	/*0x17A8*/     VOID *pShimData;
	/*0x17B0*/     ULONG32      HeapData;
	/*0x17B4*/     UINT8        Padding7[4];
	/*0x17B8*/     VOID *CurrentTransactionHandle;
	/*0x17C0*/     struct _TEB_ACTIVE_FRAME *ActiveFrame;
	/*0x17C8*/     VOID *FlsData;
	/*0x17D0*/     VOID *PreferredLanguages;
	/*0x17D8*/     VOID *UserPrefLanguages;
	/*0x17E0*/     VOID *MergedPrefLanguages;
	/*0x17E8*/     ULONG32      MuiImpersonation;
	union                                                            // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x17EC*/         UINT16       CrossTebFlags;
		/*0x17EC*/         UINT16       SpareCrossTebBits : 16;                         // 0 BitPosition                       
	};
	union                                                            // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x17EE*/         UINT16       SameTebFlags;
		struct                                                       // 16 elements, 0x2 bytes (sizeof)     
		{
			/*0x17EE*/             UINT16       SafeThunkCall : 1;                          // 0 BitPosition                       
			/*0x17EE*/             UINT16       InDebugPrint : 1;                           // 1 BitPosition                       
			/*0x17EE*/             UINT16       HasFiberData : 1;                           // 2 BitPosition                       
			/*0x17EE*/             UINT16       SkipThreadAttach : 1;                       // 3 BitPosition                       
			/*0x17EE*/             UINT16       WerInShipAssertCode : 1;                    // 4 BitPosition                       
			/*0x17EE*/             UINT16       RanProcessInit : 1;                         // 5 BitPosition                       
			/*0x17EE*/             UINT16       ClonedThread : 1;                           // 6 BitPosition                       
			/*0x17EE*/             UINT16       SuppressDebugMsg : 1;                       // 7 BitPosition                       
			/*0x17EE*/             UINT16       DisableUserStackWalk : 1;                   // 8 BitPosition                       
			/*0x17EE*/             UINT16       RtlExceptionAttached : 1;                   // 9 BitPosition                       
			/*0x17EE*/             UINT16       InitialThread : 1;                          // 10 BitPosition                      
			/*0x17EE*/             UINT16       SessionAware : 1;                           // 11 BitPosition                      
			/*0x17EE*/             UINT16       LoadOwner : 1;                              // 12 BitPosition                      
			/*0x17EE*/             UINT16       LoaderWorker : 1;                           // 13 BitPosition                      
			/*0x17EE*/             UINT16       SkipLoaderInit : 1;                         // 14 BitPosition                      
			/*0x17EE*/             UINT16       SpareSameTebBits : 1;                       // 15 BitPosition                      
		};
	};
	/*0x17F0*/     VOID *TxnScopeEnterCallback;
	/*0x17F8*/     VOID *TxnScopeExitCallback;
	/*0x1800*/     VOID *TxnScopeContext;
	/*0x1808*/     ULONG32      LockCount;
	/*0x180C*/     LONG32       WowTebOffset;
	/*0x1810*/     VOID *ResourceRetValue;
	/*0x1818*/     VOID *ReservedForWdf;
	/*0x1820*/     UINT64       ReservedForCrt;
	/*0x1828*/     struct _GUID EffectiveContainerId;                               // 4 elements, 0x10 bytes (sizeof)     
}TEB, *PTEB;

typedef struct _OBJECT_HEADER                                // 23 elements, 0x38 bytes (sizeof) 
{
	/*0x000*/     INT64        PointerCount;
	union                                                    // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x008*/         INT64        HandleCount;
		/*0x008*/         VOID *NextToFree;
	};
	/*0x010*/     struct _EX_PUSH_LOCK Lock;                               // 7 elements, 0x8 bytes (sizeof)   
	/*0x018*/     UINT8        TypeIndex;
	union                                                    // 2 elements, 0x1 bytes (sizeof)   
	{
		/*0x019*/         UINT8        TraceFlags;
		struct                                               // 2 elements, 0x1 bytes (sizeof)   
		{
			/*0x019*/             UINT8        DbgRefTrace : 1;                    // 0 BitPosition                    
			/*0x019*/             UINT8        DbgTracePermanent : 1;              // 1 BitPosition                    
		};
	};
	/*0x01A*/     UINT8        InfoMask;
	union                                                    // 2 elements, 0x1 bytes (sizeof)   
	{
		/*0x01B*/         UINT8        Flags;
		struct                                               // 8 elements, 0x1 bytes (sizeof)   
		{
			/*0x01B*/             UINT8        NewObject : 1;                      // 0 BitPosition                    
			/*0x01B*/             UINT8        KernelObject : 1;                   // 1 BitPosition                    
			/*0x01B*/             UINT8        KernelOnlyAccess : 1;               // 2 BitPosition                    
			/*0x01B*/             UINT8        ExclusiveObject : 1;                // 3 BitPosition                    
			/*0x01B*/             UINT8        PermanentObject : 1;                // 4 BitPosition                    
			/*0x01B*/             UINT8        DefaultSecurityQuota : 1;           // 5 BitPosition                    
			/*0x01B*/             UINT8        SingleHandleEntry : 1;              // 6 BitPosition                    
			/*0x01B*/             UINT8        DeletedInline : 1;                  // 7 BitPosition                    
		};
	};
	/*0x01C*/     ULONG32      Reserved;
	union                                                    // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x020*/         struct _OBJECT_CREATE_INFORMATION *ObjectCreateInfo;
		/*0x020*/         VOID *QuotaBlockCharged;
	};
	/*0x028*/     VOID *SecurityDescriptor;
	/*0x030*/     struct _QUAD Body;                                       // 2 elements, 0x8 bytes (sizeof)   
}OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY                // 5 elements, 0x18 bytes (sizeof) 
{
	union                                                    // 2 elements, 0x8 bytes (sizeof)  
	{
		/*0x000*/         struct _IMAGE_RUNTIME_FUNCTION_ENTRY *FunctionTable;
		/*0x000*/         struct _DYNAMIC_FUNCTION_TABLE *DynamicTable;
	};
	/*0x008*/     VOID *ImageBase;
	/*0x010*/     ULONG32      SizeOfImage;
	/*0x014*/     ULONG32      SizeOfTable;
}INVERTED_FUNCTION_TABLE_ENTRY, *PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE                    // 5 elements, 0x1810 bytes (sizeof) 
{
	/*0x000*/     ULONG32      CurrentSize;
	/*0x004*/     ULONG32      MaximumSize;
	/*0x008*/     ULONG32      Epoch;
	/*0x00C*/     UINT8        Overflow;
	/*0x00D*/     UINT8        _PADDING0_[0x3];
	/*0x010*/     struct _INVERTED_FUNCTION_TABLE_ENTRY TableEntry[256];
}INVERTED_FUNCTION_TABLE, *PINVERTED_FUNCTION_TABLE;