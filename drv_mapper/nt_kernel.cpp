#include "nt_kernel.h"
#include "mem_search.h"

#include <utility>

nt_kernel::nt_kernel()
{
	get_ntos_module();

	get_members();
	get_apis();
}

nt_kernel::~nt_kernel()
{
	this->members.clear();
	this->apis.clear();
}

HANDLE nt_kernel::get_process_kernel_handle(uint32_t process_id)
{
	PHANDLE_TABLE HandleTable = (PHANDLE_TABLE)members["ObpKernelHandleTable"];
	
	PVOID TableCode = (PVOID)HandleTable->TableCode;
	LONG TableLevel = (ULONG_PTR)TableCode & 0x3;

	PEPROCESS_BY p;
	HANDLE Handle = 0;

	bool found = false;

	if (TableLevel == 0)
	{
		for (ULONG64 i = 0; i < 255 && !found; ++i)
		{
			HANDLE h = (HANDLE)((i * 4) ^ KERNEL_HANDLE_MASK);
			NTSTATUS s = ObReferenceObjectByHandle(h, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID *)&p, NULL);
			if (NT_SUCCESS(s))
			{
				if (p->UniqueProcessId == reinterpret_cast<void *>(process_id));
				{
					Handle = h;
					found = true;
				}
			}
		}
	}
	else if (TableLevel == 1)
	{
		for (ULONG64 i = 0; i < 512 && !found; ++i)
		{
			for (ULONG64 j = 0; j < 255 && !found; ++j)
			{
				HANDLE h = (HANDLE)(((i << 10) | (j * 4)) ^ KERNEL_HANDLE_MASK);
				NTSTATUS s = ObReferenceObjectByHandle(h, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID *)&p, NULL);
				if (NT_SUCCESS(s))
				{
					if (p->UniqueProcessId == reinterpret_cast<void *>(process_id))
					{
						Handle = h;
						found = true;
					}
				}
			}
		}
	}
	else if (TableLevel == 2)
	{
		for (ULONG64 i = 0; i < 512 && !found; ++i)
		{
			for (ULONG64 j = 0; j < 512 && !found; ++j)
			{
				for (ULONG64 k = 0; k < 255 && !found; ++k)
				{
					HANDLE h = (HANDLE)(((i << 19) | (j << 10) | (k * 4)) ^ KERNEL_HANDLE_MASK);
					NTSTATUS s = ObReferenceObjectByHandle(h, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID *)&p, NULL);
					if (NT_SUCCESS(s))
					{
						if (p->UniqueProcessId == reinterpret_cast<void *>(process_id))
						{
							Handle = h;
							found = true;
						}
					}
				}
			}
		}
	}

	return Handle;
}

void nt_kernel::get_ntos_module()
{
	PLIST_ENTRY current_list = PsLoadedModuleList;
	PLIST_ENTRY next_list;

	for (next_list = current_list->Flink;
		next_list != current_list;
		next_list = next_list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(next_list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		UNICODE_STRING usNtos;
		RtlInitUnicodeString(&usNtos, L"ntoskrnl.exe");

		if (RtlCompareUnicodeString(&usNtos, &module->BaseDllName, true) == 0)
		{
			this->ntos_module = module;
			return;
		}
	}
	this->ntos_module = (PLDR_DATA_TABLE_ENTRY)PsLoadedModuleList;
}

void *nt_kernel::ntos_base()
{
	return ntos_module->DllBase;
}

uint32_t nt_kernel::ntos_size()
{
	return ntos_module->SizeOfImage;
}

void *nt_kernel::api(const std::string fn_name)
{
	return apis[fn_name];
}

void *nt_kernel::member(const std::string mem_name)
{
	return members[mem_name];
}

void nt_kernel::get_members()
{
	// kernel handle table
	get_ObpKernelHandleTable();

	get_ObTypeIndexTable();
}

void nt_kernel::get_apis()
{
	// TODO 使用函数内偏移, 有兼容性问题

	// mm
	get_MmQueryWorkingSetInformation();

	// psquery
	get_PspQueryQuotaLimits();
	get_PspSetQuotaLimits();

	// ps
	get_PsSuspendProcess();
	get_PsResumeProcess();

	// vm query
	get_NtQueryVirtualMemory();


	get_PspCheckForInvalidAccessByProtection();
	get_PsGetNextProcessThread();
	get_DbgkpWakeTarget();
	get_PsSynchronizeWithThreadInsertion();
	get_PsSuspendThread();
	get_PsResumeThread();
	get_DbgkpSectionToFileHandle();
	get_MmGetFileNameForAddress();
	get_PsCallImageNotifyRoutines();
	get_PsCaptureExceptionPort();
	get_DbgkpSendErrorMessage();
	get_DbgkpSuspendProcess();
	get_PsThawProcess();
	get_DbgkpSuppressDbgMsg();
	get_DbgkpConvertKernelToUserStateChange();
	get_DbgkpOpenHandles();
	get_PsQuerySystemDllInfo();
	get_PsTerminateProcess();
	get_PsGetNextProcess();
	get_ObCreateObjectType();
	get_RtlInsertInvertedFunctionTable();
	get_RtlRemoveInvertedFunctionTable();

	// 调试相关
	get_NtDebugActiveProcess();
	get_DbgkCreateThread();
	get_DbgkExitThread();
	get_DbgkExitProcess();
	get_DbgkMapViewOfSection();
	get_DbgkUnMapViewOfSection();
	get_KiDispatchException();
	get_NtWaitForDebugEvent();
	get_NtCreateDebugObject();
	get_DbgkpCloseObject();
	get_NtDebugContinue();
	get_DbgkpMarkProcessPeb();
	get_DbgkClearProcessDebugObject();
	get_DbgkForwardException();
	get_ObpRemoveObjectRoutine();
	get_DbgkpSendApiMessageLpc();
}


void nt_kernel::get_ObpKernelHandleTable()
{
	PEPROCESS_BY SystemProcess = (PEPROCESS_BY)PsInitialSystemProcess;
	PHANDLE_TABLE HandleTable = (PHANDLE_TABLE)SystemProcess->ObjectTable;
	members.insert(std::pair("ObpKernelHandleTable", HandleTable));
}

void nt_kernel::get_ObTypeIndexTable()
{
	// ObReferenceObjectByPointer
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                   // amov     [rsp+arg_0], rbx
		0x48, 0x89, 0x74, 0x24, 0xCC,                   // mov     [rsp+arg_8], rsi
		0x57,                                           // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                         // sub     rsp, 30h
		0x48, 0x8B, 0xF1,                               // mov     rsi, rcx
		0x4D, 0x85, 0xC0,                               // test    r8, r8
		0x74, 0xCC,                                     // jz      short loc_14026E1A8
		0x48, 0x8D, 0x41, 0xCC,                         // lea     rax, [rcx-30h]
		0x48, 0xC1, 0xE8, 0x08,                         // shr     rax, 8
		0x0F, 0xB6, 0xC8,                               // movzx   ecx, al
		0x0F, 0xB6, 0x46, 0xCC,                         // movzx   eax, byte ptr [rsi-18h]
		0x48, 0x33, 0xC8,                               // xor     rcx, rax
		0x0F, 0xB6, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // movzx   eax, byte ptr cs:ObHeaderCookie
		0x48, 0x33, 0xC8,                               // xor     rcx, rax
		0x48, 0x8D, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // lea     rax, ObTypeIndexTable
		0x4C, 0x39, 0x04, 0xC8,                         // cmp     [rax+rcx*8], r8
		0x75, 0xCC,                                     // jnz     short loc_14026E1AD
		0x83, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 0x00,       // cmp     cs:ObpTraceFlags, 0
		0xBB, 0x01, 0x00, 0x00, 0x00,                   // mov     ebx, 1
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC              // jnz     loc_140434B18
	};

	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	uint32_t *offset = (uint32_t *)(matched_ptr + 54);
	matched_ptr = matched_ptr + 54 + 4 + *offset;
	
	members.insert(std::pair("ObTypeIndexTable", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_MmQueryWorkingSetInformation()
{
	pattern_search ps{
		0x48, 0x8B, 0xD9,                                       // mov     rbx, rc
		0x4D, 0x8B, 0xF1,                                       // mov     r14, r
		0x49, 0x8B, 0xF0,                                       // mov     rsi, r
		0x48, 0x8B, 0xFA,                                       // mov     rdi, rd
		0x41, 0x83, 0x27, 0x00,                                 // and     dword ptr [r15], 0
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,   // mov     rax, gs:188h
		0x48, 0x8B, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC,               // mov     rbp, [rax+0B8h]  --
		0x48, 0x81, 0xC5, 0xCC, 0xCC, 0xCC, 0xCC,               // add     rbp, 680h        --
		0x48, 0x8B, 0xCD                                        // mov     rcx, rb
	};

	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x1d;

	apis.insert(std::pair("MmQueryWorkingSetInformation", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PspQueryQuotaLimits()
{
	pattern_search ps{
		0x56,											// push    rsi
		0x57,											// push    rdi
		0x41, 0x56,										// push    r14
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,		// sub     rsp, 100h       ; Integer Subtraction
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,		// mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,								// xor     rax, rsp        ; Logical Exclusive OR
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,	// mov     [rsp+118h+var_20], rax
		0x41, 0x8B, 0xF9,								// mov     edi, r9d
		0x4D, 0x8B, 0xF0,								// mov     r14, r8
		0x48, 0x8B, 0xD9,								// mov     rbx, rcx
		0x48, 0x8B, 0xB4, 0x24, 0xCC, 0xCC, 0xCC, 0xCC, // mov     rsi, [rsp+118h+arg_20]
		0x33, 0xD2,										// xor     edx, edx        ; Val
		0x44, 0x8D, 0x42, 0x58,							// lea     r8d, [rdx+58h]  ; Size
		0x48, 0x8D, 0x4C, 0x24, 0xCC					// lea     rcx, [rsp+118h+QuotaLimits] ; Dst
	};

	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 5;

	apis.insert(std::pair("PspQueryQuotaLimits", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PspSetQuotaLimits()
{
	pattern_search ps{
		0xF7, 0xC1, 0xE0, 0xFF, 0xFF, 0xFF,         // test    ecx, 0FFFFFFE0h
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,         // jnz     loc_14059FDC0  
		0x8B, 0xC1,                                 // mov     eax, ec
		0x83, 0xE0, 0xCC,                           // and     eax, 3         
		0x3C, 0xCC,                                 // cmp     al, 3         
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,         // jz      loc_14059FDC0  
		0x8B, 0xC1,                                 // mov     eax, ec
		0x83, 0xE0, 0xCC,                           // and     eax, 0Ch       
		0x3C, 0xCC,                                 // cmp     al, 0Ch       
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,         // jz      loc_14059FDC0  
		0xB8, 0xCC, 0xCC, 0xCC, 0xCC,               // mov     eax, 8
		0x84, 0xCB,                                 // test    bl, cl        
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,         // jnz     loc_14059FDCA  
		0xF6, 0xC1, 0xCC                            // test    cl, 2          
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x14d;

	apis.insert(std::pair("PspSetQuotaLimits", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsSuspendProcess()
{
	pattern_search ps{
		0x41, 0x56,                                             // push    r14
		0x48, 0x83, 0xEC, 0xCC,                                 // sub     rsp, 20h
		0x65, 0x48, 0x8B, 0x2C, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,   // mov     rbp, gs:188h
		0x48, 0x8B, 0xF1,                                       // mov     rsi, rcx
		0x66, 0xFF, 0x8D, 0xCC, 0xCC, 0xCC, 0xCC,               // dec     word ptr [rbp+1E4h]
		0x4C, 0x8D, 0xB1, 0xCC, 0xCC, 0xCC, 0xCC,               // lea     r14, [rcx+458h]
		0x49, 0x8B, 0xCE,                                       // mov     rcx, r14
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                           // call    ExAcquireRundownProtec
		0x3C, 0x01,                                             // cmp     al, 
		0x75, 0xCC,                                             // jnz     short loc_14090A0C
		0x33, 0xD2,                                             // xor     edx, ed
		0x48, 0x8B, 0xCE,                                       // mov     rcx, rsi
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC                            // call    PsGetNextProcessThread
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x13;

	apis.insert(std::pair("PsSuspendProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsResumeProcess()
{
	pattern_search ps{
		0x41, 0x56,                                                 // push    r14       
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 20h        ; Integer Subtraction                   
		0x65, 0x48, 0x8B, 0xCC, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rsi, gs:188h                                                   
		0x48, 0x8B, 0xCC,                                           // mov     rbp, rcx               
		0x66, 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,                   // dec     word ptr [rsi+1E4h] ; Decrement by 1                                       
		0x4C, 0x8D, 0xB1, 0xCC, 0xCC, 0xCC, 0xCC,                   // lea     r14, [rcx+2E0h] ; Load Effective Address                                       
		0x49, 0x8B, 0xCE,                                           // mov     rcx, r14               
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    ExAcquireRundownProtection_0 ; Call Procedure                           
		0x3C, 0x01,                                                 // cmp     al, 1           ; Compare Two Operands       
		0x75, 0xCC,                                                 // jnz     short loc_1404346CD ; Jump if Not Zero (ZF=0)       
		0x33, 0xD2,                                                 // xor     edx, edx        ; Logical Exclusive OR       
		0x48, 0x8B, 0xCC                                            // mov     rcx, rbp               
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x13;

	apis.insert(std::pair("PsResumeProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_NtQueryVirtualMemory()
{
	// 通过MmQueryVirtualMemory函数的硬编码查找NtQueryVirtualMemory
	pattern_search ps{
		0x48, 0x85, 0xCC,           // test    rsi, rsi
		0x74, 0xCC,                 // jz      short loc_140600A5A
		0x0F, 0xB6, 0xCC, 0xCC,     // movzx   eax, byte ptr [rsi+
		0x48, 0xC1, 0xE0, 0xCC,     // shl     rax, 20h
		0x8B, 0xCC, 0xCC,           // mov     ecx, [rsi+18h]
		0x48, 0x0B, 0xC1,           // or      rax, rcx
		0x48, 0x3B, 0xCC,           // cmp     rdi, rax
		0x72, 0xCC,                 // jb      short loc_140600A46
		0x0F, 0xB6, 0xCC, 0xCC,     // movzx   edx, byte ptr [rsi+
		0x48, 0xC1, 0xE2, 0xCC,     // shl     rdx, 20h
		0x8B, 0xCC, 0xCC,           // mov     ecx, [rsi+1Ch]
		0x48, 0x0B, 0xD1,           // or      rdx, rcx
		0x48, 0x3B, 0xCC,           // cmp     rdi, rdx
		0x76, 0xCC,                 // jbe     short loc_140600A53
		0x48, 0x3B, 0xCC,           // cmp     rdi, rax
		0x72, 0xCC,                 // jb      short loc_140600A46
		0x48, 0x8B, 0xCC, 0xCC,     // mov     rax, [rsi+8]
		0x48, 0x85, 0xC0,           // test    rax, rax
		0x74, 0xCC,                 // jz      short loc_140600A5A
		0x48, 0x8B, 0xCC,           // mov     rsi, rax
		0xEB, 0xCC                  // jmp     short loc_140600A08
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x278;

	apis.insert(std::pair("NtQueryVirtualMemory", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PspCheckForInvalidAccessByProtection()
{
	pattern_search ps{
		0x45, 0x32, 0xC9,                // xor     r9b, r9b                
		0x8A, 0xC2,                      // mov     al, dl        
		0x84, 0xC9,                      // test    cl, cl        
		0x75, 0xCC,                      // jnz     short loc_1406B7C02        
		0x41, 0x8A, 0xC1,                // mov     al, r9b                
		0x48, 0x83, 0xC4, 0xCC,          // add     rsp, 28h                    
		0xC3,                            // retn    
		0xCC,                            // align 2    
		0x41, 0x8A, 0xD0,                // mov     dl, r8b                
		0x8A, 0xC8,                      // mov     cl, al 
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 4;

	apis.insert(std::pair("PspCheckForInvalidAccessByProtection", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsGetNextProcessThread()
{
	pattern_search ps{
		0x57,                                                   // push    rdi
		0x41, 0x54,                                             // push    r12
		0x41, 0x55,                                             // push    r13
		0x41, 0x56,                                             // push    r14
		0x41, 0x57,                                             // push    r15
		0x48, 0x83, 0xEC, 0xCC,                                 // sub     rsp, 20h
		0x65, 0x4C, 0x8B, 0x24, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,   // mov     r12, gs:188h
		0x4C, 0x8D, 0xA9, 0xCC, 0xCC, 0xCC, 0xCC,               // lea     r13, [rcx+5E0h]
		0x33, 0xDB,                                             // xor     ebx, ebx
		0x48, 0x8B, 0xFA,                                       // mov     rdi, rdx
		0x44, 0x8B, 0xFB,                                       // mov     r15d, ebx
		0x44, 0x8B, 0xF3,                                       // mov     r14d, ebx
		0x66, 0x41, 0xFF, 0x8C, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,   // dec     word ptr [r12+1E4h]
		0x48, 0x8D, 0xA9, 0xCC, 0xCC, 0xCC, 0xCC                // lea     rbp, [rcx+438h]
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0xF;

	apis.insert(std::pair("PsGetNextProcessThread", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpWakeTarget()
{
	pattern_search ps{
		0x57,                                       // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                     // sub     rsp, 20h
		0x8B, 0x41, 0xCC,                           // mov     eax, [rcx+4Ch]
		0x48, 0x8B, 0xD9,                           // mov     rbx, rcx
		0x48, 0x8B, 0x79, 0xCC,                     // mov     rdi, [rcx+40h]
		0xA8, 0xCC,                                 // test    al, 20h
		0x74, 0xCC,                                 // jz      short loc_140883605
		0x33, 0xD2,                                 // xor     edx, edx
		0x48, 0x8B, 0xCF,                           // mov     rcx, rdi
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,               // call    PsResumeThread
		0x8B, 0x43, 0xCC,                           // mov     eax, [rbx+4Ch]
		0xA8, 0xCC,                                 // test    al, 8
		0x74, 0xCC,                                 // jz      short loc_140883618
		0x48, 0x8D, 0x8F, 0xCC, 0xCC, 0xCC, 0xCC,   // lea     rcx, [rdi+4F8h]
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,               // call    ExReleaseRundownProtection
		0x8B, 0x43, 0xCC                            // mov     eax, [rbx+4Ch]
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 5;

	apis.insert(std::pair("DbgkpWakeTarget", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsSynchronizeWithThreadInsertion()
{
	// 通过NtGetCurrentProcessorNumber找该函数
	pattern_search ps{
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,        // mov     rax, gs:20h
		0x0F, 0xB6, 0x90, 0xCC, 0xCC, 0xCC, 0xCC,                    // movzx   edx, byte ptr [rax+0D1h]
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,        // mov     rax, gs:188h
		0x48, 0x8B, 0x88, 0xCC, 0xCC, 0xCC, 0xCC,                    // mov     rcx, [rax+0B8h]
		0x48, 0x8B, 0x81, 0xCC, 0xCC, 0xCC, 0xCC,                    // mov     rax, [rcx+580h]
		0x48, 0x85, 0xC0,                                            // test    rax, rax
		0x74, 0xCC,                                                  // jz      short loc_140905007
		0x0F, 0xB7, 0x40, 0xCC,                                      // movzx   eax, word ptr [rax+8]
		0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                                // mov     ecx, 14Ch
		0x66, 0x3B, 0xC1,                                            // cmp     ax, cx
		0x74, 0xCC,                                                  // jz      short loc_140905004
		0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                                // mov     ecx, 1C4h
		0x66, 0x3B, 0xC1,                                            // cmp     ax, cx
		0x75, 0xCC                                                   // jnz     short loc_140905007
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x48;

	apis.insert(std::pair("PsSynchronizeWithThreadInsertion", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsSuspendThread()
{
	pattern_search ps{
		0x53,                                                       // push    rbx
		0x56,                                                       // push    rsi
		0x57,                                                       // push    rdi
		0x41, 0x56,                                                 // push    r14
		0x41, 0x57,                                                 // push    r15
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 30h
		0x4C, 0x8B, 0xF2,                                           // mov     r14, rdx
		0x48, 0x8B, 0xF9,                                           // mov     rdi, rcx
		0x83, 0x64, 0x24, 0xCC, 0xCC,                               // and     [rsp+58h+var_38], 0
		0x65, 0x48, 0x8B, 0x34, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rsi, gs:188h
		0x48, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+58h+arg_10], rsi
		0x66, 0xFF, 0x8E, 0xCC, 0xCC, 0xCC, 0xCC,                   // dec     word ptr [rsi+1E4h]
		0x4C, 0x8D, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                   // lea     r15, [rcx+4F8h]
		0x4C, 0x89, 0x7C, 0x24, 0xCC,                               // mov     [rsp+58h+arg_18], r15
		0x49, 0x8B, 0xCF,                                           // mov     rcx, r15
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    ExAcquireRundownProtection
		0x84, 0xC0,                                                 // test    al, al
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,                         // jz      loc_14082E3AE
		0x8B, 0x87, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     eax, [rdi+510h]
		0xA8, 0x01,                                                 // test    al, 1
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC                          // jnz     loc_14082E3A4
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0xa;

	apis.insert(std::pair("PsSuspendThread", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsResumeThread()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_0], rbx
		0x48, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+arg_8], rsi
		0x57,                                                       // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 20h
		0x48, 0x8B, 0xDA,                                           // mov     rbx, rdx
		0x48, 0x8B, 0xF9,                                           // mov     rdi, rcx
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    KeResumeThread
		0x65, 0x48, 0x8B, 0x14, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rdx, gs:188h
		0x8B, 0xF0,                                                 // mov     esi, eax
		0x83, 0xF8, 0x01,                                           // cmp     eax, 1
		0x75, 0xCC,                                                 // jnz     short loc_1406B4E9B
		0x4C, 0x8B, 0x87, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     r8, [rdi+220h]
		0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                               // mov     eax, 8000h
		0x41, 0x8B, 0x88, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     ecx, [r8+87Ch]
		0x85, 0xC8,                                                 // test    eax, ecx
		0x74, 0xCC                                                  // jz      short loc_1406B4EB5
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsResumeThread", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpSectionToFileHandle()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,       // mov     [rsp-8+arg_0], rbx
		0x48, 0x89, 0x7C, 0x24, 0xCC,       // mov     [rsp-8+arg_18], rdi
		0x55,                               // push    rbp
		0x48, 0x8B, 0xEC,                   // mov     rbp, rsp
		0x48, 0x83, 0xEC, 0xCC,             // sub     rsp, 70h
		0x83, 0x65, 0xCC, 0xCC,             // and     dword ptr [rbp+ObjectAttributes+4], 0
		0x48, 0x8D, 0x55, 0xCC,             // lea     rdx, [rbp+P]
		0x83, 0x65, 0xCC, 0xCC,             // and     dword ptr [rbp+ObjectAttributes+1Ch], 0
		0x0F, 0x57, 0xC0,                   // xorps   xmm0, xmm0
		0x48, 0x83, 0x65, 0xCC, 0xCC,       // and     [rbp+FileHandle], 0
		0x48, 0x83, 0x65, 0xCC, 0xCC,       // and     [rbp+P], 0
		0x0F, 0x11, 0x45, 0xCC,             // movups  xmmword ptr [rbp+IoStatusBlock.___u0], xmm0
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,       // call    MmGetFileNameForSection
		0x85, 0xC0,                         // test    eax, eax
		0x78, 0xCC,                         // js      short loc_1408856FB
		0x48, 0x8B, 0x7D, 0xCC,             // mov     rdi, [rbp+P]
		0x4C, 0x8D, 0x4D, 0xCC,             // lea     r9, [rbp+IoStatusBlock] ; IoStatusBlock
		0x48, 0x83, 0x65, 0xCC, 0xCC,       // and     [rbp+ObjectAttributes.RootDirectory], 0
		0x4C, 0x8D, 0x45, 0xCC,             // lea     r8, [rbp+ObjectAttributes] ; ObjectAttributes
		0x0F, 0x57, 0xC0                    // xorps   xmm0, xmm0
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpSectionToFileHandle", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_MmGetFileNameForAddress()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                   // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,             // mov     [rax+8], rbx
		0x48, 0x89, 0x68, 0xCC,             // mov     [rax+10h], rbp
		0x56,                               // push    rsi
		0x57,                               // push    rdi
		0x41, 0x56,                         // push    r14
		0x48, 0x83, 0xEC, 0xCC,             // sub     rsp, 30h
		0x83, 0x60, 0xCC, 0x00,             // and     dword ptr [rax+18h], 0
		0x4C, 0x8D, 0x40, 0xCC,             // lea     r8, [rax+20h]
		0x4C, 0x8B, 0xF2,                   // mov     r14, rdx
		0xBA, 0x02, 0x00, 0x00, 0x00,       // mov     edx, 2
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,       // call    MiObtainReferencedVadEx
		0x48, 0x8B, 0xD8,                   // mov     rbx, rax
		0x48, 0x85, 0xC0,                   // test    rax, rax
		0x75, 0xCC,                         // jnz     short loc_1408C167E
		0xB8, 0x41, 0x01, 0x00, 0xC0,       // mov     eax, 0C0000141h
		0xE9, 0xCC, 0xCC, 0xCC, 0xCC        // jmp     loc_1408C1741
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("MmGetFileNameForAddress", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_PsCallImageNotifyRoutines()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                                           // mov     rax, rsp
		0x41, 0x57,                                                 // push    r15
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 60h
		0x48, 0x89, 0x58, 0xCC,                                     // mov     [rax+8], rbx
		0x0F, 0x57, 0xC0,                                           // xorps   xmm0, xmm0
		0x48, 0x89, 0x68, 0xCC,                                     // mov     [rax+18h], rbp
		0x49, 0x8B, 0xD8,                                           // mov     rbx, r8
		0x48, 0x89, 0x70, 0xCC,                                     // mov     [rax-10h], rsi
		0x48, 0x8B, 0xE9,                                           // mov     rbp, rcx
		0x0F, 0x11, 0x40, 0xCC,                                     // movups  xmmword ptr [rax-38h], xmm0
		0x65, 0x4C, 0x8B, 0x3C, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     r15, gs:188h
		0x49, 0x8B, 0xF1,                                           // mov     rsi, r9
		0x48, 0x89, 0x78, 0xCC,                                     // mov     [rax-18h], rdi
		0x48, 0x8B, 0xFA,                                           // mov     rdi, rdx
		0x4C, 0x89, 0x60, 0xCC,                                     // mov     [rax-20h], r12
		0x66, 0x41, 0xFF, 0x8F, 0xCC, 0xCC, 0xCC, 0xCC,             // dec     word ptr [r15+1E4h]
		0x45, 0x33, 0xE4,                                           // xor     r12d, r12d
		0x4C, 0x89, 0x60, 0xCC,                                     // mov     [rax+10h], r12
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    KeAreAllApcsDisabled
		0x84, 0xC0,                                                 // test    al, al
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,                         // jnz     loc_1407E6AA0
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsCallImageNotifyRoutines", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsCaptureExceptionPort()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_8], rbx
		0x48, 0x89, 0x6C, 0x24, 0xCC,                               // mov     [rsp+arg_10], rbp
		0x48, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+arg_18], rsi
		0x57,                                                       // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 20h
		0x33, 0xED,                                                 // xor     ebp, ebp
		0x48, 0x8B, 0xD9,                                           // mov     rbx, rcx
		0x48, 0x39, 0xA9, 0xCC, 0xCC, 0xCC, 0xCC,                   // cmp     [rcx+4B0h], rbp
		0x74, 0xCC,                                                 // jz      short loc_1406B2ECB
		0x65, 0x48, 0x8B, 0x34, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rsi, gs:188h 
		0x66, 0xFF, 0x8E, 0xCC, 0xCC, 0xCC, 0xCC,                   // dec     word ptr [rsi+1E4h]
		0x48, 0x8D, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                   // lea     rdi, [rcx+438h]
		0x33, 0xD2,                                                 // xor     edx, edx        ; BugCheckParameter1
		0x48, 0x8B, 0xCF                                            // mov     rcx, rdi        ; BugCheckParameter2
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsCaptureExceptionPort", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_DbgkpSendErrorMessage()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                   // mov     [rsp-8+arg_8], rbx
		0x55,                                           // push    rbp
		0x56,                                           // push    rsi
		0x57,                                           // push    rdi
		0x41, 0x54,                                     // push    r12
		0x41, 0x55,                                     // push    r13
		0x41, 0x56,                                     // push    r14
		0x41, 0x57,                                     // push    r15
		0x48, 0x8D, 0x6C, 0x24, 0xCC,                   // lea     rbp, [rsp-30h]
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,       // sub     rsp, 130h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                               // xor     rax, rsp
		0x48, 0x89, 0x45, 0xCC,                         // mov     [rbp+60h+var_40], rax
		0x8B, 0xFA,                                     // mov     edi, edx
		0x89, 0x54, 0x24, 0xCC,                         // mov     [rsp+160h+var_11C], edx
		0x33, 0xD2,                                     // xor     edx, edx        ; Val
		0x48, 0x89, 0x4C, 0x24, 0xCC,                   // mov     [rsp+160h+var_100], rcx
		0x4D, 0x8B, 0xE0,                               // mov     r12, r8
		0x48, 0x8D, 0x4D, 0xCC,                         // lea     rcx, [rbp+60h+Dst] ; Dst
		0x44, 0x8D, 0x42, 0xCC                          // lea     r8d, [rdx+60h]  ; Size
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpSendErrorMessage", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_DbgkpSuspendProcess()
{
	pattern_search ps{
		0x40, 0x53,                                                 // push    rbx
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 20h
		0x65, 0x48, 0x8B, 0x1C, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rbx, gs:188h
		0x66, 0xFF, 0x8B, 0xCC, 0xCC, 0xCC, 0xCC,                   // dec     word ptr [rbx+1E4h]
		0x33, 0xD2,                                                 // xor     edx, edx
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    PsFreezeProcess
		0x84, 0xC0,                                                 // test    al, al
		0x74, 0xCC,                                                 // jz      short loc_1408857D5
		0xB0, 0x01,                                                 // mov     al, 1
		0xEB, 0xCC,                                                 // jmp     short loc_1408857DF
		0x48, 0x8B, 0xCB,                                           // mov     rcx, rbx
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    KeLeaveCriticalRegionThread
		0x32, 0xC0,                                                 // xor     al, al
		0x48, 0x83, 0xC4, 0xCC,                                     // add     rsp, 20h
		0x5B,                                                       // pop     rbx
		0xC3                                                        // retn
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpSuspendProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsThawProcess()
{
	pattern_search ps{
		0x88, 0x54, 0x24, 0xCC,                                     // mov     [rsp+arg_8], dl
		0x48, 0x89, 0x4C, 0x24, 0xCC,                               // mov     [rsp+arg_0], rcx
		0x53,                                                       // push    rbx
		0x56,                                                       // push    rsi
		0x57,                                                       // push    rdi
		0x41, 0x54,                                                 // push    r12
		0x41, 0x56,                                                 // push    r14
		0x41, 0x57,                                                 // push    r15
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 28h
		0x40, 0x8A, 0xF2,                                           // mov     sil, dl
		0x48, 0x8B, 0xF9,                                           // mov     rdi, rcx
		0x65, 0x4C, 0x8B, 0x34, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     r14, gs:188h
		0x4C, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+58h+arg_18], r14
		0x84, 0xD2,                                                 // test    dl, dl
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,                         // jz      loc_1406F2CC3
		0x48, 0x83, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,             // cmp     qword ptr [rcx+508h], 0
		0x74, 0xCC,                                                 // jz      short loc_1406F2C16
		0x8B, 0x81, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     eax, [rcx+464h]
		0xA8, 0xCC                                                  // test    al, 8
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsThawProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpSuppressDbgMsg()
{
	pattern_search ps{
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 18h
		0x48, 0x8B, 0xD1,                                           // mov     rdx, rcx
		0xC7, 0x04, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     [rsp+18h+var_18], 0
		0x8A, 0x81, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     al, [rcx+17EEh]
		0x84, 0xC0,                                                 // test    al, al
		0x79, 0xCC,                                                 // jns     short loc_14088573A
		0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                               // mov     ecx, 1
		0x89, 0x0C, 0x24,                                           // mov     [rsp+18h+var_18], ecx
		0xEB, 0xCC,                                                 // jmp     short loc_14088579D
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x48, 0x8B, 0x80, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, [rax+0B8h]
		0x48, 0x83, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x00              // cmp     qword ptr [rax+580h], 0
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpSuppressDbgMsg", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpConvertKernelToUserStateChange()
{
	pattern_search ps{
		0x0F, 0x10, 0x42, 0xCC,                         // movups  xmm0, xmmword ptr [rdx+28h]
		0xF3, 0x0F, 0x7F, 0x41, 0xCC,                   // movdqu  xmmword ptr [rcx+8], xmm0
		0x44, 0x8B, 0x82, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     r8d, [rdx+80h]
		0x45, 0x85, 0xC0,                               // test    r8d, r8d
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,             // jz      loc_140882500
		0x41, 0x83, 0xE8, 0xCC,                         // sub     r8d, 1
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,             // jz      loc_1408824EC
		0x41, 0x83, 0xE8, 0xCC,                         // sub     r8d, 1
		0x74, 0xCC,                                     // jz      short loc_1408824BB
		0x41, 0x83, 0xE8, 0xCC,                         // sub     r8d, 1
		0x74, 0xCC,                                     // jz      short loc_1408824AA
		0x41, 0x83, 0xE8, 0xCC,                         // sub     r8d, 1
		0x74, 0xCC,                                     // jz      short loc_1408824A2
		0x41, 0x83, 0xE8, 0xCC,                         // sub     r8d, 1
		0x74, 0xCC,                                     // jz      short loc_14088247C
		0x41, 0x83, 0xF8, 0xCC,                         // cmp     r8d, 1
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,             // jnz     locret_14088258B
		0xC7, 0x01, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     dword ptr [rcx], 0Ah
		0x48, 0x8B, 0x82, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, [rdx+88h]
		0x48, 0x89, 0x41, 0xCC                          // mov     [rcx+18h], rax
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpConvertKernelToUserStateChange", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpOpenHandles()
{
	pattern_search ps{
		0x48, 0x89, 0x6C, 0x24, 0xCC,                               // mov     [rsp+arg_0], rbp
		0x48, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+arg_8], rsi
		0x57,                                                       // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 40h
		0x44, 0x8B, 0x09,                                           // mov     r9d, [rcx]
		0x4D, 0x8B, 0xD0,                                           // mov     r10, r8
		0x48, 0x8B, 0xEA,                                           // mov     rbp, rdx
		0x48, 0x8B, 0xF9,                                           // mov     rdi, rcx
		0x41, 0x83, 0xE9, 0xCC,                                     // sub     r9d, 2
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,                         // jz      loc_140882850
		0x41, 0x83, 0xE9, 0xCC,                                     // sub     r9d, 1
		0x74, 0xCC,                                                 // jz      short loc_14088278E
		0x41, 0x83, 0xF9, 0xCC,                                     // cmp     r9d, 6
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,                         // jnz     loc_140882885
		0x48, 0x8B, 0x71, 0xCC,                                     // mov     rsi, [rcx+18h]
		0x48, 0x85, 0xF6,                                           // test    rsi, rsi
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,                         // jz      loc_140882885
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC        // mov     rax, gs:188h
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpOpenHandles", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsQuerySystemDllInfo()
{
	pattern_search ps{
		0x48, 0x63, 0xC1,                               // movsxd  rax, ecx
		0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,       // lea     rcx, PspSystemDlls
		0x48, 0x8B, 0x04, 0xC1,                         // mov     rax, [rcx+rax*8]
		0x48, 0x85, 0xC0,                               // test    rax, rax
		0x74, 0xCC,                                     // jz      short loc_1406B781C
		0x48, 0x83, 0x78, 0xCC, 0x00,                   // cmp     qword ptr [rax+28h], 0
		0x74, 0xCC,                                     // jz      short loc_1406B781C
		0x48, 0x83, 0xC0, 0xCC,                         // add     rax, 10h
		0xC3                                            // retn
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsQuerySystemDllInfo", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsTerminateProcess()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_0], rbx
		0x57,                                                       // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 20h
		0x65, 0x48, 0x8B, 0x3C, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rdi, gs:188h
		0x66, 0xFF, 0x8F, 0xCC, 0xCC, 0xCC, 0xCC,                   // dec     word ptr [rdi+1E4h]
		0x44, 0x8B, 0xC2,                                           // mov     r8d, edx
		0x41, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     r9d, 1
		0x48, 0x8B, 0xD7,                                           // mov     rdx, rdi
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    PspTerminateProcess
		0x48, 0x8B, 0xCF,                                           // mov     rcx, rdi
		0x8B, 0xD8,                                                 // mov     ebx, eax
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    KeLeaveCriticalRegionThread
		0x8B, 0xC3,                                                 // mov     eax, ebx
		0x48, 0x8B, 0x5C, 0x24, 0xCC,                               // mov     rbx, [rsp+28h+arg_0]
		0x48, 0x83, 0xC4, 0xCC,                                     // add     rsp, 20h
		0x5F,                                                       // pop     rdi
		0xC3                                                        // retn
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsTerminateProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_PsGetNextProcess()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_0], rbx
		0x48, 0x89, 0x6C, 0x24, 0xCC,                               // mov     [rsp+arg_8], rbp
		0x48, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+arg_10], rsi
		0x57,                                                       // push    rdi
		0x41, 0x56,                                                 // push    r14
		0x41, 0x57,                                                 // push    r15
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 20h
		0x65, 0x48, 0x8B, 0x2C, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rbp, gs:188h
		0x45, 0x33, 0xF6,                                           // xor     r14d, r14d
		0x33, 0xF6,                                                 // xor     esi, esi
		0x48, 0x8B, 0xF9,                                           // mov     rdi, rcx
		0x66, 0xFF, 0x8D, 0xCC, 0xCC, 0xCC, 0xCC,                   // dec     word ptr [rbp+1E6h]
		0x33, 0xD2,                                                 // xor     edx, edx        ; BugCheckParameter1
		0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC                    // lea     rcx, PspActiveProcessLock ; BugCheckParameter2
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("PsGetNextProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_ObCreateObjectType()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                               // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,                         // mov     [rax+20h], rbx
		0x55,                                           // push    rbp
		0x56,                                           // push    rsi
		0x57,                                           // push    rdi
		0x41, 0x54,                                     // push    r12
		0x41, 0x55,                                     // push    r13
		0x41, 0x56,                                     // push    r14
		0x41, 0x57,                                     // push    r15
		0x48, 0x8D, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC,       // lea     rbp, [rax-128h]
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,       // sub     rsp, 1F0h
		0x0F, 0x29, 0x70, 0xCC,                         // movaps  xmmword ptr [rax-48h], xmm6
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                               // xor     rax, rsp
		0x48, 0x89, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     [rbp+120h+var_50], rax
		0x48, 0x8B, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, [rbp+120h+arg_20]
		0x4D, 0x8B, 0xF8,                               // mov     r15, r8
		0x48, 0x8B, 0xFA,                               // mov     rdi, rdx
		0x48, 0x89, 0x45, 0xCC,                         // mov     [rbp+120h+var_178], rax
		0x4C, 0x8B, 0xF1,                               // mov     r14, rcx
		0x4C, 0x89, 0x4C, 0x24, 0xCC,                   // mov     [rsp+220h+var_1D8], r9
		0x33, 0xD2,                                     // xor     edx, edx        ; Val
		0x48, 0x8D, 0x4D, 0xCC,                         // lea     rcx, [rbp+120h+Dst] ; Dst
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     r8d, 0D8h       ; Size
		0x4D, 0x8B, 0xE9                                // mov     r13, r9
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];
	matched_ptr -= 0x20;

	apis.insert(std::pair("ObCreateObjectType", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_RtlInsertInvertedFunctionTable()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                   // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,             // mov     [rax+8], rbx
		0x57,                               // push    rdi
		0x48, 0x83, 0xEC, 0xCC,             // sub     rsp, 40h
		0x48, 0x83, 0x60, 0xCC, 0xCC,       // and     qword ptr [rax-18h], 0
		0x4C, 0x8D, 0x40, 0xCC,             // lea     r8, [rax+20h]
		0x83, 0x60, 0xCC, 0xCC,             // and     dword ptr [rax+20h], 0
		0x8B, 0xDA,                         // mov     ebx, edx
		0x48, 0x8D, 0x50, 0xCC,             // lea     rdx, [rax-18h]
		0xC6, 0x40, 0xCC, 0xCC,             // mov     byte ptr [rax+18h], 0
		0x48, 0x8B, 0xF9,                   // mov     rdi, rcx
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,       // call    RtlCaptureImageExceptionValues
		0x48, 0x8D, 0x4C, 0x24, 0xCC,       // lea     rcx, [rsp+48h+arg_10]
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC        // call    MmLockLoadedModuleListExclusive
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("RtlInsertInvertedFunctionTable", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_RtlRemoveInvertedFunctionTable()
{
	pattern_search ps{
		0x40, 0x53,                                     // push    rbx
		0x48, 0x83, 0xEC, 0xCC,                         // sub     rsp, 20h
		0x48, 0x8B, 0xD9,                               // mov     rbx, rcx
		0xC6, 0x44, 0x24, 0xCC, 0xCC,                   // mov     [rsp+28h+arg_8], 0
		0x48, 0x8D, 0x4C, 0x24, 0xCC,                   // lea     rcx, [rsp+28h+arg_8]
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                   // call    MmLockLoadedModuleListExclusive
		0x48, 0x8B, 0xD3,                               // mov     rdx, rbx
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                   // call    RtlxRemoveInvertedFunctionTable
		0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,       // lea     rcx, PsLoadedModuleSpinLock
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                   // call    ExReleaseSpinLockExclusiveFromDpcLevel
		0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     eax, cs:KiIrqlFlags
		0x85, 0xC0,                                     // test    eax, eax
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC              // jnz     loc_14048AC5A
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("RtlRemoveInvertedFunctionTable", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_NtDebugActiveProcess()
{
	pattern_search ps{
		0x4C, 0x8B, 0xDC,                                           // mov     r11, rsp
		0x49, 0x89, 0x5B, 0xCC,                                     // mov     [r11+8], rbx
		0x49, 0x89, 0x6B, 0xCC,                                     // mov     [r11+10h], rbp
		0x56,                                                       // push    rsi
		0x57,                                                       // push    rdi
		0x41, 0x56,                                                 // push    r14
		0x48, 0x83, 0xEC, 0xCC,                                     // sub     rsp, 50h
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x4C, 0x8B, 0xF2,                                           // mov     r14, rdx
		0x49, 0x83, 0x63, 0xCC, 0xCC,                               // and     qword ptr [r11-38h], 0
		0xBA, 0xCC, 0xCC, 0xCC, 0xCC,                               // mov     edx, 800h
		0x4C, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     r8, cs:PsProcessType
		0x49, 0x83, 0x63, 0xCC, 0x00,                               // and     qword ptr [r11+18h], 0
		0x40, 0x8A, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     bpl, [rax+232h]
		0x49, 0x8D, 0x43, 0xCC,                                     // lea     rax, [r11+18h]
		0x49, 0x83, 0x63, 0xCC, 0x00,                               // and     qword ptr [r11-28h], 0
		0x44, 0x8A, 0xCD,                                           // mov     r9b, bpl
		0x49, 0x89, 0x43, 0xCC,                                     // mov     [r11-40h], rax
		0xC7, 0x44, 0x24, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     dword ptr [rsp+68h+Object], 4F676244h
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    ObReferenceObjectByHandleWithTag
		0x85, 0xC0,                                                 // test    eax, eax
		0x0F, 0x88, 0xCC, 0xCC, 0xCC, 0xCC                          // js      loc_140883A06
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("NtDebugActiveProcess", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkCreateThread()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                       // mov     [rsp+arg_8], rbx
		0x48, 0x89, 0x74, 0x24, 0xCC,                       // mov     [rsp+arg_10], rsi
		0x57,                                               // push    rdi
		0x41, 0x54,                                         // push    r12
		0x41, 0x55,                                         // push    r13
		0x41, 0x56,                                         // push    r14
		0x41, 0x57,                                         // push    r15
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,           // sub     rsp, 1B0h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,           // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                   // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,     // mov     [rsp+1D8h+var_38], rax
		0x4C, 0x8B, 0xF1,                                   // mov     r14, rcx
		0x48, 0x89, 0x4C, 0x24, 0xCC,                       // mov     [rsp+1D8h+var_198], rcx
		0x33, 0xD2,                                         // xor     edx, edx        ; Val
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                 // mov     r8d, 110h       ; Size
		0x48, 0x8D, 0x8C, 0x24, 0xCC, 0xCC, 0xCC, 0xCC      // lea     rcx, [rsp+1D8h+Dst] ; Dst
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkCreateThread", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkExitThread()
{
	pattern_search ps{
		0x40, 0x53,                                                 // push    rbx
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                   // sub     rsp, 140h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                           // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     [rsp+148h+var_18], rax
		0x8B, 0xD9,                                                 // mov     ebx, ecx
		0x33, 0xD2,                                                 // xor     edx, edx        ; Val
		0x48, 0x8D, 0x4C, 0x24, 0xCC,                               // lea     rcx, [rsp+148h+Dst] ; Dst
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     r8d, 110h       ; Size
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    memset
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x48, 0x8B, 0x88, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rcx, [rax+0B8h] ; BugCheckParameter2
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x8B, 0x90, 0xCC, 0xCC, 0xCC, 0xCC                          // mov     edx, [rax+510h]
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[1];

	apis.insert(std::pair("DbgkExitThread", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkExitProcess()
{
	pattern_search ps{
		0x40, 0x53,                                                 // push    rbx
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                   // sub     rsp, 140h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                           // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     [rsp+148h+var_18], rax
		0x8B, 0xD9,                                                 // mov     ebx, ecx
		0x33, 0xD2,                                                 // xor     edx, edx        ; Val
		0x48, 0x8D, 0x4C, 0x24, 0xCC,                               // lea     rcx, [rsp+148h+Dst] ; Dst
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     r8d, 110h       ; Size
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    memset
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x48, 0x8B, 0x88, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rcx, [rax+0B8h] ; BugCheckParameter2
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x8B, 0x90, 0xCC, 0xCC, 0xCC, 0xCC                          // mov     edx, [rax+510h]
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkExitProcess", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_DbgkMapViewOfSection()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_18], rbx
		0x56,                                                       // push    rsi
		0x57,                                                       // push    rdi
		0x41, 0x56,                                                 // push    r14
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                   // sub     rsp, 150h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                           // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     [rsp+168h+var_28], rax
		0x49, 0x8B, 0xF0,                                           // mov     rsi, r8
		0x4C, 0x8B, 0xF2,                                           // mov     r14, rdx
		0x48, 0x8B, 0xF9,                                           // mov     rdi, rcx
		0x48, 0x89, 0x4C, 0x24, 0xCC,                               // mov     [rsp+168h+var_148], rcx
		0x33, 0xD2,                                                 // xor     edx, edx        ; Val
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     r8d, 110h       ; Size
		0x48, 0x8D, 0x4C, 0x24, 0xCC,                               // lea     rcx, [rsp+168h+Dst] ; Dst
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    memset
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x80, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x00,                   // cmp     byte ptr [rax+232h], 0
		0x74, 0xCC,                                                 // jz      short loc_1406B93E5
		0x65, 0x48, 0x8B, 0x0C, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rcx, gs:188h
		0x8B, 0x81, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     eax, [rcx+510h]
		0xA8, 0x04                                                  // test    al, 4
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkMapViewOfSection", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkUnMapViewOfSection()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_8], rbx
		0x57,                                                       // push    rdi
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                   // sub     rsp, 140h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                           // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     [rsp+148h+var_18], rax
		0x48, 0x8B, 0xFA,                                           // mov     rdi, rdx
		0x48, 0x8B, 0xD9,                                           // mov     rbx, rcx
		0x33, 0xD2,                                                 // xor     edx, edx        ; Val
		0x48, 0x8D, 0x4C, 0x24, 0xCC,                               // lea     rcx, [rsp+148h+Dst] ; Dst
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     r8d, 110h       ; Size
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                               // call    memset
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x80, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x00,                   // cmp     byte ptr [rax+232h], 0
		0x74, 0xCC,                                                 // jz      short loc_1406FB237
		0x65, 0x4C, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     r8, gs:188h
		0x41, 0x8B, 0x80, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     eax, [r8+510h]
		0xA8, 0x04,                                                 // test    al, 4
		0x75, 0xCC,                                                 // jnz     short loc_1406FB237
		0x48, 0x83, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0x00,             // cmp     qword ptr [rbx+578h], 0
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC                          // jnz     loc_14082A694
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkUnMapViewOfSection", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_KiDispatchException()
{
	pattern_search ps{
		0x40, 0x55,                                     // push    rbp
		0x53,                                           // push    rbx
		0x56,                                           // push    rsi
		0x41, 0x54,                                     // push    r12
		0x41, 0x56,                                     // push    r14
		0x41, 0x57,                                     // push    r15
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,       // sub     rsp, 188h
		0x48, 0x8D, 0x6C, 0x24, 0xCC,                   // lea     rbp, [rsp+30h]
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC5,                               // xor     rax, rbp
		0x48, 0x89, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     [rbp+180h+var_38], rax
		0x45, 0x8A, 0xE1,                               // mov     r12b, r9b
		0x44, 0x88, 0x4D, 0xCC,                         // mov     byte ptr [rbp+180h+BugCheckParameter3], r9b
		0x4D, 0x8B, 0xF0,                               // mov     r14, r8
		0x48, 0x89, 0x55, 0xCC,                         // mov     [rbp+180h+var_170], rdx
		0x48, 0x8B, 0xD9,                               // mov     rbx, rcx
		0x48, 0x89, 0x4D, 0xCC,                         // mov     [rbp+180h+var_138], rcx
		0x4C, 0x89, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     [rbp+180h+var_100], r8
		0x48, 0x83, 0x65, 0xCC, 0xCC,                   // and     [rbp+180h+var_158], 0
		0x83, 0x65, 0xCC, 0xCC,                         // and     [rbp+180h+var_168], 0
		0x33, 0xD2,                                     // xor     edx, edx        ; Val
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     r8d, 94h        ; Size
		0x48, 0x8D, 0x8D, 0xCC, 0xCC, 0xCC, 0xCC        // lea     rcx, [rbp+180h+Dst] ; Dst
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("KiDispatchException", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_NtWaitForDebugEvent()
{
	pattern_search ps{
		0x40, 0x53,                                                 // push    rbx
		0x56,                                                       // push    rsi
		0x57,                                                       // push    rdi
		0x41, 0x54,                                                 // push    r12
		0x41, 0x55,                                                 // push    r13
		0x41, 0x56,                                                 // push    r14
		0x41, 0x57,                                                 // push    r15
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                   // sub     rsp, 150h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xCC,                                           // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     [rsp+188h+var_48], rax
		0x49, 0x8B, 0xF1,                                           // mov     rsi, r9
		0x40, 0x8A, 0xFA,                                           // mov     dil, dl
		0x88, 0x54, 0x24, 0xCC,                                     // mov     [rsp+188h+Alertable], dl
		0x48, 0x8B, 0xD9,                                           // mov     rbx, rcx
		0x4C, 0x89, 0x44, 0x24, 0xCC,                               // mov     [rsp+188h+Timeout], r8
		0x45, 0x33, 0xF6,                                           // xor     r14d, r14d
		0x4C, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+188h+var_150], r14
		0x4C, 0x89, 0x74, 0x24, 0xCC,                               // mov     [rsp+188h+var_138], r14
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x44, 0x8A, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     r15b, [rax+232h]
		0x33, 0xD2,                                                 // xor     edx, edx        ; Val
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                         // mov     r8d, 0B8h       ; Size
		0x48, 0x8D, 0x8C, 0x24, 0xCC, 0xCC, 0xCC, 0xCC              // lea     rcx, [rsp+188h+Dst] ; Dst
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("NtWaitForDebugEvent", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_NtCreateDebugObject()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                                               // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,                                         // mov     [rax+8], rbx
		0x48, 0x89, 0x70, 0xCC,                                         // mov     [rax+10h], rsi
		0x48, 0x89, 0x78, 0xCC,                                         // mov     [rax+18h], rdi
		0x41, 0x56,                                                     // push    r14
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                       // sub     rsp, 80h
		0x41, 0x8B, 0xF1,                                               // mov     esi, r9d
		0x44, 0x8B, 0xF2,                                               // mov     r14d, edx
		0x48, 0x8B, 0xF9,                                               // mov     rdi, rcx
		0x48, 0x83, 0x60, 0xCC, 0x00,                                   // and     qword ptr [rax-28h], 0
		0x48, 0x83, 0x60, 0xCC, 0x00,                                   // and     qword ptr [rax-30h], 0
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,           // mov     rax, gs:188h
		0x44, 0x8A, 0x90, 0x32, 0x02, 0x00, 0x00,                       // mov     r10b, [rax+232h]
		0x45, 0x84, 0xD2,                                               // test    r10b, r10b
		0x74, 0xCC,                                                     // jz      short loc_1408836A7
		0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,     // mov     rcx, 7FFFFFFF0000h
		0x48, 0x3B, 0xF9,                                               // cmp     rdi, rcx
		0x48, 0x0F, 0x42, 0xCF,                                         // cmovb   rcx, rdi
		0x48, 0x8B, 0x01,                                               // mov     rax, [rcx]
		0x48, 0x89, 0x01                                                // mov     [rcx], rax
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("NtCreateDebugObject", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_DbgkpCloseObject()
{
	pattern_search ps{
		0x49, 0x83, 0xF9, 0x01,                 // cmp     r9, 1
		0x0F, 0x87, 0xCC, 0xCC, 0xCC, 0xCC,     // ja      locret_140882419
		0x48, 0x8B, 0xC4,                       // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,                 // mov     [rax+8], rbx
		0x48, 0x89, 0x68, 0xCC,                 // mov     [rax+10h], rbp
		0x48, 0x89, 0x70, 0xCC,                 // mov     [rax+18h], rsi
		0x48, 0x89, 0x78, 0xCC,                 // mov     [rax+20h], rdi
		0x41, 0x56,                             // push    r14
		0x48, 0x83, 0xEC, 0xCC,                 // sub     rsp, 20h
		0x48, 0x8D, 0x4A, 0xCC,                 // lea     rcx, [rdx+18h]  ; FastMutex
		0x48, 0x8B, 0xEA,                       // mov     rbp, rdx
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,           // call    ExAcquireFastMutex
		0x83, 0x4D, 0xCC, 0x01,                 // or      dword ptr [rbp+60h], 1
		0x4C, 0x8D, 0x75, 0xCC,                 // lea     r14, [rbp+50h]
		0x49, 0x8B, 0x36,                       // mov     rsi, [r14]
		0x48, 0x8D, 0x4D, 0xCC,                 // lea     rcx, [rbp+18h]
		0x4D, 0x89, 0x36,                       // mov     [r14], r14
		0x4D, 0x89, 0x76, 0xCC                  // mov     [r14+8], r14
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpCloseObject", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_NtDebugContinue()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                                               // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,                                         // mov     [rax+8], rbx
		0x48, 0x89, 0x70, 0xCC,                                         // mov     [rax+10h], rsi
		0x48, 0x89, 0x78, 0xCC,                                         // mov     [rax+18h], rdi
		0x41, 0x54,                                                     // push    r12
		0x41, 0x56,                                                     // push    r14
		0x41, 0x57,                                                     // push    r15
		0x48, 0x83, 0xEC, 0xCC,                                         // sub     rsp, 50h
		0x41, 0x8B, 0xD8,                                               // mov     ebx, r8d
		0x0F, 0x57, 0xC0,                                               // xorps   xmm0, xmm0
		0x0F, 0x11, 0x40, 0xCC,                                         // movups  xmmword ptr [rax-28h], xmm0
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,           // mov     rax, gs:188h
		0x44, 0x8A, 0x88, 0xCC, 0xCC, 0xCC, 0xCC,                       // mov     r9b, [rax+232h] ; AccessMode
		0x45, 0x84, 0xC9,                                               // test    r9b, r9b
		0x74, 0xCC,                                                     // jz      short loc_140883A6B
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,     // mov     rax, 7FFFFFFF0000h
		0x48, 0x3B, 0xD0,                                               // cmp     rdx, rax
		0x48, 0x0F, 0x42, 0xC2,                                         // cmovb   rax, rdx
		0x8A, 0x00,                                                     // mov     al, [rax]
		0x0F, 0x10, 0x02                                                // movups  xmm0, xmmword ptr [rdx]
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("NtDebugContinue", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpMarkProcessPeb()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                       // mov     [rsp+arg_8], rbx
		0x57,                                               // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                             // sub     rsp, 60h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,           // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                   // xor     rax, rsp
		0x48, 0x89, 0x44, 0x24, 0xCC,                       // mov     [rsp+68h+var_10], rax
		0x48, 0x8B, 0xD9,                                   // mov     rbx, rcx
		0x0F, 0x57, 0xC0,                                   // xorps   xmm0, xmm0
		0x0F, 0x11, 0x44, 0x24, 0xCC,                       // movups  [rsp+68h+var_40], xmm0
		0x0F, 0x11, 0x44, 0x24, 0xCC,                       // movups  [rsp+68h+var_30], xmm0
		0x0F, 0x11, 0x44, 0x24, 0xCC,                       // movups  [rsp+68h+var_20], xmm0
		0x48, 0x8D, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC,           // lea     rdi, [rcx+458h]
		0x48, 0x89, 0x7C, 0x24, 0xCC,                       // mov     [rsp+68h+var_48], rdi
		0x48, 0x8B, 0xCF,                                   // mov     rcx, rdi
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                       // call    ExAcquireRundownProtection
		0x84, 0xC0,                                         // test    al, al
		0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,                 // jz      loc_1408826E5
		0x48, 0x83, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0x00      // cmp     qword ptr [rbx+550h], 0
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpMarkProcessPeb", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_DbgkClearProcessDebugObject()
{
	pattern_search ps{
		0x48, 0x8B, 0xC4,                               // mov     rax, rsp
		0x48, 0x89, 0x58, 0xCC,                         // mov     [rax+8], rbx
		0x48, 0x89, 0x70, 0xCC,                         // mov     [rax+10h], rsi
		0x48, 0x89, 0x78, 0xCC,                         // mov     [rax+18h], rdi
		0x4C, 0x89, 0x70, 0xCC,                         // mov     [rax+20h], r14
		0x55,                                           // push    rbp
		0x48, 0x8B, 0xEC,                               // mov     rbp, rsp
		0x48, 0x83, 0xEC, 0xCC,                         // sub     rsp, 30h
		0x48, 0x8B, 0xF1,                               // mov     rsi, rcx
		0x48, 0x8B, 0xFA,                               // mov     rdi, rdx
		0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,       // lea     rcx, DbgkpProcessDebugPortMutex ; FastMutex
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                   // call    ExAcquireFastMutex
		0x48, 0x8B, 0x9E, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rbx, [rsi+578h]
		0x48, 0x85, 0xDB,                               // test    rbx, rbx
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC,             // jnz     loc_140842F64
		0x33, 0xDB,                                     // xor     ebx, ebx
		0xBF, 0x53, 0x03, 0x00, 0xC0                    // mov     edi, 0C0000353h
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkClearProcessDebugObject", reinterpret_cast<void *>(matched_ptr)));
}


void nt_kernel::get_DbgkForwardException()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                   // mov     [rsp-8+arg_8], rbx
		0x48, 0x89, 0x74, 0x24, 0xCC,                   // mov     [rsp-8+arg_10], rsi
		0x55,                                           // push    rbp
		0x57,                                           // push    rdi
		0x41, 0x54,                                     // push    r12
		0x41, 0x56,                                     // push    r14
		0x41, 0x57,                                     // push    r15
		0x48, 0x8D, 0x6C, 0x24, 0xCC,                   // lea     rbp, [rsp-50h]
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,       // sub     rsp, 150h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                               // xor     rax, rsp
		0x48, 0x89, 0x45, 0xCC,                         // mov     [rbp+70h+var_30], rax
		0x48, 0x83, 0x64, 0x24, 0xCC, 0x00,             // and     [rsp+170h+var_150], 0
		0x45, 0x8A, 0xF8,                               // mov     r15b, r8b
		0x40, 0x8A, 0xFA,                               // mov     dil, dl
		0x4C, 0x8B, 0xE1,                               // mov     r12, rcx
		0x33, 0xD2,                                     // xor     edx, edx        ; Val
		0x48, 0x8D, 0x4C, 0x24, 0xCC,                   // lea     rcx, [rsp+170h+Dst] ; Dst
		0x41, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     r8d, 110h       ; Size
		0xE8, 0xCC, 0xCC, 0xCC, 0xCC,                   // call    memset
		0x45, 0x84, 0xFF,                               // test    r15b, r15b
		0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC              // jnz     loc_1408345AA
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkForwardException", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_ObpRemoveObjectRoutine()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                   // mov     [rsp+arg_8], rbx
		0x48, 0x89, 0x6C, 0x24, 0xCC,                   // mov     [rsp+arg_10], rbp
		0x48, 0x89, 0x74, 0x24, 0xCC,                   // mov     [rsp+arg_18], rsi
		0x57,                                           // push    rdi
		0x48, 0x83, 0xEC, 0xCC,                         // sub     rsp, 50h
		0x48, 0x8B, 0xD9,                               // mov     rbx, rcx
		0x48, 0x8D, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC,       // lea     rdi, ObTypeIndexTable
		0x48, 0x8B, 0xC1,                               // mov     rax, rcx
		0x0F, 0xB6, 0xF2,                               // movzx   esi, dl
		0x48, 0xC1, 0xE8, 0xCC,                         // shr     rax, 8
		0x0F, 0xB6, 0xC8,                               // movzx   ecx, al
		0x0F, 0xB6, 0x43, 0xCC,                         // movzx   eax, byte ptr [rbx+18h]
		0x48, 0x33, 0xC8,                               // xor     rcx, rax
		0x0F, 0xB6, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,       // movzx   eax, byte ptr cs:ObHeaderCookie
		0x48, 0x33, 0xC8,                               // xor     rcx, rax
		0x48, 0x8B, 0x3C, 0xCF,                         // mov     rdi, [rdi+rcx*8]
		0x48, 0x3B, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC        // cmp     rdi, cs:ObpTypeObjectType
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("ObpRemoveObjectRoutine", reinterpret_cast<void *>(matched_ptr)));
}

void nt_kernel::get_DbgkpSendApiMessageLpc()
{
	pattern_search ps{
		0x48, 0x89, 0x5C, 0x24, 0xCC,                               // mov     [rsp+arg_10], rbx
		0x55,                                                       // push    rbp
		0x56,                                                       // push    rsi
		0x57,                                                       // push    rdi
		0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC,                   // sub     rsp, 300h
		0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rax, cs:__security_cookie
		0x48, 0x33, 0xC4,                                           // xor     rax, rsp
		0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC,             // mov     [rsp+318h+var_28], rax
		0x65, 0x48, 0x8B, 0x04, 0x25, 0xCC, 0xCC, 0xCC, 0xCC,       // mov     rax, gs:188h
		0x41, 0x8A, 0xF0,                                           // mov     sil, r8b
		0x48, 0x8B, 0xFA,                                           // mov     rdi, rdx
		0x48, 0x8B, 0xD9,                                           // mov     rbx, rcx
		0x48, 0x8B, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC,                   // mov     rbp, [rax+0B8h]
		0x45, 0x84, 0xC0,                                           // test    r8b, r8b
		0x74, 0xCC,                                                 // jz      short loc_140884D5A
		0x48, 0x8B, 0xCD                                            // mov     rcx, rbp
	};
	std::vector<ptr_t> matched;
	ps.search(0xcc, ntos_base(), ntos_size(), matched, 0, 3);
	ptr_t matched_ptr = matched[0];

	apis.insert(std::pair("DbgkpSendApiMessageLpc", reinterpret_cast<void *>(matched_ptr)));
}