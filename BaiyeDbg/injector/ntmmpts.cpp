#include "ntmmpts.h"

BOOLEAN PtsInitializePtBase(IN BOOLEAN IsRandom, IN ULONG_PTR Cr3, OUT PMMPTS_BASE PtBase)
{
    BOOLEAN v1; // bl
    PHYSICAL_ADDRESS pml4t; // rdi
    __int64 *pml4t_va; // r11
    int slot; // edx
    __int64 index; // rcx
    __int64 v6; // r8

    PHYSICAL_ADDRESS temp_pml4t;

    v1 = FALSE;
    
    if (IsRandom)
    {
        //pml4t.QuadPart = __readcr3();
        pml4t.QuadPart = Cr3;

        temp_pml4t = pml4t;
        temp_pml4t.QuadPart &= ~0xfff;

        pml4t_va = (__int64 *)MmGetVirtualForPhysical(temp_pml4t);
        
        if (pml4t_va)
        {
            slot = 0;
            index = 0i64;

            while ((pml4t_va[index] & 0xFFFFFFFFF000i64) != pml4t.QuadPart)
            {
                ++index;
                ++slot;

                if (index >= 512)
                {
                    return FALSE;
                }
            }

            v1 = TRUE;

            v6 = (slot + 0x1FFFE00i64) << 39;
            PtBase->PteBase = (slot + 0x1FFFE00i64) << 39;
            PtBase->PdeBase = v6 + ((__int64)slot << 30);
            PtBase->PpeBase = v6 + ((__int64)slot << 30) + ((__int64)slot << 21);
            PtBase->PxeBase = (ULONG64)( PtBase->PpeBase + ((__int64)slot << 12) );
            PtBase->PxeSelfMappingIndex = slot;

            //g_pxe_end = (__int64)g_pxe_base + 4096;
            //g_pte_end = v6 + 0x8000000000i64;
        }
    }
    else
    {
        PtBase->PteBase = 0xFFFFF68000000000i64;
        PtBase->PdeBase = 0xFFFFF6FB40000000i64;
        PtBase->PpeBase = 0xFFFFF6FB7DA00000i64;
        PtBase->PxeBase = 0xFFFFF6FB7DBED000i64;
        PtBase->PxeSelfMappingIndex = 493i64;

        v1 = TRUE;

        //g_pxe_end = 0xFFFFF6FB7DBEE000i64;
        //g_pte_end = 0xFFFFF70000000000i64;
    }

    return v1;
}

PVOID PtsAddressOfPte(IN PMMPTS_BASE PtBase, PVOID VirtualAddress)
{
    return (PVOID)((((ULONG64)VirtualAddress & 0xffffffffffff) >> 12 << 3) + PtBase->PteBase);
}

PVOID PtsAddressOfPde(IN PMMPTS_BASE PtBase, PVOID VirtualAddress)
{
    return (PVOID)((((ULONG64)VirtualAddress & 0xffffffffffff) >> 21 << 3) + PtBase->PdeBase);
}

PVOID PtsAddressOfPpe(IN PMMPTS_BASE PtBase, PVOID VirtualAddress)
{
    return (PVOID)((((ULONG64)VirtualAddress & 0xffffffffffff) >> 30 << 3) + PtBase->PpeBase);
}

PVOID PtsAddressOfPxe(IN PMMPTS_BASE PtBase, PVOID VirtualAddress)
{
    return (PVOID)((((ULONG64)VirtualAddress & 0xffffffffffff) >> 39 << 3) + PtBase->PxeBase);
}