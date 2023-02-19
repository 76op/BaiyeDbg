#pragma once
#ifndef __NTMI_H__
#define __NTMI_H__

#include <ntifs.h>
#include "ntstructs.h"
#include "../_kernel_struct.h"


#define VAD_STARTING_VPN(Node)      \
    *( (PULONG32) ((PUCHAR)Node + 0x18) ) | ( (ULONG_PTR) (*((PUCHAR)Node + 0x20)) << 32 )

#define VAD_ENDING_VPN(Node)      \
    *( (PULONG32) ((PUCHAR)Node + 0x1C) ) | ( (ULONG_PTR) (*((PUCHAR)Node + 0x21)) << 32 )


//
// A pair of macros to deal with the packing of parent & balance in the
// MMADDRESS_NODE.
//

#define SANITIZE_PARENT_NODE(Parent) ((PRTL_BALANCED_NODE)(((ULONG_PTR)(Parent)) & ~0x3))


//++
//
// ULONG
// MI_ROUND_TO_SIZE (
//     IN ULONG LENGTH,
//     IN ULONG ALIGNMENT
//     )
//
// Routine Description:
//
//
// The ROUND_TO_SIZE macro takes a LENGTH in bytes and rounds it up to a
// multiple of the alignment.
//
// Arguments:
//
//     LENGTH - LENGTH in bytes to round up to.
//
//     ALIGNMENT - alignment to round to, must be a power of 2, e.g, 2**n.
//
// Return Value:
//
//     Returns the LENGTH rounded up to a multiple of the alignment.
//
//--

#define MI_ROUND_TO_SIZE(LENGTH,ALIGNMENT)     \
                    (((LENGTH) + ((ALIGNMENT) - 1)) & ~((ALIGNMENT) - 1))


//++
//
// PVOID
// MI_ALIGN_TO_SIZE (
//     IN PVOID VA
//     IN ULONG ALIGNMENT
//     )
//
// Routine Description:
//
//
// The MI_ALIGN_TO_SIZE macro takes a virtual address and returns a
// virtual address for that page with the specified alignment.
//
// Arguments:
//
//     VA - Virtual address.
//
//     ALIGNMENT - alignment to round to, must be a power of 2, e.g, 2**n.
//
// Return Value:
//
//     Returns the aligned virtual address.
//
//--

#define MI_ALIGN_TO_SIZE(VA,ALIGNMENT) ((PVOID)((ULONG_PTR)(VA) & ~((ULONG_PTR) ALIGNMENT - 1)))


#define MI_VA_TO_PAGE(va) ((ULONG_PTR)(va) >> PAGE_SHIFT)

#define MI_VA_TO_VPN(va)  ((ULONG_PTR)(va) >> PAGE_SHIFT)

#define MI_VPN_TO_VA(vpn)  (PVOID)((vpn) << PAGE_SHIFT)

#define MI_VPN_TO_VA_ENDING(vpn)  (PVOID)(((vpn) << PAGE_SHIFT) | (PAGE_SIZE - 1))


#define MM_HIGHEST_VAD_ADDRESS ((PVOID)((ULONG_PTR)MM_HIGHEST_USER_ADDRESS - (64 * 1024)))

#define X64K (ULONG)65536

PRTL_BALANCED_NODE
MiGetNextNode(
    IN PRTL_BALANCED_NODE Node
);

PRTL_BALANCED_NODE
MiGetPreviousNode(
    IN PRTL_BALANCED_NODE Node
);

NTSTATUS MiFindEmptyAddressRangeInTree(
    IN RTL_AVL_TREE Vad,
    IN SIZE_T SizeOfRange,
    IN ULONG_PTR Alignment,
    OUT PVOID *Base
);

NTSTATUS MiFindEmptyAddressRangeDownTree(
    IN RTL_AVL_TREE Vad,
    IN SIZE_T SizeOfRange,
    IN PVOID HighestAddressToEndAt,
    IN ULONG_PTR Alignment,
    OUT PVOID *Base
);

NTSTATUS MiMapPagesForMdl(
    IN PMDL Mdl,
    PVOID Va,
    SIZE_T Size
);

NTSTATUS MiAllocateVirtualMemoryForMdlPages(
    IN PMDL Mdl,
    IN OUT PVOID *BaseAddress,
    SIZE_T Size
);

#endif // !__NTMI_H__
