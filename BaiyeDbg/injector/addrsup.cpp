#include "ntmi.h"
#include "ia32.h"
#include "ntmmpts.h"
#include "ntkernels.h"

PRTL_BALANCED_NODE
MiGetPreviousNode(
    IN PRTL_BALANCED_NODE Node
)
{
    PRTL_BALANCED_NODE Previous;
    PRTL_BALANCED_NODE Parent;

    Previous = Node;

    if (Previous->Left == NULL) {

        Parent = SANITIZE_PARENT_NODE(Previous->ParentValue);

        while (Parent != Previous) {

            //
            // Locate the first ancestor of this node of which this
            // node is the right child of and return that node as the
            // Previous element.
            //

            if (Parent->Right == Previous) {

                if (Parent == SANITIZE_PARENT_NODE(Previous->ParentValue)) {
                    return NULL;
                }

                return Parent;
            }

            Previous = Parent;
            Parent = SANITIZE_PARENT_NODE(Previous->ParentValue);
        }
        return NULL;
    }

    //
    // A left child exists, locate the right most child of that left child.
    //

    Previous = Previous->Left;

    while (Previous->Right != NULL) {
        Previous = Previous->Right;
    }

    return Previous;
}


PRTL_BALANCED_NODE
MiGetNextNode(
    IN PRTL_BALANCED_NODE Node
)
{
    PRTL_BALANCED_NODE Next;
    PRTL_BALANCED_NODE Parent;
    PRTL_BALANCED_NODE Left;

    Next = Node;

    if (Next->Right == NULL) {

        do {

            Parent = SANITIZE_PARENT_NODE(Next->ParentValue);

            ASSERT(Parent != NULL);

            if (Parent == Next) {
                return NULL;
            }

            //
            // Locate the first ancestor of this node of which this
            // node is the left child of and return that node as the
            // next element.
            //

            if (Parent->Left == Next) {
                return Parent;
            }

            Next = Parent;

        } while (TRUE);
    }

    //
    // A right child exists, locate the left most child of that right child.
    //

    Next = Next->Right;

    do {

        Left = Next->Left;

        if (Left == NULL) {
            break;
        }

        Next = Left;

    } while (TRUE);

    return Next;
}

NTSTATUS MiFindEmptyAddressRangeInTree(
    IN RTL_AVL_TREE Vad,
    IN SIZE_T SizeOfRange,
    IN ULONG_PTR Alignment,
    OUT PVOID *Base)
{
    RTL_BALANCED_NODE *Node;
    RTL_BALANCED_NODE *NextNode;
    ULONG_PTR AlignmentVpn;
    ULONG_PTR SizeOfRangeVpn;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;

    AlignmentVpn = Alignment >> PAGE_SHIFT;

    SizeOfRangeVpn = (SizeOfRange + (PAGE_SIZE - 1)) >> PAGE_SHIFT;

    Node = Vad.Root;

    while (Node->Left != NULL) {
        Node = Node->Left;
    }

    // StartingVpn = *(Node + 0x18) | (*(Node + 0x20) << 32);
    StartingVpn = VAD_STARTING_VPN(Node);

    //
    // Check to see if a range exists between the lowest address VAD
    // and lowest user address.
    //

    if (StartingVpn > MI_VA_TO_VPN(MM_LOWEST_USER_ADDRESS)) {

        if (SizeOfRangeVpn <
            (StartingVpn - MI_VA_TO_VPN(MM_LOWEST_USER_ADDRESS))) {

            *Base = MM_LOWEST_USER_ADDRESS;
            return STATUS_SUCCESS;
        }
    }

    do {

        NextNode = MiGetNextNode(Node);

        if (NextNode != NULL) {

            StartingVpn = VAD_STARTING_VPN(NextNode);
            EndingVpn = VAD_ENDING_VPN(NextNode);

            if (SizeOfRangeVpn <= ((ULONG_PTR)StartingVpn - MI_ROUND_TO_SIZE(1 + EndingVpn, AlignmentVpn))) 
            {

                //
                // Check to ensure that the ending address aligned upwards
                // is not greater than the starting address.
                //

                if ((ULONG_PTR)StartingVpn >
                    MI_ROUND_TO_SIZE(1 + EndingVpn,
                        AlignmentVpn)) {

                    *Base = (PVOID)MI_ROUND_TO_SIZE(
                        (ULONG_PTR)MI_VPN_TO_VA_ENDING(EndingVpn),
                        Alignment);
                    return STATUS_SUCCESS;
                }
            }

        }
        else {

            StartingVpn = VAD_STARTING_VPN(Node);
            EndingVpn = VAD_ENDING_VPN(Node);

            //
            // No more descriptors, check to see if this fits into the remainder
            // of the address space.
            //

            if ((((ULONG_PTR)EndingVpn + MI_VA_TO_VPN(X64K)) <
                MI_VA_TO_VPN(MM_HIGHEST_VAD_ADDRESS))
                &&
                (SizeOfRange <=
                    ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS -
                        (ULONG_PTR)MI_ROUND_TO_SIZE(
                            (ULONG_PTR)MI_VPN_TO_VA(EndingVpn), Alignment)))) {

                *Base = (PVOID)MI_ROUND_TO_SIZE(
                    (ULONG_PTR)MI_VPN_TO_VA_ENDING(EndingVpn),
                    Alignment);
                return STATUS_SUCCESS;
            }
            return STATUS_NO_MEMORY;
        }
        Node = NextNode;

    } while (TRUE);
}

NTSTATUS MiFindEmptyAddressRangeDownTree(
    IN RTL_AVL_TREE Vad,
    IN SIZE_T SizeOfRange,
    IN PVOID HighestAddressToEndAt,
    IN ULONG_PTR Alignment,
    OUT PVOID *Base
)
{
    PRTL_BALANCED_NODE Node;
    PRTL_BALANCED_NODE PreviousNode;
    ULONG_PTR AlignedEndingVa;
    PVOID OptimalStart;
    ULONG_PTR OptimalStartVpn;
    ULONG_PTR HighestVpn;
    ULONG_PTR AlignmentVpn;

    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;

    SizeOfRange = MI_ROUND_TO_SIZE(SizeOfRange, PAGE_SIZE);

    if (((ULONG_PTR)HighestAddressToEndAt + 1) < SizeOfRange) {
        return STATUS_NO_MEMORY;
    }

    HighestVpn = MI_VA_TO_VPN(HighestAddressToEndAt);

    //
    // Locate the Node with the highest starting address.
    //

    OptimalStart = (PVOID)(MI_ALIGN_TO_SIZE(
        (((ULONG_PTR)HighestAddressToEndAt + 1) - SizeOfRange),
        Alignment));

    Node = Vad.Root;

    if (Node == NULL)
    {
        //
        // The tree is empty, any range is okay.
        //

        *Base = OptimalStart;
        return STATUS_SUCCESS;
    }

    //
    // See if an empty slot exists to hold this range, locate the largest
    // element in the tree.
    //

    while (Node->Right != NULL) {
        Node = Node->Right;
    }

    //
    // Walk the tree backwards looking for a fit.
    //

    OptimalStartVpn = MI_VA_TO_VPN(OptimalStart);
    AlignmentVpn = MI_VA_TO_VPN(Alignment);

    do {

        PreviousNode = MiGetPreviousNode(Node);

        if (PreviousNode != NULL)
        {

            //
            // Is the ending Va below the top of the address to end at.
            //

            StartingVpn = VAD_STARTING_VPN(PreviousNode);
            EndingVpn = VAD_ENDING_VPN(PreviousNode);

            if (EndingVpn < OptimalStartVpn) {
                if ((SizeOfRange >> PAGE_SHIFT) <=
                    ((ULONG_PTR)StartingVpn -
                        (ULONG_PTR)MI_ROUND_TO_SIZE(1 + EndingVpn,
                            AlignmentVpn))) {

                    //
                    // See if the optimal start will fit between these
                    // two VADs.
                    //

                    if ((OptimalStartVpn > EndingVpn) &&
                        (HighestVpn < StartingVpn)) {
                        *Base = OptimalStart;
                        return STATUS_SUCCESS;
                    }

                    //
                    // Check to ensure that the ending address aligned upwards
                    // is not greater than the starting address.
                    //

                    if ((ULONG_PTR)StartingVpn >
                        (ULONG_PTR)MI_ROUND_TO_SIZE(1 + EndingVpn,
                            AlignmentVpn)) {

                        *Base = MI_ALIGN_TO_SIZE(
                            (ULONG_PTR)MI_VPN_TO_VA(StartingVpn) - SizeOfRange,
                            Alignment);
                        return STATUS_SUCCESS;
                    }
                }
            }
        }
        else
        {
            //
            // No more descriptors, check to see if this fits into the remainder
            // of the address space.
            //

            StartingVpn = VAD_STARTING_VPN(Node);
            EndingVpn = VAD_ENDING_VPN(Node);

            if (StartingVpn > MI_VA_TO_VPN(MM_LOWEST_USER_ADDRESS)) {
                if ((SizeOfRange >> PAGE_SHIFT) <=
                    ((ULONG_PTR)StartingVpn - MI_VA_TO_VPN(MM_LOWEST_USER_ADDRESS))) {

                    //
                    // See if the optimal start will fit between these
                    // two VADs.
                    //

                    if (HighestVpn < StartingVpn) {
                        *Base = OptimalStart;
                        return STATUS_SUCCESS;
                    }

                    *Base = MI_ALIGN_TO_SIZE(
                        (ULONG_PTR)MI_VPN_TO_VA(StartingVpn) - SizeOfRange,
                        Alignment);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NO_MEMORY;
        }

    } while (TRUE);
}

VOID MiMakeSystemAddressValid(PVOID AddressOfPte)
{
    //
    // 环境:
    // Kernel mode, APCs disabled, working set pushlock held, process attached
    //

    NTSTATUS Status;

    PETHREAD_BY Thread;
    PEPROCESS_BY Process;

    Thread = (PETHREAD_BY)PsGetCurrentThread();
    Process = (PEPROCESS_BY)PsGetCurrentProcess();

    while (1)
    {
        if (MmIsAddressValid(AddressOfPte))
            break;

        Status = ntfuncs.MmAccessFault(0, AddressOfPte, KernelMode, NULL);
        
        if (!NT_SUCCESS(Status))
        {
            KeBugCheckEx(0x7Au, 1ui64, Status, (ULONG_PTR)Process, (ULONG_PTR)AddressOfPte);
        }
    }
}

NTSTATUS MiMapPagesForMdl(
    IN PMDL Mdl,
    PVOID Va,
    SIZE_T Size
)
{
    //
    // 环境:
    // APCs disable, working set mutex held, address creation mutex held, process attached
    //

    PETHREAD_BY Thread;
    PEPROCESS_BY Process;
    CR3 DirBase;
    SIZE_T NumberOfPages;
    PUCHAR TempVa;

    Thread = (PETHREAD_BY)PsGetCurrentThread();
    Process = (PEPROCESS_BY)PsGetCurrentProcess();

    DirBase.AsUInt = Process->Pcb.DirectoryTableBase;

    NumberOfPages = Size / PAGE_SIZE;
    TempVa = (PUCHAR)Va;

    PPFN_NUMBER PfnArray = MmGetMdlPfnArray(Mdl);

    MMPTS_BASE PtBase = { 0 };
    if (!PtsInitializePtBase(TRUE, DirBase.AsUInt, &PtBase))
    {
        return STATUS_NO_MEMORY;
    }

    do {
        PTE_64 *Pte = (PTE_64 *)PtsAddressOfPte(&PtBase, TempVa);
        //PDE_64 *Pde = PtsAddressOfPde(&PtBase, TempVa);
        //PDPTE_64 *Ppe = PtsAddressOfPpe(&PtBase, TempVa);
        //PML4E_64 *Pxe = PtsAddressOfPxe(&PtBase, TempVa);
         
        MiMakeSystemAddressValid(Pte);

        Pte->Present = 1;
        Pte->Write = 1;
        Pte->Supervisor = 1;
        Pte->Dirty = 1;
        Pte->Accessed = 1;
        Pte->PageLevelWriteThrough = 1;
        Pte->PageFrameNumber = *PfnArray;

        NumberOfPages -= 1;
        PfnArray += 1;
        TempVa += PAGE_SIZE;

    } while (NumberOfPages != 0);

    return STATUS_SUCCESS;
}