#include "_global.h"
#include "log.h"

#define RANDOM_SEED_INIT 0x3AF84E05
static ULONG RandomSeed = RANDOM_SEED_INIT;

ULONG RtlNextRandom(ULONG Min, ULONG Max) // [Min,Max)
{
    if (RandomSeed == RANDOM_SEED_INIT)  // One-time seed initialisation. It doesn't have to be good, just not the same every time
        RandomSeed = (ULONG)__rdtsc();

    // NB: In user mode, the correct scale for RtlUniform/RtlRandom/RtlRandomEx is different on Win 10+:
    // Scale = (RtlNtMajorVersion() >= 10 ? MAXUINT32 : MAXINT32) / (Max - Min);
    // The KM versions seem to have been unaffected by this change, at least up until RS3.
    // If this ever starts returning values >= Max, try the above scale instead
    const ULONG Scale = (ULONG)MAXINT32 / (Max - Min);
    return RtlRandomEx(&RandomSeed) / Scale + Min;
}

uint32_t pool_tag()
{
    ULONG PoolTags[] =
    {
        ' prI', // Allocated IRP packets
        '+prI', // I/O verifier allocated IRP packets
        'eliF', // File objects
        'atuM', // Mutant objects
        'sFtN', // ntfs.sys!StrucSup.c
        'ameS', // Semaphore objects
        'RwtE', // Etw KM RegEntry
        'nevE', // Event objects
        ' daV', // Mm virtual address descriptors
        'sdaV', // Mm virtual address descriptors (short)
        'aCmM', // Mm control areas for mapped files
        '  oI', // I/O manager
        'tiaW', // WaitCompletion Packets
        'eSmM', // Mm secured VAD allocation
        'CPLA', // ALPC port objects
        'GwtE', // ETW GUID
        ' ldM', // Memory Descriptor Lists
        'erhT', // Thread objects
        'cScC', // Cache Manager Shared Cache Map
        'KgxD', // Vista display driver support
    };

    ULONG NumPoolTags = ARRAYSIZE(PoolTags);
    const ULONG Index = RtlNextRandom(0, NumPoolTags);
    NT_ASSERT(Index <= NumPoolTags - 1);
    return PoolTags[Index];
}


void foreach_logical_core(void (*callback_fn)(void *), void *context)
{
    uint16_t group_count = KeQueryActiveGroupCount();

    for (uint16_t group_number = 0; group_number < group_count; ++group_number)
    {
        DWORD processor_count = KeQueryActiveProcessorCountEx(group_number);

        for (DWORD processor_number = 0; processor_number < processor_count; ++processor_number)
        {
            GROUP_AFFINITY group_affinity = { 0 };
            group_affinity.Mask = (KAFFINITY)(1) << processor_number;
            group_affinity.Group = group_number;
            KeSetSystemGroupAffinityThread(&group_affinity, NULL);

            callback_fn(context);
        }
    }

    KeRevertToUserAffinityThread();
}

void *operator new  (size_t size) { return ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG); }
void *operator new[](size_t size) { return ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG); }
void *operator new  (size_t size, std::align_val_t alignment) { return ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG); }
void *operator new[](size_t size, std::align_val_t alignment) { return ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG); }

void operator delete  (void *address) { ExFreePool(address); }
void operator delete[](void *address) { ExFreePool(address); }
void operator delete[](void *address, std::size_t) { ExFreePool(address); }
void operator delete  (void *address, std::size_t) { ExFreePool(address); }
void operator delete  (void *address, std::align_val_t) { ExFreePool(address); }
void operator delete[](void *address, std::align_val_t) { ExFreePool(address); }
void operator delete[](void *address, std::size_t, std::align_val_t) { ExFreePool(address); }
void operator delete  (void *address, std::size_t, std::align_val_t) { ExFreePool(address); }