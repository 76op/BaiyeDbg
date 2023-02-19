#pragma once

#include <ntifs.h>
#include <ntdef.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>

#include <windef.h>

#include <cstring>
#include <cstdint>
#include <cstddef>      // std::byte
#include <cinttypes>
#include <numeric>
#include <type_traits>

#define BY_PAGE_ALIGN(Va)  ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define POOL_TAG pool_tag()

uint32_t pool_tag();

void foreach_logical_core(void (*callback_fn)(void *), void *context);

union large_t
{
    uint64_t quad;

    struct {
        uint32_t low;
        uint32_t high;
    };
};