#pragma once
#include <ntddk.h>
#include <cstdint>

//
// Maximum number of CPUs.
//
#define BHVP_MAX_CPU  256

//
// Multi-Processor functions.
//

EXTERN_C
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);


EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);


EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

namespace mp
{
	void ipi_call(void(*callback)(void *), void *context) noexcept;
	void dpc_call(void(*callback)(void *), void *context) noexcept;

	uint32_t cpu_count() noexcept;
	uint32_t cpu_index() noexcept;

	//
	// Inter-Processor Interrupt - runs specified method on all logical CPUs.
	//
	template <typename T>
	inline void ipi_call(T function) noexcept
	{
		ipi_call([](void *context) noexcept { ((T *)(context))->operator()(); }, &function);
	}

	template <typename T>
	inline void dpc_call(T function) noexcept
	{
		dpc_call([](void *context) noexcept { ((T *)(context))->operator()(); }, &function);
	}
}