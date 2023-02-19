#include "mp.h"

namespace mp
{
	uint32_t cpu_count() noexcept
	{
		return KeQueryActiveProcessorCountEx(0);
	}

	uint32_t cpu_index() noexcept
	{
		return KeGetCurrentProcessorNumberEx(0);
	}

	void ipi_call(void(*callback)(void *), void *context) noexcept
	{
        struct ipi_ctx
        {
            void *context;
            void(*callback)(void *);
        } ipi_context{
          context,
          callback
        };

        KeIpiGenericCall([](ULONG_PTR Context) noexcept -> ULONG_PTR {
            //
            // Note that the function is called with IRQL at IPI_LEVEL.
            // Keep in mind that this effectively forbids us to call most of the kernel
            // functions.
            //

            auto ipi_context = reinterpret_cast<ipi_ctx *>(Context);
            auto context = ipi_context->context;
            auto callback = ipi_context->callback;

            callback(context);
            return 0;
        }, (ULONG_PTR)&ipi_context);
	}

    void dpc_call(void(*callback)(void *), void *context) noexcept
    {
        struct dpc_ctx
        {
            void *context;
            void(*callback)(void *);
        } dpc_context{
          context,
          callback
        };

        KeGenericCallDpc([](PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2) noexcept -> VOID {
            //
            // Note that the function is called with IRQL at IPI_LEVEL.
            // Keep in mind that this effectively forbids us to call most of the kernel
            // functions.
            //

            auto dpc_context = reinterpret_cast<dpc_ctx *>(Context);
            auto context = dpc_context->context;
            auto callback = dpc_context->callback;

            callback(context);
            
            // Wait for all DPCs to synchronize at this point
            KeSignalCallDpcSynchronize(SystemArgument2);

            // Mark the DPC as being complete
            KeSignalCallDpcDone(SystemArgument1);
            }, (PVOID)&dpc_context);
    }
}