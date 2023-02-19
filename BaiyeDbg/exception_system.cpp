#include "exception_system.h"

void *seh_guard::dll_base = nullptr;
size_t seh_guard::image_size = 0;

Fn_RtlInsertInvertedFunctionTable seh_guard::RtlInsertInvertedFunctionTable = nullptr;
Fn_RtlRemoveInvertedFunctionTable seh_guard::RtlRemoveInvertedFunctionTable = nullptr;

std::atomic<bool> *seh_guard::_lock;

void seh_guard::initialize(void *dll_base, size_t image_size)
{
	seh_guard::dll_base = dll_base;
	seh_guard::image_size = image_size;

	nt_kernel *ntkrnl = new nt_kernel;
	seh_guard::RtlInsertInvertedFunctionTable = (Fn_RtlInsertInvertedFunctionTable)ntkrnl->api("RtlInsertInvertedFunctionTable");
	seh_guard::RtlRemoveInvertedFunctionTable = (Fn_RtlRemoveInvertedFunctionTable)ntkrnl->api("RtlRemoveInvertedFunctionTable");
	delete ntkrnl;

	seh_guard::_lock = new std::atomic<bool>(false);
}

void seh_guard::destory()
{
	delete seh_guard::_lock;
}

void seh_guard::lock()
{
	bool excepted = false;
	while (!seh_guard::_lock->compare_exchange_weak(excepted, true)) {
		YieldProcessor();
		excepted = false;
	}
}

void seh_guard::unlock()
{
	seh_guard::_lock->store(false);
}

seh_guard::seh_guard()
{
	seh_guard::lock();

	seh_guard::RtlInsertInvertedFunctionTable(seh_guard::dll_base, seh_guard::image_size);
}

seh_guard::~seh_guard()
{
	seh_guard::RtlRemoveInvertedFunctionTable(seh_guard::dll_base);
	
	seh_guard::unlock();
}


INVERTED_FUNCTION_TABLE exception_system::function_table = { 0 };

hyper_hook_t *exception_system::hook_RtlpxLookupFunctionTable = nullptr;

void exception_system::initialize(void *image_base, int image_size)
{
	PIMAGE_RUNTIME_FUNCTION_ENTRY RuntimeFunctionTable;
	ULONG SizeOfTable;

	nt_kernel *ntkrnl = new nt_kernel;

	Fn_RtlCaptureImageExceptionValues RtlCaptureImageExceptionValues = (Fn_RtlCaptureImageExceptionValues)ntkrnl->api("RtlCaptureImageExceptionValues");
	RtlCaptureImageExceptionValues(image_base, &RuntimeFunctionTable, &SizeOfTable);

	exception_system::function_table.CurrentSize = 1;
	exception_system::function_table.Epoch = 1;
	exception_system::function_table.MaximumSize = 255;
	exception_system::function_table.Overflow = 0;

	exception_system::function_table.TableEntry[0].FunctionTable = RuntimeFunctionTable;
	exception_system::function_table.TableEntry[0].ImageBase = image_base;
	exception_system::function_table.TableEntry[0].SizeOfImage = image_size;
	exception_system::function_table.TableEntry[0].SizeOfTable = SizeOfTable;

	void *pRtlpxLookupFunctionTable = ntkrnl->api("RtlpxLookupFunctionTable");
	exception_system::hook_RtlpxLookupFunctionTable = hyper::hook(pRtlpxLookupFunctionTable, exception_system::New_RtlpxLookupFunctionTable);

	delete ntkrnl;
}

void exception_system::destory()
{
	if (exception_system::hook_RtlpxLookupFunctionTable)
	{
		hyper::unhook(exception_system::hook_RtlpxLookupFunctionTable);
	}
}

PIMAGE_RUNTIME_FUNCTION_ENTRY NTAPI exception_system::New_RtlpxLookupFunctionTable(
	PVOID ControlPc,
	PINVERTED_FUNCTION_TABLE_ENTRY TableEntry
)
{
	PIMAGE_RUNTIME_FUNCTION_ENTRY RuntimeFunction = NULL;

	PVOID ImageBase = exception_system::function_table.TableEntry[0].ImageBase;
	PVOID ImageBaseMax = (PCHAR)ImageBase + exception_system::function_table.TableEntry[0].SizeOfImage;

	if (ControlPc >= ImageBase && ControlPc < ImageBaseMax)
	{
		*TableEntry = exception_system::function_table.TableEntry[0];
		RuntimeFunction = exception_system::function_table.TableEntry[0].FunctionTable;

		return RuntimeFunction;
	}
	else
	{
		Fn_RtlpxLookupFunctionTable RtlpxLookupFunctionTable = (Fn_RtlpxLookupFunctionTable)hook_RtlpxLookupFunctionTable->bridge();
		return RtlpxLookupFunctionTable(ControlPc, TableEntry);
	}
}