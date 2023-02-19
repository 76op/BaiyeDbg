#pragma once
#include "nt_kernel.h"
#include "hooklib.h"

#include <intrin.h>

#include <atomic>

/// <summary>
/// 用于解决驱动的异常处理问题
/// </summary>

class seh_guard
{
private:
	static void *dll_base;
	static size_t image_size;

	static Fn_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable;
	static Fn_RtlRemoveInvertedFunctionTable RtlRemoveInvertedFunctionTable;

	static std::atomic<bool> *_lock;
	static void lock();
	static void unlock();

public:
	static void initialize(void *dll_base, size_t image_size);
	static void destory();

public:
	seh_guard();
	~seh_guard();
};

class exception_system
{
private:
	static INVERTED_FUNCTION_TABLE function_table;

private:
	static hyper_hook_t *hook_RtlpxLookupFunctionTable;

public:
	static void initialize(void *image_base, int image_size);
	static void destory();

public:
	static PIMAGE_RUNTIME_FUNCTION_ENTRY NTAPI New_RtlpxLookupFunctionTable(
		PVOID ControlPc,
		PINVERTED_FUNCTION_TABLE_ENTRY TableEntry
	);
};