#include "handle.h"
#include "nt_kernel.h"
#include "mm.h"
#include <intrin.h>

#ifdef DBG 
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"#%d [DriverMap]: " format "\n", KeGetCurrentProcessorNumberEx(0), ##__VA_ARGS__)
#else
#define Log(format, ...)
#endif // DBG 

void set_invalid_msr(uint8_t *msr_arr, uint32_t msr_id)
{
	uint32_t idx = msr_id / 8;
	uint32_t bit_offset = msr_id % 7;

	msr_arr[idx] |= 1 << bit_offset;
}

void cache_invalid_msr(uint8_t *msr_arr)
{
	for (int i = 0; i <= 0x1fff; i++)
	{
		__try
		{
			__readmsr(i);
		}
		__except (1)
		{
			set_invalid_msr(msr_arr, i);
		}
	}
}

struct ntkrnl_t
{
	nt_kernel *krnl;
};

static ntkrnl_t ntkrnk;

void InitHandle()
{
	ntkrnk.krnl = new nt_kernel;
}

void UnInitHandle()
{
	delete ntkrnk.krnl;
}

struct kernel_ext_t
{
	void *driver_unload;
	uint8_t *invalid_msr_low;

	void *dll_base;
	size_t image_size;
};


#define IO_CTL_SYSLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 2048, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_CTL_SYSUNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 2049, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

NTSTATUS DispatchHandle(PDEVICE_OBJECT DeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T byte_size = 0;

	// 获取io堆栈位置
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

	switch (stack->MajorFunction)
	{
	case IRP_MJ_CREATE:
	case IRP_MJ_CLOSE:
		break;
	case IRP_MJ_DEVICE_CONTROL:
	{
		ULONG CtrlCode = stack->Parameters.DeviceIoControl.IoControlCode;

		if (CtrlCode == IO_CTL_SYSLOAD)
		{
			PeFile *in_data = (PeFile *)pIrp->AssociatedIrp.SystemBuffer;

			// 加载PE
			pe_image pe;
			pe.load(in_data->file_data, in_data->file_size);
			Log("DllBase: %p", pe.section_data());
			Fn_DriverEntry entry = pe.sys_ep();

			uint8_t *msr_arr = new uint8_t[0x400];

			kernel_ext_t kernel_ext = { 0 };
			kernel_ext.invalid_msr_low = msr_arr;
			kernel_ext.dll_base = pe.section_data();
			kernel_ext.image_size = pe.image_size();

			Fn_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable = 
				(Fn_RtlInsertInvertedFunctionTable)ntkrnk.krnl->api("RtlInsertInvertedFunctionTable");
			RtlInsertInvertedFunctionTable(pe.section_data(), pe.image_size());

			Log("sys_load, call entry_point");

			// 调用EP
			status = entry(nullptr, &kernel_ext);

			Fn_RtlRemoveInvertedFunctionTable RtlRemoveInvertedFunctionTable =
				(Fn_RtlRemoveInvertedFunctionTable)ntkrnk.krnl->api("RtlRemoveInvertedFunctionTable");
			RtlRemoveInvertedFunctionTable(pe.section_data());

			delete[] msr_arr; 

			// 保存数据，卸载时用
			pe_load_data_t *out_data = (pe_load_data_t *)pIrp->AssociatedIrp.SystemBuffer;
			out_data->section_data = (void *)(reinterpret_cast<uint64_t>(pe.section_data()) ^ 0x77);
			out_data->section_handle = (HANDLE)(reinterpret_cast<uint64_t>(pe.section_handle()) ^ 0x77);
			out_data->driver_unload = (void *)((uint64_t)kernel_ext.driver_unload ^ 0x77);
			out_data->image_size = pe.image_size() ^ 0x77;

			byte_size = sizeof(pe_load_data_t);

			pe.erase_header();
		}
		else if (CtrlCode == IO_CTL_SYSUNLOAD)
		{
			pe_load_data_t *in_data = (pe_load_data_t *)pIrp->AssociatedIrp.SystemBuffer;

			void *section_data = (void *)(reinterpret_cast<uint64_t>(in_data->section_data) ^ 0x77);
			HANDLE section_handle = (HANDLE)(reinterpret_cast<uint64_t>(in_data->section_handle) ^ 0x77);
			size_t image_size = in_data->image_size ^ 0x77;

			Fn_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable =
				(Fn_RtlInsertInvertedFunctionTable)ntkrnk.krnl->api("RtlInsertInvertedFunctionTable");
			RtlInsertInvertedFunctionTable(section_data, image_size);

			// 调用卸载函数
			Fn_DriverUnload unload_entry = (Fn_DriverUnload)(reinterpret_cast<uint64_t>(in_data->driver_unload) ^ 0x77);
			unload_entry(nullptr);

			Fn_RtlRemoveInvertedFunctionTable RtlRemoveInvertedFunctionTable =
				(Fn_RtlRemoveInvertedFunctionTable)ntkrnk.krnl->api("RtlRemoveInvertedFunctionTable");
			RtlRemoveInvertedFunctionTable(section_data);

			// 清理内存
			pe_image pe(section_data, section_handle);
			pe.unload();

			status = STATUS_SUCCESS;
			byte_size = 0;
		}
	}
	break;
	default:
		break;
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = byte_size; // 读写了多少字节
	IoCompleteRequest(pIrp, IO_NO_INCREMENT); // 完成请求
	return status;
}