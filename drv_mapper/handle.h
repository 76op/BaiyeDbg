#pragma once
#include "_global.h"
#include "pe_image.h"

NTSTATUS DispatchHandle(PDEVICE_OBJECT DeviceObject, PIRP pIrp);

struct PeFile
{
	void *file_data;
	size_t file_size;
};

struct pe_load_data_t
{
	void *section_data;
	size_t image_size;
	HANDLE section_handle;
	void *driver_unload;
};

void InitHandle();
void UnInitHandle();