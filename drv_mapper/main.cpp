#include "_global.h"
#include "handle.h"

UNICODE_STRING usDeviceName = RTL_CONSTANT_STRING(L"\\Device\\baiye_md");
UNICODE_STRING usSymbolName = RTL_CONSTANT_STRING(L"\\??\\baiye_md");
PDEVICE_OBJECT pDeviceObject = NULL;

EXTERN_C VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	IoDeleteSymbolicLink(&usSymbolName);
	IoDeleteDevice(pDeviceObject);

	UnInitHandle();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	pDriverObject->DriverUnload = DriverUnload;

	InitHandle();

	// 创建一个设备
	status = IoCreateDevice(pDriverObject, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	// 设置了一个设备对象名称和该设备的用户可视名称之间的符号链接
	// 向应用程序公开的连接符号，别的程序才能和你的驱动通信
	status = IoCreateSymbolicLink(&usSymbolName, &usDeviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	SIZE_T i;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		pDriverObject->MajorFunction[i] = DispatchHandle;
	}
	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}