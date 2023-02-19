#include "user_system.h"
#include "_kernel_struct.h"

#include "memory.h"
#include "log.h"

std::list<user_hook_t> *user_system::user_hooks;
user_hook_t *user_system::h_DbgUiRemoteBreakin = nullptr;

void user_system::initialize()
{
	user_hooks = new std::list<user_hook_t>();
}

void user_system::destory()
{
	if (user_hooks) delete user_hooks;
}


/// <summary>
/// 由3环进程调用该函数
/// address是用户模式函数的地址
/// 先将该函数复制到内核内存中，用于换页，然后切换进程进行ept hook
/// 由于函数在ntdll中，所以不同的进程ntdll的地址应该也一样
/// </summary>
/// <param name="process_id">被hook进程id</param>
/// <param name="address">函数地址</param>
void user_system::hook_r3(uint64_t process_id, void *address)
{
	// 清楚最后12位
	void *orignal_page = (void*)((uint64_t)address & ~0xfff);
	size_t size = 0x1000;

	PMDL mdl;
	NTSTATUS Status;

	Status = memory::lock_memory(process_id, orignal_page, size, &mdl);

	if (!NT_SUCCESS(Status))
	{
		Log("Lock faild");
		return;
	}

	// 申请内核内存，用于ept换页
	void *fake_page = new uint8_t[size];
	RtlCopyMemory(fake_page, orignal_page, size);
	
	PEPROCESS_BY Process;
	KAPC_STATE Apc;

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)process_id, (PEPROCESS *)&Process);

	if (!NT_SUCCESS(Status))
	{
		Log("Get process faild");
	}

	KeStackAttachProcess((PEPROCESS)Process, &Apc);

	hook_page_t hook_page = {
		MmGetPhysicalAddress(orignal_page).QuadPart, 
		MmGetPhysicalAddress(fake_page).QuadPart
	};

	foreach_logical_core(
		[](void *context) {
			//__vmm_vmxcall(vm_call::ept_hide, reinterpret_cast<uint64_t>(context), 0x21568899, 0);
			hook_page_t *hook_page = (hook_page_t *)context;
			install_ept_hook(hook_page->original_pa, hook_page->fake_pa);
		}, &hook_page
	);

	KeUnstackDetachProcess(&Apc);
}