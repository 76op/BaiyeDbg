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
/// ��3�����̵��øú���
/// address���û�ģʽ�����ĵ�ַ
/// �Ƚ��ú������Ƶ��ں��ڴ��У����ڻ�ҳ��Ȼ���л����̽���ept hook
/// ���ں�����ntdll�У����Բ�ͬ�Ľ���ntdll�ĵ�ַӦ��Ҳһ��
/// </summary>
/// <param name="process_id">��hook����id</param>
/// <param name="address">������ַ</param>
void user_system::hook_r3(uint64_t process_id, void *address)
{
	// ������12λ
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

	// �����ں��ڴ棬����ept��ҳ
	void *fake_page = new uint8_t[size];
	RtlCopyMemory(fake_page, orignal_page, size);
	
	PEPROCESS_BY Process;
	KAPC_STATE Apc;

	// ��ȡ��HOOK�Ľ��̽ṹ�壬���ڸ���
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