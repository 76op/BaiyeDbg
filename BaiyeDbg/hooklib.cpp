#include "hooklib.h"
#include "log.h"
#include "lde.h"
#include "_global.h"

#include <list>

//
//exec_code_length ��Ҫ���ڵ���14
//
static hook_struct_t *hook_internal_with_fake(void *original_api, void *fake_api, void *newfunc, uint32_t exec_code_length)
{
    //allocate structure
    hook_struct_t *hook_struct = (hook_struct_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(hook_struct_t), POOL_TAG);
    if (!hook_struct) return nullptr;

    RtlZeroMemory(hook_struct, sizeof(hook_struct_t));

    // ������ת����
    // ���ڴ��Լ��ĺ�����ת��ԭ����
    if (exec_code_length != 0) {
        hook_struct->exec_code_length = exec_code_length;

        // ������ת��ַ��������ת��ַ���ԭ������ͷ������
        uint64_t bridge_addr = ((uint64_t)&hook_struct->jmp_opcodes.orig) + EXEC_CODE_LENGTH - exec_code_length;
        hook_struct->jmp_opcodes.bridge_addr = (void *)bridge_addr;
        RtlCopyMemory((void *)bridge_addr, original_api, exec_code_length);

        // ����ͷ������ִ�����ִ���������ת����
        large_t jmp_addr = { (uint64_t)original_api + exec_code_length };
        hook_struct->jmp_opcodes.push = 0x68;
        hook_struct->jmp_opcodes.low_part = jmp_addr.low;
        hook_struct->jmp_opcodes.mov_rsp[0] = 0xc7;
        hook_struct->jmp_opcodes.mov_rsp[1] = 0x44;
        hook_struct->jmp_opcodes.mov_rsp[2] = 0x24;
        hook_struct->jmp_opcodes.mov_rsp[3] = 0x04;
        hook_struct->jmp_opcodes.high_part = jmp_addr.high;
        hook_struct->jmp_opcodes.ret = 0xc3;
    }

    // ���汻hook�ĺ�����ַ
    hook_struct->addr = (uint64_t)fake_api;

    large_t large = { (uint64_t)newfunc };
    //set hooking opcode
    hook_struct->hook_opcodes.push = 0x68;
    hook_struct->hook_opcodes.low_part = large.low;
    hook_struct->hook_opcodes.mov_rsp[0] = 0xc7;
    hook_struct->hook_opcodes.mov_rsp[1] = 0x44;
    hook_struct->hook_opcodes.mov_rsp[2] = 0x24;
    hook_struct->hook_opcodes.mov_rsp[3] = 0x04;
    hook_struct->hook_opcodes.high_part = large.high;
    hook_struct->hook_opcodes.ret = 0xc3;

    // ����ԭ�������ڻ�ԭ
    RtlCopyMemory(&hook_struct->orig, (const void *)original_api, sizeof(hook_opcodes_t));

    // д��hook����, д�뵽��ҳ���У�����vtִ��ԭҳ��ʱ���л�����ҳ��
    RtlCopyMemory((void *)fake_api, &hook_struct->hook_opcodes, sizeof(hook_opcodes_t));

    //Log("hook_struct: %p.", hook_struct);
    //Log("bridge_addr: %p.", hook_struct->jmp_opcodes.bridge_addr);

    return hook_struct;
}

namespace hooklib
{
    hook_struct_t *hook_with_fake(void *original_api, void *fake_api, void *newfunc, uint32_t exec_code_length)
    {
        if (original_api == nullptr) return nullptr;

        return hook_internal_with_fake(original_api, fake_api, newfunc, exec_code_length);
    }

    void unhook(hook_struct_t *hook_struct, bool free)
    {
        if (hook_struct && hook_struct->addr)
        {
            RtlCopyMemory((void *)hook_struct->addr, hook_struct->orig, sizeof(hook_opcodes_t));
        }
        if (free)
        {
            delete hook_struct;
        }
    }
}


namespace hyper
{
    std::list<page_ref_t *> *page_refs = nullptr;

    hyper_hook_t *hook(void *original_api, void *new_api)
    {
        // ��ʼ��hyper_hook_t, ���ڱ���hook��Ϣ
        hyper_hook_t *ept_hook = new hyper_hook_t;
        if (!ept_hook) return nullptr;

        RtlZeroMemory(ept_hook, sizeof(hyper_hook_t));

        //Log("original_api: %p, new_api: %p", original_api, new_api);

        // ��ȡ��Ҫhook��ָ���
        size_t code_lenth = lde::instruction_len(original_api, 14);

        // ��һ�γ�ʼ��page_refs
        if (page_refs == nullptr)
        {
            page_refs = new std::list<page_ref_t *>();
        }

        void *original_api_align = PAGE_ALIGN(original_api);
        size_t original_api_offset = BYTE_OFFSET(original_api);

         // ҳ�Ƿ��Ѿ��к���hook
         page_ref_t *page_ref = nullptr;
         for (auto &page_ref_ : *page_refs)
         {
             if (page_ref_->original_va == (uint64_t)original_api_align)
             {
                 page_ref = page_ref_;
                 break;
             }
         }

         if (page_ref)
         {
             // ҳ���Ѵ��ڣ�����������
             ++page_ref->ref_count;

             // ��Ϊ��ͬһ��ҳ���У�����ֻ�޸�data_fake�е�����
             void *fake_page = reinterpret_cast<void *>(page_ref->fake_va);

             void *fake_api = reinterpret_cast<uint8_t *>(fake_page) + original_api_offset;

             // hook��ҳ���еĺ���
             hook_struct_t *hook_struct = hooklib::hook_with_fake(original_api, fake_api, new_api, code_lenth);

             // ����hook����
             ept_hook->hook_struct = hook_struct;
             ept_hook->api_addr = (uint64_t)original_api;
             ept_hook->page_ref = page_ref;

             return ept_hook;
         }
         else
         {
             // �����ҳ��
             void *fake_page = new uint8_t[PAGE_SIZE];

             if (!fake_page)
             {
                 delete ept_hook;
                 return nullptr;
             }

             // ��ԭ�������ݸ��Ƶ���ҳ��
             RtlCopyMemory(fake_page, original_api_align, PAGE_SIZE);

             // ��ʼ��ҳ�����ü���
             page_ref = new page_ref_t;
             if (!page_ref)
             {
                 delete fake_page;
                 delete ept_hook;
                 return nullptr;
             }

             *page_ref = { 0 };

             page_ref->original_va = reinterpret_cast<uint64_t>(original_api_align);
             page_ref->fake_va = reinterpret_cast<uint64_t>(fake_page);

             page_ref->original_pa = MmGetPhysicalAddress(original_api_align).QuadPart;
             page_ref->fake_pa = MmGetPhysicalAddress(fake_page).QuadPart;

             page_ref->ref_count = 1;
             page_refs->push_back(page_ref);

             // hook ��ҳ���е�api
             void *fake_api = (uint8_t *)fake_page + original_api_offset;
             hook_struct_t *hook_struct = hooklib::hook_with_fake(original_api, fake_api, new_api, code_lenth);

             ept_hook->hook_struct = hook_struct;
             ept_hook->api_addr = reinterpret_cast<uint64_t>(original_api);
             ept_hook->page_ref = page_ref;

             install_ept_hook(page_ref->original_pa, page_ref->fake_pa);

             return ept_hook;
         }
    }

    void unhook(ept_hook_t *ept_hook)
    {
        if (!ept_hook || !ept_hook->page_ref) return;

        page_ref_t *page_ref = ept_hook->page_ref;
        --page_ref->ref_count;

        if (page_ref->ref_count < 1)
        {
            remove_ept_hook(page_ref->original_pa);

            // ����hook
            hooklib::unhook(ept_hook->hook_struct);

            // �ͷ��ڴ�
            delete reinterpret_cast<void *>(ept_hook->page_ref->fake_va);
            delete ept_hook;
        }
        else
        {
            // ����hook
            hooklib::unhook(ept_hook->hook_struct);
            delete ept_hook;
        }

        if (page_refs->size() < 1)
        {
            delete page_refs;
            page_refs = nullptr;
        }
    }
}