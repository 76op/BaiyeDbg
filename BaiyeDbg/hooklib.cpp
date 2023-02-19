#include "hooklib.h"
#include "log.h"
#include "lde.h"
#include "_global.h"

#include <list>

//
//exec_code_length 需要大于等于14
//
static hook_struct_t *hook_internal_with_fake(void *original_api, void *fake_api, void *newfunc, uint32_t exec_code_length)
{
    //allocate structure
    hook_struct_t *hook_struct = (hook_struct_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(hook_struct_t), POOL_TAG);
    if (!hook_struct) return nullptr;

    RtlZeroMemory(hook_struct, sizeof(hook_struct_t));

    // 设置跳转代码
    // 用于从自己的函数跳转到原函数
    if (exec_code_length != 0) {
        hook_struct->exec_code_length = exec_code_length;

        // 计算跳转地址，并向跳转地址填充原函数的头部数据
        uint64_t bridge_addr = ((uint64_t)&hook_struct->jmp_opcodes.orig) + EXEC_CODE_LENGTH - exec_code_length;
        hook_struct->jmp_opcodes.bridge_addr = (void *)bridge_addr;
        RtlCopyMemory((void *)bridge_addr, original_api, exec_code_length);

        // 函数头部代码执行完后，执行这里的跳转代码
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

    // 保存被hook的函数地址
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

    // 保存原数据用于还原
    RtlCopyMemory(&hook_struct->orig, (const void *)original_api, sizeof(hook_opcodes_t));

    // 写入hook代码, 写入到假页面中，这样vt执行原页面时会切换到假页面
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
        // 初始化hyper_hook_t, 用于保存hook信息
        hyper_hook_t *ept_hook = new hyper_hook_t;
        if (!ept_hook) return nullptr;

        RtlZeroMemory(ept_hook, sizeof(hyper_hook_t));

        //Log("original_api: %p, new_api: %p", original_api, new_api);

        // 获取需要hook的指令长度
        size_t code_lenth = lde::instruction_len(original_api, 14);

        // 第一次初始化page_refs
        if (page_refs == nullptr)
        {
            page_refs = new std::list<page_ref_t *>();
        }

        void *original_api_align = PAGE_ALIGN(original_api);
        size_t original_api_offset = BYTE_OFFSET(original_api);

         // 页是否已经有函数hook
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
             // 页面已存在，则增加引用
             ++page_ref->ref_count;

             // 因为在同一个页面中，所以只修改data_fake中的数据
             void *fake_page = reinterpret_cast<void *>(page_ref->fake_va);

             void *fake_api = reinterpret_cast<uint8_t *>(fake_page) + original_api_offset;

             // hook假页面中的函数
             hook_struct_t *hook_struct = hooklib::hook_with_fake(original_api, fake_api, new_api, code_lenth);

             // 保存hook数据
             ept_hook->hook_struct = hook_struct;
             ept_hook->api_addr = (uint64_t)original_api;
             ept_hook->page_ref = page_ref;

             return ept_hook;
         }
         else
         {
             // 申请假页面
             void *fake_page = new uint8_t[PAGE_SIZE];

             if (!fake_page)
             {
                 delete ept_hook;
                 return nullptr;
             }

             // 将原本的数据复制到假页面
             RtlCopyMemory(fake_page, original_api_align, PAGE_SIZE);

             // 初始化页面引用计数
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

             // hook 假页面中的api
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

            // 清理hook
            hooklib::unhook(ept_hook->hook_struct);

            // 释放内存
            delete reinterpret_cast<void *>(ept_hook->page_ref->fake_va);
            delete ept_hook;
        }
        else
        {
            // 清理hook
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