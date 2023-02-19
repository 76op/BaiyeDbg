//#pragma once
//#include <cstdint>
//
//#define VMCALL_DBVM_REGISTER_CR3_EDIT_CALLBACK		(16 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_RETURN_FROM_CR3_EDIT_CALLBACK	(17 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_GETCR0							(18 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_GETCR3							(19 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_GETCR4							(20 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_RAISEPRIVILEGE					(21 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_REDIRECTINT14					(22 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_INT14REDIRECTED					(23 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_REDIRECTINT3					(24 | VMCALL_DBVM_MASK)
//#define VMCALL_DBVM_INT3REDIRECTED					(25 | VMCALL_DBVM_MASK)
//
//namespace dbvm
//{
//    struct hv::vcpu;
//
//    // dbvm version
//    inline constexpr uint32_t version = 1;
//
//    // dhvm hypercall mask
//    inline constexpr uint64_t hypercall_mask = 0x40000000;
//
//    // dbvm basic VMCALLs
//    enum hypercall_code : uint64_t {
//        hypercall_get_version =         (0 | hypercall_mask),
//        hypercall_change_password =     (1 | hypercall_mask),
//        hypercall_read_phys_mem =       (3 | hypercall_mask),
//        hypercall_write_phys_mem =      (4 | hypercall_mask),
//        hypercall_redirect_int1 =       (9 | hypercall_mask),
//        hypercall_int1_redirected =     (10 | hypercall_mask),
//        hypercall_change_selectors =    (12 | hypercall_mask),
//        hypercall_block_interrupts =    (13 | hypercall_mask),
//        hypercall_restore_interrupts =  (14 | hypercall_mask),
//    };
//
//    namespace hc
//    {
//        // get dbvm version
//        void get_version(hv::vcpu *cpu);
//
//        void change_password(hv::vcpu *cpu);
//
//        // read from arbitrary physical memory
//        void read_phys_mem(hv::vcpu *cpu);
//
//        // write to arbitrary physical memory
//        void write_phys_mem(hv::vcpu *cpu);
//
//        // redirect int1 to new produce
//        void redirect_int1(hv::vcpu *cpu);
//
//        // set if it has just redirected a interrupt, cleared by vmcall query command
//        void int1_redirected(hv::vcpu *cpu);
//
//        void change_selectors(hv::vcpu *cpu);
//
//        void block_interrupts(hv::vcpu *cpu);
//
//        void restore_interrupts(hv::vcpu *cpu);
//    } // namespace hc
//
//    void handle_interrupt_01(hv::vcpu *const cpu);
//} // namespace dbvm