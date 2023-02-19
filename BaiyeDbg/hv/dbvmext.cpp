//#include "dbvmext.h"
//#include "vcpu.h"
//#include "ia32.hpp"
//#include "vmx.h"
//
//namespace dbvm
//{
//	namespace hc
//	{
//
//		// get dbvm version
//		void get_version(hv::vcpu *cpu)
//		{
//			auto const ctx = cpu->ctx;
//			ctx->rax = version;
//		}
//
//		void change_password(hv::vcpu *cpu)
//		{
//			auto const ctx = cpu->ctx;
//			ctx->rax = 0;
//		}
//
//		// read from arbitrary physical memory
//		void read_phys_mem(hv::vcpu *cpu)
//		{
//			auto const ctx = cpu->ctx;
//			ctx->rax = 0;
//		}
//
//		// write to arbitrary physical memory
//		void write_phys_mem(hv::vcpu *cpu)
//		{
//			auto const ctx = cpu->ctx;
//			ctx->rax = 0;
//		}
//
//		// redirect int1 to new produce
//		void redirect_int1(hv::vcpu *cpu);
//
//		// set if it has just redirected a interrupt, cleared by vmcall query command
//		void int1_redirected(hv::vcpu *cpu);
//
//		void change_selectors(hv::vcpu *cpu);
//
//		void block_interrupts(hv::vcpu *cpu);
//
//		void restore_interrupts(hv::vcpu *cpu);
//
//	} // namespace hc
//
//	void handle_interrupt_01(hv::vcpu *const cpu)
//	{
//        //emulate the breakpoint interrupt
//        dr7 dr7_;
//        dr7_.flags = hv::vmx_vmread(VMCS_GUEST_DR7);
//
//        dr6 dr6_;
//        dr6_.flags = __readdr(6);
//        
//        //isFault = 0; //isDebugFault(vmread(vm_exit_qualification), dr7.DR7);
//
//        dr6 dr6_exit_qualification;
//        dr6_exit_qualification.flags = hv::vmx_vmread(VMCS_EXIT_QUALIFICATION);
//
//        //The documentation says about the exit qualification: Any of these bits may be set even if its corresponding enabling bit in DR7 is not set.
//        //The documentation also says for dr6: They may or may not be set if the breakpoint is not enabled by the Ln or the Gn flags in register DR7.
//        //therefore, just passing them 1 on 1
//
//        //also: Certain debug exceptions may clear bits 0-3. The remaining contents of the DR6 register are never cleared by the processor.
//        dr6_.flags &= ~(0xf); //zero the b0 to b3 flags
//
//        /*
//        RFLAGS rflags;
//        rflags.value = vmread(vm_guest_rflags);
//        if(rflags.TF)
//        {
//          sendstring("TF is 1");
//          dr6.DR6 |= dr6_exit_qualification.DR6 & 0x600f; //the 4 b0-b3 flags, BS and BD
//        }
//        else
//        {
//          sendstring("TF is 0");
//          dr6.DR6 |= dr6_exit_qualification.DR6 & 0x200f; //the 4 b0-b3 flags, BD
//        }
//        */
//
//        dr6_.flags |= dr6_exit_qualification.flags & 0x600f; //the 4 b0-b3 flags, BS and BD
//        dr6_.restricted_transactional_memory = ~dr6_exit_qualification.restricted_transactional_memory;
//        //if ((dr6_exit_qualification.RTM)==0) dr6.RTM=1; //if this is 0, set RTM to 1
//
//        __writedr(6, dr6_.flags);
//
//        //if (currentcpuinfo->Ultimap.Active)
//        //    ultimap_handleDB(currentcpuinfo);
//        //else
//        //    vmwrite(vm_guest_IA32_DEBUGCTL, vmread(vm_guest_IA32_DEBUGCTL) & ~1); //disable the LBR bit ( if it isn't already disabled)
//        hv::vmx_vmwrite(VMCS_GUEST_DEBUGCTL, hv::vmx_vmread(VMCS_GUEST_DEBUGCTL) & ~1);
//        
//        //set GD to 0
//        dr7_.general_detect = 0;
//        hv::vmx_vmwrite(VMCS_GUEST_DR7, dr7_.flags);
//
//        //interrupt redirection for int 1
//        if (int1redirection_idtbypass == 0)
//        {
//            //simple int1 redirection, or not even a different int
//            intinfo.interruptvector = int1redirection;
//            currentcpuinfo->int1happened = (int1redirection != 1); //only set if redirection to something else than 1
//        }
//        else
//        {
//            int r;
//            //emulate the interrupt completly, bypassing the idt vector and use what's given in
//            //int14redirection_idtbypass_cs and int14redirection_idtbypass_rip
//
//            r = emulateExceptionInterrupt(currentcpuinfo, vmregisters,
//                int1redirection_idtbypass_cs, int1redirection_idtbypass_rip,
//                intinfo.haserrorcode, vmread(vm_exit_interruptionerror), isFault);
//
//            nosendchar[getAPICID()] = orig;
//
//            if (r == 0)
//                return 0;
//
//            //else failure to handle it
//
//        }
//	}
//
//} //namespace dbvm