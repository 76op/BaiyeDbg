#include "hypercall.h"
#include "_global.h"
#include "hv/hypercalls.h"
#include "hv/vmx.h"

void install_ept_hook(uint64_t original_pa, uint64_t fake_pa)
{
    hv::hypercall_input input{};
    input.key = hv::hypercall_key;
    input.code = hv::hypercall_code::hypercall_install_ept_hook;
    input.args[0] = original_pa;
    input.args[1] = fake_pa;

    foreach_logical_core(
        [](void *input) {
            hv::vmx_vmcall(*reinterpret_cast<hv::hypercall_input *>(input));
        }, &input
    );
}

void remove_ept_hook(uint64_t original_pa)
{
    hv::hypercall_input input{};
    input.key = hv::hypercall_key;
    input.code = hv::hypercall_code::hypercall_remove_ept_hook;
    input.args[0] = original_pa;

    foreach_logical_core(
        [](void *input) {
            hv::vmx_vmcall(*reinterpret_cast<hv::hypercall_input *>(input));
        }, &input
    );
}