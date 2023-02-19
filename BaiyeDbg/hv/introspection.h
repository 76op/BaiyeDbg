#pragma once

#include "vmx.h"

#include <ntddk.h>

namespace hv {

// get the KPCR of the current guest (the pointer should stay constant per-vcpu)
PKPCR current_guest_kpcr();

// get the ETHREAD of the current guest
PETHREAD current_guest_ethread();

// get the EPROCESS of the current guest
PEPROCESS current_guest_eprocess();

} // namespace hv

