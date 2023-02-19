#pragma once
#include <cstdint>

void install_ept_hook(uint64_t original_pa, uint64_t fake_pa);

void remove_ept_hook(uint64_t original_pa);