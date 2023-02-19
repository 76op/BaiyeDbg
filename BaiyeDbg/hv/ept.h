#pragma once

#include "ia32.hpp"

namespace hv {

struct vcpu;

// number of PDs in the EPT paging structures
inline constexpr size_t ept_pd_count = 64;
inline constexpr size_t ept_free_page_count = 10;

struct vcpu_ept_hook_node {
  vcpu_ept_hook_node* next;

  // these can be stored as 32-bit integers to conserve space since
  // nobody is going to have more than 16,000 GB of physical memory
  uint32_t orig_pfn;
  uint32_t exec_pfn;
};

struct vcpu_ept_hooks {
  // buffer of nodes (there can be unused nodes in the middle
  // of the buffer if a hook was removed for example)
  static constexpr size_t capacity = 64;
  vcpu_ept_hook_node buffer[capacity];

  // list of currently active EPT hooks
  vcpu_ept_hook_node* active_list_head;

  // list of unused nodes
  vcpu_ept_hook_node* free_list_head;
};

struct vcpu_ept_data {
  // EPT PML4
  alignas(0x1000) ept_pml4e pml4[512];

  // EPT PDPT - a single one covers 512GB of physical memory
  alignas(0x1000) ept_pdpte pdpt[512];
  static_assert(ept_pd_count <= 512, "Only 512 EPT PDs are supported!");

  // an array of EPT PDs - each PD covers 1GB
  union {
    alignas(0x1000) ept_pde     pds[ept_pd_count][512];
    alignas(0x1000) ept_pde_2mb pds_2mb[ept_pd_count][512];
  };

  // free pages that can be used to split PDEs or for other purposes
  alignas(0x1000) uint8_t free_pages[ept_free_page_count][0x1000];

  // an array of PFNs that point to each free page in the free page array
  uint64_t free_page_pfns[ept_free_page_count];

  // # of free pages that are currently in use
  size_t num_used_free_pages;

  // EPT hooks
  vcpu_ept_hooks hooks;
};

// identity-map the EPT paging structures
void prepare_ept(vcpu_ept_data& ept);

// update the memory types in the EPT paging structures based on the MTRRs.
// this function should only be called from root-mode during vmx-operation.
void update_ept_memory_type(vcpu_ept_data& ept);

// set the memory type in every EPT paging structure to the specified value
void set_ept_memory_type(vcpu_ept_data& ept, uint8_t memory_type);

// get the corresponding EPT PDPTE for a given physical address
ept_pdpte* get_ept_pdpte(vcpu_ept_data& ept, uint64_t physical_address);

// get the corresponding EPT PDE for a given physical address
ept_pde* get_ept_pde(vcpu_ept_data& ept, uint64_t physical_address);

// get the corresponding EPT PTE for a given physical address
ept_pte* get_ept_pte(vcpu_ept_data& ept,
    uint64_t physical_address, bool force_split = false);

// split a 2MB EPT PDE so that it points to an EPT PT
void split_ept_pde(vcpu_ept_data& ept, ept_pde_2mb* pde_2mb);

// memory read/written will use the original page while code
// being executed will use the executable page instead
bool install_ept_hook(vcpu_ept_data& ept,
    uint64_t original_page_pfn, uint64_t executable_page_pfn);

// remove an EPT hook that was installed with install_ept_hook()
void remove_ept_hook(vcpu_ept_data& ept, uint64_t original_page_pfn);

// find the EPT hook for the specified PFN
vcpu_ept_hook_node* find_ept_hook(vcpu_ept_data& ept, uint64_t original_page_pfn);

} // namespace hv

