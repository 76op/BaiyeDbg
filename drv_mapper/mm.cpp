#include "mm.h"
#include "_global.h"
#include <type_traits>

namespace mm
{
	void *allocate(size_t size)
	{
		return ExAllocatePool(NonPagedPool, size);
	}

	void free(void *pointer)
	{
		ExFreePool(pointer);
	}
}

void *operator new  (size_t size) { return mm::allocate(size); }
void *operator new[](size_t size) { return mm::allocate(size); }
void *operator new  (size_t size, std::align_val_t alignment) { return mm::allocate(size); }
void *operator new[](size_t size, std::align_val_t alignment) { return mm::allocate(size); }

void operator delete  (void *address) { mm::free(address); }
void operator delete[](void *address) { mm::free(address); }
void operator delete[](void *address, std::size_t) {mm::free(address); }
void operator delete  (void *address, std::size_t) { mm::free(address); }
void operator delete  (void *address, std::align_val_t) { mm::free(address); }
void operator delete[](void *address, std::align_val_t) {        mm::free(address);                     }
void operator delete[](void *address, std::size_t, std::align_val_t) {        mm::free(address);                     }
void operator delete  (void *address, std::size_t, std::align_val_t) { mm::free(address); }