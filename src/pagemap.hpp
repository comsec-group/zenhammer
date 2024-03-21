#include <cstdio>
#include <cstdlib>

#pragma once

class pagemap {
public:
    static uintptr_t virt_to_phys(void*);
};