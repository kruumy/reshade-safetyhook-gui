#include "pointer_analysis.h"
#include "memory_utils.h"

pointer_analysis::report pointer_analysis::analyze_pointer(uintptr_t addr)
{
    pointer_analysis::report r{};

    uintptr_t target;
    if (!memory_utils::safe_read(addr, target))
    {
        return r;
    }

    r.as_uintptr.emplace(target);

    if ((addr & 3) == 0)
    {
        alignas(4) float f;
        if (memory_utils::safe_read(addr, f))
        {
            r.as_float.emplace(f);
        }
    }

    if ((addr & 7) == 0)
    {
        alignas(8) double d;
        if (memory_utils::safe_read(addr, d))
        {
            r.as_double.emplace(d);
        }
    }

    memory_utils::safe_read_string(addr, r.as_string);

    return r;
}
