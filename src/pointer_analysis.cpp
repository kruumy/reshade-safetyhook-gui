#include "pointer_analysis.h"
#include "memory_utils.h"

pointer_analysis::report pointer_analysis::analyze_pointer(uintptr_t addr)
{
    pointer_analysis::report result{};
    result.is_readable_ptr = memory_utils::is_readable_pointer(addr);

    if (!result.is_readable_ptr)
        return result;

    uintptr_t target = 0;
    if (memory_utils::safe_read(addr, target))
    {
        result.as_uintptr = target;
    }
    {
        alignas(4) float f{};
        if ((addr & 3) == 0 && memory_utils::safe_read(addr, f))
            result.as_float = f;
    }
    {
        alignas(8) double d{};
        if ((addr & 7) == 0 && memory_utils::safe_read(addr, d))
            result.as_double = d;
    }
    memory_utils::safe_read_string(addr, result.as_string);

    return result;
}