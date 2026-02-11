#pragma once
#include <optional>
#include <string>

namespace pointer_analysis
{
    struct report
    {
        std::optional<uintptr_t> as_uintptr;
        std::optional<float> as_float;
        std::optional<double> as_double;
        std::string as_string;
        inline bool is_readable_ptr() const
        {
            return as_uintptr.has_value();
        }
    };

    report analyze_pointer(uintptr_t addr);
} // namespace pointer_analysis