#pragma once
#include <optional>
#include <string>

namespace pointer_analysis
{
    struct report
    {
        bool is_readable_ptr = false;
        std::optional<uintptr_t> as_uintptr;
        std::optional<float> as_float;
        std::optional<double> as_double;
        std::string as_string;
        // TODO  as_vec3, as_vec2
    };

    report analyze_pointer(uintptr_t addr);
}