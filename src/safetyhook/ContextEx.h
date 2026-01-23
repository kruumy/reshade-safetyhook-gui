#pragma once
#include <string>
#include <safetyhook.hpp>

namespace safetyhook
{

    struct ContextEx : Context
    {
    public:
        std::string to_string() const;
    };

}
