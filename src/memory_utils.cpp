#include "memory_utils.h"



bool memory_utils::is_executable_pointer(const void* ptr)
{
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);

    if (!looks_like_pointer(addr))
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;

    constexpr DWORD executable_flags =
        PAGE_EXECUTE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY;

    if ((mbi.Protect & executable_flags) == 0)
        return false;

    return true;
}

bool memory_utils::safe_read_string(uintptr_t addr, std::string& out, bool replace_line_endings)
{
    out.clear();
    out.reserve(MAX_STRING_LEN);

    if (!looks_like_pointer(addr))
        return false;

    __try
    {
        const char* p = reinterpret_cast<const char*>(addr);

        for (size_t i = 0; i < MAX_STRING_LEN; ++i)
        {
            char c = p[i];

            if (c == '\0')
                break;

            if (replace_line_endings && (c == '\n' || c == '\r')) {
                out.append(c == '\n' ? "\\n" : "\\r");
                continue;
            }

            if (std::isprint(static_cast<unsigned char>(c)))
            {
                out.push_back(c);
            }
            else
            {
                return false;
            }
        }

        return !out.empty();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}