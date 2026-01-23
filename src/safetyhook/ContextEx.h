#pragma once

#include <cstdint>
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>
#include <safetyhook.hpp>

namespace safetyhook
{
    struct ContextEx : safetyhook::Context
    {
        std::string to_string() const
        {
            std::stringstream ss;
            ss << std::hex << std::uppercase;

            auto log_reg = [&](const char* name, uintptr_t value) 
                {
                    ss << name << ": 0x" << value << "\n";
                };

#if SAFETYHOOK_ARCH_X86_64
            log_reg("RAX", this->rax); log_reg("RBX", this->rbx);
            log_reg("RCX", this->rcx); log_reg("RDX", this->rdx);
            log_reg("RSI", this->rsi); log_reg("RDI", this->rdi);
            log_reg("RBP", this->rbp); log_reg("RSP", this->rsp);
#else
            log_reg("EAX", this->eax); log_reg("EBX", this->ebx);
            log_reg("ECX", this->ecx); log_reg("EDX", this->edx);
            log_reg("EBP", this->ebp); log_reg("ESP", this->esp);
#endif
            return ss.str();
        }
    };
}
