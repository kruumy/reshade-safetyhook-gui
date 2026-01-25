#include "ContextEx.h"
#include "memory_utils.h"
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <limits>
#include <cctype>
#include <windows.h>

namespace safetyhook
{
    static void log_pointer_analysis(std::ostringstream& ss, const memory_utils::pointer_analysis_report& report, uintptr_t report_addr)
    {
        if (!report.is_valid_ptr)
        {
            return;
        }

        ss << " -> 0x" << std::hex << *reinterpret_cast<int*>(report_addr) << " | ";

        if (report.as_float)
        {
            ss << "float(" << *report.as_float << ") ";
        }
        if (report.as_double)
        {
            ss << "double(" << *report.as_double << ") ";
        }
        if (!report.as_string.empty())
        {
            ss << "string(" << report.as_string << ") ";
        }
    }

    static void log_reg(std::ostringstream& ss, const char* name, uintptr_t v)
    {
        ss << std::left << std::setw(6) << name
            << " = 0x"
            << std::hex
            << std::setw(sizeof(uintptr_t) * 2)
            << std::setfill('0')
            << v
            << std::setfill(' ');

        auto analysis_report = memory_utils::analyze_pointer(v);
        log_pointer_analysis(ss, analysis_report, v);
        ss << "\n";
    }

    static void log_xmm(std::ostringstream& ss, const char* name, const Xmm& x)
    {
        ss << std::left << std::setw(6) << name << " = ";

        ss << "hex(";
        for (int i = 15; i >= 0; --i)
        {
            ss << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(x.u8[i]);
        }
        ss << std::setfill(' ') << ") ";

        ss << "f32[";
        for (int i = 0; i < 4; ++i)
        {
            ss << x.f32[i];
            if (i != 3)
                ss << ", ";
        }
        ss << "] ";

        ss << "f64[" << x.f64[0] << ", " << x.f64[1] << "]";
        ss << "\n";
    }

    std::string ContextEx::to_string() const
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase;

#if SAFETYHOOK_ARCH_X86_64
        log_reg(ss, "RAX", rax); log_reg(ss, "RBX", rbx);
        log_reg(ss, "RCX", rcx); log_reg(ss, "RDX", rdx);
        log_reg(ss, "RSI", rsi); log_reg(ss, "RDI", rdi);
        log_reg(ss, "RBP", rbp); log_reg(ss, "RSP", rsp);
        log_reg(ss, "R8", r8);   log_reg(ss, "R9", r9);
        log_reg(ss, "R10", r10); log_reg(ss, "R11", r11);
        log_reg(ss, "R12", r12); log_reg(ss, "R13", r13);
        log_reg(ss, "R14", r14); log_reg(ss, "R15", r15);
        log_reg(ss, "RIP", rip);
        log_reg(ss, "RFL", rflags);

        log_xmm(ss, "XMM0", xmm0);   log_xmm(ss, "XMM1", xmm1);
        log_xmm(ss, "XMM2", xmm2);   log_xmm(ss, "XMM3", xmm3);
        log_xmm(ss, "XMM4", xmm4);   log_xmm(ss, "XMM5", xmm5);
        log_xmm(ss, "XMM6", xmm6);   log_xmm(ss, "XMM7", xmm7);
        log_xmm(ss, "XMM8", xmm8);   log_xmm(ss, "XMM9", xmm9);
        log_xmm(ss, "XMM10", xmm10); log_xmm(ss, "XMM11", xmm11);
        log_xmm(ss, "XMM12", xmm12); log_xmm(ss, "XMM13", xmm13);
        log_xmm(ss, "XMM14", xmm14); log_xmm(ss, "XMM15", xmm15);
#else
        log_reg(ss, "EAX", eax); log_reg(ss, "EBX", ebx);
        log_reg(ss, "ECX", ecx); log_reg(ss, "EDX", edx);
        log_reg(ss, "ESI", esi); log_reg(ss, "EDI", edi);
        log_reg(ss, "EBP", ebp); log_reg(ss, "ESP", esp);
        log_reg(ss, "EIP", eip);
        log_reg(ss, "EFL", eflags);

        log_xmm(ss, "XMM0", xmm0); log_xmm(ss, "XMM1", xmm1);
        log_xmm(ss, "XMM2", xmm2); log_xmm(ss, "XMM3", xmm3);
        log_xmm(ss, "XMM4", xmm4); log_xmm(ss, "XMM5", xmm5);
        log_xmm(ss, "XMM6", xmm6); log_xmm(ss, "XMM7", xmm7);
#endif

        return ss.str();
    }
}
