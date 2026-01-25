#pragma once
#include "memory_utils.h"

namespace gui::midhook::entry::live
{
    void draw_analysis(const memory_utils::pointer_analysis_report& report)
    {
        if (!report.is_valid_ptr)
        {
            return;
        }

        ImGui::PushID("analysis");

        std::stringstream ss;

        ss << " -> 0x" << std::hex << *reinterpret_cast<int*>(report.pointer) << " | ";

        if (report.as_float)
            ss << "float(" << *report.as_float << ") ";
        if (report.as_double)
            ss << "double(" << *report.as_double << ") ";
        if (!report.as_string.empty())
            ss << "string(" << report.as_string << ") ";

        ImGui::SameLine();
        ImGui::Text("%s", ss.str().c_str());

        ImGui::PopID();
    }

    void draw_register(const std::string& name, uintptr_t reg, const memory_utils::pointer_analysis_report* report)
    {
        ImGui::PushID(name.c_str());

        ImGui::Text((name + ": ").c_str());
        
        std::string hex_str = std::format("0x{:0{}X}", reg, sizeof(uintptr_t) * 2);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, ImGuiInputTextFlags_ReadOnly);

        if (report)
        {
            draw_analysis(*report);
        }

        ImGui::PopID();
    }

	void draw(midhook_wrapper& hook)
	{
        ImGui::SetNextWindowSize(ImVec2(0, 0), ImGuiCond_FirstUseEver);
		if (ImGui::Begin(std::format("Live 0x{:X} View", (uintptr_t)hook.hook.target_address()).c_str(), &hook.show_live_window, ImGuiWindowFlags_AlwaysAutoResize))
		{
            auto& ctx = hook.last_context;

#if SAFETYHOOK_ARCH_X86_64
            draw_register("RAX", ctx.rax);
            draw_register("RBX", ctx.rbx);
            draw_register("RCX", ctx.rcx);
            draw_register("RDX", ctx.rdx);
            draw_register("RSI", ctx.rsi);
            draw_register("RDI", ctx.rdi);
            draw_register("RBP", ctx.rbp);
            draw_register("RSP", ctx.rsp);
            draw_register("R8", ctx.r8);
            draw_register("R9", ctx.r9);
            draw_register("R10", ctx.r10);
            draw_register("R11", ctx.r11);
            draw_register("R12", ctx.r12);
            draw_register("R13", ctx.r13);
            draw_register("R14", ctx.r14);
            draw_register("R15", ctx.r15);
            draw_register("RIP", ctx.rip);
#else
            draw_register("EAX", ctx.ctx.eax, &ctx.eax_report);
            draw_register("EBX", ctx.ctx.ebx, &ctx.ebx_report);
            draw_register("ECX", ctx.ctx.ecx, &ctx.ecx_report);
            draw_register("EDX", ctx.ctx.edx, &ctx.edx_report);
            draw_register("ESI", ctx.ctx.esi, &ctx.esi_report);
            draw_register("EDI", ctx.ctx.edi, &ctx.edi_report);
            draw_register("EBP", ctx.ctx.ebp, &ctx.ebp_report);
            draw_register("ESP", ctx.ctx.esp, &ctx.esp_report);
            draw_register("EIP", ctx.ctx.eip, nullptr);
#endif
		}
		ImGui::End();
	}
}

