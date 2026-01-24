#pragma once

namespace gui::midhook::entry::live
{
    void draw_register(const std::string& name, uintptr_t reg)
    {
        ImGui::PushID(name.c_str());

        ImGui::Text((name + ": ").c_str());
        
        std::string hex_str = std::format("0x{:0{}X}", reg, sizeof(uintptr_t) * 2);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, ImGuiInputTextFlags_ReadOnly);

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
            draw_register("EAX", ctx.eax);
            draw_register("EBX", ctx.ebx);
            draw_register("ECX", ctx.ecx);
            draw_register("EDX", ctx.edx);
            draw_register("ESI", ctx.esi);
            draw_register("EDI", ctx.edi);
            draw_register("EBP", ctx.ebp);
            draw_register("ESP", ctx.esp);
            draw_register("EIP", ctx.eip);
#endif
		}
		ImGui::End();
	}
}

