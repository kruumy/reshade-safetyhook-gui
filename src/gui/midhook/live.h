#pragma once
#include "memory_utils.h"
#include <inttypes.h>

namespace gui::midhook::live
{
    void draw_analysis(const pointer_analysis::report& report)
    {
        if (!report.is_readable_ptr())
        {
            return;
        }

        ImGui::PushID("ptr_analysis");

        std::stringstream ss;
        ss << std::hex << std::uppercase;

        ss << " -> ";
        ss << "0x" << report.as_uintptr.value() << "  "; // no need to check has_value as is_readable_ptr() does

        if (report.as_float.has_value())
        {
            ss << "float(" << report.as_float.value() << ") ";
        }

        if (report.as_double.has_value())
        {
            ss << "double(" << report.as_double.value() << ") ";
        }

        if (!report.as_string.empty())
        {
            ss << "string(" << report.as_string << ") ";
        }

        ImGui::SameLine();
        ImGui::Text("%s", ss.str().c_str());

        ImGui::PopID();
    }

    void draw_control_register(const std::string& name, midhook_wrapper::control_register_definition& reg, bool is_hook_enabled)
    {
        ImGui::PushID(name.c_str());

        ImGui::Text((name + ": ").c_str());

        ImGui::BeginDisabled(!reg.do_override);

        std::string hex_str = std::format("0x{:0{}X}", reg.do_override ? reg.override_value : reg.value, sizeof(void*) * 2);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, reg.do_override ? 0 : ImGuiInputTextFlags_ReadOnly);

        ImGui::EndDisabled();
        if (reg.do_override)
        {
            unsigned long long addr = 0;
            try
            {
                addr = std::stoull(hex_str, nullptr, 16);
            }
            catch (...) {}
            reg.override_value = addr;
        }

        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        {
            ImGui::BeginTooltip();
            ImGui::Text("dec: %llu", static_cast<unsigned long long>(reg.value));
            ImGui::EndTooltip();
        }

        ImGui::BeginDisabled(is_hook_enabled && !reg.do_override);
        ImGui::SameLine();
        ImGui::Checkbox("Override", &reg.do_override);
        ImGui::EndDisabled();

        ImGui::PopID();
    }

    void draw_register(const std::string& name, midhook_wrapper::offset_register_definition& reg, bool is_hook_enabled)
    {
        draw_control_register(name, reg, is_hook_enabled);
        ImGui::PushID(name.c_str());
        draw_analysis(reg.report);
		ImGui::PopID();
    }

    bool draw_offset(const std::string& name, bool is_hook_enabled, size_t i, std::vector<std::pair<int, midhook_wrapper::offset_register_definition>>& offset_definitions)
    {
        ImGui::PushID(static_cast<int>(i));
        auto& reg = offset_definitions[i];

        if (ImGui::Button("-"))
        {
            offset_definitions.erase(offset_definitions.begin() + i);
            ImGui::PopID();
            return false;
        }

        ImGui::SameLine();
        ImGui::Text((name + " +").c_str());

        ImGui::SameLine();
        ImGui::SetNextItemWidth(75);
        ImGui::InputInt(("##offset_" + name + "_" + std::to_string(i)).c_str(), &reg.first, 1, sizeof(void*),
            (is_hook_enabled && reg.second.do_override) ? ImGuiInputTextFlags_ReadOnly : 0);

        ImGui::SameLine();
        ImGui::Text(": ");

        ImGui::SameLine();
        ImGui::Text("%s", std::format("0x{:0{}X}", reg.second.value, sizeof(void*) * 2).c_str());

        if (reg.second.report.as_uintptr.has_value())
        {
            ImGui::SameLine();
            ImGui::Text(" -> ");

            ImGui::BeginDisabled(!reg.second.do_override);
            std::string hex_str = std::format("0x{:0{}X}", reg.second.do_override ? reg.second.override_value : reg.second.report.as_uintptr.value(), sizeof(void*) * 2);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
            ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, reg.second.do_override ? 0 : ImGuiInputTextFlags_ReadOnly);
            ImGui::EndDisabled();

            if (reg.second.do_override)
            {
                unsigned long long addr = 0;
                try
                {
                    addr = std::stoull(hex_str, nullptr, 16);
                }
                catch (...) {}
                reg.second.override_value = addr;
            }

            ImGui::BeginDisabled(is_hook_enabled && !reg.second.do_override);
            ImGui::SameLine();
            ImGui::Checkbox("Override", &reg.second.do_override);
            ImGui::EndDisabled();
        }

        draw_analysis(reg.second.report);

        ImGui::PopID();
        return true;
    }

    void draw_offsets(const std::string& name, midhook_wrapper::general_purpose_register_definition& reg, bool is_hook_enabled)
    {
        constexpr float INDENT = 32.0f;

        ImGui::PushID(name.c_str());
        ImGui::Indent(INDENT);

        for (size_t i = 0; i < reg.offset_definitions.size();)
        {
            
            if (draw_offset(name, is_hook_enabled, i, reg.offset_definitions))
            {
                ++i;
            }
        }

        if (ImGui::Button("+"))
        {
            reg.offset_definitions.emplace_back(
                static_cast<int>(sizeof(void*)),
                midhook_wrapper::offset_register_definition{}
            );
        }

        ImGui::Unindent(INDENT);
        ImGui::PopID();
    }

    void draw_register_and_offsets(const std::string& name, midhook_wrapper::general_purpose_register_definition& reg, bool is_hook_enabled)
    {
        ImGui::Separator();
        draw_register(name, reg, is_hook_enabled);
        draw_offsets(name, reg, is_hook_enabled);
    }

    void draw_xmm_register(const int reg_num, midhook_wrapper::xmm_register_definition& reg, bool is_hook_enabled)
    {
        ImGui::PushID(std::format("XMM{}", reg_num).c_str());

        std::string label = std::format("XMM{}: ", reg_num);
        ImGui::Text(label.c_str());

        ImGui::BeginDisabled(!reg.do_override);
		
        size_t xmm_raw_byte_width = ImGui::CalcTextSize("FFFFFFFFFFFFFFFF  FFFFFFFFFFFFFFFF").x;
        ImGui::SameLine();
        ImGui::SetNextItemWidth(xmm_raw_byte_width);
        safetyhook::Xmm* xmm = reg.do_override ? &reg.override_value : &reg.value;
        char hex_buffer[sizeof(safetyhook::Xmm) * 2 + 1/*space*/ + 1/*null term*/] = {0};
        std::snprintf(hex_buffer, sizeof(hex_buffer), "%016" PRIX64 " %016" PRIX64, xmm->u64[0], xmm->u64[1]);
        if (ImGui::InputText("##xmm_bytes", hex_buffer, sizeof(hex_buffer), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase))
        {
            std::istringstream iss(hex_buffer);
            std::string token;
            size_t idx = 0;
            while (iss >> token && idx < 2) 
            {
                try 
                {
                    uint64_t val = std::stoull(token, nullptr, 16);
                    xmm->u64[idx++] = val;
                }
                catch (...) {}
            }
        }

		ImGui::Indent(ImGui::CalcTextSize(label.c_str()).x);
		ImGui::Dummy(ImVec2(0.0f, 0.0f));

        auto draw_float = [&](size_t i) 
        {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(xmm_raw_byte_width / static_cast<float>(4));
            ImGui::DragFloat(("##f" + std::to_string(i)).c_str(), &((reg.do_override ? reg.override_value : reg.value).f32[i]), 1.0f, 0.0f, 0.0f, "%.3f");
        };
        draw_float(1); draw_float(0); draw_float(3); draw_float(2);

        ImGui::Dummy(ImVec2(0.0f, 0.0f));
        for (size_t i = 0; i < 2; i++)
        {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(xmm_raw_byte_width / static_cast<float>(2));
            ImGui::InputDouble(("##d" + std::to_string(i)).c_str(), &((reg.do_override ? reg.override_value : reg.value).f64[i]), 1.0, 10.0, "%.6f");
		}
        ImGui::Unindent(ImGui::CalcTextSize(label.c_str()).x);

        ImGui::EndDisabled();

        ImGui::BeginDisabled(is_hook_enabled && !reg.do_override);
        ImGui::SameLine();
        ImGui::Checkbox("Override", &reg.do_override);
        ImGui::EndDisabled();

        ImGui::PopID();
    }

	void draw(midhook_wrapper& hook)
	{
        ImGui::SetNextWindowSize(ImVec2(0, 0), ImGuiCond_FirstUseEver);
		if (ImGui::Begin(std::format("Live 0x{:X} View", hook.hook.target_address()).c_str(), &hook.show_live_window, ImGuiWindowFlags_AlwaysAutoResize))
		{
            flash_row_background(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - hook.last_hit_time).count());

            bool enabled = hook.hook.enabled();
            if (ImGui::Checkbox("Enabled", &enabled))
            {
                enabled ? hook.hook.enable() : hook.hook.disable();
            }

            ImGui::BeginDisabled(hook.hook.enabled());
            ImGui::SameLine();
            if (ImGui::Button("Set Trampoline to next RET"))
            {
                if (auto ret_location = memory_utils::find_next_mnemonic(hook.hook.target_address(), ZYDIS_MNEMONIC_RET))
                {
                    hook.live_control_context[midhook_wrapper::control_register::EIP].override_value = ret_location;
                    hook.live_control_context[midhook_wrapper::control_register::EIP].do_override = true;
                }
                else
                {
                    reshade::log::message(reshade::log::level::error, "Could not find next ret instruction");
                }
            }
            ImGui::EndDisabled();

            ImGui::SameLine();
            ImGui::Text("Hits: %d", hook.hit_amount);

#if SAFETYHOOK_ARCH_X86_32
            draw_register_and_offsets("EAX", hook.live_context[midhook_wrapper::general_purpose_register::EAX], hook.hook.enabled());
            draw_register_and_offsets("ECX", hook.live_context[midhook_wrapper::general_purpose_register::ECX], hook.hook.enabled());
            draw_register_and_offsets("EDX", hook.live_context[midhook_wrapper::general_purpose_register::EDX], hook.hook.enabled());
            draw_register_and_offsets("EBX", hook.live_context[midhook_wrapper::general_purpose_register::EBX], hook.hook.enabled());
            draw_register_and_offsets("ESI", hook.live_context[midhook_wrapper::general_purpose_register::ESI], hook.hook.enabled());
            draw_register_and_offsets("EDI", hook.live_context[midhook_wrapper::general_purpose_register::EDI], hook.hook.enabled());
            draw_register_and_offsets("EBP", hook.live_context[midhook_wrapper::general_purpose_register::EBP], hook.hook.enabled());
            draw_register_and_offsets("ESP", hook.live_context[midhook_wrapper::general_purpose_register::ESP], hook.hook.enabled());
            draw_control_register("EIP", hook.live_control_context[midhook_wrapper::control_register::EIP], hook.hook.enabled());
            draw_control_register("EFLAGS", hook.live_control_context[midhook_wrapper::control_register::EFLAGS], hook.hook.enabled());
#elif SAFETYHOOK_ARCH_X86_64
            // TODO
#endif
            ImGui::Separator();
            if (ImGui::BeginTable("xmm_registers", 2))
            {
                for (size_t i = 0; i < hook.live_xmm_context.size(); i += 2)
                {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    draw_xmm_register(i, hook.live_xmm_context[i], hook.hook.enabled());
                    if (i + 1 < hook.live_xmm_context.size())
                    {
                        ImGui::TableSetColumnIndex(1);
                        draw_xmm_register(i + 1, hook.live_xmm_context[i + 1], hook.hook.enabled());
                    }
                }
                ImGui::EndTable();
            }
		}
		ImGui::End();
	}
}

