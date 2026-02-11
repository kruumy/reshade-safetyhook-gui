#pragma once
#include <format>
#include <imgui.h>
#include <inttypes.h>
#include <reshade.hpp>
#include <safetyhook.hpp>
#include <sstream>
#include <string>

namespace gui::utils
{
    static inline void flash_row_background(long ms_since_hit, int length_ms = 1000)
    {
        if (ms_since_hit < 1000)
        {
            float t = 1.0f - (float(ms_since_hit) / length_ms);

            ImU32 col = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 1.0f, 0.0f, t * 0.3f));
            ImVec2 p0 = ImGui::GetCursorScreenPos();
            ImVec2 p1 = {p0.x + ImGui::GetContentRegionAvail().x, p0.y + ImGui::GetFrameHeightWithSpacing()};

            ImGui::GetWindowDrawList()->AddRectFilled(p0, p1, col);
        }
    }

    static inline void InputHex(uintptr_t& value)
    {
        std::string hex_str = std::format("0x{:0{}X}", value, sizeof(uintptr_t) * 2);
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::InputText("##input_hex", hex_str.data(), hex_str.capacity() + 1))
        {
            unsigned long long addr = 0;
            try
            {
                addr = std::stoull(hex_str, nullptr, 16);
            }
            catch (...)
            {
            }
            value = addr;
        }
    }

    static inline void InputHex(safetyhook::Xmm& xmm)
    {
        char hex_buffer[sizeof(safetyhook::Xmm) * 2 + 1 /*null term*/] = {0x0};
        std::snprintf(hex_buffer, sizeof(hex_buffer), "%016" PRIX64 "%016" PRIX64, xmm.u64[0], xmm.u64[1]);
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_buffer).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::InputText("##xmm_bytes", hex_buffer, sizeof(hex_buffer),
                             ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase))
        {
            std::istringstream iss(hex_buffer);
            std::string token;
            size_t idx = 0;
            while (iss >> token && idx < 2)
            {
                try
                {
                    uint64_t val = std::stoull(token, nullptr, 16);
                    xmm.u64[idx++] = val;
                }
                catch (...)
                {
                }
            }
        }
    }

} // namespace gui::utils