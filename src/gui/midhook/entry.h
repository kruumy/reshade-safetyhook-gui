#pragma once
#include "log.h"

namespace gui::midhook::entry
{
    inline void draw(midhook_wrapper& hook, size_t index)
    {
        ImGui::PushID(&hook);

        auto ms_since_hit =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - hook.last_hit_time).count();

        if (ms_since_hit < 1000)
        {
            float t = 1.0f - (float(ms_since_hit) / 1000.0f);

            ImU32 col = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 1.0f, 0.0f, t * 0.3f));
            ImVec2 p0 = ImGui::GetCursorScreenPos();
            ImVec2 p1 =
            {
                p0.x + ImGui::GetContentRegionAvail().x,
                p0.y + ImGui::GetFrameHeightWithSpacing()
            };

            ImGui::GetWindowDrawList()->AddRectFilled(p0, p1, col);
        }

        if (ImGui::Button("X"))
        {
            midhook_wrapper::midhooks.erase(midhook_wrapper::midhooks.begin() + index);
            ImGui::PopID();
            return;
        }

        ImGui::SameLine();
        ImGui::Text("0x%p", hook.hook.target());

        ImGui::SameLine();

        bool enabled = hook.hook.enabled();
        if (ImGui::Checkbox("Enabled", &enabled))
        {
            enabled ? hook.hook.enable() : hook.hook.disable();
        }

        ImGui::SameLine();

        if (ImGui::Button(hook.show_log_window ? "Close History" : "Open History"))
        {
            hook.show_log_window = !hook.show_log_window;
        }

        if (hook.show_log_window)
        {
            log::draw(hook);
        }

        ImGui::SameLine();
        ImGui::Text("Hits: %d", hook.hit_amount);

        ImGui::PopID();
    }
}