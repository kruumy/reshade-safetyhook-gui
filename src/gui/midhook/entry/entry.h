#pragma once
#include "live.h"

namespace gui::midhook::entry
{
    inline void draw(midhook_wrapper& hook, size_t index)
    {
        ImGui::PushID(&hook);

        flash_row_background(std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::steady_clock::now() - hook.last_hit_time).count());

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
        if (ImGui::Button(hook.show_live_window ? "Close Live View" : "Open Live View"))
        {
            hook.show_live_window = !hook.show_live_window;
        }

        if (hook.show_live_window)
        {
            live::draw(hook);
        }

        ImGui::SameLine();
        ImGui::Text("Hits: %d", hook.hit_amount);

        ImGui::PopID();
    }
}