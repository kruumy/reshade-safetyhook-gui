#pragma once
#include "imgui.h"
#include "live.hpp"

namespace gui::midhook
{
    inline bool draw_midhook_row(midhook_wrapper& hook, size_t index)
    {
        ImGui::PushID(hook.hook.target_address());

        gui::utils::flash_row_background(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - hook.last_hit_time)
                .count());

        if (ImGui::Button("X"))
        {
            midhook_wrapper::midhooks.erase(midhook_wrapper::midhooks.begin() + index);
            ImGui::PopID();
            return false;
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

        ImGui::SameLine();
        ImGui::Text("Hits: %d", hook.hit_count);

        if (hook.show_live_window)
        {
            live::draw(hook);
        }

        ImGui::PopID();
        return true;
    }

    inline void draw()
    {
        ImGui::PushID("midhook");

        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
        ImGui::TextWrapped("Mid hooks are a very flexible kind of hook that provides access to the CPU context at the "
                           "point in which the hook was hit. This gives direct register access to nearly any point "
                           "within a functions execution path.");
        ImGui::PopStyleColor();

        static char add_address_buffer[32] = "";
        ImGui::InputText("Hex Address", add_address_buffer, IM_ARRAYSIZE(add_address_buffer));

        ImGui::SameLine();
        if (ImGui::Button("+"))
        {
            unsigned long long addr = 0;
            try
            {
                addr = std::stoull(add_address_buffer, nullptr, 16);
            }
            catch (...)
            {
            }

            std::shared_ptr<midhook_wrapper> midhook = midhook_wrapper::create(reinterpret_cast<void*>(addr));
            if (midhook)
            {
                memset(add_address_buffer, 0, sizeof(add_address_buffer));
            }
            else
            {
                reshade::log::message(reshade::log::level::error,
                                      "Failed to create midhook. This address may already be hooked or is invalid.");
            }
        }

        for (size_t i = 0; i < midhook_wrapper::midhooks.size();)
        {
            midhook_wrapper::midhooks[i]->on_imgui_render();
            ImGui::Separator();
            if (draw_midhook_row(*midhook_wrapper::midhooks[i], i))
            {
                ++i;
            }
        }

        ImGui::PopID();
    }

} // namespace gui::midhook
