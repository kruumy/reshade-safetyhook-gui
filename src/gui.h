#pragma once
#include <imgui.h>
#include <reshade.hpp>
#include "hook_manager.h"
#include <string>

namespace gui
{
    

    void draw_hook(midhook_definition& hook, size_t index)
    {
        ImGui::PushID(&hook);
        if (ImGui::Button("X"))
        {
            hook.disable();
            hook_manager::hooks.erase(hook_manager::hooks.begin() + index);
            ImGui::PopID();
            return;
        }

        ImGui::SameLine();

        char address_text[32];
        sprintf_s(address_text, "0x%p", hook.target);
        ImGui::Text("%s", address_text);

        ImGui::SameLine();

        if (ImGui::Checkbox("Enabled", &hook.is_enabled))
        {
            if (hook.is_enabled)
            {
                hook.enable();
            }
            else
            {
                hook.disable();
            }
        }

        ImGui::Separator();
        ImGui::PopID();
    }

    void draw(reshade::api::effect_runtime* runtime)
    {
        static char add_address_buffer[32] = "";
        ImGui::InputText("Hex Address", add_address_buffer, sizeof(add_address_buffer));

        ImGui::SameLine();
        if (ImGui::Button("Add Hook"))
        {
            unsigned long long addr = 0;
            try 
            {
                addr = std::stoull(add_address_buffer, nullptr, 16);
            }
            catch (...) { }

            if (addr != 0)
            {
                auto new_hook = std::make_unique<midhook_definition>();
                new_hook->target = reinterpret_cast<void*>(addr);
                new_hook->is_enabled = false;

                hook_manager::hooks.push_back(std::move(new_hook));

                memset(add_address_buffer, 0, sizeof(add_address_buffer));
            }
        }

        for (size_t i = 0; i < hook_manager::hooks.size(); ++i)
        {
            draw_hook(*hook_manager::hooks[i], i);
        }
    }
}