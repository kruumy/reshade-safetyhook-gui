#pragma once
#include "allocator.hpp"
#include "midhook/midhook.hpp"
#include "midhook_wrapper.hpp"
#include "utils.hpp"
#include <imgui.h>
#include <reshade.hpp>

namespace gui
{
    void draw(reshade::api::effect_runtime* runtime)
    {

        ImGui::PushID("reshade-safetyhook-gui");

        if (ImGui::CollapsingHeader("Mid Hooks", ImGuiTreeNodeFlags_DefaultOpen))
        {
            midhook::draw();
        }

        if (ImGui::CollapsingHeader("Allocator", ImGuiTreeNodeFlags_DefaultOpen))
        {
            allocator::draw();
        }

        ImGui::PopID();
    }
} // namespace gui