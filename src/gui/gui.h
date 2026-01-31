#pragma once
#include <imgui.h>
#include <reshade.hpp>
#include "utils.h"
#include "midhook_wrapper.h"
#include "midhook/midhook.h"
#include "allocator.h"

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
}