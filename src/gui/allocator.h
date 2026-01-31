#pragma once
namespace gui::allocator
{
    namespace data_type
    {
        enum type
        {
            String,
            Int,
            Float
        };constexpr size_t AMOUNT_OF_TYPES = 3;

        constexpr std::string_view to_string(type _type)
        {
            switch (_type)
            {
            case type::String:  return "String";
            case type::Int:		return "Int";
            case type::Float:   return "Float";
            }
            std::unreachable();
        }
    }
    static inline std::vector<std::pair<data_type::type, safetyhook::Allocation>> allocations;

    bool draw_allocation_row(data_type::type type, safetyhook::Allocation& allocation, size_t index)
    {
        ImGui::PushID(&allocation);

        std::string_view type_str = data_type::to_string(type);
        ImGui::TextUnformatted(type_str.data());

        ImGui::SameLine();

        char addr_buf[32];
        snprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)allocation.address());
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(addr_buf).x + ImGui::GetStyle().FramePadding.x * 2.0f + 2.0f);
        ImGui::InputText("##address", addr_buf, sizeof(addr_buf), ImGuiInputTextFlags_ReadOnly | ImGuiInputTextFlags_CharsHexadecimal);

        ImGui::SameLine();
        if (allocation.data() == nullptr)
        {
            ImGui::TextUnformatted("Invalid allocation (null data)");
        }
        else
        {
            switch (type)
            {
            case data_type::String:
				ImGui::InputText("##", reinterpret_cast<char*>(allocation.data()), allocation.size());
                break;
            case data_type::Int:
				ImGui::InputInt("##", reinterpret_cast<int*>(allocation.data()));
                break;
            case data_type::Float:
				ImGui::InputFloat("##", reinterpret_cast<float*>(allocation.data()));
                break;
            default:
                ImGui::TextUnformatted("Unknown type");
                break;
            }
        }

        ImGui::SameLine();
        ImGui::Text("%zu bytes", allocation.size());

        ImGui::SameLine();

        if (ImGui::Button("Free"))
        {
            allocations.erase(allocations.begin() + index);
            ImGui::PopID();
            return false;
        }

        ImGui::PopID();
        return true;
    }

    void draw()
    {
        ImGui::PushID("allocator");

        static data_type::type current_type = data_type::type::String;
        ImGui::PushItemWidth(100);
        if (ImGui::BeginCombo("##type_combo", data_type::to_string(current_type).data()))
        {
            for (int i = 0; i < data_type::AMOUNT_OF_TYPES; ++i)
            {
                data_type::type candidate = static_cast<data_type::type>(i);
                bool is_selected = (candidate == current_type);
                if (ImGui::Selectable(data_type::to_string(candidate).data(), is_selected))
                {
                    current_type = candidate;
                }
                if (is_selected)
                {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }

        ImGui::PopItemWidth();

        static char string_buffer[256] = {};
        static int int_value = 0;
        static float float_value = 0.0f;
        ImGui::SameLine();
        switch (current_type)
        {
        case data_type::String:
            ImGui::InputText("##input", string_buffer, sizeof(string_buffer));
            break;
        case data_type::Int:
            ImGui::InputInt("##input", &int_value);
            break;
        case data_type::Float:
            ImGui::InputFloat("##input", &float_value);
            break;
        default:
            ImGui::TextUnformatted("Unknown type selected");
            break;
        }

        ImGui::SameLine();
        if (ImGui::Button("Allocate"))
        {
            size_t allocation_size = 0;
            void* allocation_ptr = nullptr;
            switch (current_type)
            {
            case data_type::String:
                allocation_size = strlen(string_buffer) + 1;
                allocation_ptr = static_cast<void*>(string_buffer);
                break;
            case data_type::Int:
                allocation_size = sizeof(int_value);
                allocation_ptr = static_cast<void*>(&int_value);
                break;
            case data_type::Float:
                allocation_size = sizeof(float_value);
                allocation_ptr = static_cast<void*>(&float_value);
                break;
            default:
                break;
            }

            if (allocation_ptr && allocation_size > 0)
            {
                auto allocation = safetyhook::Allocator::global()->allocate(allocation_size);
                if (allocation.has_value())
                {
                    memcpy(allocation.value().data(), allocation_ptr, allocation_size);
                    allocations.push_back({ current_type, std::move(allocation.value()) });
                    memset(allocation_ptr, 0, allocation_size);
                }
            }
        }

        for (size_t i = 0; i < allocations.size(); )
        {
            ImGui::Separator();
            if (draw_allocation_row(allocations[i].first, allocations[i].second, i))
            {
                ++i;
            }
        }

        ImGui::PopID();
    }
}

