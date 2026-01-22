#include <map>
#include <windows.h>
#include <safetyhook.hpp>
#include <string>
#include <format>
#include <unordered_map>
#include "private_member_stealer.h"
#include <chrono>

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#elif SAFETYHOOK_ARCH_X86_32
#define IP_REG eip
#endif

struct MidHookInlineTag
{
	typedef safetyhook::InlineHook safetyhook::MidHook::* type;
};

template struct private_member_stealer<MidHookInlineTag, &safetyhook::MidHook::m_hook>;
safetyhook::InlineHook safetyhook::MidHook::* get_member(MidHookInlineTag);


class midhook_definition
{
public:
	std::chrono::steady_clock::time_point last_hit_time{};
	SafetyHookMid hook;

	midhook_definition(void* target_addr)
	{
		auto result = safetyhook::MidHook::create(target_addr, &trampoline, safetyhook::MidHook::Flags::StartDisabled);

		if (result)
		{
			hook = std::move(*result);
			auto& m_hook = hook.*get_member(MidHookInlineTag{});

			instance_registry[m_hook.trampoline().address()] = this;
		}
		else
		{
			reshade::log::message(reshade::log::level::error, std::format("Failed to create midhook at 0x{:X}", reinterpret_cast<uintptr_t>(hook.target())).c_str());
		}

		reshade::log::message(reshade::log::level::debug, std::format("Created midhook at: 0x{:X}", this->hook.target_address()).c_str());
	}

	~midhook_definition()
	{
		auto& m_hook = hook.*get_member(MidHookInlineTag{});
		uintptr_t tramp_addr = m_hook.trampoline().address();

		instance_registry.erase(tramp_addr);
		hook = {};

		reshade::log::message(reshade::log::level::debug, std::format("Removed midhook at: 0x{:X}", this->hook.target_address()).c_str());
	}
private:
	inline static std::unordered_map<uintptr_t, midhook_definition*> instance_registry;

	void destination(SafetyHookContext& ctx)
	{
		last_hit_time = std::chrono::steady_clock::now();

		reshade::log::message(reshade::log::level::debug, std::format("midhook destination called: 0x{:X}", this->hook.target_address()).c_str());
	}

	static void trampoline(SafetyHookContext& ctx)
	{
		if (instance_registry.contains(ctx.IP_REG))
		{
			midhook_definition* instance = instance_registry[ctx.IP_REG];
			instance->destination(ctx);
			return;
		}

		reshade::log::message(reshade::log::level::error, std::format("Could not find IP in registry: 0x{:X}", static_cast<uintptr_t>(ctx.IP_REG)).c_str());
	}
};