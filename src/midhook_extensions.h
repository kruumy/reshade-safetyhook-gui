#pragma once
#include <safetyhook.hpp>

namespace midhook_extensions
{
    struct MidHookInlineTag
    {
        using type = safetyhook::InlineHook safetyhook::MidHook::*;
    };
    template <typename Tag, typename Tag::type M>
    struct private_member_stealer
    {
        friend typename Tag::type get_member(Tag)
        {
            return M;
        }
    };

    template struct private_member_stealer<MidHookInlineTag, &safetyhook::MidHook::m_hook>;

    safetyhook::InlineHook safetyhook::MidHook::* get_member(MidHookInlineTag);

    inline const safetyhook::InlineHook& get_internal_hook(const safetyhook::MidHook& hook)
    {
        return hook.*get_member(MidHookInlineTag{});
    }

    inline const safetyhook::Allocation& get_trampoline(const safetyhook::MidHook& hook)
    {
        return get_internal_hook(hook).trampoline();
    }
}