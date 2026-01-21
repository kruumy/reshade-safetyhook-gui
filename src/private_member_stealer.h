#pragma once

template <typename Tag, typename Tag::type M>
struct private_member_stealer
{
    friend typename Tag::type get_member(Tag)
    {
        return M;
    }
};