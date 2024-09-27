#include "Hook.h"
#include <unordered_map>
#include <memory>
#include <cstdint>

namespace Hook
{
    struct Hook_t
    {
        void Apply()
        {
            if (!m_Applied)
            {
                if (m_Hook->IsDetour())
                    m_Original = m_Hook->Apply(m_NewFunc);
                else
                    m_Original = m_Hook->Apply(m_Index, m_NewFunc);

                m_Applied = true;
            }
        }

        template<typename Fn>
        Fn GetOriginal() volatile
        {
            return reinterpret_cast<Fn>(m_Original);
        }

        Hook_t() = default;

        Hook_t(const uintptr_t NewFunc, const uintptr_t Original)
            : m_Original(Original), m_NewFunc(NewFunc), m_Index(0), m_Applied(false)
        {
            m_Hook = std::make_shared<CDetour>(Original);
        }

        Hook_t(const uintptr_t NewFunc, const uint32_t Index, const uintptr_t Ent)
            : m_NewFunc(NewFunc), m_Index(Index), m_Applied(false)
        {
            m_Hook = std::make_shared<CVTableHook>(Ent);
        }

        std::shared_ptr<CHook> m_Hook;
        uintptr_t m_Original{};
        uintptr_t m_NewFunc;
        uint32_t m_Index;
        bool m_Applied;
    };

    inline std::unordered_map<uintptr_t, Hook_t> HookList;

    inline void AddHook(uintptr_t TargetFunc, uintptr_t NewFunc, bool IsVTable = false, uint32_t Index = 0, uintptr_t Ent = 0)
    {
        auto it = HookList.find(TargetFunc);

        if (it == HookList.end())
        {
            if (IsVTable)
                HookList[TargetFunc] = Hook_t(NewFunc, Index, Ent);
            else
                HookList[TargetFunc] = Hook_t(NewFunc, TargetFunc);
        }
    }

    inline void RemoveHook(uintptr_t TargetFunc)
    {
        auto it = HookList.find(TargetFunc);

        if (it != HookList.end())
            HookList.erase(it);
    }

    inline void ApplyHooks()
    {
        for (auto& [TargetFunc, CurHook] : HookList)
            CurHook.Apply();
    }
}