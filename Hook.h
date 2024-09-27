#include <cstdint>
#include <vector>
#include <memory>
#include <cstring>
#include <windows.h>
#include "LDisASM.h"

class CHook
{
public:
	virtual uintptr_t Apply(uintptr_t Dest) { return 0; }
	virtual uintptr_t Apply(const uint32_t Index, uintptr_t Func) { return 0; }
	virtual bool IsDetour() { return false; }
	virtual ~CHook() {}
};

class CDetour : public CHook
{
	void* m_Original = nullptr;
	std::vector<std::uint8_t> m_OriginalBytes;
	std::uint8_t* m_Src{};

public:
	CDetour() = default;
	__forceinline CDetour(uintptr_t Ent) : m_Src(reinterpret_cast<std::uint8_t*>(Ent)) {}

	~CDetour() override
	{
		DWORD OldProtect;
		VirtualProtect(m_Src, m_OriginalBytes.size(), PAGE_EXECUTE_READWRITE, &OldProtect);
		memcpy(m_Src, m_OriginalBytes.data(), m_OriginalBytes.size());
		VirtualProtect(m_Src, m_OriginalBytes.size(), OldProtect, &OldProtect);

		if (m_Original)
			VirtualFree(m_Original, 0, MEM_RELEASE);
	}

	__forceinline bool IsDetour() override { return true; }

	__forceinline uintptr_t Apply(uintptr_t Dest) override
	{
		auto Add = 0;
		DWORD Len = 0;
		auto Opcode = m_Src;

		while (Opcode - m_Src < 5)
		{
			if (*Opcode == 0xE8)
				Add = Len + 1;
			if (*Opcode == 0x3B)
				Len += 2;
			else if (*Opcode == 0x66)
				Len += 5;
			else
				// x86 mode
				Len += LDisASM(Opcode, false);

			Opcode = m_Src + Len;
		}

		const auto OpCode = std::make_unique<std::uint8_t[]>(Len + 5);
		auto ReturnMem = VirtualAlloc(nullptr, Len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		for (std::uint32_t I = 0; I < Len; I++)
			OpCode[I] = m_Src[I];

		OpCode[Len] = 0xE9;
		*reinterpret_cast<std::uint32_t*>(OpCode.get() + Len + 1) = reinterpret_cast<std::uint32_t>(m_Src) - (reinterpret_cast<std::uint32_t>(ReturnMem) + 5);

		std::memcpy(ReturnMem, OpCode.get(), Len + 5);

		if (Add)
		{
			*reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uint32_t>(ReturnMem) + Add) -= reinterpret_cast<uintptr_t>(ReturnMem);
			*reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uint32_t>(ReturnMem) + Add) += reinterpret_cast<uintptr_t>(m_Src);
		}

		DWORD OldProtect;
		VirtualProtect(m_Src, Len, PAGE_EXECUTE_READWRITE, &OldProtect);

		*m_Src = 0xE9;
		*reinterpret_cast<std::uint32_t*>(m_Src + 1) = (uintptr_t)(Dest)-reinterpret_cast<std::uint32_t>(m_Src) - 5;
		for (std::uint32_t I = 5; I < Len; ++I)
			m_Src[I] = 0x90;

		VirtualProtect(m_Src, Len, OldProtect, &OldProtect);

		return reinterpret_cast<uintptr_t>(m_Original = ReturnMem);
	}
};

class CVTableHook : public CHook
{
public:
	explicit CVTableHook(uintptr_t Ent)
	{
		m_Base = reinterpret_cast<uintptr_t*>(Ent);
		m_Original = *m_Base;

		const auto L = Length() + 1;
		m_Current = std::make_unique<uint32_t[]>(L);
		std::memcpy(m_Current.get(), reinterpret_cast<void*>(m_Original - sizeof(uint32_t)), L * sizeof(uint32_t));

		PatchPointer(m_Base);
	}

	~CVTableHook() override
	{
		DWORD OldProtect;
		VirtualProtect(m_Base, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &OldProtect);

		*m_Base = m_Original;
		VirtualProtect(m_Base, sizeof(uintptr_t), OldProtect, &OldProtect);
	}

	__forceinline uintptr_t Apply(const uint32_t Index, uintptr_t Func) override
	{
		auto Old = reinterpret_cast<uintptr_t*>(m_Original)[Index];
		m_Current.get()[Index + 1] = Func;
		return Old;
	}

	void PatchPointer(uintptr_t* Location) const
	{
		if (!Location)
			return;

		DWORD OldProtect;
		VirtualProtect(Location, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &OldProtect);
		*Location = reinterpret_cast<uint32_t>(m_Current.get()) + sizeof(uint32_t);
		VirtualProtect(Location, sizeof(uintptr_t), OldProtect, &OldProtect);
	}

private:
	uint32_t Length() const
	{
		uint32_t Index;
		const auto Vmt = reinterpret_cast<uint32_t*>(m_Original);

		for (Index = 0; Vmt[Index]; Index++)
		{
			if (IS_INTRESOURCE(Vmt[Index]))
				break;
		}

		return Index;
	}

	std::uintptr_t* m_Base;
	std::uintptr_t m_Original;
	std::unique_ptr<uint32_t[]> m_Current;
};