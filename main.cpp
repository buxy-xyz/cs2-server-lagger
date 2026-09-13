#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#include <array>
#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment( lib, "bcrypt.lib" )
#pragma comment( lib, "psapi.lib" )

// -------------------------------- //

static HANDLE g_console{ INVALID_HANDLE_VALUE };

static void console_print(const char* text) noexcept
{
	if (!text || g_console == INVALID_HANDLE_VALUE)
	{
		return;
	}

	const auto len{ std::strlen(text) };
	if (!len)
	{
		return;
	}

	DWORD written{};
	WriteConsoleA(g_console, text, static_cast<DWORD>(len), &written, nullptr);
}

static void console_printf(const char* fmt, ...) noexcept
{
	char buf[512]{};
	va_list ap;
	va_start(ap, fmt);
	const auto n{ _vsnprintf_s(buf, sizeof buf, _TRUNCATE, fmt, ap) };
	va_end(ap);

	if (n > 0)
	{
		console_print(buf);
	}
}

// -------------------------------- //

namespace config
{
	std::atomic<bool>         server_lagger{ false };
	std::atomic<std::int32_t> server_lagger_mode{ 1 };
	std::atomic<std::int32_t> server_lagger_amount{ 1 };
	std::atomic<bool>         server_lagger_active{ false };
}

[[nodiscard]] static std::int32_t clamp_int(
	std::int32_t v,
	std::int32_t lo,
	std::int32_t hi) noexcept
{
	if (v < lo)
	{
		return lo;
	}

	if (v > hi)
	{
		return hi;
	}

	return v;
}

// -------------------------------- //

static std::mutex g_pattern_mutex;

static HANDLE    g_process{};
static uintptr_t g_client_base{};
static uintptr_t g_engine_base{};
static uintptr_t g_network_base{};

static uintptr_t g_network_game_client{};
static uintptr_t g_network_messages{};
static void* g_frame_stage_notify{};

// -------------------------------- //

[[nodiscard]] static std::size_t get_module_size(uintptr_t module_base) noexcept
{
	if (!module_base)
	{
		return 0;
	}

	auto* base{ reinterpret_cast<std::uint8_t*>(module_base) };
	auto* dos{ reinterpret_cast<IMAGE_DOS_HEADER*>(base) };

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	auto* nt{ reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew) };
	if (nt->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	return nt->OptionalHeader.SizeOfImage;
}

[[nodiscard]] static bool compare_bytes(
	const std::uint8_t* data,
	const std::uint8_t* pattern,
	const char* mask) noexcept
{
	for (; *mask; ++mask, ++data, ++pattern)
	{
		if (*mask == 'x' && *data != *pattern)
		{
			return false;
		}
	}

	return true;
}

// -------------------------------- //

[[nodiscard]] static uintptr_t find_pattern(
	const char* module_name,
	const char* pattern) noexcept
{
	std::lock_guard<std::mutex> lock{ g_pattern_mutex };

	uintptr_t module_base{};
	if (std::strcmp(module_name, "client.dll") == 0)
	{
		module_base = g_client_base;
	}
	else if (std::strcmp(module_name, "engine2.dll") == 0)
	{
		module_base = g_engine_base;
	}
	else if (std::strcmp(module_name, "networksystem.dll") == 0)
	{
		module_base = g_network_base;
	}
	else
	{
		return 0;
	}

	if (!module_base)
	{
		return 0;
	}

	const auto module_size{ get_module_size(module_base) };
	if (!module_size)
	{
		return 0;
	}

	std::vector<std::uint8_t> pattern_bytes;
	std::string mask;

	const char* p{ pattern };
	while (*p)
	{
		if (*p == ' ')
		{
			++p;
			continue;
		}

		if (*p == '?')
		{
			pattern_bytes.push_back(0);
			mask += '?';
			++p;

			if (*p == '?')
			{
				++p;
			}

			continue;
		}

		if (!std::isxdigit(static_cast<unsigned char>(p[0])) ||
			p[1] == '\0' ||
			!std::isxdigit(static_cast<unsigned char>(p[1])))
		{
			return 0;
		}

		char byte_str[3]{ p[0], p[1], '\0' };
		pattern_bytes.push_back(static_cast<std::uint8_t>(std::strtoul(byte_str, nullptr, 16)));
		mask += 'x';
		p += 2;
	}

	if (pattern_bytes.empty() || pattern_bytes.size() >= module_size)
	{
		return 0;
	}

	std::vector<std::uint8_t> buffer;
	try
	{
		buffer.resize(module_size);
	}
	catch (const std::bad_alloc&)
	{
		return 0;
	}

	SIZE_T bytes_read{};
	if (!ReadProcessMemory(g_process,
		reinterpret_cast<LPCVOID>(module_base),
		buffer.data(),
		module_size,
		&bytes_read))
	{
		return 0;
	}

	if (bytes_read < pattern_bytes.size())
	{
		return 0;
	}

	for (std::size_t i{ 0 }; i + pattern_bytes.size() <= bytes_read; ++i)
	{
		if (compare_bytes(buffer.data() + i, pattern_bytes.data(), mask.c_str()))
		{
			return module_base + i;
		}
	}

	return 0;
}

// -------------------------------- //

static void dump_bytes(
	const char* prefix,
	const std::uint8_t* p,
	std::size_t n) noexcept
{
	console_print(prefix);

	for (std::size_t i{ 0 }; i < n; ++i)
	{
		console_printf("%02X ", p[i]);
	}

	console_print("\n");
}

[[nodiscard]] static uintptr_t resolve_rip_ptr(uintptr_t match) noexcept
{
	if (!match)
	{
		return 0;
	}

	const auto disp{ *reinterpret_cast<const std::int32_t*>(match + 3) };
	return match + 7 + disp;
}

[[nodiscard]] static bool resolve_all_signatures() noexcept
{
	console_print("[sig] === starting signature scan ===\n");

	constexpr const char* k_sig_frame_stage_notify =
		"48 89 5C 24 ? 48 89 6C 24 ? 57 48 83 EC ? 48 8B F9 33 ED";

	constexpr const char* k_sig_network_game_client =
		"48 8B 05 ? ? ? ? 48 85 C0 74 06 88 90";

	constexpr const char* k_sig_network_messages =
		"48 8B 0D ? ? ? ? 4C 8B 43 ? 48 8B 01";

	console_printf("[sig] client.dll        base = %p\n",
		reinterpret_cast<void*>(g_client_base));

	console_printf("[sig] engine2.dll       base = %p\n",
		reinterpret_cast<void*>(g_engine_base));

	console_printf("[sig] networksystem.dll base = %p\n",
		reinterpret_cast<void*>(g_network_base));

	const auto fsn{ find_pattern("client.dll",        k_sig_frame_stage_notify) };
	const auto ngc{ find_pattern("engine2.dll",       k_sig_network_game_client) };
	const auto pnm{ find_pattern("networksystem.dll", k_sig_network_messages) };

	console_printf("[sig] FrameStageNotify  raw = %p\n", reinterpret_cast<void*>(fsn));
	console_printf("[sig] NetworkGameClient raw = %p\n", reinterpret_cast<void*>(ngc));
	console_printf("[sig] NetworkMessages   raw = %p\n", reinterpret_cast<void*>(pnm));

	if (!fsn)
	{
		console_print("[sig] FAIL: FrameStageNotify not found\n");
		return false;
	}

	if (!ngc)
	{
		console_print("[sig] FAIL: NetworkGameClient not found\n");
		return false;
	}

	if (!pnm)
	{
		console_print("[sig] FAIL: NetworkMessages not found\n");
		return false;
	}

	dump_bytes("[sig]   fsn bytes: ", reinterpret_cast<const std::uint8_t*>(fsn), 32);
	dump_bytes("[sig]   ngc bytes: ", reinterpret_cast<const std::uint8_t*>(ngc), 24);
	dump_bytes("[sig]   pnm bytes: ", reinterpret_cast<const std::uint8_t*>(pnm), 24);

	g_frame_stage_notify = reinterpret_cast<void*>(fsn);
	g_network_game_client = resolve_rip_ptr(ngc);
	g_network_messages = resolve_rip_ptr(pnm);

	console_printf("[sig] NetworkGameClient -> %p\n",
		reinterpret_cast<void*>(g_network_game_client));

	console_printf("[sig] NetworkMessages   -> %p\n",
		reinterpret_cast<void*>(g_network_messages));

	console_print("[sig] === done ===\n");
	return true;
}

// -------------------------------- //

[[nodiscard]] static std::size_t instruction_length(
	const std::uint8_t* p,
	std::size_t max_len) noexcept
{
	std::size_t i{ 0 };

	for (;; )
	{
		if (i >= max_len)
		{
			return 0;
		}

		const auto b{ p[i] };
		if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
			b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
			b == 0x64 || b == 0x65)
		{
			++i;
			continue;
		}

		break;
	}

	bool has_rex{ false };
	if (i < max_len && (p[i] & 0xF0) == 0x40)
	{
		has_rex = true;
		++i;
	}

	if (i >= max_len)
	{
		return 0;
	}

	const auto op{ p[i++] };
	std::uint8_t op2{};
	bool two_byte{ false };

	if (op == 0x0F)
	{
		if (i >= max_len)
		{
			return 0;
		}

		op2 = p[i++];
		two_byte = true;

		if (op2 == 0x38 || op2 == 0x3A)
		{
			if (i >= max_len)
			{
				return 0;
			}

			++i;
		}
	}

	bool has_mod_rm{ false };
	if (two_byte)
	{
		if (!(op2 == 0x05 || op2 == 0x0B || op2 == 0x31 || op2 == 0x34 ||
			op2 == 0x35 || op2 == 0xA2 || op2 == 0xA0 || op2 == 0xA1 ||
			op2 == 0xA8 || op2 == 0xA9 || op2 == 0x77))
		{
			has_mod_rm = true;
		}
	}
	else
	{
		static constexpr bool k_has_mod_rm[256]{
			1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1
		};

		has_mod_rm = k_has_mod_rm[op];
	}

	if (has_mod_rm)
	{
		if (i >= max_len)
		{
			return 0;
		}

		const auto modrm{ p[i++] };
		const auto mod{ static_cast<std::uint8_t>(modrm >> 6) };
		const auto rm{ static_cast<std::uint8_t>(modrm & 7) };

		if (mod != 3 && rm == 4)
		{
			if (i >= max_len)
			{
				return 0;
			}

			const auto sib{ p[i++] };
			const auto base{ static_cast<std::uint8_t>(sib & 7) };

			if (mod == 0 && base == 5)
			{
				i += 4;
			}
			else if (mod == 1)
			{
				i += 1;
			}
			else if (mod == 2)
			{
				i += 4;
			}
		}
		else
		{
			if (mod == 1)
			{
				i += 1;
			}
			else if (mod == 2 || (mod == 0 && rm == 5))
			{
				i += 4;
			}
		}
	}

	if (!two_byte)
	{
		switch (op)
		{
		case 0x70: case 0x71: case 0x72: case 0x73:
		case 0x74: case 0x75: case 0x76: case 0x77:
		case 0x78: case 0x79: case 0x7A: case 0x7B:
		case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		case 0xE0: case 0xE1: case 0xE2: case 0xE3:
		case 0xEB:
			i += 1;
			break;

		case 0xE8:
		case 0xE9:
			i += 4;
			break;

		case 0x6A:
			i += 1;
			break;

		case 0x68:
			i += 4;
			break;

		case 0xB0: case 0xB1: case 0xB2: case 0xB3:
		case 0xB4: case 0xB5: case 0xB6: case 0xB7:
			i += 1;
			break;

		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
			i += has_rex ? 8 : 4;
			break;

		case 0x04: case 0x0C: case 0x14: case 0x1C:
		case 0x24: case 0x2C: case 0x34: case 0x3C:
		case 0xA8:
			i += 1;
			break;

		case 0x05: case 0x0D: case 0x15: case 0x1D:
		case 0x25: case 0x2D: case 0x35: case 0x3D:
		case 0xA9:
			i += 4;
			break;

		case 0x80:
			i += 1;
			break;

		case 0x81:
			i += 4;
			break;

		case 0x83:
			i += 1;
			break;

		case 0x69:
			i += 4;
			break;

		case 0x6B:
			i += 1;
			break;

		case 0xC0:
		case 0xC1:
			i += 1;
			break;

		case 0xF6:
			i += 1;
			break;

		case 0xF7:
			i += 4;
			break;

		case 0xC2:
			i += 2;
			break;

		default:
			break;
		}
	}

	return (i && i <= max_len) ? i : 0;
}

// -------------------------------- //

enum mh_status
{
	MH_OK = 0,
	MH_ERROR_ALREADY_INITIALIZED,
	MH_ERROR_NOT_INITIALIZED,
	MH_ERROR_ALREADY_CREATED,
	MH_ERROR_NOT_CREATED,
	MH_ERROR_MEMORY_ALLOC,
	MH_ERROR_MEMORY_PROTECT,
	MH_ERROR_NOT_EXECUTABLE
};

static void* const k_all_hooks{
	reinterpret_cast<void*>(static_cast<std::intptr_t>(-1))
};

struct hook_entry
{
	void* target{};
	void* detour{};
	void* trampoline{};
	std::uint8_t original[32]{};
	std::size_t  prologue_len{};
	bool         enabled{};
};

static std::vector<hook_entry> g_hooks;
static bool                    g_hooks_initialized{ false };

[[nodiscard]] static bool set_protection(
	void* addr,
	std::size_t size,
	DWORD prot,
	DWORD* old) noexcept
{
	return VirtualProtect(addr, size, prot, old) != FALSE;
}

static void flush_code(void* addr, std::size_t size) noexcept
{
	FlushInstructionCache(GetCurrentProcess(), addr, size);
}

static void write_abs_jump(std::uint8_t* dst, void* dest) noexcept
{
	dst[0] = 0x48;
	dst[1] = 0xB8;

	*reinterpret_cast<std::uint64_t*>(dst + 2) =
		static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dest));

	dst[10] = 0xFF;
	dst[11] = 0xE0;
}

struct thread_freezer
{
	std::vector<HANDLE> threads;

	~thread_freezer()
	{
		for (std::size_t i{ 0 }; i < this->threads.size(); ++i)
		{
			ResumeThread(this->threads[i]);
			CloseHandle(this->threads[i]);
		}
	}

	void freeze() noexcept
	{
		const auto pid{ GetCurrentProcessId() };
		const auto tid{ GetCurrentThreadId() };

		const auto snap{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
		if (snap == INVALID_HANDLE_VALUE)
		{
			return;
		}

		THREADENTRY32 te{};
		te.dwSize = sizeof(te);

		if (Thread32First(snap, &te))
		{
			do
			{
				if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid)
				{
					const auto h{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID) };
					if (h)
					{
						SuspendThread(h);
						this->threads.push_back(h);
					}
				}

				te.dwSize = sizeof(te);
			} while (Thread32Next(snap, &te));
		}

		CloseHandle(snap);
	}
};

[[nodiscard]] static mh_status mh_initialize() noexcept
{
	if (g_hooks_initialized)
	{
		return MH_ERROR_ALREADY_INITIALIZED;
	}

	g_hooks_initialized = true;
	return MH_OK;
}

[[nodiscard]] static mh_status mh_uninitialize() noexcept
{
	if (!g_hooks_initialized)
	{
		return MH_ERROR_NOT_INITIALIZED;
	}

	for (auto& h : g_hooks)
	{
		if (h.enabled)
		{
			DWORD old{};
			if (set_protection(h.target, h.prologue_len, PAGE_EXECUTE_READWRITE, &old))
			{
				std::memcpy(h.target, h.original, h.prologue_len);
				set_protection(h.target, h.prologue_len, old, &old);
				flush_code(h.target, h.prologue_len);
			}
		}

		if (h.trampoline)
		{
			VirtualFree(h.trampoline, 0, MEM_RELEASE);
		}
	}

	g_hooks.clear();
	g_hooks_initialized = false;
	return MH_OK;
}

[[nodiscard]] static mh_status mh_create_hook(
	void* target,
	void* detour,
	void** original) noexcept
{
	if (!g_hooks_initialized)
	{
		return MH_ERROR_NOT_INITIALIZED;
	}

	if (!target || !detour)
	{
		return MH_ERROR_NOT_EXECUTABLE;
	}

	for (const auto& h : g_hooks)
	{
		if (h.target == target)
		{
			return MH_ERROR_ALREADY_CREATED;
		}
	}

	MEMORY_BASIC_INFORMATION mbi{};
	if (!VirtualQuery(target, &mbi, sizeof(mbi)))
	{
		return MH_ERROR_NOT_EXECUTABLE;
	}

	if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
		PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
	{
		return MH_ERROR_NOT_EXECUTABLE;
	}

	const auto* p{ static_cast<const std::uint8_t*>(target) };
	std::size_t prologue_len{ 0 };

	while (prologue_len < 12)
	{
		const auto len{ instruction_length(p + prologue_len, 24 - prologue_len) };
		if (!len)
		{
			return MH_ERROR_NOT_EXECUTABLE;
		}

		prologue_len += len;
	}

	if (prologue_len > 32)
	{
		return MH_ERROR_NOT_EXECUTABLE;
	}

	hook_entry entry;
	entry.target = target;
	entry.detour = detour;
	entry.prologue_len = prologue_len;
	std::memcpy(entry.original, target, prologue_len);

	auto* tramp{ VirtualAlloc(nullptr, 96, MEM_RESERVE | MEM_COMMIT,
							   PAGE_EXECUTE_READWRITE) };
	if (!tramp)
	{
		return MH_ERROR_MEMORY_ALLOC;
	}

	auto* t{ static_cast<std::uint8_t*>(tramp) };
	std::memcpy(t, entry.original, prologue_len);
	write_abs_jump(t + prologue_len,
		static_cast<std::uint8_t*>(target) + prologue_len);
	flush_code(tramp, prologue_len + 12);

	entry.trampoline = tramp;

	if (original)
	{
		*original = tramp;
	}

	g_hooks.push_back(entry);
	return MH_OK;
}

static void patch_target(hook_entry& h) noexcept
{
	DWORD old{};
	if (!set_protection(h.target, h.prologue_len, PAGE_EXECUTE_READWRITE, &old))
	{
		return;
	}

	auto* dst{ static_cast<std::uint8_t*>(h.target) };
	write_abs_jump(dst, h.detour);

	for (std::size_t i{ 12 }; i < h.prologue_len; ++i)
	{
		dst[i] = 0x90;
	}

	set_protection(h.target, h.prologue_len, old, &old);
	flush_code(h.target, h.prologue_len);
}

static void unpatch_target(hook_entry& h) noexcept
{
	DWORD old{};
	if (!set_protection(h.target, h.prologue_len, PAGE_EXECUTE_READWRITE, &old))
	{
		return;
	}

	std::memcpy(h.target, h.original, h.prologue_len);
	set_protection(h.target, h.prologue_len, old, &old);
	flush_code(h.target, h.prologue_len);
}

[[nodiscard]] static mh_status mh_enable_hook(void* target) noexcept
{
	if (!g_hooks_initialized)
	{
		return MH_ERROR_NOT_INITIALIZED;
	}

	thread_freezer freezer;
	freezer.freeze();

	for (auto& h : g_hooks)
	{
		if (target != k_all_hooks && h.target != target)
		{
			continue;
		}

		if (h.enabled)
		{
			continue;
		}

		patch_target(h);
		h.enabled = true;
	}

	return MH_OK;
}

[[nodiscard]] static mh_status mh_disable_hook(void* target) noexcept
{
	if (!g_hooks_initialized)
	{
		return MH_ERROR_NOT_INITIALIZED;
	}

	thread_freezer freezer;
	freezer.freeze();

	for (auto& h : g_hooks)
	{
		if (target != k_all_hooks && h.target != target)
		{
			continue;
		}

		if (!h.enabled)
		{
			continue;
		}

		unpatch_target(h);
		h.enabled = false;
	}

	return MH_OK;
}

// -------------------------------- //

#define xorn( x ) ( x )
#define xors( x ) ( x )

template <typename ret_t, typename... args_t>
[[nodiscard]] static ret_t invoke_vcall(
	void* obj,
	std::int32_t idx,
	args_t... args) noexcept
{
	auto** vtable{ *reinterpret_cast<void***>(obj) };
	auto fn{ reinterpret_cast<ret_t(__fastcall*)(void*, args_t...)>(vtable[idx]) };
	return fn(obj, args...);
}

#define INVOKE_VCALL( ret, idx, obj, ... ) \
	invoke_vcall<ret>( obj, idx, ##__VA_ARGS__ )

// -------------------------------- //

namespace
{
	struct server_lagger_profile_t
	{
		std::uint32_t messages_per_datagram;
		std::int32_t  maximum_datagrams_per_tick;
		std::size_t   packet_offsets_per_message;
	};

	constexpr server_lagger_profile_t k_mode_one_profile{ 0x41, 0x0E, 0x05C3 };
	constexpr server_lagger_profile_t k_mode_two_profile{ 0x06, 0x77, 0x3FC0 };

	struct bit_read_t
	{
		const void* data;
		std::int32_t  data_bytes;
		std::int32_t  data_bits;
		std::int32_t  current_bit;
		std::uint32_t reserved;
		const char* debug_name;
		bool          overflow;
		bool          initialized;
		bool          dword_safe;
		std::uint8_t  tail[5];
	};

	static_assert(sizeof(bit_read_t) == 0x28);
	static_assert(offsetof(bit_read_t, overflow) == 0x20);

	constexpr std::size_t k_payload_capacity{
		10 + 16320 + 1 + sizeof(std::uint64_t) + 1 + 5
	};

	struct voice_payload_t
	{
		std::array<std::uint8_t, k_payload_capacity> bytes{};
		std::size_t                                  size{};
	};

	struct voice_runtime_t
	{
		void* network_client{};
		std::int32_t tick{ -1 };
	};

	[[nodiscard]] const server_lagger_profile_t& selected_server_lagger_profile() noexcept
	{
		return config::server_lagger_mode.load() == 1
			? k_mode_two_profile
			: k_mode_one_profile;
	}

	std::mt19937_64 g_voice_xuid_generator{ std::random_device{}() };

	void append_varint(
		std::uint32_t value,
		std::vector<std::uint8_t>& output) noexcept
	{
		do
		{
			auto byte{ static_cast<std::uint8_t>(value & 0x7Fu) };
			value >>= 7u;

			if (value)
			{
				byte |= 0x80u;
			}

			output.push_back(byte);
		} while (value);
	}

	[[nodiscard]] voice_payload_t make_voice_payload(
		const server_lagger_profile_t& profile,
		std::uint64_t xuid,
		std::uint32_t tick) noexcept
	{
		const auto audio_payload_bytes{
			2 + 2 + 3 + profile.packet_offsets_per_message
		};

		const std::uint8_t prefix[10]{
			0x0A,
			static_cast<std::uint8_t>((audio_payload_bytes & 0x7F) | 0x80),
			static_cast<std::uint8_t>(audio_payload_bytes >> 7u),
			0x08, 0x02, 0x12, 0x00,
			0x42,
			static_cast<std::uint8_t>((profile.packet_offsets_per_message & 0x7F) | 0x80),
			static_cast<std::uint8_t>(profile.packet_offsets_per_message >> 7u),
		};

		voice_payload_t payload;
		for (std::size_t i{ 0 }; i < 10; ++i)
		{
			payload.bytes[i] = prefix[i];
		}

		std::size_t offset{ 10 + profile.packet_offsets_per_message };
		payload.bytes[offset++] = 0x11;

		for (std::size_t byte{ 0 }; byte < sizeof(xuid); ++byte)
		{
			payload.bytes[offset++] =
				static_cast<std::uint8_t>(xuid >> (byte * 8u));
		}

		payload.bytes[offset++] = 0x18;

		do
		{
			auto encoded{ static_cast<std::uint8_t>(tick & 0x7Fu) };
			tick >>= 7u;

			if (tick)
			{
				encoded |= 0x80u;
			}

			payload.bytes[offset++] = encoded;
		} while (tick);

		payload.size = offset;
		return payload;
	}

	void destroy_message(void* message) noexcept
	{
		if (message)
		{
			INVOKE_VCALL(void, xorn(0), message, xorn(1u));
		}
	}

	[[nodiscard]] void* network_messages() noexcept
	{
		const auto address{ g_network_messages };
		return address ? *reinterpret_cast<void**>(address) : nullptr;
	}

	[[nodiscard]] void* make_voice_message(const voice_payload_t& payload) noexcept
	{
		auto* messages{ network_messages() };
		if (!messages)
		{
			return nullptr;
		}

		auto* record{ INVOKE_VCALL(void*, xorn(30), messages, 22) };
		if (!record)
		{
			return nullptr;
		}

		auto* info{ INVOKE_VCALL(std::uint8_t*, xorn(12), messages, record) };
		auto* binding{ info ? *reinterpret_cast<void**>(info + 0x08) : nullptr };
		if (!binding)
		{
			return nullptr;
		}

		auto* message{ INVOKE_VCALL(void*, xorn(6), binding) };
		if (!message)
		{
			return nullptr;
		}

		std::vector<std::uint8_t> framed;
		framed.reserve(payload.size + 6);
		append_varint(static_cast<std::uint32_t>(payload.size), framed);
		framed.insert(framed.end(),
			payload.bytes.begin(),
			payload.bytes.begin() + payload.size);

		const auto logical_size{ framed.size() };
		framed.resize(logical_size + 4);

		bit_read_t reader;
		reader.data = framed.data();
		reader.data_bytes = static_cast<std::int32_t>(logical_size);
		reader.data_bits = static_cast<std::int32_t>(logical_size * 8);
		reader.current_bit = 0;
		reader.reserved = 0;
		reader.debug_name = "Server Lagger";
		reader.overflow = false;
		reader.initialized = true;
		reader.dword_safe = true;
		for (std::size_t i{ 0 }; i < 5; ++i)
		{
			reader.tail[i] = 0;
		}

		if (!INVOKE_VCALL(bool, xorn(4), messages, &reader, message) ||
			reader.overflow)
		{
			destroy_message(message);
			return nullptr;
		}

		return message;
	}

	void send_voice_payload(
		void* channel,
		const voice_payload_t& payload,
		const server_lagger_profile_t& profile,
		std::uint32_t datagrams) noexcept
	{
		auto* prototype{ make_voice_message(payload) };
		if (!prototype)
		{
			return;
		}

		bool transport_available{ true };
		for (std::uint32_t datagram{ 0 };
			datagram < datagrams && transport_available;
			++datagram)
		{
			std::uint32_t batch_sent{ 0 };
			for (; batch_sent < profile.messages_per_datagram; ++batch_sent)
			{
				auto* message{ INVOKE_VCALL(void*, xorn(4), prototype) };
				if (!message)
				{
					transport_available = false;
					break;
				}

				const auto accepted{
					INVOKE_VCALL(bool, xorn(39), channel, message,
								  static_cast<std::int8_t>(-1))
				};
				destroy_message(message);

				if (!accepted)
				{
					transport_available = false;
					break;
				}
			}

			if (batch_sent)
			{
				INVOKE_VCALL(std::int32_t, xorn(41), channel,
					xors("Server Lagger POC"), nullptr);
			}
		}

		destroy_message(prototype);
	}
}

static void server_lagger() noexcept
{
	static voice_runtime_t runtime;

	if (!config::server_lagger_active.load())
	{
		config::server_lagger.store(false);
		runtime = voice_runtime_t{};
		return;
	}

	{
		static std::uint64_t last_flip{ 0 };
		const auto now{ GetTickCount64() };

		if (now - last_flip >= 10)
		{
			last_flip = now;
			config::server_lagger.store(!config::server_lagger.load());
		}
	}

	if (!config::server_lagger.load())
	{
		return;
	}

	const auto network_client_address{ g_network_game_client };
	auto* network_client{ network_client_address
		? *reinterpret_cast<void**>(network_client_address)
		: nullptr };

	if (!network_client)
	{
		runtime = voice_runtime_t{};
		return;
	}

	const auto current_tick{ INVOKE_VCALL(std::int32_t, xorn(5), network_client) };
	if (runtime.network_client == network_client && runtime.tick == current_tick)
	{
		return;
	}

	runtime.network_client = network_client;
	runtime.tick = current_tick;

	auto* channel{ INVOKE_VCALL(void*, xorn(41), network_client, xorn(0)) };
	if (!channel || !INVOKE_VCALL(bool, xorn(47), channel))
	{
		return;
	}

	const auto& profile{ selected_server_lagger_profile() };
	const auto configured_amount{ config::server_lagger_amount.load() };

	const auto amount{
		static_cast<std::uint32_t>(
			clamp_int(configured_amount, 1, profile.maximum_datagrams_per_tick))
	};

	const auto payload{ make_voice_payload(
		profile,
		g_voice_xuid_generator(),
		static_cast<std::uint32_t>(current_tick)) };

	send_voice_payload(channel, payload, profile, amount);
}

// -------------------------------- //

using frame_stage_notify_fn = void(__fastcall*)(void*, std::int32_t);
static frame_stage_notify_fn g_original_frame_stage_notify{};

static void __fastcall frame_stage_notify_hook(
	void* self,
	std::int32_t stage) noexcept
{
	if (stage == 12)
	{
		server_lagger();
	}

	g_original_frame_stage_notify(self, stage);
}

// -------------------------------- //

static void print_settings() noexcept
{
	const auto* state_str{
		config::server_lagger_active.load() ? "ON" : "OFF"
	};

	console_printf("[settings] state=%s | mode=%d | amount=%d | range=1..%d\n", // literal range notation cuz lazy
		state_str,
		config::server_lagger_mode.load(),
		config::server_lagger_amount.load(),
		config::server_lagger_mode.load() == 1 ? 119 : 14);
}

// -------------------------------- //

[[nodiscard]] static bool edge(
	std::int32_t vk,
	std::string& prev) noexcept
{
	const bool now{ (GetAsyncKeyState(vk) & 0x8000) != 0 };
	const bool was{
		vk >= 0 && vk < static_cast<std::int32_t>(prev.size()) &&
		prev[static_cast<std::size_t>(vk)] != 0
	};

	if (vk >= 0 && vk < static_cast<std::int32_t>(prev.size()))
	{
		prev[static_cast<std::size_t>(vk)] = static_cast<char>(now);
	}

	return now && !was;
}

struct key_repeat
{
	bool          held{};
	std::uint64_t first_down{};
	std::uint64_t last_repeat{};
};

[[nodiscard]] static bool key_held_any(
	std::int32_t a,
	std::int32_t b) noexcept
{
	return (GetAsyncKeyState(a) & 0x8000) != 0 ||
		(GetAsyncKeyState(b) & 0x8000) != 0;
}

[[nodiscard]] static bool key_repeat_fire(
	bool held,
	key_repeat& state,
	std::uint64_t initial_delay_ms = 400,
	std::uint64_t repeat_every_ms = 50) noexcept
{
	const auto now{ GetTickCount64() };

	if (!held)
	{
		state.held = false;
		return false;
	}

	if (!state.held)
	{
		state.held = true;
		state.first_down = now;
		state.last_repeat = now;
		return true;
	}

	if (now - state.first_down < initial_delay_ms)
	{
		return false;
	}

	if (now - state.last_repeat >= repeat_every_ms)
	{
		state.last_repeat = now;
		return true;
	}

	return false;
}

[[nodiscard]] static bool pump_input(std::string& prev) noexcept
{
	bool changed{ false };

	if (edge(VK_F1, prev))
	{
		config::server_lagger_active.store(true);
		config::server_lagger.store(true);
		changed = true;
	}

	if (edge(VK_F2, prev))
	{
		config::server_lagger_active.store(false);
		config::server_lagger.store(false);
		changed = true;
	}

	if (edge(VK_F3, prev))
	{
		config::server_lagger_mode.store(1);

		if (config::server_lagger_amount.load() > 14)
		{
			config::server_lagger_amount.store(14);
		}

		changed = true;
	}

	if (edge(VK_F4, prev))
	{
		config::server_lagger_mode.store(2);
		changed = true;
	}

	if (edge(VK_F5, prev))
	{
		print_settings();
	}

	static key_repeat plus_repeat;
	static key_repeat minus_repeat;

	const bool plus_held{ key_held_any(VK_ADD, VK_OEM_PLUS) };
	const bool minus_held{ key_held_any(VK_SUBTRACT, VK_OEM_MINUS) };

	const bool plus_fire{ key_repeat_fire(plus_held, plus_repeat) };
	const bool minus_fire{ key_repeat_fire(minus_held, minus_repeat) };

	if (plus_fire || minus_fire)
	{
		const auto max_amount{
			config::server_lagger_mode.load() == 1 ? 119 : 14
		};

		const auto step{ plus_fire ? 1 : -1 };
		const auto next{
			clamp_int(config::server_lagger_amount.load() + step,
					   1, max_amount)
		};

		if (next != config::server_lagger_amount.load())
		{
			config::server_lagger_amount.store(next);
			changed = true;
		}
	}

	if (changed)
	{
		print_settings();
	}

	return edge(VK_END, prev);
}

// -------------------------------- //

[[nodiscard]] static bool wait_for_game_modules(HMODULE self) noexcept
{
	for (;; )
	{
		if (GetAsyncKeyState(VK_END) & 0x8000)
		{
			console_print("[exit] unloading.\n");
			FreeLibraryAndExitThread(self, 0);
		}

		const auto client{ GetModuleHandleW(L"client.dll") };
		const auto engine{ GetModuleHandleW(L"engine2.dll") };
		const auto net{ GetModuleHandleW(L"networksystem.dll") };

		if (client && engine && net)
		{
			g_client_base = reinterpret_cast<uintptr_t>(client);
			g_engine_base = reinterpret_cast<uintptr_t>(engine);
			g_network_base = reinterpret_cast<uintptr_t>(net);
			return true;
		}

		Sleep(100);
	}
}

// -------------------------------- //

static void start_worker(HMODULE self) noexcept
{
	const auto have_console{ AllocConsole() };
	if (have_console)
	{
		SetConsoleTitleW(L"server lagger POC");
		SetConsoleCtrlHandler([](DWORD) -> BOOL { return TRUE; }, TRUE);

		const auto hw{ GetConsoleWindow() };
		if (hw)
		{
			const auto sm{ GetSystemMenu(hw, FALSE) };
			if (sm)
			{
				DeleteMenu(sm, 0xF060, MF_BYCOMMAND);
				DrawMenuBar(hw);
			}
		}
	}

	g_console = GetStdHandle(STD_OUTPUT_HANDLE);
	g_process = GetCurrentProcess();

	console_print(
		"F1  - enable\n"
		"F2  - disable\n"
		"F3  - mode 1\n"
		"F4  - mode 2\n"
		"+/- - change force\n"
		"F5  - print current settings\n"
		"END - unload DLL\n\n");

	console_print("[wait] waiting for CS2 modules...\n");
	wait_for_game_modules(self);

	if (!resolve_all_signatures())
	{
		console_print("[error] current CS2 signatures were not found.\n");
		Sleep(3000);
		FreeLibraryAndExitThread(self, 0);
	}

	if (mh_initialize() != MH_OK)
	{
		console_print("[error] MinHook initialization failed.\n");
		Sleep(1500);
		FreeLibraryAndExitThread(self, 0);
	}

	if (mh_create_hook(g_frame_stage_notify,
		reinterpret_cast<void*>(&frame_stage_notify_hook),
		reinterpret_cast<void**>(&g_original_frame_stage_notify)) != MH_OK)
	{
		console_print("[error] FrameStageNotify hook creation failed.\n");
		mh_uninitialize();
		Sleep(1500);
		FreeLibraryAndExitThread(self, 0);
	}

	if (mh_enable_hook(g_frame_stage_notify) != MH_OK)
	{
		console_print("[error] FrameStageNotify hook enable failed.\n");
		mh_uninitialize();
		Sleep(1500);
		FreeLibraryAndExitThread(self, 0);
	}

	console_print("[ready] hook installed.\n");
	print_settings();

	std::string prev(256, '\0');
	while (!pump_input(prev))
	{
		Sleep(25);
	}

	console_print("[exit] removing hook.\n");
	mh_disable_hook(k_all_hooks);
	mh_uninitialize();
	Sleep(100);
	FreeLibraryAndExitThread(self, 0);
}

// -------------------------------- //

extern "C" BOOL WINAPI DllMain(
	HMODULE hModule,
	DWORD reason,
	LPVOID) noexcept
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);

		if (const auto t{ CreateThread(
				nullptr, 0,
				[](LPVOID p) -> DWORD
				{
					start_worker(static_cast<HMODULE>(p));
					return 0;
				},
				hModule, 0, nullptr) })
		{
			CloseHandle(t);
		}

		break;

	default:
		break;
	}

	return TRUE;
}