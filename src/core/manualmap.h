#pragma once
#ifndef MMAP_MANUALMAP_H
#define MMAP_MANUALMAP_H

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <vector>

namespace mmap
{
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using s64 = std::int64_t;

    struct map_config
    {
        bool  wipe_headers = true;
        bool  run_tls      = true;
        bool  allow_crt    = true;
        bool  try_hijack   = true;
        DWORD timeout_ms   = 20000;
    };

    struct map_result
    {
        bool  ok      = false;
        u64   base    = 0;
        DWORD error   = 0;
        char  message[256] = {};
    };

    inline void set_msg(map_result& r, const char* m)
    {
        std::snprintf(r.message, sizeof(r.message), "%s", m ? m : "");
    }

    inline bool ReadMem(HANDLE p, u64 addr, void* out, size_t n)
    {
        if (!addr || !n) return false;
        SIZE_T rd = 0;
        return ReadProcessMemory(p, (LPCVOID)(uintptr_t)addr, out, n, &rd) && rd == n;
    }

    inline bool WriteMem(HANDLE p, u64 addr, const void* in, size_t n)
    {
        if (!addr || !n) return false;
        SIZE_T wr = 0;
        return WriteProcessMemory(p, (LPVOID)(uintptr_t)addr, in, n, &wr) && wr == n;
    }

    inline u64 ReadPtr(HANDLE p, u64 addr, bool is64)
    {
        u64 v = 0;
        if (is64) { if (!ReadMem(p, addr, &v, 8)) return 0; }
        else      { u32 t = 0; if (!ReadMem(p, addr, &t, 4)) return 0; v = t; }
        return v;
    }

    inline bool OurProcessIs64()
    {
        BOOL wow = FALSE;
        if (!IsWow64Process(GetCurrentProcess(), &wow)) return false;
        return wow == FALSE;
    }

    inline bool TargetIs64(HANDLE proc)
    {
        using pfnIW64P2 = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
        static pfnIW64P2 p2 = (pfnIW64P2)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        if (p2)
        {
            USHORT pm = 0, nm = 0;
            if (p2(proc, &pm, &nm))
                return pm == IMAGE_FILE_MACHINE_UNKNOWN;
        }
        BOOL wow = FALSE;
        if (IsWow64Process(proc, &wow))
            return wow == FALSE;
        return OurProcessIs64();
    }

    inline u64 RemotePeb(HANDLE proc, bool target64)
    {
        using pfnNtQIP = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        static pfnNtQIP NtQIP =
            (pfnNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        if (!NtQIP) return 0;

        if (target64)
        {
            if (!OurProcessIs64()) return 0;
            struct PBI64 { u64 r1, peb, r2, r3, pid, r4; } pbi{};
            ULONG len = 0;
            if (NtQIP(proc, 0 , &pbi, sizeof(pbi), &len) != 0) return 0;
            return pbi.peb;
        }

        if (OurProcessIs64())
        {
            u64 peb32 = 0;
            ULONG len = 0;
            if (NtQIP(proc, 26 , &peb32, sizeof(peb32), &len) != 0) return 0;
            return peb32;
        }

        struct PBI32 { u32 r1, peb, r2, r3, pid, r4; } pbi{};
        ULONG len = 0;
        if (NtQIP(proc, 0, &pbi, sizeof(pbi), &len) != 0) return 0;
        return pbi.peb;
    }

    inline bool WideNameMatches(const wchar_t* a, const wchar_t* b)
    {
        return a && b && _wcsicmp(a, b) == 0;
    }

    inline u64 RemoteModuleBase(HANDLE proc, bool target64, const char* dll, u32* size_out)
    {
        if (size_out) *size_out = 0;
        if (!dll) return 0;

        wchar_t want[MAX_PATH] = {};
        MultiByteToWideChar(CP_ACP, 0, dll, -1, want, MAX_PATH);

        const u64 peb = RemotePeb(proc, target64);
        if (!peb) return 0;

        const u64 ldr_off   = target64 ? 0x18 : 0x0C;
        const u64 list_off  = target64 ? 0x20 : 0x14;

        const u64 base_off  = target64 ? 0x20 : 0x10;
        const u64 size_off  = target64 ? 0x30 : 0x18;
        const u64 name_off  = target64 ? 0x48 : 0x24;

        const u64 ldr = ReadPtr(proc, peb + ldr_off, target64);
        if (!ldr) return 0;

        const u64 head = ldr + list_off;
        u64 entry = ReadPtr(proc, head, target64);

        for (int guard = 0; entry && entry != head && guard < 512; ++guard)
        {
            u64 base = ReadPtr(proc, entry + base_off, target64);
            u16 name_len = 0;
            ReadMem(proc, entry + name_off, &name_len, sizeof(name_len));
            u64 name_buf = ReadPtr(proc, entry + name_off + (target64 ? 8 : 4), target64);

            if (base && name_buf && name_len > 1 && name_len < 512)
            {
                wchar_t buf[256] = {};
                u32 take = name_len < (u32)sizeof(buf) - 2 ? name_len : (u32)sizeof(buf) - 2;
                if (ReadMem(proc, name_buf, buf, take))
                {
                    buf[take / sizeof(wchar_t)] = 0;
                    if (WideNameMatches(buf, want))
                    {
                        if (size_out)
                        {
                            u32 sz = 0;
                            ReadMem(proc, entry + size_off, &sz, sizeof(sz));
                            *size_out = sz;
                        }
                        return base;
                    }
                }
            }
            entry = ReadPtr(proc, entry, target64);
        }
        return 0;
    }

    struct remote_pe
    {
        u64  base    = 0;
        u64  nt      = 0;
        bool is64    = false;
        u32  size    = 0;
        u32  entry   = 0;
        u32  dirs    = 0;
        u64  dir_base = 0;
    };

    inline bool ReadRemotePe(HANDLE proc, u64 base, remote_pe& out)
    {
        IMAGE_DOS_HEADER dos{};
        if (!ReadMem(proc, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;

        u32 sig = 0;
        if (!ReadMem(proc, base + dos.e_lfanew, &sig, 4) || sig != IMAGE_NT_SIGNATURE) return false;

        IMAGE_FILE_HEADER fh{};
        if (!ReadMem(proc, base + dos.e_lfanew + 4, &fh, sizeof(fh))) return false;

        const u64 opt = base + dos.e_lfanew + 4 + sizeof(fh);
        u16 magic = 0;
        if (!ReadMem(proc, opt, &magic, 2)) return false;

        out.base = base;
        out.nt   = base + dos.e_lfanew;

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER64 oh{};
            if (!ReadMem(proc, opt, &oh, sizeof(oh))) return false;
            out.is64 = true;
            out.size = oh.SizeOfImage;
            out.entry = oh.AddressOfEntryPoint;
            out.dirs = oh.NumberOfRvaAndSizes;
            out.dir_base = opt + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER32 oh{};
            if (!ReadMem(proc, opt, &oh, sizeof(oh))) return false;
            out.is64 = false;
            out.size = oh.SizeOfImage;
            out.entry = oh.AddressOfEntryPoint;
            out.dirs = oh.NumberOfRvaAndSizes;
            out.dir_base = opt + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        }
        else return false;

        return out.size != 0;
    }

    inline bool ReadRemoteDir(HANDLE proc, const remote_pe& pe, u32 index, IMAGE_DATA_DIRECTORY& dd)
    {
        dd = {};
        if (index >= pe.dirs) return false;
        const u64 addr = pe.dir_base + (u64)index * sizeof(IMAGE_DATA_DIRECTORY);
        return ReadMem(proc, addr, &dd, sizeof(dd));
    }

    inline bool ReadRemoteCStr(HANDLE proc, u64 addr, char* out, size_t cap)
    {
        if (!addr || !cap) return false;
        out[0] = 0;
        size_t used = 0;
        while (used + 1 < cap)
        {
            char chunk[64];
            size_t want = cap - used - 1;
            if (want > sizeof(chunk)) want = sizeof(chunk);
            if (!ReadMem(proc, addr + used, chunk, want)) return false;
            for (size_t i = 0; i < want; ++i)
            {
                if (chunk[i] == 0) { out[used] = 0; return true; }
                out[used++] = chunk[i];
            }
        }
        out[used] = 0;
        return true;
    }

    inline u64 RemoteProcByName(HANDLE proc, u64 mod, const char* func, bool target64, int depth);

    inline u64 RemoteLoadLibrary(HANDLE proc, bool target64, const char* dll);

    inline u64 RemoteProcByOrdinal(HANDLE proc, u64 mod, u16 ordinal, bool target64, int depth);

    inline u64 ResolveForwarder(HANDLE proc, u64 mod, const remote_pe& pe,
                                const IMAGE_DATA_DIRECTORY& exp,
                                u32 rva, bool target64, int depth)
    {
        if (depth >= 8) return 0;
        if (rva < exp.VirtualAddress || rva >= exp.VirtualAddress + exp.Size) return 0;

        char fwd[256] = {};
        if (!ReadRemoteCStr(proc, mod + rva, fwd, sizeof(fwd))) return 0;

        char* dot = std::strchr(fwd, '.');
        if (!dot) return 0;
        *dot = 0;

        char dll[MAX_PATH];
        std::snprintf(dll, sizeof(dll), "%s.dll", fwd);
        const char* fn = dot + 1;

        const u64 target = RemoteLoadLibrary(proc, target64, dll);
        if (!target) return 0;
        (void)pe;
        return RemoteProcByName(proc, target, fn, target64, depth + 1);
    }

    inline u64 RemoteProcByName(HANDLE proc, u64 mod, const char* func, bool target64, int depth)
    {
        if (!mod || !func || depth >= 8) return 0;

        remote_pe pe{};
        if (!ReadRemotePe(proc, mod, pe)) return 0;

        IMAGE_DATA_DIRECTORY exp{};
        if (!ReadRemoteDir(proc, pe, IMAGE_DIRECTORY_ENTRY_EXPORT, exp)) return 0;
        if (!exp.VirtualAddress) return 0;

        IMAGE_EXPORT_DIRECTORY ed{};
        if (!ReadMem(proc, mod + exp.VirtualAddress, &ed, sizeof(ed))) return 0;
        if (!ed.NumberOfNames || !ed.AddressOfNames || !ed.AddressOfNameOrdinals) return 0;

        const u32 name_count = ed.NumberOfNames > 8192 ? 8192 : ed.NumberOfNames;

        for (u32 i = 0; i < name_count; ++i)
        {
            u32 name_rva = 0;
            if (!ReadMem(proc, mod + ed.AddressOfNames + (u64)i * 4, &name_rva, 4)) continue;
            if (!name_rva) continue;

            char name[256] = {};
            if (!ReadRemoteCStr(proc, mod + name_rva, name, sizeof(name))) continue;
            if (std::strcmp(name, func) != 0) continue;

            u16 ord = 0;
            if (!ReadMem(proc, mod + ed.AddressOfNameOrdinals + (u64)i * 2, &ord, 2)) return 0;

            u32 fn_rva = 0;
            if (!ReadMem(proc, mod + ed.AddressOfFunctions + (u64)ord * 4, &fn_rva, 4)) return 0;
            if (!fn_rva) return 0;

            const u64 fwd = ResolveForwarder(proc, mod, pe, exp, fn_rva, target64, depth);
            if (fwd) return fwd;

            return mod + fn_rva;
        }
        return 0;
    }

    inline u64 RemoteProcByOrdinal(HANDLE proc, u64 mod, u16 ordinal, bool target64, int depth)
    {
        if (!mod || depth >= 8) return 0;

        remote_pe pe{};
        if (!ReadRemotePe(proc, mod, pe)) return 0;

        IMAGE_DATA_DIRECTORY exp{};
        if (!ReadRemoteDir(proc, pe, IMAGE_DIRECTORY_ENTRY_EXPORT, exp)) return 0;
        if (!exp.VirtualAddress) return 0;

        IMAGE_EXPORT_DIRECTORY ed{};
        if (!ReadMem(proc, mod + exp.VirtualAddress, &ed, sizeof(ed))) return 0;
        if (ordinal < ed.Base) return 0;

        u32 fn_rva = 0;
        const u32 idx = (u32)ordinal - ed.Base;
        if (!ReadMem(proc, mod + ed.AddressOfFunctions + (u64)idx * 4, &fn_rva, 4)) return 0;
        if (!fn_rva) return 0;

        const u64 fwd = ResolveForwarder(proc, mod, pe, exp, fn_rva, target64, depth);
        if (fwd) return fwd;

        return mod + fn_rva;
    }

    inline u64 CreateStubPage(HANDLE proc, bool target64, u64 fn, u64 arg0, u32 reason,
                              u64* out_flag);

    inline bool WaitRemoteFlag(HANDLE proc, u64 flag, DWORD timeout_ms, u64* out_value = nullptr);

    inline u64 CreateStubPage(HANDLE proc, bool target64, u64 fn, u64 arg0, u32 reason,
                              u64* out_flag)
    {
        const SIZE_T page = 0x1000;
        u8* page_mem = (u8*)VirtualAllocEx(proc, nullptr, page, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!page_mem) return 0;

        const u64 stub = (u64)(uintptr_t)page_mem;
        const u64 flag = stub + 0x100;

        std::vector<u8> code;

        auto put32 = [&](u32 v) { for (int i = 0; i < 4; ++i) code.push_back((u8)(v >> (8 * i))); };
        auto put64 = [&](u64 v) { for (int i = 0; i < 8; ++i) code.push_back((u8)(v >> (8 * i))); };

        if (target64)
        {
            code.push_back(0x48); code.push_back(0xB9); put64(arg0);
            code.push_back(0xBA); put32(reason);
            code.push_back(0x45); code.push_back(0x31); code.push_back(0xC0);
            code.push_back(0x48); code.push_back(0xB8); put64(fn);
            code.push_back(0x48); code.push_back(0x83); code.push_back(0xE4); code.push_back(0xF0);
            code.push_back(0x48); code.push_back(0x83); code.push_back(0xEC); code.push_back(0x20);
            code.push_back(0xFF); code.push_back(0xD0);
            code.push_back(0x48); code.push_back(0x89); code.push_back(0xC2);
            code.push_back(0x48); code.push_back(0xB9); put64(flag);
            const u8 store[] = { 0x48, 0x89, 0x51, 0x08 };
            code.insert(code.end(), store, store + sizeof(store));
            const u8 done[] = { 0xC7, 0x01, 0x01, 0x00, 0x00, 0x00 };
            code.insert(code.end(), done, done + sizeof(done));
            code.push_back(0xEB); code.push_back(0xFE);
        }
        else
        {
            const u8 push0[] = { 0x6A, 0x00 };
            code.insert(code.end(), push0, push0 + 2);
            code.push_back(0x68); put32(reason);
            code.push_back(0x68); put32((u32)arg0);
            code.push_back(0xB8); put32((u32)fn);
            code.push_back(0xFF); code.push_back(0xD0);
            const u8 save[] = { 0x89, 0xC2 };
            code.insert(code.end(), save, save + sizeof(save));
            code.push_back(0xB8); put32((u32)flag);
            const u8 store[] = { 0x89, 0x50, 0x08 };
            code.insert(code.end(), store, store + sizeof(store));
            const u8 done[] = { 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00 };
            code.insert(code.end(), done, done + sizeof(done));
            code.push_back(0xEB); code.push_back(0xFE);
        }

        if (code.size() >= 0x100 || !WriteMem(proc, stub, code.data(), code.size()))
        {
            VirtualFreeEx(proc, page_mem, 0, MEM_RELEASE);
            return 0;
        }

        FlushInstructionCache(proc, page_mem, code.size());
        if (out_flag) *out_flag = flag;
        return stub;
    }

    inline bool WaitRemoteFlag(HANDLE proc, u64 flag, DWORD timeout_ms, u64* out_value)
    {
        const ULONGLONG deadline = GetTickCount64() + timeout_ms;
        while (GetTickCount64() < deadline)
        {
            u32 v = 0;
            if (ReadMem(proc, flag, &v, sizeof(v)) && v != 0)
            {
                if (out_value)
                {
                    u64 result = 0;
                    if (!ReadMem(proc, flag + 8, &result, sizeof(result)))
                        result = 0;
                    *out_value = result;
                }
                return true;
            }
            Sleep(10);
        }
        return false;
    }

    inline DWORD PickThread(DWORD pid)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        DWORD tid = 0;
        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return tid;
    }

    inline bool RunRemote(HANDLE proc, bool target64, u64 fn, u64 arg0, u32 reason,
                          const map_config& cfg, u64* out_value = nullptr)
    {
        u64 flag = 0;
        const u64 stub = CreateStubPage(proc, target64, fn, arg0, reason, &flag);
        if (!stub) return false;

        bool done = false;
        const bool ours64 = OurProcessIs64();

        const bool can_hijack = ours64 || !target64;
        if (cfg.try_hijack && can_hijack)
        {
            const DWORD pid = GetProcessId(proc);
            const DWORD tid = PickThread(pid);
            if (tid)
            {
                HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                       THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, tid);
                if (th)
                {
                    if (SuspendThread(th) != (DWORD)-1)
                    {
#ifdef _WIN64
                        if (target64)
                        {
                            CONTEXT ctx{};
                            ctx.ContextFlags = CONTEXT_ALL;
                            if (GetThreadContext(th, &ctx))
                            {
                                CONTEXT saved = ctx;
                                void* stack = VirtualAllocEx(proc, nullptr, 0x40000,
                                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                if (stack)
                                {
                                    ctx.Rip = stub;
                                    ctx.Rsp = ((u64)(uintptr_t)stack + 0x40000 - 0x100) & ~(u64)0xF;
                                    ctx.ContextFlags = CONTEXT_ALL;
                                    if (SetThreadContext(th, &ctx))
                                    {
                                        ResumeThread(th);
                                        done = WaitRemoteFlag(proc, flag, cfg.timeout_ms, out_value);
                                        SuspendThread(th);
                                        SetThreadContext(th, &saved);
                                        ResumeThread(th);
                                    }
                                    VirtualFreeEx(proc, stack, 0, MEM_RELEASE);
                                }
                            }
                        }
                        else
                        {
                            WOW64_CONTEXT ctx{};
                            ctx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER |
                                               WOW64_CONTEXT_SEGMENTS | WOW64_CONTEXT_FLOATING_POINT |
                                               WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_EXTENDED_REGISTERS;
                            if (Wow64GetThreadContext(th, &ctx))
                            {
                                WOW64_CONTEXT saved = ctx;
                                void* stack = VirtualAllocEx(proc, nullptr, 0x40000,
                                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                if (stack)
                                {
                                    ctx.Eip = (DWORD)stub;
                                    ctx.Esp = (DWORD)(((u64)(uintptr_t)stack + 0x40000 - 0x100) & ~(u64)0xF);
                                    if (Wow64SetThreadContext(th, &ctx))
                                    {
                                        ResumeThread(th);
                                        done = WaitRemoteFlag(proc, flag, cfg.timeout_ms, out_value);
                                        SuspendThread(th);
                                        Wow64SetThreadContext(th, &saved);
                                        ResumeThread(th);
                                    }
                                    VirtualFreeEx(proc, stack, 0, MEM_RELEASE);
                                }
                            }
                        }
#else
                        if (!target64)
                        {
                            CONTEXT ctx{};
                            ctx.ContextFlags = CONTEXT_ALL;
                            if (GetThreadContext(th, &ctx))
                            {
                                CONTEXT saved = ctx;
                                void* stack = VirtualAllocEx(proc, nullptr, 0x40000,
                                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                if (stack)
                                {
                                    ctx.Eip = (DWORD)stub;
                                    ctx.Esp = (DWORD)(((u64)(uintptr_t)stack + 0x40000 - 0x100) & ~(u64)0xF);
                                    ctx.ContextFlags = CONTEXT_ALL;
                                    if (SetThreadContext(th, &ctx))
                                    {
                                        ResumeThread(th);
                                        done = WaitRemoteFlag(proc, flag, cfg.timeout_ms, out_value);
                                        SuspendThread(th);
                                        SetThreadContext(th, &saved);
                                        ResumeThread(th);
                                    }
                                    VirtualFreeEx(proc, stack, 0, MEM_RELEASE);
                                }
                            }
                        }
#endif
                        if (!done) ResumeThread(th);
                    }
                    CloseHandle(th);
                }
            }
        }

        if (!done && cfg.allow_crt)
        {
            HANDLE th = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)(uintptr_t)stub,
                                           nullptr, 0, nullptr);
            if (th)
            {
                done = WaitRemoteFlag(proc, flag, cfg.timeout_ms, out_value);
                if (done) TerminateThread(th, 0);
                CloseHandle(th);
            }
        }

        if (done) VirtualFreeEx(proc, (LPVOID)(uintptr_t)stub, 0, MEM_RELEASE);
        return done;
    }

    inline u64 RemoteLoadLibrary(HANDLE proc, bool target64, const char* dll)
    {
        u64 existing = RemoteModuleBase(proc, target64, dll, nullptr);
        if (existing) return existing;

        const u64 k32 = RemoteModuleBase(proc, target64, "kernel32.dll", nullptr);
        if (!k32) return 0;

        const u64 fn = RemoteProcByName(proc, k32, "LoadLibraryA", target64, 0);
        if (!fn) return 0;

        const size_t n = std::strlen(dll) + 1;
        void* name_mem = VirtualAllocEx(proc, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!name_mem) return 0;

        if (!WriteMem(proc, (u64)(uintptr_t)name_mem, dll, n))
        {
            VirtualFreeEx(proc, name_mem, 0, MEM_RELEASE);
            return 0;
        }

        map_config cfg;
        cfg.timeout_ms = 30000;
        u64 hmod = 0;
        RunRemote(proc, target64, fn, (u64)(uintptr_t)name_mem, 0, cfg, &hmod);

        VirtualFreeEx(proc, name_mem, 0, MEM_RELEASE);

        if (hmod) return hmod;
        return RemoteModuleBase(proc, target64, dll, nullptr);
    }

    inline DWORD ProtectionFor(u32 characteristics)
    {
        const bool exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec) return write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
        return write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS);
    }

    inline map_result map_dll(DWORD pid, const char* dll_path, const map_config& cfg)
    {
        map_result res;

        std::FILE* f = nullptr;
        if (fopen_s(&f, dll_path, "rb") != 0 || !f)
        {
            res.error = GetLastError();
            set_msg(res, "cannot open dll");
            return res;
        }

        std::fseek(f, 0, SEEK_END);
        const long fsz = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        if (fsz <= 0)
        {
            std::fclose(f);
            set_msg(res, "empty dll");
            return res;
        }

        std::vector<u8> file((size_t)fsz);
        if (std::fread(file.data(), 1, file.size(), f) != file.size())
        {
            std::fclose(f);
            set_msg(res, "short read");
            return res;
        }
        std::fclose(f);

        if (file.size() < sizeof(IMAGE_DOS_HEADER))
        {
            set_msg(res, "not a pe");
            return res;
        }

        auto* dos = (const IMAGE_DOS_HEADER*)file.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        {
            set_msg(res, "bad dos header");
            return res;
        }

        const size_t nt_off = (size_t)dos->e_lfanew;
        if (nt_off + sizeof(IMAGE_NT_HEADERS32) > file.size())
        {
            set_msg(res, "truncated nt headers");
            return res;
        }

        auto* sig = (const u32*)(file.data() + nt_off);
        if (*sig != IMAGE_NT_SIGNATURE)
        {
            set_msg(res, "bad nt signature");
            return res;
        }

        auto* fh = (const IMAGE_FILE_HEADER*)(file.data() + nt_off + 4);
        const size_t opt_off = nt_off + 4 + sizeof(IMAGE_FILE_HEADER);
        const auto* magic = (const u16*)(file.data() + opt_off);

        const bool img64 = (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        const bool pe32 = (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        if (!img64 && !pe32)
        {
            set_msg(res, "unsupported optional header");
            return res;
        }

        const IMAGE_OPTIONAL_HEADER64* oh64 = img64
            ? (const IMAGE_OPTIONAL_HEADER64*)(file.data() + opt_off) : nullptr;
        const IMAGE_OPTIONAL_HEADER32* oh32 = pe32
            ? (const IMAGE_OPTIONAL_HEADER32*)(file.data() + opt_off) : nullptr;

        const u64 image_base = img64 ? oh64->ImageBase : (u64)oh32->ImageBase;
        const u32 size_image = img64 ? oh64->SizeOfImage : oh32->SizeOfImage;
        const u32 size_headers = img64 ? oh64->SizeOfHeaders : oh32->SizeOfHeaders;
        const u32 entry_rva = img64 ? oh64->AddressOfEntryPoint : oh32->AddressOfEntryPoint;
        const u32 dll_char = img64 ? oh64->DllCharacteristics : oh32->DllCharacteristics;
        const u32 dir_count = img64 ? oh64->NumberOfRvaAndSizes : oh32->NumberOfRvaAndSizes;
        const IMAGE_DATA_DIRECTORY* dirs = img64 ? oh64->DataDirectory : oh32->DataDirectory;

        auto data_dir = [&](u32 idx) -> IMAGE_DATA_DIRECTORY
        {
            IMAGE_DATA_DIRECTORY d{};
            if (idx < dir_count) d = dirs[idx];
            return d;
        };

        HANDLE proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                                  PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
                                  PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!proc)
        {
            res.error = GetLastError();
            set_msg(res, "OpenProcess failed");
            return res;
        }

        const bool target64 = TargetIs64(proc);
        if ((target64 && !img64) || (!target64 && img64))
        {
            CloseHandle(proc);
            set_msg(res, "dll bitness does not match target");
            return res;
        }

        if (!pe32 && !img64)
        {
            CloseHandle(proc);
            set_msg(res, "unsupported image");
            return res;
        }

        if (target64 && !OurProcessIs64())
        {
            CloseHandle(proc);
            set_msg(res, "32-bit loader cannot map into a 64-bit target (build x64)");
            return res;
        }

        const IMAGE_DATA_DIRECTORY reloc_dir = data_dir(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        const bool has_reloc = reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0;
        const bool dynamic_base = (dll_char & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;

        void* remote = nullptr;
        if (image_base && (!has_reloc || !dynamic_base))
        {
            remote = VirtualAllocEx(proc, (LPVOID)(uintptr_t)image_base, size_image,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        if (!remote)
        {
            remote = VirtualAllocEx(proc, nullptr, size_image,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        if (!remote)
        {
            res.error = GetLastError();
            CloseHandle(proc);
            set_msg(res, "VirtualAllocEx failed");
            return res;
        }

        const u64 remote_base = (u64)(uintptr_t)remote;

        std::vector<u8> img(size_image, 0);

        size_t hdr = size_headers < file.size() ? size_headers : file.size();
        if (hdr > size_image) hdr = size_image;
        std::memcpy(img.data(), file.data(), hdr);

        const size_t sec_off = opt_off + fh->SizeOfOptionalHeader;
        if (sec_off + (size_t)fh->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > file.size())
        {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc);
            set_msg(res, "truncated section table");
            return res;
        }

        const auto* sec = (const IMAGE_SECTION_HEADER*)(file.data() + sec_off);

        for (u32 i = 0; i < fh->NumberOfSections; ++i)
        {
            const IMAGE_SECTION_HEADER& s = sec[i];
            if (!s.VirtualAddress || !s.SizeOfRawData) continue;
            if (s.VirtualAddress >= size_image) continue;

            u32 raw = s.SizeOfRawData;
            u32 vrt = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            if (raw > vrt) raw = vrt;
            if (s.VirtualAddress + raw > size_image) continue;
            if ((size_t)s.PointerToRawData + raw > file.size()) continue;

            std::memcpy(img.data() + s.VirtualAddress, file.data() + s.PointerToRawData, raw);
        }

        if (has_reloc && image_base != remote_base)
        {
            const u64 delta = (u64)((s64)remote_base - (s64)image_base);
            u32 cursor = 0;
            while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= reloc_dir.Size)
            {
                IMAGE_BASE_RELOCATION blk{};
                std::memcpy(&blk, img.data() + reloc_dir.VirtualAddress + cursor, sizeof(blk));
                if (!blk.SizeOfBlock || blk.VirtualAddress >= size_image) break;

                const u32 count = (blk.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(u16);
                const u16* items = (const u16*)(img.data() + reloc_dir.VirtualAddress + cursor +
                                                sizeof(IMAGE_BASE_RELOCATION));

                for (u32 j = 0; j < count; ++j)
                {
                    const u16 type = (u16)(items[j] >> 12);
                    const u16 off = (u16)(items[j] & 0x0FFF);
                    const u64 at = (u64)blk.VirtualAddress + off;

                    if (type == IMAGE_REL_BASED_ABSOLUTE) continue;

                    if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        if (at + 4 > size_image) continue;
                        u32 v = 0;
                        std::memcpy(&v, img.data() + at, 4);
                        v = (u32)(v + (u32)delta);
                        std::memcpy(img.data() + at, &v, 4);
                    }
                    else if (type == IMAGE_REL_BASED_DIR64)
                    {
                        if (at + 8 > size_image) continue;
                        u64 v = 0;
                        std::memcpy(&v, img.data() + at, 8);
                        v = (u64)(v + delta);
                        std::memcpy(img.data() + at, &v, 8);
                    }
                }
                cursor += blk.SizeOfBlock;
            }
        }
        else if (has_reloc == false && image_base != remote_base)
        {
        }

        const IMAGE_DATA_DIRECTORY imp_dir = data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (imp_dir.VirtualAddress && imp_dir.VirtualAddress < size_image)
        {
            const u64 base_at = imp_dir.VirtualAddress;
            for (u32 i = 0;; ++i)
            {
                const u64 at = base_at + (u64)i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                if (at + sizeof(IMAGE_IMPORT_DESCRIPTOR) > size_image) break;

                IMAGE_IMPORT_DESCRIPTOR id{};
                std::memcpy(&id, img.data() + at, sizeof(id));
                if (!id.Name && !id.FirstThunk) break;
                if (!id.Name || id.Name >= size_image) break;

                const char* dll = (const char*)(img.data() + id.Name);
                char module_name[MAX_PATH] = {};
                std::snprintf(module_name, sizeof(module_name), "%s", dll);

                const u64 mod = RemoteLoadLibrary(proc, target64, module_name);
                if (!mod) continue;

                const u32 thunk_rva = id.OriginalFirstThunk ? id.OriginalFirstThunk : id.FirstThunk;
                const u32 iat_rva = id.FirstThunk;
                if (!thunk_rva || !iat_rva) continue;

                const u32 step = img64 ? 8 : 4;
                for (u32 t = 0;; ++t)
                {
                    const u64 taddr = (u64)thunk_rva + (u64)t * step;
                    const u64 iaddr = (u64)iat_rva + (u64)t * step;
                    if (taddr + step > size_image || iaddr + step > size_image) break;

                    u64 entry = 0;
                    if (img64) std::memcpy(&entry, img.data() + taddr, 8);
                    else
                    {
                        u32 e32 = 0;
                        std::memcpy(&e32, img.data() + taddr, 4);
                        entry = e32;
                    }
                    if (!entry) break;

                    u64 resolved = 0;
                    const char* fname = "(ordinal)";

                    if (img64)
                    {
                        const bool by_ordinal = (entry & IMAGE_ORDINAL_FLAG64) != 0;
                        if (by_ordinal)
                            resolved = RemoteProcByOrdinal(proc, mod, (u16)(entry & 0xFFFF), target64, 0);
                        else
                        {
                            const u32 rva = (u32)(entry & 0x7FFFFFFF);
                            if (rva + 2 < size_image)
                            {
                                fname = (const char*)(img.data() + rva + 2);
                                resolved = RemoteProcByName(proc, mod, fname, target64, 0);
                            }
                        }
                    }
                    else
                    {
                        const bool by_ordinal = (entry & IMAGE_ORDINAL_FLAG32) != 0;
                        if (by_ordinal)
                            resolved = RemoteProcByOrdinal(proc, mod, (u16)(entry & 0xFFFF), target64, 0);
                        else
                        {
                            const u32 rva = (u32)(entry & 0x7FFFFFFF);
                            if (rva + 2 < size_image)
                            {
                                fname = (const char*)(img.data() + rva + 2);
                                resolved = RemoteProcByName(proc, mod, fname, target64, 0);
                            }
                        }
                    }

                    if (!resolved) continue;
                    if (img64) std::memcpy(img.data() + iaddr, &resolved, 8);
                    else
                    {
                        u32 r32 = (u32)resolved;
                        std::memcpy(img.data() + iaddr, &r32, 4);
                    }
                }
            }
        }

        if (!WriteMem(proc, remote_base, img.data(), size_image))
        {
            res.error = GetLastError();
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            CloseHandle(proc);
            set_msg(res, "WriteProcessMemory(image) failed");
            return res;
        }

        for (u32 i = 0; i < fh->NumberOfSections; ++i)
        {
            const IMAGE_SECTION_HEADER& s = sec[i];
            if (!s.VirtualAddress || !s.Misc.VirtualSize) continue;
            if (s.VirtualAddress >= size_image) continue;
            u32 sz = s.Misc.VirtualSize;
            if (s.VirtualAddress + sz > size_image) sz = size_image - s.VirtualAddress;

            DWORD old = 0;
            VirtualProtectEx(proc, (LPVOID)(uintptr_t)(remote_base + s.VirtualAddress), sz,
                             ProtectionFor(s.Characteristics), &old);
        }

        FlushInstructionCache(proc, (LPCVOID)(uintptr_t)remote_base, size_image);

        const IMAGE_DATA_DIRECTORY tls_dir = data_dir(IMAGE_DIRECTORY_ENTRY_TLS);
        if (cfg.run_tls && tls_dir.VirtualAddress && tls_dir.VirtualAddress < size_image)
        {
            u64 callbacks_va = 0;
            if (img64)
            {
                IMAGE_TLS_DIRECTORY64 tls{};
                if (tls_dir.VirtualAddress + sizeof(tls) <= size_image)
                {
                    std::memcpy(&tls, img.data() + tls_dir.VirtualAddress, sizeof(tls));
                    callbacks_va = tls.AddressOfCallBacks;
                }
            }
            else
            {
                IMAGE_TLS_DIRECTORY32 tls{};
                if (tls_dir.VirtualAddress + sizeof(tls) <= size_image)
                {
                    std::memcpy(&tls, img.data() + tls_dir.VirtualAddress, sizeof(tls));
                    callbacks_va = tls.AddressOfCallBacks;
                }
            }

            if (callbacks_va)
            {
                const u32 step = img64 ? 8 : 4;
                for (u32 i = 0; i < 64; ++i)
                {
                    const u64 slot = callbacks_va + (u64)i * step;
                    u64 cb = 0;
                    if (img64)
                    {
                        if (!ReadMem(proc, slot, &cb, 8)) break;
                    }
                    else
                    {
                        u32 cb32 = 0;
                        if (!ReadMem(proc, slot, &cb32, 4)) break;
                        cb = cb32;
                    }
                    if (!cb) break;
                    RunRemote(proc, target64, cb, remote_base, 1, cfg);
                }
            }
        }

        bool init = true;
        if (entry_rva)
        {
            init = RunRemote(proc, target64, remote_base + entry_rva, remote_base, 1, cfg);
        }

        if (!init)
        {
            res.error = GetLastError();
            set_msg(res, "DllMain did not complete (hijack + crt both failed)");
            CloseHandle(proc);
            return res;
        }

        if (cfg.wipe_headers)
        {
            DWORD old = 0;
            const u64 page = size_headers ? size_headers : 0x1000;
            if (VirtualProtectEx(proc, (LPVOID)(uintptr_t)remote_base, page, PAGE_READWRITE, &old))
            {
                std::vector<u8> zero(page, 0);
                WriteMem(proc, remote_base, zero.data(), page);
                VirtualProtectEx(proc, (LPVOID)(uintptr_t)remote_base, page, PAGE_READONLY, &old);
            }
        }

        res.ok = true;
        res.base = remote_base;
        set_msg(res, "ok");
        CloseHandle(proc);
        return res;
    }
}

#endif
