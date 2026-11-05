#include <windows.h>
#include <tlhelp32.h>
#include <d3d11.h>
#include <dxgi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <wininet.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <timeapi.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winmm.lib")

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/imgui_freetype.h"

#include "core/manualmap.h"
#include "core/release.h"
#include "core/icon_font.hpp"
#include "core/github_icon.hpp"

namespace
{
    constexpr DWORD kProcessAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    constexpr const char* kBotoxDllName = "botox.dll";

    struct target_t
    {
        const char*    label;
        const char*    repo;
        const wchar_t* exe;
        const char*    bin_subdir;
        bool           manual_map;
    };

    constexpr target_t kTargets[] =
    {
        { "botox",     "gumballpanties-sudo/botox",     L"csgo.exe",     "",    true  },
        { "botox tf2", "gumballpanties-sudo/botox-tf2", L"tf_win64.exe", "tf2", false },
    };
    constexpr int kTargetCount = (int)(sizeof(kTargets) / sizeof(kTargets[0]));

    enum release_state : LONG { kRelLoading = 0, kRelOffline, kRelMissing, kRelOk };

    inline float Approach(float cur, float target, float speed, float dt)
    {
        return cur + (target - cur) * (1.0f - expf(-speed * dt));
    }

    bool FileHasData(const char* path)
    {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return false;
        return (fad.dwFileAttributes != INVALID_FILE_ATTRIBUTES) &&
               !(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
               (fad.nFileSizeLow > 0 || fad.nFileSizeHigh > 0);
    }

    bool ValidPeFile(const char* path)
    {
        HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;

        bool ok = false;
        LARGE_INTEGER size{};
        IMAGE_DOS_HEADER dos{};
        IMAGE_FILE_HEADER fh{};
        DWORD sig = 0, read = 0;

        if (GetFileSizeEx(file, &size) &&
            size.QuadPart >= (LONGLONG)sizeof(IMAGE_DOS_HEADER) &&
            size.QuadPart <= (LONGLONG)(512u << 20) &&
            ReadFile(file, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE &&
            dos.e_lfanew > 0 && (LONGLONG)dos.e_lfanew + 4 + (LONGLONG)sizeof(fh) < size.QuadPart)
        {
            SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN);
            if (ReadFile(file, &sig, sizeof(sig), &read, nullptr) && read == sizeof(sig) &&
                sig == IMAGE_NT_SIGNATURE &&
                ReadFile(file, &fh, sizeof(fh), &read, nullptr) && read == sizeof(fh) &&
                fh.NumberOfSections >= 1 && fh.NumberOfSections <= 96 &&
                fh.SizeOfOptionalHeader >= 0xE0)
            {
                ok = true;
            }
        }
        CloseHandle(file);
        return ok;
    }

    bool Sha256File(const char* path, char out[65])
    {
        out[0] = 0;
        HCRYPTPROV prov = 0;
        HCRYPTHASH hash = 0;
        HANDLE file = INVALID_HANDLE_VALUE;
        bool ok = false;

        if (!CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return false;

        if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash))
        {
            file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE)
            {
                BYTE buf[65536];
                DWORD read = 0;
                bool read_ok = true;
                for (;;)
                {
                    if (!ReadFile(file, buf, sizeof(buf), &read, nullptr)) { read_ok = false; break; }
                    if (read == 0) break;
                    if (!CryptHashData(hash, buf, read, 0)) { read_ok = false; break; }
                }
                ok = read_ok;

                BYTE digest[32]{};
                DWORD len = sizeof(digest);
                if (ok && CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0) && len == sizeof(digest))
                {
                    static const char hex[] = "0123456789abcdef";
                    for (DWORD i = 0; i < len; ++i)
                    {
                        out[i * 2] = hex[digest[i] >> 4];
                        out[i * 2 + 1] = hex[digest[i] & 0x0f];
                    }
                    out[len * 2] = 0;
                }
                else ok = false;
            }
            CryptDestroyHash(hash);
        }
        CryptReleaseContext(prov, 0);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        return ok;
    }

    release_state FetchRelease(const char* repo, release::asset_info& out)
    {
        out = {};
        HINTERNET hInternet = InternetOpenA("botox-loader/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return kRelOffline;

        char url[256];
        snprintf(url, sizeof(url), "https://api.github.com/repos/%s/releases/latest", repo);

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_SECURE |
                      INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, "Accept: application/vnd.github+json\r\n", -1, flags, 0);
        if (!hUrl)
        {
            InternetCloseHandle(hInternet);
            return kRelOffline;
        }

        DWORD status = 0, status_len = sizeof(status);
        HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &status_len, nullptr);

        std::string json;
        char buf[4096];
        DWORD read = 0;
        while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0)
            json.append(buf, read);

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);

        if (status == 404) return kRelMissing;
        if (status != 200) return kRelOffline;
        return release::find_asset(json, kBotoxDllName, out) ? kRelOk : kRelMissing;
    }

    bool DownloadToFile(const char* url, const char* out_path)
    {
        HINTERNET hInternet = InternetOpenA("botox-loader/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return false;

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_SECURE |
                      INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, nullptr, 0, flags, 0);
        if (!hUrl)
        {
            InternetCloseHandle(hInternet);
            return false;
        }

        HANDLE hFile = CreateFileA(out_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return false;
        }

        char buf[8192];
        DWORD read = 0, written = 0;
        bool ok = true;
        while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0)
        {
            if (!WriteFile(hFile, buf, read, &written, nullptr) || written != read)
            {
                ok = false;
                break;
            }
        }

        CloseHandle(hFile);
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return ok;
    }

    bool GetBotoxBinDir(const char* subdir, char* out, size_t cap)
    {
        char ap[MAX_PATH]{};
        if (!GetEnvironmentVariableA("APPDATA", ap, MAX_PATH)) return false;
        char base[MAX_PATH]{};
        snprintf(base, sizeof(base), "%s\\botox", ap);
        CreateDirectoryA(base, nullptr);
        snprintf(out, cap, "%s\\bin", base);
        CreateDirectoryA(out, nullptr);
        if (subdir && *subdir)
        {
            const size_t len = strlen(out);
            snprintf(out + len, cap - len, "\\%s", subdir);
            CreateDirectoryA(out, nullptr);
        }
        return true;
    }

    bool EnsureBotoxDll(const target_t& target, char* out_path, size_t cap, char* err, size_t err_cap)
    {
        char bin[MAX_PATH]{};
        if (!GetBotoxBinDir(target.bin_subdir, bin, sizeof(bin)))
        {
            lstrcpynA(err, "APPDATA not set", (int)err_cap);
            return false;
        }

        char cached[MAX_PATH * 2]{};
        snprintf(cached, sizeof(cached), "%s\\%s", bin, kBotoxDllName);

        release::asset_info info;
        const release_state rs = FetchRelease(target.repo, info);
        const bool got_sha = rs == kRelOk && info.sha256.size() == 64;
        const char* latest_sha = info.sha256.c_str();
        const bool have_cache = FileHasData(cached) && ValidPeFile(cached);

        // cache only skips download when sha proves it is latest; unknown sha = redownload
        if (have_cache && got_sha)
        {
            char local_sha[65] = {};
            if (Sha256File(cached, local_sha) && _stricmp(local_sha, latest_sha) == 0)
            {
                lstrcpynA(out_path, cached, (DWORD)cap);
                return true;
            }
        }

        if (rs == kRelMissing)
        {
            snprintf(err, err_cap, "no %s release on github", target.label);
            return false;
        }

        // versioned asset url matches the sha; releases/latest/download can lag behind api
        char url[512]{};
        if (rs == kRelOk && info.url.rfind("https://", 0) == 0)
            lstrcpynA(url, info.url.c_str(), (int)sizeof(url));
        else
            snprintf(url, sizeof(url), "https://github.com/%s/releases/latest/download/%s", target.repo, kBotoxDllName);

        char part[MAX_PATH * 2 + 8]{};
        snprintf(part, sizeof(part), "%s.part", cached);
        DeleteFileA(part);

        if (DownloadToFile(url, part) && FileHasData(part) && ValidPeFile(part))
        {
            if (got_sha)
            {
                char downloaded_sha[65] = {};
                if (!Sha256File(part, downloaded_sha) || _stricmp(downloaded_sha, latest_sha) != 0)
                {
                    DeleteFileA(part);
                    lstrcpynA(err, "download sha256 mismatch", (int)err_cap);
                    return false;
                }
            }
            bool moved = MoveFileExA(part, cached, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
            if (!moved)
            {
                // old dll still loaded in game = file locked, but rename works on mapped images
                char old[MAX_PATH * 2 + 8]{};
                snprintf(old, sizeof(old), "%s.old", cached);
                DeleteFileA(old);
                if (MoveFileExA(cached, old, MOVEFILE_REPLACE_EXISTING))
                {
                    moved = MoveFileExA(part, cached, MOVEFILE_WRITE_THROUGH) != 0;
                    if (moved) DeleteFileA(old);
                    else MoveFileExA(old, cached, 0);
                }
            }
            if (moved)
            {
                lstrcpynA(out_path, cached, (DWORD)cap);
                return true;
            }
        }
        DeleteFileA(part);

        // newer release known = never fall back to old dll; only offline may use cache
        if (have_cache && !got_sha)
        {
            lstrcpynA(out_path, cached, (DWORD)cap);
            return true;
        }
        snprintf(err, err_cap, got_sha ? "failed to update %s" : "failed to download %s", target.label);
        return false;
    }

    struct target_patch
    {
        uintptr_t address;
        BYTE      saved[16];
        SIZE_T    length;
    };

    std::string TargetSystemDllPath(const char* module, bool target64)
    {
        char win[MAX_PATH] = {};
        if (!GetWindowsDirectoryA(win, MAX_PATH)) return std::string();
        if (!target64)
        {
            char wow[MAX_PATH] = {};
            snprintf(wow, sizeof(wow), "%s\\SysWOW64\\%s", win, module);
            if (GetFileAttributesA(wow) != INVALID_FILE_ATTRIBUTES) return wow;
        }
        char sys[MAX_PATH] = {};
        if (!GetSystemDirectoryA(sys, MAX_PATH)) return std::string();
        char full[MAX_PATH * 2] = {};
        snprintf(full, sizeof(full), "%s\\%s", sys, module);
        return full;
    }

    bool ReadFileBytesAtRva(const char* path, DWORD rva, void* out, SIZE_T length)
    {
        HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;

        const DWORD size = GetFileSize(file, nullptr);
        if (size == INVALID_FILE_SIZE || size < sizeof(IMAGE_DOS_HEADER) || size > (64u << 20))
        {
            CloseHandle(file);
            return false;
        }

        std::vector<BYTE> data(size);
        DWORD read = 0;
        const bool read_ok = ReadFile(file, data.data(), size, &read, nullptr) && read == size;
        CloseHandle(file);
        if (!read_ok) return false;

        const auto* dos = (const IMAGE_DOS_HEADER*)data.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            (size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > size)
            return false;

        const size_t nt = (size_t)dos->e_lfanew;
        if (*(const DWORD*)(data.data() + nt) != IMAGE_NT_SIGNATURE) return false;

        const auto* fh = (const IMAGE_FILE_HEADER*)(data.data() + nt + 4);
        const size_t sec_off = nt + 4 + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader;
        if (sec_off + (size_t)fh->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > size) return false;

        const auto* sec = (const IMAGE_SECTION_HEADER*)(data.data() + sec_off);
        for (WORD i = 0; i < fh->NumberOfSections; ++i)
        {
            const IMAGE_SECTION_HEADER& s = sec[i];
            DWORD span = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            if (rva < s.VirtualAddress || rva >= s.VirtualAddress + span) continue;

            const DWORD delta = rva - s.VirtualAddress;
            if (delta >= s.SizeOfRawData || (size_t)s.PointerToRawData + delta + length > size) return false;

            memcpy(out, data.data() + s.PointerToRawData + delta, length);
            return true;
        }
        return false;
    }

    bool RemoteExportRaw(HANDLE process, uintptr_t base, bool target64, const char* func,
                         DWORD& rva, bool& forwarded)
    {
        IMAGE_DOS_HEADER dos{};
        if (!mmap::ReadMem(process, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;

        DWORD sig = 0;
        if (!mmap::ReadMem(process, base + dos.e_lfanew, &sig, sizeof(sig)) || sig != IMAGE_NT_SIGNATURE) return false;

        const uintptr_t opt = base + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
        DWORD exp_rva = 0, exp_size = 0;
        if (target64)
        {
            IMAGE_OPTIONAL_HEADER64 oh{};
            if (!mmap::ReadMem(process, opt, &oh, sizeof(oh))) return false;
            exp_rva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exp_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        else
        {
            IMAGE_OPTIONAL_HEADER32 oh{};
            if (!mmap::ReadMem(process, opt, &oh, sizeof(oh))) return false;
            exp_rva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exp_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (!exp_rva || exp_size == 0) return false;

        IMAGE_EXPORT_DIRECTORY ed{};
        if (!mmap::ReadMem(process, base + exp_rva, &ed, sizeof(ed))) return false;
        if (!ed.NumberOfNames || ed.NumberOfNames > 8192 || !ed.AddressOfFunctions ||
            !ed.AddressOfNames || !ed.AddressOfNameOrdinals) return false;

        for (DWORD i = 0; i < ed.NumberOfNames; ++i)
        {
            DWORD name_rva = 0;
            if (!mmap::ReadMem(process, base + ed.AddressOfNames + (uintptr_t)i * 4, &name_rva, 4) || !name_rva) continue;

            char name[256] = {};
            if (!mmap::ReadRemoteCStr(process, base + name_rva, name, sizeof(name))) continue;
            if (strcmp(name, func) != 0) continue;

            WORD ordinal = 0;
            if (!mmap::ReadMem(process, base + ed.AddressOfNameOrdinals + (uintptr_t)i * 2, &ordinal, 2)) return false;
            if (ordinal >= ed.NumberOfFunctions) return false;

            DWORD fn_rva = 0;
            if (!mmap::ReadMem(process, base + ed.AddressOfFunctions + (uintptr_t)ordinal * 4, &fn_rva, 4) || !fn_rva) return false;

            forwarded = fn_rva >= exp_rva && fn_rva < exp_rva + exp_size;
            rva = fn_rva;
            return true;
        }
        return false;
    }

    SIZE_T HookLength(const BYTE* b)
    {
        if (b[0] == 0xE9) return 6;
        if (b[0] == 0xEB) return 5;
        if (b[0] == 0x68 && b[5] == 0xC3) return 6;
        if (b[0] == 0xB8 && b[5] == 0xFF && b[6] == 0xE0) return 7;
        if ((b[0] == 0x48 || b[0] == 0x49) && b[1] >= 0xB8 && b[1] <= 0xBF &&
            b[10] == 0xFF && (b[11] & 0xF8) == 0xE0) return 12;
        if (b[0] == 0xFF && b[1] == 0x25) return 6;
        return 0;
    }

    void PatchTargetFunction(HANDLE process, bool target64, const char* module, const char* func,
                             std::vector<target_patch>& patches)
    {
        const uintptr_t base = (uintptr_t)mmap::RemoteModuleBase(process, target64, module, nullptr);
        if (!base) return;

        DWORD rva = 0;
        bool forwarded = false;
        if (!RemoteExportRaw(process, base, target64, func, rva, forwarded) || forwarded) return;

        BYTE remote[16] = {};
        const uintptr_t address = base + rva;
        if (!ReadProcessMemory(process, (LPCVOID)address, remote, sizeof(remote), nullptr)) return;

        SIZE_T length = HookLength(remote);
        if (length == 0)
        {
            BYTE clean[5] = {};
            const std::string path = TargetSystemDllPath(module, target64);
            if (path.empty() || !ReadFileBytesAtRva(path.c_str(), rva, clean, sizeof(clean))) return;
            if (!memcmp(remote, clean, sizeof(clean))) return;
            length = sizeof(clean);
        }

        const std::string path = TargetSystemDllPath(module, target64);
        if (path.empty()) return;

        BYTE clean[16] = {};
        if (!ReadFileBytesAtRva(path.c_str(), rva, clean, length)) return;
        if (!memcmp(remote, clean, length)) return;

        DWORD old = 0;
        if (!VirtualProtectEx(process, (LPVOID)address, length, PAGE_EXECUTE_READWRITE, &old)) return;
        const BOOL wrote = WriteProcessMemory(process, (LPVOID)address, clean, length, nullptr);
        VirtualProtectEx(process, (LPVOID)address, length, old, &old);
        if (!wrote) return;

        FlushInstructionCache(process, (LPCVOID)address, length);

        target_patch patch{};
        patch.address = address;
        patch.length = length;
        memcpy(patch.saved, remote, length);
        patches.push_back(patch);
    }

    void UnhookTargetLoader(HANDLE process, bool target64, std::vector<target_patch>& patches)
    {
        static const char* modules[] = { "kernel32.dll", "kernelbase.dll", "ntdll.dll" };
        static const char* funcs[] =
        {
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "FreeLibrary", "LdrLoadDll", "NtOpenFile"
        };

        for (const char* module : modules)
        {
            const uintptr_t base = (uintptr_t)mmap::RemoteModuleBase(process, target64, module, nullptr);
            if (!base) continue;
            for (const char* func : funcs)
                PatchTargetFunction(process, target64, module, func, patches);
        }
    }

    void RestoreTargetPatches(HANDLE process, std::vector<target_patch>& patches)
    {
        for (const target_patch& patch : patches)
        {
            DWORD old = 0;
            if (VirtualProtectEx(process, (LPVOID)patch.address, patch.length,
                                 PAGE_EXECUTE_READWRITE, &old))
            {
                WriteProcessMemory(process, (LPVOID)patch.address, patch.saved, patch.length, nullptr);
                VirtualProtectEx(process, (LPVOID)patch.address, patch.length, old, &old);
                FlushInstructionCache(process, (LPCVOID)patch.address, patch.length);
            }
        }
        patches.clear();
    }

    struct UnhookScope
    {
        HANDLE process = nullptr;
        std::vector<target_patch> patches;

        bool Begin(DWORD pid)
        {
            process = OpenProcess(kProcessAccess, FALSE, pid);
            if (!process) return false;
            const bool target64 = mmap::TargetIs64(process);
            UnhookTargetLoader(process, target64, patches);
            return true;
        }

        ~UnhookScope()
        {
            if (process)
            {
                RestoreTargetPatches(process, patches);
                CloseHandle(process);
            }
        }
    };

    bool ManualMapInject(DWORD process_id, const char* dll_path, char* err, size_t err_cap)
    {
        UnhookScope hook;
        hook.Begin(process_id);

        mmap::map_config cfg;
        cfg.wipe_headers = true;
        cfg.run_tls      = true;
        cfg.allow_crt    = true;
        cfg.try_hijack   = true;
        cfg.timeout_ms   = 30000;

        mmap::map_result r = mmap::map_dll(process_id, dll_path, cfg);
        if (r.ok) return true;

        if (err && err_cap)
            lstrcpynA(err, r.message[0] ? r.message : "manual map failed", (int)err_cap);
        return false;
    }

    DWORD FindProcessId(const wchar_t* process_name)
    {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        DWORD pid = 0;
        if (Process32FirstW(hSnapshot, &pe32))
        {
            do
            {
                if (_wcsicmp(pe32.szExeFile, process_name) == 0)
                {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        return pid;
    }

    struct enum_ctx { DWORD pid; HWND hwnd; };
    BOOL CALLBACK EnumGameWindowProc(HWND hwnd, LPARAM lp)
    {
        auto* c = (enum_ctx*)lp;
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid != c->pid) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        RECT rc{};
        if (!GetClientRect(hwnd, &rc)) return TRUE;
        if ((rc.right - rc.left) < 128 || (rc.bottom - rc.top) < 128) return TRUE;
        c->hwnd = hwnd;
        return FALSE;
    }

    HWND FindGameWindow(DWORD pid)
    {
        enum_ctx c{ pid, nullptr };
        EnumWindows(EnumGameWindowProc, (LPARAM)&c);
        return c.hwnd;
    }

    bool RemoteHasModule(DWORD pid, const char* module)
    {
        HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!p) return false;
        const bool target64 = mmap::TargetIs64(p);
        bool found = false;
        if (!(target64 && !mmap::OurProcessIs64()))
            found = mmap::RemoteModuleBase(p, target64, module, nullptr) != 0;
        CloseHandle(p);
        return found;
    }

    bool FindValveWindow(DWORD pid)
    {
        const HWND hwnd = FindWindowA("Valve001", nullptr);
        if (!hwnd) return false;
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        return wpid == pid;
    }

    bool IsGameReady(DWORD pid)
    {
        if (!FindGameWindow(pid) && !FindValveWindow(pid)) return false;
        if (!RemoteHasModule(pid, "client.dll")) return false;
        if (!RemoteHasModule(pid, "engine.dll") && !RemoteHasModule(pid, "engine2.dll")) return false;
        return true;
    }

    static WORD DllMachine(const char* path)
    {
        HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return 0;
        WORD machine = 0;
        IMAGE_DOS_HEADER dos{};
        DWORD read = 0;
        if (ReadFile(file, &dos, sizeof(dos), &read, nullptr) && dos.e_magic == IMAGE_DOS_SIGNATURE)
        {
            SetFilePointer(file, dos.e_lfanew + 4, nullptr, FILE_BEGIN);
            ReadFile(file, &machine, sizeof(machine), &read, nullptr);
        }
        CloseHandle(file);
        return machine;
    }

    bool StandardInject(DWORD process_id, const char* dll_path, char* err = nullptr, size_t err_cap = 0)
    {
        HANDLE process = OpenProcess(kProcessAccess, FALSE, process_id);
        if (!process || process == INVALID_HANDLE_VALUE)
        {
            if (err && err_cap) snprintf(err, err_cap, "OpenProcess failed (%lu)", GetLastError());
            return false;
        }

#ifdef _WIN64
        BOOL wow64 = FALSE;
        const bool cross_arch = IsWow64Process(process, &wow64) && wow64;
#else
        const bool cross_arch = false;
        BOOL wow64 = FALSE;
        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);
        if (IsWow64Process(process, &wow64) && !wow64 && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            if (err && err_cap) lstrcpynA(err, "64-bit target needs the x64 loader", (int)err_cap);
            CloseHandle(process);
            return false;
        }
#endif

        UnhookScope hook;
        hook.Begin(process_id);

        const WORD expected = cross_arch ? IMAGE_FILE_MACHINE_I386 :
#ifdef _WIN64
                              IMAGE_FILE_MACHINE_AMD64;
#else
                              IMAGE_FILE_MACHINE_I386;
#endif
        const WORD machine = DllMachine(dll_path);
        if (machine && machine != expected)
        {
            if (err && err_cap) snprintf(err, err_cap, "wrong dll bitness (0x%04x)", machine);
            CloseHandle(process);
            return false;
        }

        uintptr_t load_library = 0;
        if (cross_arch)
        {
            const uintptr_t kernel32 = (uintptr_t)mmap::RemoteModuleBase(process, false, "kernel32.dll", nullptr);
            if (!kernel32)
            {
                if (err && err_cap) lstrcpynA(err, "32-bit kernel32 not found", (int)err_cap);
                CloseHandle(process);
                return false;
            }
            load_library = (uintptr_t)mmap::RemoteProcByName(process, kernel32, "LoadLibraryA", false, 0);
            if (!load_library)
            {
                if (err && err_cap) lstrcpynA(err, "32-bit LoadLibraryA not found", (int)err_cap);
                CloseHandle(process);
                return false;
            }
        }
        else
        {
            load_library = (uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        }

        if (!load_library || (cross_arch && load_library > 0xFFFFFFFFull))
        {
            if (err && err_cap) lstrcpynA(err, "LoadLibraryA address invalid", (int)err_cap);
            CloseHandle(process);
            return false;
        }

        const SIZE_T path_length = strlen(dll_path) + 1;
        LPVOID remote_path = VirtualAllocEx(process, nullptr, path_length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!remote_path)
        {
            if (err && err_cap) snprintf(err, err_cap, "VirtualAllocEx failed (%lu)", GetLastError());
            CloseHandle(process);
            return false;
        }

        if (cross_arch && (uintptr_t)remote_path > 0xFFFFFFFFull)
        {
            if (err && err_cap) lstrcpynA(err, "remote allocation outside 32-bit", (int)err_cap);
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            CloseHandle(process);
            return false;
        }

        if (!WriteProcessMemory(process, remote_path, dll_path, path_length, nullptr))
        {
            if (err && err_cap) snprintf(err, err_cap, "WriteProcessMemory failed (%lu)", GetLastError());
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            CloseHandle(process);
            return false;
        }

        HANDLE remote_thread = CreateRemoteThread(
            process,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)load_library,
            remote_path,
            0,
            nullptr
        );

        if (!remote_thread || remote_thread == INVALID_HANDLE_VALUE)
        {
            if (err && err_cap) snprintf(err, err_cap, "CreateRemoteThread failed (%lu)", GetLastError());
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            CloseHandle(process);
            return false;
        }

        const DWORD wait_result = WaitForSingleObject(remote_thread, 30000);
        if (wait_result == WAIT_TIMEOUT)
        {
            if (err && err_cap) lstrcpynA(err, "LoadLibraryA timed out", (int)err_cap);
            CloseHandle(remote_thread);
            CloseHandle(process);
            return false;
        }

        DWORD exit_code = 0;
        GetExitCodeThread(remote_thread, &exit_code);
        const bool thread_crashed = exit_code >= 0x80000000u;

        if (thread_crashed && err && err_cap)
            snprintf(err, err_cap, "LoadLibraryA thread crashed (0x%08lx)", exit_code);
        else if (exit_code == 0 && err && err_cap)
            snprintf(err, err_cap, "LoadLibraryA returned 0");

        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(remote_thread);
        CloseHandle(process);
        return exit_code != 0 && !thread_crashed;
    }
}

static ImFont* g_font_ui = nullptr;
static ImFont* g_font_bold = nullptr;
static ImFont* g_font_icon = nullptr;
enum { kIconGithub, kIconClose, kIconMinimize, kIconCount };
static int g_icon_rect[kIconCount] = { -1, -1, -1 };

static const float kCloseIconPoints[] =
{
    8.382f, 17.025f, 6.975f, 15.625f, 10.593f, 12.0f, 6.975f, 8.4f, 8.382f, 7.0f, 12.0f, 10.615f,
    15.593f, 7.0f, 17.0f, 8.4f, 13.382f, 12.0f, 17.0f, 15.625f, 15.593f, 17.025f, 12.0f, 13.41f,
};

// baseline-minimize moved up from y 19..21 so its bottom sits on the close glyph's bottom
static const float kMinimizeIconPoints[] = { 6.0f, 15.025f, 18.0f, 15.025f, 18.0f, 17.025f, 6.0f, 17.025f };

constexpr const char* kLoaderRepoUrl = "https://github.com/gumballpanties-sudo/botox-loader";

static float g_dpi = 100.0f;
static float g_accent[3] = { 129 / 255.0f, 99 / 255.0f, 251 / 255.0f };

static float g_scale = 1.0f;
static float kBandH, kBottomBandH, kPad, kGap, kItemH, kRounding, kWindowRounding;

static float S(float v) { return v * g_scale; }

static void UpdateMetrics()
{
    g_scale = g_dpi / 100.0f;
    kBandH = ImFloor(S(25.0f));
    kBottomBandH = ImFloor(S(12.0f));
    kPad = ImFloor(S(8.0f));
    kGap = ImFloor(S(6.0f));
    kItemH = ImFloor(S(24.0f));
    kRounding = S(3.0f);
    kWindowRounding = S(5.0f);
}

static int WindowW() { return (int)ImFloor(S(260.0f)); }

static float ChromeButtonW() { return ImFloor(S(22.0f)); }

static float ChromeButtonX(float right_edge, int index)
{
    return right_edge - ImFloor(S(4.0f)) - ChromeButtonW() * (float)(index + 1);
}

static int WindowH()
{
    return (int)(kBandH + kPad + (kPad * 2.0f + kItemH * kTargetCount + kGap * (kTargetCount - 1)) + kPad + kItemH + kPad + kBottomBandH);
}

static bool ConfigPath(char* out, size_t cap)
{
    char ap[MAX_PATH]{};
    if (!GetEnvironmentVariableA("APPDATA", ap, MAX_PATH)) return false;
    snprintf(out, cap, "%s\\botox", ap);
    CreateDirectoryA(out, nullptr);
    const size_t len = strlen(out);
    snprintf(out + len, cap - len, "\\loader.cfg");
    return true;
}

static void LoadSettings()
{
    char path[MAX_PATH * 2]{};
    FILE* f = nullptr;
    if (!ConfigPath(path, sizeof(path)) || fopen_s(&f, path, "r") != 0 || !f) return;

    char line[128];
    while (fgets(line, sizeof(line), f))
    {
        float dpi = 0.0f;
        int r = 0, g = 0, b = 0;
        if (sscanf_s(line, "dpi=%f", &dpi) == 1)
            g_dpi = ImClamp(dpi, 25.0f, 200.0f);
        else if (sscanf_s(line, "accent=%d %d %d", &r, &g, &b) == 3)
        {
            g_accent[0] = ImClamp(r, 0, 255) / 255.0f;
            g_accent[1] = ImClamp(g, 0, 255) / 255.0f;
            g_accent[2] = ImClamp(b, 0, 255) / 255.0f;
        }
    }
    fclose(f);
}

static void SaveSettings()
{
    char path[MAX_PATH * 2]{};
    FILE* f = nullptr;
    if (!ConfigPath(path, sizeof(path)) || fopen_s(&f, path, "w") != 0 || !f) return;
    fprintf(f, "dpi=%.0f\naccent=%d %d %d\n", g_dpi,
            (int)(g_accent[0] * 255.0f + 0.5f), (int)(g_accent[1] * 255.0f + 0.5f), (int)(g_accent[2] * 255.0f + 0.5f));
    fclose(f);
}

static ImU32 Fade(ImU32 col, float alpha)
{
    const ImU32 a = (ImU32)((float)((col >> IM_COL32_A_SHIFT) & 0xFF) * ImClamp(alpha, 0.0f, 1.0f));
    return (col & ~IM_COL32_A_MASK) | (a << IM_COL32_A_SHIFT);
}

static void DrawIcon(ImDrawList* dl, int icon, const ImVec2& box_min, const ImVec2& box_size, ImU32 col)
{
    ImFontAtlas* atlas = ImGui::GetIO().Fonts;
    const ImFontAtlasCustomRect* r = g_icon_rect[icon] >= 0 ? atlas->GetCustomRectByIndex(g_icon_rect[icon]) : nullptr;
    if (!r) return;

    ImVec2 uv0, uv1;
    atlas->CalcCustomRectUV(r, &uv0, &uv1);
    const float sz = (float)r->Width;
    const ImVec2 o(ImFloor(box_min.x + (box_size.x - sz) * 0.5f), ImFloor(box_min.y + (box_size.y - sz) * 0.5f));
    dl->AddImage(atlas->TexID, o, ImVec2(o.x + sz, o.y + sz), uv0, uv1, col);
}

static ImFont* LoadFont(ImGuiIO& io, const char* file, float size)
{
    ImFontConfig cfg;
    cfg.FontBuilderFlags = g_dpi == 100.0f ? ImGuiFreeTypeBuilderFlags_Monochrome | ImGuiFreeTypeBuilderFlags_MonoHinting
                                           : ImGuiFreeTypeBuilderFlags_LightHinting;

    char path[MAX_PATH * 2]{};
    char win[MAX_PATH]{};
    GetWindowsDirectoryA(win, MAX_PATH);
    snprintf(path, sizeof(path), "%s\\Fonts\\%s", win, file);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES)
        if (ImFont* font = io.Fonts->AddFontFromFileTTF(path, size, &cfg))
            return font;

    cfg.SizePixels = size;
    return io.Fonts->AddFontDefault(&cfg);
}

static ImU32 AccentCol(float alpha)
{
    return ImGui::ColorConvertFloat4ToU32(ImVec4(g_accent[0], g_accent[1], g_accent[2], ImClamp(alpha, 0.0f, 1.0f)));
}

static ImU32 TextCol(float hover, float lit)
{
    const float a = 0.5f + 0.5f * hover;
    return ImGui::ColorConvertFloat4ToU32(ImVec4(ImLerp(1.0f, g_accent[0], lit), ImLerp(1.0f, g_accent[1], lit),
                                                 ImLerp(1.0f, g_accent[2], lit), a + (1.0f - a) * lit));
}

static void FadedLine(ImDrawList* dl, float x, float y, float w, float alpha)
{
    if (alpha <= 0.001f) return;
    const ImU32 c = AccentCol(alpha);
    const ImU32 z = AccentCol(0.0f);
    const float mid = x + w * 0.5f;
    dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(mid, y + 1.0f), z, c, c, z);
    dl->AddRectFilledMultiColor(ImVec2(mid, y), ImVec2(x + w, y + 1.0f), c, z, z, c);
}

static void AddShimmerText(ImDrawList* dl, ImFont* font, const ImVec2& pos, const char* text)
{
    float w = 0.5f + 0.5f * std::sin((float)ImGui::GetTime() * 2.8f);
    w = w * w * (3.0f - 2.0f * w);
    const ImU32 col = IM_COL32((int)(145.0f + 101.0f * w), (int)(149.0f + 99.0f * w), (int)(158.0f + 94.0f * w), 240);
    dl->AddText(font, font->FontSize, pos, col, text);
}

static bool  g_window_dragging = false;
static POINT g_window_drag_offset{};
static POINT g_window_drag_start{};
static bool  g_window_drag_prev_down = false;
static bool  g_win_smooth_init = false;
static float g_win_pos_x = 0.0f;
static float g_win_pos_y = 0.0f;
static float g_win_target_x = 0.0f;
static float g_win_target_y = 0.0f;

static void HandleWindowDrag(HWND hwnd, const ImVec2& local_min, const ImVec2& local_max, bool allow_start = true)
{
    POINT cur{};
    ::GetCursorPos(&cur);

    RECT wr{};
    ::GetWindowRect(hwnd, &wr);

    if (!g_win_smooth_init)
    {
        g_win_pos_x = (float)wr.left;
        g_win_pos_y = (float)wr.top;
        g_win_target_x = (float)wr.left;
        g_win_target_y = (float)wr.top;
        g_win_smooth_init = true;
    }

    const bool down = (::GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    const bool just_pressed = down && !g_window_drag_prev_down;
    g_window_drag_prev_down = down;

    const bool inside = cur.x >= wr.left + (LONG)local_min.x && cur.x < wr.left + (LONG)local_max.x &&
                        cur.y >= wr.top + (LONG)local_min.y && cur.y < wr.top + (LONG)local_max.y;

    if (!g_window_dragging && just_pressed && inside && allow_start)
    {
        g_window_dragging = true;
        g_window_drag_start = cur;
        g_window_drag_offset.x = cur.x - wr.left;
        g_window_drag_offset.y = cur.y - wr.top;
        g_win_pos_x = (float)wr.left;
        g_win_pos_y = (float)wr.top;
        g_win_target_x = (float)wr.left;
        g_win_target_y = (float)wr.top;
    }

    if (g_window_dragging)
    {
        if (!down)
        {
            g_window_dragging = false;
        }
        else
        {
            g_win_target_x = (float)(cur.x - g_window_drag_offset.x);
            g_win_target_y = (float)(cur.y - g_window_drag_offset.y);
        }
    }

    const float dt = ImClamp(ImGui::GetIO().DeltaTime, 0.001f, 0.05f);
    const bool needs_move = g_window_dragging ||
                            fabsf(g_win_pos_x - g_win_target_x) > 0.1f ||
                            fabsf(g_win_pos_y - g_win_target_y) > 0.1f;

    if (needs_move)
    {
        const float speed = 28.0f;
        g_win_pos_x = Approach(g_win_pos_x, g_win_target_x, speed, dt);
        g_win_pos_y = Approach(g_win_pos_y, g_win_target_y, speed, dt);

        if (!g_window_dragging &&
            fabsf(g_win_pos_x - g_win_target_x) < 0.25f &&
            fabsf(g_win_pos_y - g_win_target_y) < 0.25f)
        {
            g_win_pos_x = g_win_target_x;
            g_win_pos_y = g_win_target_y;
        }

        const int nx = (int)std::lround(g_win_pos_x);
        const int ny = (int)std::lround(g_win_pos_y);

        if (nx != wr.left || ny != wr.top)
        {
            ::SetWindowPos(hwnd, nullptr, nx, ny, 0, 0,
                           SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }
}

static ID3D11Device*           g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dContext = nullptr;
static IDXGISwapChain*         g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static bool g_running = true;
static bool g_closing = false;
static float g_fade = 0.0f;

constexpr float kAnimDuration = 0.25f;

static bool g_settings_open = false;
static float g_settings_fade = 0.0f;
static bool g_scale_dirty = false;

static int g_target = 0;
static volatile LONG g_release_state[kTargetCount] = {};
static char g_release_date[kTargetCount][32] = {};

static bool g_injecting = false;
static volatile LONG g_inject_state = 0;
static const char* volatile g_inject_stage = "";
static char g_inject_err[256] = {};
static float g_inject_ok_at = 0.0f;

static DWORD WINAPI ReleaseInfoThread(LPVOID param)
{
    const int i = (int)(INT_PTR)param;
    release::asset_info info;
    const release_state rs = FetchRelease(kTargets[i].repo, info);
    if (rs == kRelOk)
        lstrcpynA(g_release_date[i], release::short_date(info.updated_at).c_str(), (int)sizeof(g_release_date[i]));
    InterlockedExchange(&g_release_state[i], rs);
    return 0;
}

static const char* ReleaseLabel(int i)
{
    switch (InterlockedCompareExchange(&g_release_state[i], 0, 0))
    {
    case kRelOk:      return g_release_date[i];
    case kRelMissing: return "no release";
    case kRelOffline: return "offline";
    default:          return "...";
    }
}

static DWORD WINAPI InjectionWorkerThread(LPVOID param)
{
    const int ti = (int)(INT_PTR)param;
    const target_t& target = kTargets[ti];

    g_inject_stage = "downloading";
    char dll_path[MAX_PATH * 2] = {};
    if (!EnsureBotoxDll(target, dll_path, sizeof(dll_path), g_inject_err, sizeof(g_inject_err)))
    {
        InterlockedExchange(&g_inject_state, 3);
        return 0;
    }

    g_inject_stage = "waiting for game";
    DWORD pid = FindProcessId(target.exe);
    if (pid == 0)
    {
        g_inject_stage = "start the game";
        for (int i = 0; i < 1800 && pid == 0; ++i)
        {
            Sleep(100);
            pid = FindProcessId(target.exe);
        }
    }

    if (pid == 0)
    {
        snprintf(g_inject_err, sizeof(g_inject_err), "%ls process not found", target.exe);
        InterlockedExchange(&g_inject_state, 3);
        return 0;
    }

    bool ready = false;
    for (int i = 0; i < 900; ++i)
    {
        DWORD cur_pid = FindProcessId(target.exe);
        if (cur_pid != 0 && cur_pid != pid)
            pid = cur_pid;

        if (IsGameReady(pid))
        {
            ready = true;
            break;
        }
        Sleep(100);
    }

    if (!ready)
    {
        lstrcpynA(g_inject_err, "game did not become ready", sizeof(g_inject_err));
        InterlockedExchange(&g_inject_state, 3);
        return 0;
    }

    Sleep(300);
    g_inject_stage = "injecting";

    char map_err[256] = {};
    bool ok = target.manual_map && ManualMapInject(pid, dll_path, map_err, sizeof(map_err));
    if (!ok)
    {
        char std_err[256] = {};
        if (StandardInject(pid, dll_path, std_err, sizeof(std_err)))
        {
            ok = true;
        }
        else if (target.manual_map)
        {
            snprintf(g_inject_err, sizeof(g_inject_err), "map: %s | std: %s",
                     map_err[0] ? map_err : "failed",
                     std_err[0] ? std_err : "failed");
        }
        else
        {
            snprintf(g_inject_err, sizeof(g_inject_err), "std: %s", std_err[0] ? std_err : "failed");
        }
    }

    InterlockedExchange(&g_inject_state, ok ? 2 : 3);
    return 0;
}

static void RequestClose()
{
    g_closing = true;
}

static void DrawChrome(HWND hwnd)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetWindowPos();
    const ImVec2 s = ImGui::GetWindowSize();
    const float dt = ImGui::GetIO().DeltaTime;
    static float s_hover[3] = {};

    dl->AddRectFilled(p, ImVec2(p.x + s.x, p.y + s.y), IM_COL32(10, 10, 10, 255), kWindowRounding);
    dl->AddRectFilled(p, ImVec2(p.x + s.x, p.y + kBandH), IM_COL32(25, 25, 25, 255), kWindowRounding, ImDrawFlags_RoundCornersTop);
    FadedLine(dl, p.x, p.y + kBandH - 1.0f, s.x, 1.0f);
    dl->AddRectFilled(ImVec2(p.x, p.y + s.y - kBottomBandH), ImVec2(p.x + s.x, p.y + s.y), IM_COL32(25, 25, 25, 255),
                      kWindowRounding, ImDrawFlags_RoundCornersBottom);
    FadedLine(dl, p.x, p.y + s.y - kBottomBandH, s.x, 1.0f);
    dl->AddRect(p, ImVec2(p.x + s.x, p.y + s.y), IM_COL32(50, 50, 50, 255), kWindowRounding);

    const char* title = "botox";
    const char* suffix = " | loader";
    const ImVec2 ts = g_font_bold->CalcTextSizeA(g_font_bold->FontSize, FLT_MAX, 0.0f, title);
    const ImVec2 ss = g_font_ui->CalcTextSizeA(g_font_ui->FontSize, FLT_MAX, 0.0f, suffix);
    const float tx = ImFloor(p.x + (s.x - ts.x - ss.x) * 0.5f);
    const float ty = ImFloor(p.y + (kBandH - ts.y) * 0.5f);
    dl->AddText(g_font_bold, g_font_bold->FontSize, ImVec2(tx, ty), IM_COL32(255, 255, 255, 255), title);
    dl->AddText(g_font_ui, g_font_ui->FontSize, ImVec2(tx + ts.x, ty), AccentCol(1.0f), suffix);

    bool any_hover = false;
    {
        static float s_gh_hover = 0.0f;
        const ImVec2 gmin(p.x + ImFloor(S(4.0f)), p.y);
        const ImVec2 gmax(gmin.x + ChromeButtonW(), p.y + kBandH - 1.0f);
        const bool hov = ImGui::IsMouseHoveringRect(gmin, gmax, false);
        any_hover |= hov;
        s_gh_hover = Approach(s_gh_hover, hov ? 1.0f : 0.0f, 18.0f, dt);

        const int v = (int)(190.0f + 65.0f * s_gh_hover);
        DrawIcon(dl, kIconGithub, gmin, ImVec2(ChromeButtonW(), kBandH), IM_COL32(v, v, v, 255));

        if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            ::ShellExecuteA(nullptr, "open", kLoaderRepoUrl, nullptr, nullptr, SW_SHOWNORMAL);
    }

    for (int i = 0; i < 3; ++i)
    {
        const ImVec2 bmin(ChromeButtonX(p.x + s.x, i), p.y);
        const ImVec2 bmax(bmin.x + ChromeButtonW(), p.y + kBandH - 1.0f);
        const bool hov = ImGui::IsMouseHoveringRect(bmin, bmax, false);
        any_hover |= hov;
        s_hover[i] = Approach(s_hover[i], (hov || (i == 2 && g_settings_open)) ? 1.0f : 0.0f, 18.0f, dt);

        const int v = (int)(190.0f + 65.0f * s_hover[i]);
        const ImU32 col = IM_COL32(v, v, v, 255);
        if (i < 2)
        {
            DrawIcon(dl, i == 0 ? kIconClose : kIconMinimize, bmin, ImVec2(ChromeButtonW(), kBandH), col);
        }
        else
        {
            const char* cog = "\xef\x80\x93";
            const ImVec2 cs = g_font_icon->CalcTextSizeA(g_font_icon->FontSize, FLT_MAX, 0.0f, cog);
            dl->AddText(g_font_icon, g_font_icon->FontSize,
                        ImVec2(ImFloor(bmin.x + (ChromeButtonW() - cs.x) * 0.5f), ImFloor(bmin.y + (kBandH - cs.y) * 0.5f)), col, cog);
        }

        if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
        {
            if (i == 0) RequestClose();
            else if (i == 1) ::ShowWindow(hwnd, SW_MINIMIZE);
            else g_settings_open = !g_settings_open;
        }
    }

    HandleWindowDrag(hwnd, ImVec2(0.0f, 0.0f), ImVec2(ChromeButtonX(s.x, 2), kBandH), !any_hover);
}

static void DrawStatusScreen(HWND hwnd)
{
    DrawChrome(hwnd);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetWindowPos();
    const ImVec2 s = ImGui::GetWindowSize();

    const LONG state = InterlockedCompareExchange(&g_inject_state, 0, 0);
    const char* text = g_inject_stage;
    const char* sub = kTargets[g_target].label;
    ImU32 sub_col = IM_COL32(120, 120, 120, 255);
    const bool busy = state == 1;

    if (state == 2)
    {
        text = "injected";
        if (g_inject_ok_at == 0.0f)
            g_inject_ok_at = (float)ImGui::GetTime();
        if ((float)ImGui::GetTime() - g_inject_ok_at > 0.8f)
            RequestClose();
    }
    else if (state == 3)
    {
        text = "failed";
        sub = g_inject_err[0] ? g_inject_err : "unknown error";
        sub_col = IM_COL32(230, 110, 110, 240);
    }

    ImFont* main_font = g_font_bold;
    const float wrap_w = s.x - S(30.0f);
    const ImVec2 ms = main_font->CalcTextSizeA(main_font->FontSize, FLT_MAX, 0.0f, text);
    const ImVec2 dots = busy ? main_font->CalcTextSizeA(main_font->FontSize, FLT_MAX, 0.0f, "...") : ImVec2(0.0f, 0.0f);
    const ImVec2 ss = g_font_ui->CalcTextSizeA(g_font_ui->FontSize, FLT_MAX, wrap_w, sub);

    const float gap = S(4.0f);
    const float body_top = p.y + kBandH;
    const float top = ImFloor(body_top + (s.y - kBandH - kBottomBandH - (ms.y + gap + ss.y)) * 0.5f);
    const ImVec2 text_pos(ImFloor(p.x + (s.x - ms.x - dots.x) * 0.5f), top);

    if (busy)
    {
        AddShimmerText(dl, main_font, text_pos, text);
        const float t = (float)ImGui::GetTime();
        float x = text_pos.x + ms.x;
        for (int i = 0; i < 3; ++i)
        {
            const float a = 0.2f + 0.8f * (0.5f + 0.5f * std::cos((t - (float)i * 0.2f) * 6.2832f / 1.2f));
            dl->AddText(main_font, main_font->FontSize, ImVec2(x, text_pos.y), IM_COL32(245, 245, 245, (int)(255.0f * a)), ".");
            x += main_font->CalcTextSizeA(main_font->FontSize, FLT_MAX, 0.0f, ".").x;
        }
    }
    else
    {
        dl->AddText(main_font, main_font->FontSize, text_pos, state == 2 ? AccentCol(1.0f) : IM_COL32(245, 245, 245, 255), text);
    }

    dl->AddText(g_font_ui, g_font_ui->FontSize, ImVec2(ImFloor(p.x + (s.x - ss.x) * 0.5f), top + ms.y + gap),
                sub_col, sub, nullptr, wrap_w);

    const bool body_click = ImGui::IsMouseClicked(ImGuiMouseButton_Left) && ImGui::GetMousePos().y > body_top;
    if (!busy && !g_settings_open && (body_click || ImGui::IsKeyPressed(ImGuiKey_Escape)))
    {
        if (state == 2)
        {
            RequestClose();
        }
        else
        {
            g_injecting = false;
            InterlockedExchange(&g_inject_state, 0);
        }
    }
}

static void DrawGamePanel(HWND hwnd)
{
    DrawChrome(hwnd);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetWindowPos();
    const ImVec2 s = ImGui::GetWindowSize();
    const float dt = ImGui::GetIO().DeltaTime;

    static float s_row_hover[kTargetCount] = {};
    static float s_row_lit[kTargetCount] = {};
    static float s_btn_hover = 0.0f;
    static float s_btn_press = 0.0f;

    const float rounding = kRounding;
    const float row_h = kItemH;
    const float btn_h = kItemH;

    const ImVec2 box_min(p.x + kPad, p.y + kBandH + kPad);
    const ImVec2 box_max(p.x + s.x - kPad, box_min.y + kPad * 2.0f + row_h * (float)kTargetCount + kGap * (float)(kTargetCount - 1));
    dl->AddRectFilled(box_min, box_max, IM_COL32(15, 15, 15, 255), rounding);
    dl->AddRect(box_min, box_max, IM_COL32(50, 50, 50, 100), rounding);

    for (int i = 0; i < kTargetCount; ++i)
    {
        const ImVec2 rmin(box_min.x + kPad, box_min.y + kPad + (float)i * (row_h + kGap));
        const ImVec2 rmax(box_max.x - kPad, rmin.y + row_h);
        const bool hov = !g_settings_open && ImGui::IsMouseHoveringRect(rmin, rmax, false);

        s_row_hover[i] = Approach(s_row_hover[i], hov ? 1.0f : 0.0f, 18.0f, dt);
        s_row_lit[i] = Approach(s_row_lit[i], i == g_target ? 1.0f : 0.0f, 14.0f, dt);

        dl->AddRectFilled(rmin, rmax, IM_COL32(25, 25, 25, 255), rounding);
        dl->AddRect(rmin, rmax, IM_COL32(50, 50, 50, 100), rounding);
        FadedLine(dl, rmin.x, rmax.y - 1.0f, rmax.x - rmin.x, s_row_lit[i]);

        const char* label = kTargets[i].label;
        const ImVec2 ls = g_font_bold->CalcTextSizeA(g_font_bold->FontSize, FLT_MAX, 0.0f, label);
        dl->AddText(g_font_bold, g_font_bold->FontSize, ImVec2(rmin.x + kPad, ImFloor(rmin.y + (row_h - ls.y) * 0.5f)),
                    TextCol(s_row_hover[i], s_row_lit[i]), label);

        const char* date = ReleaseLabel(i);
        const ImVec2 ds = g_font_ui->CalcTextSizeA(g_font_ui->FontSize, FLT_MAX, 0.0f, date);
        dl->AddText(g_font_ui, g_font_ui->FontSize, ImVec2(rmax.x - kPad - ds.x, ImFloor(rmin.y + (row_h - ds.y) * 0.5f)),
                    IM_COL32(120, 120, 120, 255), date);

        if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            g_target = i;
    }

    const ImVec2 bmin(p.x + kPad, box_max.y + kPad);
    const ImVec2 bmax(p.x + s.x - kPad, bmin.y + btn_h);
    const bool hov = !g_settings_open && ImGui::IsMouseHoveringRect(bmin, bmax, false);
    const bool held = hov && ImGui::IsMouseDown(ImGuiMouseButton_Left);
    s_btn_hover = Approach(s_btn_hover, hov ? 1.0f : 0.0f, 18.0f, dt);
    s_btn_press = Approach(s_btn_press, held ? 1.0f : 0.0f, 24.0f, dt);

    const int fill = 25 + (int)(5.0f * s_btn_hover);
    dl->AddRectFilled(bmin, bmax, IM_COL32(fill, fill, fill, 255), rounding);
    dl->AddRect(bmin, bmax, IM_COL32(50, 50, 50, 100), rounding);
    FadedLine(dl, bmin.x, bmax.y - 1.0f, bmax.x - bmin.x, s_btn_hover);

    const char* btn_text = "inject";
    const ImVec2 bs = g_font_bold->CalcTextSizeA(g_font_bold->FontSize, FLT_MAX, 0.0f, btn_text);
    dl->AddText(g_font_bold, g_font_bold->FontSize,
                ImVec2(ImFloor(bmin.x + (bmax.x - bmin.x - bs.x) * 0.5f), ImFloor(bmin.y + (btn_h - bs.y) * 0.5f)),
                TextCol(0.4f + 0.6f * s_btn_hover, s_btn_press), btn_text);

    if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !g_injecting && !g_closing)
    {
        g_injecting = true;
        g_inject_err[0] = 0;
        g_inject_stage = "downloading";
        g_inject_ok_at = 0.0f;
        InterlockedExchange(&g_inject_state, 1);
        HANDLE thread = ::CreateThread(nullptr, 0, InjectionWorkerThread, (LPVOID)(INT_PTR)g_target, 0, nullptr);
        if (thread) CloseHandle(thread);
        else
        {
            lstrcpynA(g_inject_err, "failed to create injection thread", sizeof(g_inject_err));
            InterlockedExchange(&g_inject_state, 3);
        }
    }
}

static void DrawSettings()
{
    const float dt = ImMin(ImGui::GetIO().DeltaTime, 1.0f / 30.0f);
    const float step = dt / (kAnimDuration * 0.5f);
    g_settings_fade = ImClamp(g_settings_fade + (g_settings_open ? step : -step), 0.0f, 1.0f);

    static int s_active = 0;
    static bool s_picker = false;
    static float s_hsv[3] = {};
    static float s_dpi_edit = 100.0f;
    static float s_fill = -1.0f;
    static float s_title = 0.5f, s_acc_hover = 0.0f, s_dpi_hover = 0.0f;

    if (!g_settings_open)
    {
        s_picker = false;
        s_active = 0;
    }
    if (g_settings_fade <= 0.0f) return;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetWindowPos();
    const ImVec2 s = ImGui::GetWindowSize();
    const float a = g_settings_fade;
    const ImVec2 mouse = ImGui::GetMousePos();
    const bool clicked = g_settings_open && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
    const bool down = ImGui::IsMouseDown(ImGuiMouseButton_Left);

    const ImVec2 pmin(p.x + kPad, p.y + kBandH + kPad);
    const ImVec2 pmax(p.x + s.x - kPad, p.y + s.y - kBottomBandH - kPad);
    const float head = ImFloor(S(20.0f));
    const float line_h = g_font_ui->FontSize;

    dl->AddRectFilled(pmin, pmax, Fade(IM_COL32(20, 20, 20, 255), a), kRounding);
    dl->AddRectFilled(pmin, ImVec2(pmax.x, pmin.y + head), Fade(IM_COL32(25, 25, 25, 255), a), kRounding, ImDrawFlags_RoundCornersTop);
    dl->AddRect(pmin, pmax, Fade(IM_COL32(50, 50, 50, 100), a), kRounding);

    const bool panel_hov = ImGui::IsMouseHoveringRect(pmin, pmax, false);
    s_title = Approach(s_title, panel_hov ? 1.0f : 0.5f, 12.0f, dt);
    const char* title = "loader settings";
    const ImVec2 ts = g_font_bold->CalcTextSizeA(g_font_bold->FontSize, FLT_MAX, 0.0f, title);
    dl->AddText(g_font_bold, g_font_bold->FontSize, ImVec2(ImFloor(pmin.x + (pmax.x - pmin.x - ts.x) * 0.5f), ImFloor(pmin.y + (head - ts.y) * 0.5f)),
                IM_COL32(255, 255, 255, (int)(255.0f * s_title * a)), title);
    FadedLine(dl, pmin.x, pmin.y + head, pmax.x - pmin.x, a);

    const float x0 = pmin.x + kPad;
    const float x1 = pmax.x - kPad;
    float y = pmin.y + head + kPad;

    if (s_active == 1 && !down)
    {
        const float dpi = ImFloor(s_dpi_edit + 0.5f);
        if (dpi != g_dpi)
        {
            g_dpi = dpi;
            g_scale_dirty = true;
            SaveSettings();
        }
    }
    if ((s_active == 2 || s_active == 3) && !down)
        SaveSettings();
    if (!down)
        s_active = 0;

    {
        const char* label = "accent color";
        const ImVec2 sw_max(x1, y + line_h - S(1.0f));
        const ImVec2 sw_min(x1 - S(22.0f), sw_max.y - ImFloor(line_h - S(2.0f)));
        const bool hov = g_settings_open && ImGui::IsMouseHoveringRect(ImVec2(x0, y), ImVec2(x1, y + line_h), false);
        s_acc_hover = Approach(s_acc_hover, (hov || s_picker) ? 1.0f : 0.0f, 18.0f, dt);

        dl->AddText(g_font_ui, g_font_ui->FontSize, ImVec2(x0, y), IM_COL32(255, 255, 255, (int)(255.0f * (0.5f + 0.5f * s_acc_hover) * a)), label);
        dl->AddRectFilled(sw_min, sw_max, AccentCol(a), S(2.0f));
        dl->AddRect(sw_min, sw_max, Fade(IM_COL32(50, 50, 50, 100), a), S(2.0f));

        if (hov && clicked && s_active == 0)
        {
            s_picker = !s_picker;
            ImGui::ColorConvertRGBtoHSV(g_accent[0], g_accent[1], g_accent[2], s_hsv[0], s_hsv[1], s_hsv[2]);
        }
        y += line_h + kPad;
    }

    if (s_picker)
    {
        const float hue_w = ImFloor(S(10.0f));
        const ImVec2 sv_min(x0, y);
        const ImVec2 sv_max(x1 - hue_w - kGap, pmax.y - kPad);
        const ImVec2 hue_min(x1 - hue_w, y);
        const ImVec2 hue_max(x1, sv_max.y);

        if (clicked && s_active == 0)
        {
            if (ImGui::IsMouseHoveringRect(sv_min, sv_max, false)) s_active = 2;
            else if (ImGui::IsMouseHoveringRect(hue_min, hue_max, false)) s_active = 3;
        }
        if (s_active == 2)
        {
            s_hsv[1] = ImSaturate((mouse.x - sv_min.x) / (sv_max.x - sv_min.x));
            s_hsv[2] = 1.0f - ImSaturate((mouse.y - sv_min.y) / (sv_max.y - sv_min.y));
        }
        else if (s_active == 3)
        {
            s_hsv[0] = ImMin(ImSaturate((mouse.y - hue_min.y) / (hue_max.y - hue_min.y)), 0.9999f);
        }
        if (s_active == 2 || s_active == 3)
            ImGui::ColorConvertHSVtoRGB(s_hsv[0], s_hsv[1], s_hsv[2], g_accent[0], g_accent[1], g_accent[2]);

        float hr, hg, hb;
        ImGui::ColorConvertHSVtoRGB(s_hsv[0], 1.0f, 1.0f, hr, hg, hb);
        const ImU32 white = Fade(IM_COL32_WHITE, a);
        const ImU32 hue = ImGui::ColorConvertFloat4ToU32(ImVec4(hr, hg, hb, a));
        const ImU32 clear = IM_COL32(0, 0, 0, 0);
        const ImU32 black = Fade(IM_COL32_BLACK, a);
        dl->AddRectFilledMultiColor(sv_min, sv_max, white, hue, hue, white);
        dl->AddRectFilledMultiColor(sv_min, sv_max, clear, clear, black, black);
        dl->AddRect(sv_min, sv_max, Fade(IM_COL32(50, 50, 50, 100), a));

        const float seg = (hue_max.y - hue_min.y) / 6.0f;
        for (int i = 0; i < 6; ++i)
        {
            float r0, g0, b0, r1, g1, b1;
            ImGui::ColorConvertHSVtoRGB(i / 6.0f, 1.0f, 1.0f, r0, g0, b0);
            ImGui::ColorConvertHSVtoRGB((i + 1) / 6.0f, 1.0f, 1.0f, r1, g1, b1);
            const ImU32 c0 = ImGui::ColorConvertFloat4ToU32(ImVec4(r0, g0, b0, a));
            const ImU32 c1 = ImGui::ColorConvertFloat4ToU32(ImVec4(r1, g1, b1, a));
            dl->AddRectFilledMultiColor(ImVec2(hue_min.x, hue_min.y + seg * i), ImVec2(hue_max.x, hue_min.y + seg * (i + 1)), c0, c0, c1, c1);
        }
        dl->AddRect(hue_min, hue_max, Fade(IM_COL32(50, 50, 50, 100), a));

        const ImVec2 dot(ImLerp(sv_min.x, sv_max.x, s_hsv[1]), ImLerp(sv_min.y, sv_max.y, 1.0f - s_hsv[2]));
        dl->AddCircle(dot, S(3.5f), black, 12, S(2.0f));
        dl->AddCircle(dot, S(3.5f), white, 12, S(1.0f));
        const float hy = ImLerp(hue_min.y, hue_max.y, s_hsv[0]);
        dl->AddRectFilled(ImVec2(hue_min.x - S(1.0f), hy - S(1.0f)), ImVec2(hue_max.x + S(1.0f), hy + S(1.0f)), white);
    }
    else
    {
        const char* label = "dpi scale";
        const ImVec2 bar_min(x0, y + line_h);
        const ImVec2 bar_max(x1, bar_min.y + ImFloor(line_h - 2.0f));
        const bool hov = g_settings_open && ImGui::IsMouseHoveringRect(ImVec2(x0, bar_min.y - S(2.0f)), ImVec2(x1, bar_max.y + S(2.0f)), false);

        if (s_active != 1)
            s_dpi_edit = g_dpi;
        if (hov && clicked && s_active == 0)
            s_active = 1;
        if (s_active == 1)
            s_dpi_edit = 25.0f + ImSaturate((mouse.x - bar_min.x) / (bar_max.x - bar_min.x)) * 175.0f;

        const float target = (s_dpi_edit - 25.0f) / 175.0f * (bar_max.x - bar_min.x);
        s_fill = s_fill < 0.0f ? target : Approach(s_fill, target, 14.0f, dt);
        s_dpi_hover = Approach(s_dpi_hover, (hov || s_active == 1) ? 1.0f : 0.0f, 18.0f, dt);
        const ImU32 text = IM_COL32(255, 255, 255, (int)(255.0f * (0.5f + 0.5f * s_dpi_hover) * a));

        char value[16];
        snprintf(value, sizeof(value), "%.0f%%", s_dpi_edit);
        const ImVec2 vs = g_font_ui->CalcTextSizeA(g_font_ui->FontSize, FLT_MAX, 0.0f, value);
        dl->AddText(g_font_ui, g_font_ui->FontSize, ImVec2(x0, y - S(1.0f)), text, label);
        dl->AddText(g_font_ui, g_font_ui->FontSize, ImVec2(x1 - vs.x, y - S(1.0f)), text, value);

        dl->AddRectFilled(bar_min, bar_max, Fade(IM_COL32(25, 25, 25, 255), a), S(2.0f));
        dl->AddRect(bar_min, bar_max, Fade(IM_COL32(50, 50, 50, 100), a), S(2.0f));
        if (s_fill > 0.5f)
            dl->AddRectFilled(bar_min, ImVec2(bar_min.x + s_fill, bar_max.y), AccentCol(a), s_fill > 1.0f ? S(2.0f) : 0.0f);
    }

    const ImVec2 cog_min(ChromeButtonX(p.x + s.x, 2), p.y);
    const ImVec2 cog_max(cog_min.x + ChromeButtonW(), p.y + kBandH);
    const bool on_cog = ImGui::IsMouseHoveringRect(cog_min, cog_max, false);
    if ((clicked && !panel_hov && !on_cog && s_active == 0) || (g_settings_open && ImGui::IsKeyPressed(ImGuiKey_Escape)))
        g_settings_open = false;
}

static void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

static void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    if (SUCCEEDED(g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))))
    {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL levels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                               levels, 2, D3D11_SDK_VERSION, &sd,
                                               &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dContext);
    if (FAILED(res))
    {
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
                                           levels, 2, D3D11_SDK_VERSION, &sd,
                                           &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dContext);
    }
    if (FAILED(res) || !g_pd3dDevice || !g_pd3dContext || !g_pSwapChain)
        return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dContext) { g_pd3dContext->Release(); g_pd3dContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

// nonzero winding, 4x4 supersampled, white rgba
static void RasterizePolygon(const float* pts, int count, float view, int size, unsigned char* dst, int pitch)
{
    constexpr int kSub = 4;
    const float unit = view / (float)size;
    for (int y = 0; y < size; ++y)
    {
        for (int x = 0; x < size; ++x)
        {
            int hits = 0;
            for (int sy = 0; sy < kSub; ++sy)
            {
                const float py = ((float)y + ((float)sy + 0.5f) / kSub) * unit;
                for (int sx = 0; sx < kSub; ++sx)
                {
                    const float qx = ((float)x + ((float)sx + 0.5f) / kSub) * unit;
                    int winding = 0;
                    for (int i = 0, j = count - 1; i < count; j = i++)
                    {
                        const float ax = pts[j * 2], ay = pts[j * 2 + 1];
                        const float bx = pts[i * 2], by = pts[i * 2 + 1];
                        if ((ay <= py) != (by <= py))
                        {
                            const float cx = ax + (py - ay) * (bx - ax) / (by - ay);
                            if (cx > qx) winding += by > ay ? 1 : -1;
                        }
                    }
                    hits += winding != 0;
                }
            }
            unsigned char* p = dst + (size_t)y * pitch + (size_t)x * 4;
            p[0] = p[1] = p[2] = 255;
            p[3] = (unsigned char)(hits * 255 / (kSub * kSub));
        }
    }
}

static void BuildFonts(ImGuiIO& io)
{
    static const ImWchar cog_range[] = { 0xf013, 0xf013, 0 };

    io.Fonts->Clear();
    io.Fonts->FontBuilderIO = ImGuiFreeType::GetBuilderForFreeType();
    const float size = ImMax(1.0f, ImFloor(S(11.0f) + 0.5f));
    g_font_ui   = LoadFont(io, "verdana.ttf", size);
    g_font_bold = LoadFont(io, "verdanab.ttf", size);

    ImFontConfig icon_cfg;
    g_font_icon = io.Fonts->AddFontFromMemoryCompressedTTF(icon_font_compressed_data, (int)icon_font_compressed_size,
                                                           ImMax(1.0f, ImFloor(S(13.0f) + 0.5f)), &icon_cfg, cog_range);

    struct icon_src { const float* pts; int count; float size; };
    const icon_src icons[kIconCount] =
    {
        { github_icon_points, IM_ARRAYSIZE(github_icon_points) / 2, 16.0f },
        { kCloseIconPoints, IM_ARRAYSIZE(kCloseIconPoints) / 2, 24.0f },
        { kMinimizeIconPoints, IM_ARRAYSIZE(kMinimizeIconPoints) / 2, 24.0f },
    };

    int sizes[kIconCount] = {};
    for (int i = 0; i < kIconCount; ++i)
    {
        sizes[i] = (int)ImMax(4.0f, ImFloor(S(icons[i].size) + 0.5f));
        g_icon_rect[i] = io.Fonts->AddCustomRectRegular(sizes[i], sizes[i]);
    }
    io.Fonts->Build();

    unsigned char* px = nullptr;
    int tex_w = 0, tex_h = 0;
    io.Fonts->GetTexDataAsRGBA32(&px, &tex_w, &tex_h);
    for (int i = 0; i < kIconCount; ++i)
        if (const ImFontAtlasCustomRect* r = io.Fonts->GetCustomRectByIndex(g_icon_rect[i]); px && r && r->IsPacked())
            RasterizePolygon(icons[i].pts, icons[i].count, 24.0f, sizes[i], px + ((size_t)r->Y * tex_w + r->X) * 4, tex_w * 4);
}

static void ApplyWindowShape(HWND hwnd, bool resize)
{
    const int w = WindowW();
    const int h = WindowH();
    if (resize)
        ::SetWindowPos(hwnd, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    const int corner = (int)(kWindowRounding * 2.0f) + 1;
    ::SetWindowRgn(hwnd, ::CreateRoundRectRgn(0, 0, w + 1, h + 1, corner, corner), TRUE);
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_CLOSE:
        RequestClose();
        return 0;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    ::timeBeginPeriod(1);

    WNDCLASSEXW wc =
    {
        sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
        hInstance, ::LoadIconW(hInstance, MAKEINTRESOURCEW(1)), nullptr, nullptr, nullptr,
        L"botox", nullptr
    };
    ::RegisterClassExW(&wc);

    LoadSettings();
    UpdateMetrics();

    const int win_w = WindowW();
    const int win_h = WindowH();
    const int scr_w = GetSystemMetrics(SM_CXSCREEN);
    const int scr_h = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = ::CreateWindowExW(WS_EX_APPWINDOW | WS_EX_LAYERED, wc.lpszClassName, L"botox loader",
                                  WS_POPUP | WS_MINIMIZEBOX,
                                  (scr_w - win_w) / 2, (scr_h - win_h) / 2,
                                  win_w, win_h, nullptr, nullptr, wc.hInstance, nullptr);

    ::SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
    ApplyWindowShape(hwnd, false);

    for (int i = 0; i < kTargetCount; ++i)
        if (HANDLE t = ::CreateThread(nullptr, 0, ReleaseInfoThread, (LPVOID)(INT_PTR)i, 0, nullptr))
            CloseHandle(t);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    BuildFonts(io);

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.WindowBorderSize = 0.0f;
    style.WindowPadding = ImVec2(0.0f, 0.0f);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0, 0, 0, 0);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dContext);

    while (g_running)
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                g_running = false;
        }
        if (!g_running) break;

        if (::IsIconic(hwnd))
        {
            if (g_closing) break;
            ::Sleep(50);
            continue;
        }

        const float fade_step = ImClamp(io.DeltaTime, 0.0f, 1.0f / 30.0f) / kAnimDuration;
        g_fade = ImClamp(g_fade + (g_closing ? -fade_step : fade_step), 0.0f, 1.0f);
        if (g_closing && g_fade <= 0.0f)
            break;

        static BYTE s_alpha = 0;
        const BYTE alpha = (BYTE)(g_fade * 255.0f + 0.5f);
        if (alpha != s_alpha)
        {
            ::SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA);
            s_alpha = alpha;
        }

        if (g_scale_dirty)
        {
            g_scale_dirty = false;
            UpdateMetrics();
            BuildFonts(io);
            ImGui_ImplDX11_InvalidateDeviceObjects();
            ApplyWindowShape(hwnd, true);
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);

        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));

        ImGui::Begin("##main", nullptr,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                     ImGuiWindowFlags_NoScrollbar);

        ImGui::PopStyleColor(2);

        if (g_injecting)
            DrawStatusScreen(hwnd);
        else
            DrawGamePanel(hwnd);
        DrawSettings();

        ImGui::End();

        ImGui::Render();
        ImDrawData* draw_data = ImGui::GetDrawData();

        const float clear_color[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        g_pd3dContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(draw_data);

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    ::timeEndPeriod(1);
    return 0;
}
