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

#include "core/manualmap.h"
#include "core/sfpro_bold.hpp"

namespace
{
    constexpr DWORD kProcessAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    constexpr const char* kBotoxDllName = "botox.dll";
    constexpr const char* kBotoxUrl = "https://github.com/gumballpanties-sudo/botox/releases/latest/download/botox.dll";
    constexpr const char* kBotoxRepo = "gumballpanties-sudo/botox";
    constexpr const wchar_t* kGameExe = L"csgo.exe";
    constexpr const char* kGameAppId = "4465480";

    inline float Approach(float cur, float target, float speed, float dt)
    {
        return cur + (target - cur) * (1.0f - expf(-speed * dt));
    }

    inline float SmoothStep01(float t)
    {
        t = t < 0.0f ? 0.0f : (t > 1.0f ? 1.0f : t);
        return t * t * (3.0f - 2.0f * t);
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

    bool FetchLatestSha(const char* repo, const char* asset_name, char out_sha[65])
    {
        out_sha[0] = 0;
        if (!repo || !*repo || !asset_name || !*asset_name) return false;

        HINTERNET hInternet = InternetOpenA("botox-loader/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return false;

        char url[256];
        snprintf(url, sizeof(url), "https://api.github.com/repos/%s/releases/latest", repo);

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_SECURE |
                      INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, "Accept: application/vnd.github+json\r\n", -1, flags, 0);
        if (!hUrl)
        {
            InternetCloseHandle(hInternet);
            return false;
        }

        std::string json;
        char buf[4096];
        DWORD read = 0;
        while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0)
            json.append(buf, read);

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);

        size_t pos = json.find(asset_name);
        if (pos == std::string::npos) return false;

        size_t digest_pos = json.find("\"sha256:", pos);
        if (digest_pos == std::string::npos)
        {
            size_t asset_obj = json.rfind('{', pos);
            if (asset_obj != std::string::npos)
                digest_pos = json.find("\"sha256:", asset_obj);
        }

        if (digest_pos != std::string::npos)
        {
            digest_pos += 8;
            if (digest_pos + 64 <= json.size())
            {
                memcpy(out_sha, json.data() + digest_pos, 64);
                out_sha[64] = 0;
                return true;
            }
        }
        return false;
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

    bool GetBotoxBinDir(char* out, size_t cap)
    {
        char ap[MAX_PATH]{};
        if (!GetEnvironmentVariableA("APPDATA", ap, MAX_PATH)) return false;
        char base[MAX_PATH]{};
        snprintf(base, sizeof(base), "%s\\botox", ap);
        CreateDirectoryA(base, nullptr);
        snprintf(out, cap, "%s\\bin", base);
        CreateDirectoryA(out, nullptr);
        return true;
    }

    bool EnsureBotoxDll(char* out_path, size_t cap)
    {
        if (FileHasData(kBotoxDllName) && ValidPeFile(kBotoxDllName))
        {
            GetFullPathNameA(kBotoxDllName, (DWORD)cap, out_path, nullptr);
            return true;
        }

        char bin[MAX_PATH]{};
        if (!GetBotoxBinDir(bin, sizeof(bin))) return false;

        char cached[MAX_PATH * 2]{};
        snprintf(cached, sizeof(cached), "%s\\%s", bin, kBotoxDllName);

        char latest_sha[65] = {};
        const bool got_sha = FetchLatestSha(kBotoxRepo, kBotoxDllName, latest_sha);

        if (FileHasData(cached) && ValidPeFile(cached))
        {
            if (got_sha)
            {
                char local_sha[65] = {};
                if (Sha256File(cached, local_sha) && _stricmp(local_sha, latest_sha) == 0)
                {
                    lstrcpynA(out_path, cached, (DWORD)cap);
                    return true;
                }
            }
            else
            {
                lstrcpynA(out_path, cached, (DWORD)cap);
                return true;
            }
        }

        char part[MAX_PATH * 2 + 8]{};
        snprintf(part, sizeof(part), "%s.part", cached);
        DeleteFileA(part);

        if (DownloadToFile(kBotoxUrl, part) && FileHasData(part) && ValidPeFile(part))
        {
            if (got_sha)
            {
                char downloaded_sha[65] = {};
                if (Sha256File(part, downloaded_sha) && _stricmp(downloaded_sha, latest_sha) != 0)
                {
                    DeleteFileA(part);
                    return false;
                }
            }
            if (MoveFileExA(part, cached, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                lstrcpynA(out_path, cached, (DWORD)cap);
                return true;
            }
        }
        DeleteFileA(part);

        if (FileHasData(cached) && ValidPeFile(cached))
        {
            lstrcpynA(out_path, cached, (DWORD)cap);
            return true;
        }
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

    bool LegacyInstalled()
    {
        char steamPath[MAX_PATH] = { 0 };
        DWORD szSteam = sizeof(steamPath);
        HKEY hSteam = nullptr;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hSteam) != ERROR_SUCCESS)
            return false;

        bool found = false;
        if (RegQueryValueExA(hSteam, "SteamPath", nullptr, nullptr, (LPBYTE)steamPath, &szSteam) == ERROR_SUCCESS)
        {
            for (int i = 0; steamPath[i]; ++i)
                if (steamPath[i] == '/') steamPath[i] = '\\';

            char manifest[MAX_PATH * 2];
            snprintf(manifest, sizeof(manifest), "%s\\steamapps\\appmanifest_4465480.acf", steamPath);
            found = GetFileAttributesA(manifest) != INVALID_FILE_ATTRIBUTES;
        }
        RegCloseKey(hSteam);
        return found;
    }

    bool GetSteamInstallPath(char* out, size_t cap)
    {
        if (!out || cap == 0) return false;
        out[0] = 0;
        HKEY hSteam = nullptr;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hSteam) != ERROR_SUCCESS)
            return false;

        DWORD type = 0, size = (DWORD)cap;
        bool ok = RegQueryValueExA(hSteam, "SteamPath", nullptr, &type, (LPBYTE)out, &size) == ERROR_SUCCESS;
        RegCloseKey(hSteam);
        if (ok)
        {
            for (size_t i = 0; out[i]; ++i)
                if (out[i] == '/') out[i] = '\\';
        }
        return ok;
    }

    bool LaunchSteamApp(const char* appid, const char* extra_args = nullptr)
    {
        char steam_dir[MAX_PATH * 2]{};
        if (!GetSteamInstallPath(steam_dir, sizeof(steam_dir))) return false;

        char command[MAX_PATH * 3]{};
        snprintf(command, sizeof(command), "\"%s\\steam.exe\" -applaunch %s%s",
                 steam_dir, appid, (extra_args && *extra_args) ? extra_args : "");

        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, command, nullptr, nullptr, FALSE, 0, nullptr, steam_dir, &si, &pi))
            return false;

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    bool LaunchCsgo()
    {
        const char* appid = LegacyInstalled() ? "4465480" : "730";
        const char* extra_args = " -allow_third_party_software";
        if (LaunchSteamApp(appid, extra_args)) return true;

        char steamUrl[256]{};
        snprintf(steamUrl, sizeof(steamUrl), "steam://run/%s//-allow_third_party_software/", appid);
        HINSTANCE res = ShellExecuteA(nullptr, "open", steamUrl, nullptr, nullptr, SW_SHOWDEFAULT);
        if ((INT_PTR)res <= 32)
        {
            snprintf(steamUrl, sizeof(steamUrl), "steam://rungameid/%s", appid);
            res = ShellExecuteA(nullptr, "open", steamUrl, nullptr, nullptr, SW_SHOWDEFAULT);
        }
        return (INT_PTR)res > 32;
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

static void DrawGlassText(ImDrawList* dl, ImFont* font, float font_size, const ImVec2& pos, ImU32 col, const char* text, bool shadow = true, bool gloss = true)
{
    const int a = (col >> 24) & 0xFF;
    if (a <= 5) return;

    if (shadow)
    {
        const ImU32 sh_col = IM_COL32(0, 0, 0, (int)((float)a * 0.45f));
        dl->AddText(font, font_size, ImVec2(pos.x, pos.y + 1.0f), sh_col, text);
    }
    if (gloss)
    {
        const ImU32 gl_col = IM_COL32(255, 255, 255, (int)((float)a * 0.20f));
        dl->AddText(font, font_size, ImVec2(pos.x, pos.y - 0.5f), gl_col, text);
    }
    dl->AddText(font, font_size, pos, col, text);
}

static void DrawGlassText(ImDrawList* dl, const ImVec2& pos, ImU32 col, const char* text, bool shadow = true, bool gloss = true)
{
    DrawGlassText(dl, ImGui::GetFont(), ImGui::GetFontSize(), pos, col, text, shadow, gloss);
}

static void AddShimmerText(ImDrawList* dl, const ImVec2& pos, const char* text, float alpha = 1.0f)
{
    if (!text || !*text || alpha <= 0.001f) return;

    const float t = (float)ImGui::GetTime();
    float w = 0.5f + 0.5f * std::sin(t * 2.8f);
    w = w * w * (3.0f - 2.0f * w);
    const int a = (int)(240.0f * ImClamp(alpha, 0.0f, 1.0f));
    const ImU32 col = IM_COL32((int)(145.0f + 101.0f * w),
                               (int)(149.0f + 99.0f * w),
                               (int)(158.0f + 94.0f * w), a);
    dl->AddText(pos, col, text);
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
static float g_fade_alpha = 1.0f;
static float g_intro_t = 0.0f;

static bool g_injecting = false;
static volatile LONG g_inject_state = 0;
static char g_inject_err[256] = {};
static float g_inject_ok_at = 0.0f;

static DWORD WINAPI InjectionWorkerThread(LPVOID)
{
    char dll_path[MAX_PATH * 2] = {};
    if (!EnsureBotoxDll(dll_path, sizeof(dll_path)))
    {
        lstrcpynA(g_inject_err, "failed to download / verify botox.dll", sizeof(g_inject_err));
        InterlockedExchange(&g_inject_state, 3);
        return 0;
    }

    DWORD pid = FindProcessId(kGameExe);
    if (pid == 0)
    {
        LaunchCsgo();
        for (int i = 0; i < 900 && pid == 0; ++i)
        {
            Sleep(100);
            pid = FindProcessId(kGameExe);
        }
    }

    if (pid == 0)
    {
        lstrcpynA(g_inject_err, "csgo.exe process not found", sizeof(g_inject_err));
        InterlockedExchange(&g_inject_state, 3);
        return 0;
    }

    bool ready = false;
    for (int i = 0; i < 900; ++i)
    {
        DWORD cur_pid = FindProcessId(kGameExe);
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

    char map_err[256] = {};
    bool ok = ManualMapInject(pid, dll_path, map_err, sizeof(map_err));
    if (!ok)
    {
        char std_err[256] = {};
        if (StandardInject(pid, dll_path, std_err, sizeof(std_err)))
        {
            ok = true;
        }
        else
        {
            snprintf(g_inject_err, sizeof(g_inject_err), "map: %s | std: %s",
                     map_err[0] ? map_err : "failed",
                     std_err[0] ? std_err : "failed");
        }
    }

    if (ok)
    {
        InterlockedExchange(&g_inject_state, 2);
    }
    else
    {
        InterlockedExchange(&g_inject_state, 3);
    }

    return 0;
}

static void RequestClose()
{
    g_closing = true;
}

static void DrawStatusScreen(HWND hwnd)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 wpos = ImGui::GetWindowPos();
    const ImVec2 wsz = ImGui::GetWindowSize();

    HandleWindowDrag(hwnd, ImVec2(0.0f, 0.0f), wsz);

    dl->AddRectFilled(wpos, ImVec2(wpos.x + wsz.x, wpos.y + wsz.y), IM_COL32(0, 0, 0, 255), 0.0f);

    const LONG state = InterlockedCompareExchange(&g_inject_state, 0, 0);
    const char* text = "meowing...";
    const char* sub = nullptr;
    ImU32 sub_col = IM_COL32(190, 194, 201, 220);
    bool shimmer = true;

    if (state == 2)
    {
        text = "injected";
        sub = nullptr;
        shimmer = false;

        if (g_inject_ok_at == 0.0f)
            g_inject_ok_at = (float)ImGui::GetTime();

        if ((float)ImGui::GetTime() - g_inject_ok_at > 0.8f)
        {
            RequestClose();
        }
    }
    else if (state == 3)
    {
        text = "failed";
        sub = g_inject_err[0] ? g_inject_err : "unknown error";
        sub_col = IM_COL32(230, 110, 110, 240);
        shimmer = false;
    }

    const ImVec2 ms = ImGui::CalcTextSize(text);
    const float wrap_w = wsz.x - 30.0f;
    const bool has_sub = sub && *sub;

    ImVec2 ss{};
    if (has_sub) ss = ImGui::CalcTextSize(sub, nullptr, false, wrap_w);

    const float gap = has_sub ? 6.0f : 0.0f;
    const float total_h = ms.y + (has_sub ? gap + ss.y : 0.0f);
    const float top = wpos.y + (wsz.y - total_h) * 0.5f;

    const ImVec2 text_pos(wpos.x + (wsz.x - ms.x) * 0.5f, top);
    if (shimmer)
        AddShimmerText(dl, text_pos, text);
    else
        DrawGlassText(dl, text_pos, IM_COL32(245, 245, 245, 255), text, true, false);

    if (has_sub)
    {
        const ImVec2 spos(wpos.x + (wsz.x - ss.x) * 0.5f, top + ms.y + gap);
        dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), spos, sub_col, sub, nullptr, wrap_w);
    }

    if (state != 1)
    {
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) || ImGui::IsKeyPressed(ImGuiKey_Escape))
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
}

static void DrawGamePanel(HWND hwnd)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 wpos = ImGui::GetWindowPos();
    const ImVec2 wsz = ImGui::GetWindowSize();
    const float dt = ImGui::GetIO().DeltaTime;

    const float bar_h = 32.0f;
    const float pad = 10.0f;
    const float btn_h = 30.0f;
    const float content_l = wpos.x + pad;
    const float content_r = wpos.x + wsz.x - pad;
    const float content_w = content_r - content_l;

    const float card_y = wpos.y + bar_h + 8.0f;
    const float btn_y = wpos.y + wsz.y - pad - btn_h;
    const float card_b = btn_y - 8.0f;

    static float s_btn_hover = 0.0f;
    static float s_btn_press = 0.0f;
    static float s_close_hover = 0.0f;
    static float s_close_press = 0.0f;
    static float s_item_hover = 0.0f;

    dl->AddRectFilled(wpos, ImVec2(wpos.x + wsz.x, wpos.y + wsz.y), IM_COL32(0, 0, 0, 255), 0.0f);

    {
        const ImVec2 ts = ImGui::CalcTextSize("botox");
        DrawGlassText(dl, ImVec2(wpos.x + 14.0f, wpos.y + (bar_h - ts.y) * 0.5f),
                      IM_COL32(245, 245, 248, 255), "botox", true, false);

        const float close_sz = 16.0f;
        const ImVec2 close_pos(wpos.x + wsz.x - 12.0f - close_sz, wpos.y + (bar_h - close_sz) * 0.5f);
        const ImVec2 mouse = ImGui::GetMousePos();

        const bool hov_close = mouse.x >= close_pos.x && mouse.x < close_pos.x + close_sz &&
                               mouse.y >= close_pos.y && mouse.y < close_pos.y + close_sz;

        s_close_hover = Approach(s_close_hover, hov_close ? 1.0f : 0.0f, 22.0f, dt);
        const bool close_held = hov_close && ImGui::IsMouseDown(ImGuiMouseButton_Left);
        s_close_press = Approach(s_close_press, close_held ? 1.0f : 0.0f, 24.0f, dt);

        if (hov_close && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            RequestClose();

        const ImVec2 cc(close_pos.x + close_sz * 0.5f, close_pos.y + close_sz * 0.5f);
        const char* xglyph = "\xC3\x97";
        const float close_scale = 1.0f + 0.10f * s_close_press;
        const ImU32 xc = IM_COL32(255, 255, 255, (int)(180.0f + 75.0f * s_close_hover));
        const float xsize = 18.0f * close_scale;
        const ImVec2 xs = ImGui::GetFont()->CalcTextSizeA(xsize, 1000.0f, 0.0f, xglyph);
        dl->AddText(ImGui::GetFont(), xsize,
                    ImVec2(cc.x - xs.x * 0.5f + 0.5f, cc.y - xs.y * 0.5f - 0.5f),
                    xc, xglyph);

        HandleWindowDrag(hwnd, ImVec2(0.0f, 0.0f), ImVec2(close_pos.x - wpos.x, bar_h), !close_held);
    }

    {
        dl->AddRectFilled(ImVec2(content_l, card_y), ImVec2(content_r, card_b), IM_COL32(7, 7, 7, 255), 0.0f);
        dl->AddRect(ImVec2(content_l, card_y), ImVec2(content_r, card_b), IM_COL32(28, 28, 28, 255), 0.0f, 0, 1.0f);

        const float item_h = 28.0f;
        const ImRect item_rect(ImVec2(content_l + 4.0f, card_y + 4.0f),
                               ImVec2(content_r - 4.0f, card_y + 4.0f + item_h));

        const ImVec2 mouse = ImGui::GetMousePos();
        const bool hov = mouse.x >= item_rect.Min.x && mouse.x < item_rect.Max.x &&
                         mouse.y >= item_rect.Min.y && mouse.y < item_rect.Max.y;

        s_item_hover = Approach(s_item_hover, hov ? 1.0f : 0.0f, 22.0f, dt);

        dl->AddRectFilled(item_rect.Min, item_rect.Max, IM_COL32(20, 20, 20, 255), 0.0f);
        dl->AddRect(item_rect.Min, item_rect.Max, IM_COL32(42, 42, 42, 255), 0.0f, 0, 1.0f);

        const float ind_w = 2.5f;
        const float ind_h = 13.0f;
        const float ind_x0 = item_rect.Min.x + 4.0f;
        const float ind_y0 = item_rect.Min.y + (item_h - ind_h) * 0.5f;
        dl->AddRectFilled(ImVec2(ind_x0, ind_y0), ImVec2(ind_x0 + ind_w, ind_y0 + ind_h),
                          IM_COL32(255, 255, 255, 255), 0.0f);

        const float dot_x = item_rect.Max.x - 12.0f;
        const float dot_y = item_rect.Min.y + item_h * 0.5f;
        dl->AddCircleFilled(ImVec2(dot_x, dot_y), 4.5f, IM_COL32(255, 255, 255, 24));
        dl->AddCircleFilled(ImVec2(dot_x, dot_y), 2.2f, IM_COL32(255, 255, 255, 200));

        const ImVec2 label_pos(item_rect.Min.x + 14.0f, item_rect.Min.y + (item_h - ImGui::GetFontSize()) * 0.5f);
        DrawGlassText(dl, label_pos, IM_COL32(245, 245, 248, 255), "botox", true, false);
    }

    {
        const ImRect btn_rect(ImVec2(content_l, btn_y), ImVec2(content_r, btn_y + btn_h));
        const ImVec2 mouse = ImGui::GetMousePos();
        const bool hov = mouse.x >= btn_rect.Min.x && mouse.x < btn_rect.Max.x &&
                         mouse.y >= btn_rect.Min.y && mouse.y < btn_rect.Max.y;

        s_btn_hover = Approach(s_btn_hover, hov ? 1.0f : 0.0f, 22.0f, dt);
        const bool held = hov && ImGui::IsMouseDown(ImGuiMouseButton_Left);
        s_btn_press = Approach(s_btn_press, held ? 1.0f : 0.0f, 24.0f, dt);

        const int br = (int)(14.0f + 16.0f * s_btn_hover);
        const int bg = (int)(14.0f + 16.0f * s_btn_hover);
        const int bb = (int)(14.0f + 16.0f * s_btn_hover);
        dl->AddRectFilled(btn_rect.Min, btn_rect.Max, IM_COL32(br, bg, bb, 255), 0.0f);
        dl->AddRect(btn_rect.Min, btn_rect.Max,
                    IM_COL32(42 + (int)(30 * s_btn_hover), 42 + (int)(30 * s_btn_hover), 42 + (int)(30 * s_btn_hover), 255),
                    0.0f, 0, 1.0f);

        const char* btn_text = "inject";
        const float txt_scale = 1.0f + 0.02f * s_btn_press;
        const ImVec2 txt_base = ImGui::CalcTextSize(btn_text);
        const ImVec2 txt_sz(txt_base.x * txt_scale, txt_base.y * txt_scale);
        const ImU32 txt_col = IM_COL32(245, 245, 250, (int)(220.0f + 35.0f * s_btn_hover));

        DrawGlassText(dl, ImGui::GetFont(), ImGui::GetFontSize() * txt_scale,
                      ImVec2(btn_rect.Min.x + (content_w - txt_sz.x) * 0.5f,
                             btn_rect.Min.y + (btn_h - txt_sz.y) * 0.5f + s_btn_press * 1.0f),
                      txt_col, btn_text, true, false);

        if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !g_injecting && !g_closing)
        {
            g_injecting = true;
            g_inject_err[0] = 0;
            g_inject_ok_at = 0.0f;
            InterlockedExchange(&g_inject_state, 1);
            HANDLE thread = ::CreateThread(nullptr, 0, InjectionWorkerThread, nullptr, 0, nullptr);
            if (thread) CloseHandle(thread);
            else
            {
                lstrcpynA(g_inject_err, "failed to create injection thread", sizeof(g_inject_err));
                InterlockedExchange(&g_inject_state, 3);
            }
        }
    }
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
        hInstance, nullptr, nullptr, nullptr, nullptr,
        L"botox", nullptr
    };
    ::RegisterClassExW(&wc);

    constexpr int kWinW = 260;
    constexpr int kWinH = 160;
    const int scr_w = GetSystemMetrics(SM_CXSCREEN);
    const int scr_h = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = ::CreateWindowExW(0, wc.lpszClassName, L"botox",
                                  WS_POPUP,
                                  (scr_w - kWinW) / 2, (scr_h - kWinH) / 2,
                                  kWinW, kWinH, nullptr, nullptr, wc.hInstance, nullptr);

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

    ImFontConfig font_cfg;
    font_cfg.FontDataOwnedByAtlas = false;
    font_cfg.OversampleH = 4;
    font_cfg.OversampleV = 4;
    font_cfg.PixelSnapH = false;
    io.Fonts->AddFontFromMemoryTTF(
        const_cast<unsigned char*>(embedded_font),
        (int)embedded_font_size,
        15.5f,
        &font_cfg,
        io.Fonts->GetGlyphRangesCyrillic()
    );

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.WindowBorderSize = 0.0f;
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

        const float fade_dt = ImClamp(io.DeltaTime, 0.0f, 1.0f / 30.0f);
        if (g_closing)
        {
            g_fade_alpha = Approach(g_fade_alpha, 0.0f, 16.0f, fade_dt);
            if (g_fade_alpha <= 0.01f)
                break;
        }
        else if (g_intro_t < 1.0f)
        {
            g_intro_t += fade_dt / 0.4f;
            if (g_intro_t > 1.0f) g_intro_t = 1.0f;
            g_fade_alpha = SmoothStep01(g_intro_t);
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

        ImGui::End();

        ImGui::Render();
        ImDrawData* draw_data = ImGui::GetDrawData();

        if (g_fade_alpha < 0.999f && draw_data)
        {
            for (int n = 0; n < draw_data->CmdListsCount; ++n)
            {
                ImDrawList* cmd = draw_data->CmdLists[n];
                for (int i = 0; i < cmd->VtxBuffer.Size; ++i)
                {
                    ImDrawVert& v = cmd->VtxBuffer[i];
                    const ImU32 a = (v.col >> 24) & 0xFF;
                    const ImU32 na = (ImU32)((float)a * g_fade_alpha);
                    v.col = (v.col & 0x00FFFFFF) | (na << 24);
                }
            }
        }

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
