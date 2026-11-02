#pragma once
#include <string>
#include <cstdio>

namespace release
{
    inline std::string json_str(const std::string& json, const char* key, size_t from, size_t limit)
    {
        const std::string pat = std::string("\"") + key + "\"";
        size_t p = json.find(pat, from);
        if (p == std::string::npos || p >= limit) return {};
        p += pat.size();
        while (p < json.size() && (json[p] == ' ' || json[p] == ':' || json[p] == '\t' || json[p] == '\r' || json[p] == '\n')) ++p;
        if (p >= json.size() || json[p] != '"') return {};
        const size_t e = json.find('"', p + 1);
        if (e == std::string::npos) return {};
        return json.substr(p + 1, e - p - 1);
    }

    struct asset_info
    {
        std::string sha256;
        std::string updated_at;
        std::string url;
    };

    inline bool find_asset(const std::string& json, const std::string& asset, asset_info& out)
    {
        const size_t assets = json.find("\"assets\"");
        if (assets == std::string::npos) return false;

        for (size_t p = assets; (p = json.find("\"name\"", p)) != std::string::npos; p += 6)
        {
            if (json_str(json, "name", p, p + 1) != asset) continue;

            size_t end = json.find("\"browser_download_url\"", p);
            if (end == std::string::npos) end = json.size();

            const std::string digest = json_str(json, "digest", p, end);
            out.sha256 = (digest.size() == 71 && digest.compare(0, 7, "sha256:") == 0) ? digest.substr(7) : std::string();
            out.updated_at = json_str(json, "updated_at", p, end);
            out.url = json_str(json, "browser_download_url", p, end + 1);
            return true;
        }
        return false;
    }

    inline std::string short_date(const std::string& iso)
    {
        static const char* months[] = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
        int y = 0, m = 0, d = 0;
        if (sscanf_s(iso.c_str(), "%d-%d-%d", &y, &m, &d) != 3 || m < 1 || m > 12 || d < 1 || d > 31) return {};
        char buf[32];
        snprintf(buf, sizeof(buf), "%d %s %d", d, months[m - 1], y);
        return buf;
    }
}
