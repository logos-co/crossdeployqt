#include "pe_patch.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace cdqt {

bool patchQtCoreDllPrefixInfixPE(const fs::path& qtCorePath) {
    std::error_code ec;
    if (!fs::exists(qtCorePath, ec) || !fs::is_regular_file(qtCorePath, ec)) return false;

    std::ifstream ifs(qtCorePath, std::ios::binary);
    if (!ifs) return false;
    std::vector<std::uint8_t> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (buf.empty()) return false;

    auto patchAsciiKey = [&](const std::string& keyWithEq, const std::string& replacement) -> bool {
        bool changed = false;
        size_t pos = 0;
        while (true) {
            auto it = std::search(buf.begin() + static_cast<std::ptrdiff_t>(pos), buf.end(), keyWithEq.begin(), keyWithEq.end());
            if (it == buf.end()) break;
            pos = static_cast<size_t>(std::distance(buf.begin(), it));

            size_t valStart = pos + keyWithEq.size();
            size_t scan = valStart;
            while (scan < buf.size() && buf[scan] != 0) ++scan;
            if (scan <= valStart) { pos += keyWithEq.size(); continue; }

            const size_t valLen = scan - valStart;
            if (valLen >= replacement.size()) {
                bool needChange = false;
                for (size_t i = 0; i < replacement.size(); ++i) {
                    if (buf[valStart + i] != static_cast<std::uint8_t>(replacement[i])) { needChange = true; break; }
                }
                if (!needChange) {
                    for (size_t i = replacement.size(); i < valLen; ++i) {
                        if (buf[valStart + i] != 0) { needChange = true; break; }
                    }
                }
                if (needChange) {
                    for (size_t i = 0; i < replacement.size(); ++i) buf[valStart + i] = static_cast<std::uint8_t>(replacement[i]);
                    for (size_t i = replacement.size(); i < valLen; ++i) buf[valStart + i] = 0;
                    changed = true;
                }
            }
            pos = scan;
        }
        return changed;
    };

    auto toUtf16LeBytes = [](const std::u16string& s) {
        std::vector<std::uint8_t> out;
        out.reserve(s.size() * 2);
        for (char16_t ch : s) {
            out.push_back(static_cast<std::uint8_t>(ch & 0x00FF));
            out.push_back(static_cast<std::uint8_t>((ch >> 8) & 0x00FF));
        }
        return out;
    };

    auto patchUtf16Key = [&](const std::u16string& keyWithEq, const std::u16string& replacement) -> bool {
        bool changed = false;
        const auto keyBytes = toUtf16LeBytes(keyWithEq);
        const auto repBytes = toUtf16LeBytes(replacement);
        size_t pos = 0;
        while (true) {
            auto it = std::search(buf.begin() + static_cast<std::ptrdiff_t>(pos), buf.end(), keyBytes.begin(), keyBytes.end());
            if (it == buf.end()) break;
            pos = static_cast<size_t>(std::distance(buf.begin(), it));

            size_t valStart = pos + keyBytes.size();
            size_t scan = valStart;
            while (scan + 1 < buf.size() && !(buf[scan] == 0 && buf[scan + 1] == 0)) scan += 2;
            if (scan <= valStart) { pos += keyBytes.size(); continue; }

            const size_t valLen = scan - valStart;
            if (valLen >= repBytes.size()) {
                bool needChange = false;
                for (size_t i = 0; i < repBytes.size(); ++i) {
                    if (buf[valStart + i] != repBytes[i]) { needChange = true; break; }
                }
                if (!needChange) {
                    for (size_t i = repBytes.size(); i < valLen; ++i) {
                        if (buf[valStart + i] != 0) { needChange = true; break; }
                    }
                }
                if (needChange) {
                    for (size_t i = 0; i < repBytes.size(); ++i) buf[valStart + i] = repBytes[i];
                    for (size_t i = repBytes.size(); i < valLen; ++i) buf[valStart + i] = 0;
                    changed = true;
                }
            }
            pos = scan;
        }
        return changed;
    };

    bool any = false;
    any = patchAsciiKey("qt_prfxpath=", ".") || any;
    any = patchAsciiKey("qt_epfxpath=", ".") || any;
    any = patchAsciiKey("qt_hpfxpath=", ".") || any;
    any = patchUtf16Key(u"qt_prfxpath=", u".") || any;
    any = patchUtf16Key(u"qt_epfxpath=", u".") || any;
    any = patchUtf16Key(u"qt_hpfxpath=", u".") || any;

    if (!any) return false;
    std::ofstream ofs(qtCorePath, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    ofs.flush();
    return ofs.good();
}

} // namespace cdqt


