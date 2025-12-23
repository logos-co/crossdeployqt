#include "binary_detect.h"

#include <cstdint>
#include <fstream>
#include <system_error>

namespace cdqt {

std::optional<BinaryType> detectBinaryType(const fs::path& p, std::string& whyNot) {
    std::error_code ec;
    const auto fileSize = fs::file_size(p, ec);
    if (ec) { whyNot = "cannot stat file"; return std::nullopt; }

    std::ifstream f(p, std::ios::binary);
    if (!f) { whyNot = "cannot open file"; return std::nullopt; }

    std::uint8_t buf[16] = {0};
    f.read(reinterpret_cast<char*>(buf), sizeof(buf));
    const std::streamsize n = f.gcount();
    if (n < 4) { whyNot = "file too small"; return std::nullopt; }

    auto u32le_at = [&](std::uint64_t off, std::uint32_t& out) -> bool {
        if (off + 4 > static_cast<std::uint64_t>(fileSize)) return false;
        std::uint8_t t[4];
        f.clear(); f.seekg(static_cast<std::streamoff>(off), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(t), 4)) return false;
        out = static_cast<std::uint32_t>(t[0]) |
              (static_cast<std::uint32_t>(t[1]) << 8) |
              (static_cast<std::uint32_t>(t[2]) << 16) |
              (static_cast<std::uint32_t>(t[3]) << 24);
        return true;
    };
    auto u32be_at = [&](std::uint64_t off, std::uint32_t& out) -> bool {
        if (off + 4 > static_cast<std::uint64_t>(fileSize)) return false;
        std::uint8_t t[4];
        f.clear(); f.seekg(static_cast<std::streamoff>(off), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(t), 4)) return false;
        out = (static_cast<std::uint32_t>(t[0]) << 24) |
              (static_cast<std::uint32_t>(t[1]) << 16) |
              (static_cast<std::uint32_t>(t[2]) << 8)  |
               static_cast<std::uint32_t>(t[3]);
        return true;
    };
    auto u32be_from0 = [&]() -> std::uint32_t {
        return (static_cast<std::uint32_t>(buf[0]) << 24) |
               (static_cast<std::uint32_t>(buf[1]) << 16) |
               (static_cast<std::uint32_t>(buf[2]) << 8)  |
                static_cast<std::uint32_t>(buf[3]);
    };

    // ELF: 0x7F 'E' 'L' 'F'
    if (buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
        return BinaryType::ELF;
    }

    // PE: 'MZ' then 'PE\0\0' at e_lfanew
    if (buf[0] == 'M' && buf[1] == 'Z') {
        std::uint32_t e_lfanew = 0;
        if (fileSize >= 0x40 && u32le_at(0x3C, e_lfanew)) {
            if (e_lfanew <= static_cast<std::uint64_t>(fileSize) - 4) {
                std::uint8_t sig[4] = {0};
                f.clear(); f.seekg(static_cast<std::streamoff>(e_lfanew), std::ios::beg);
                if (f.read(reinterpret_cast<char*>(sig), 4) && sig[0]=='P' && sig[1]=='E' && sig[2]==0 && sig[3]==0) {
                    return BinaryType::PE;
                }
            }
        }
        // Fall through; some non-PE files start with MZ.
    }

    // Mach-O: thin and fat (universal)
    constexpr std::uint32_t MH_MAGIC     = 0xFEEDFACE;
    constexpr std::uint32_t MH_CIGAM     = 0xCEFAEDFE;
    constexpr std::uint32_t MH_MAGIC_64  = 0xFEEDFACF;
    constexpr std::uint32_t MH_CIGAM_64  = 0xCFFAEDFE;

    constexpr std::uint32_t FAT_MAGIC    = 0xCAFEBABE;
    constexpr std::uint32_t FAT_CIGAM    = 0xBEBAFECA;
    constexpr std::uint32_t FAT_MAGIC_64 = 0xCAFEBABF;
    constexpr std::uint32_t FAT_CIGAM_64 = 0xBFBAFECA;

    const std::uint32_t be = u32be_from0();

    if (be == MH_MAGIC || be == MH_CIGAM || be == MH_MAGIC_64 || be == MH_CIGAM_64) {
        return BinaryType::MACHO;
    }

    if (be == FAT_MAGIC || be == FAT_MAGIC_64 || be == FAT_CIGAM || be == FAT_CIGAM_64) {
        std::uint32_t nfat_arch = 0;
        bool be_header = (be == FAT_MAGIC || be == FAT_MAGIC_64);
        bool ok = be_header ? u32be_at(4, nfat_arch) : u32le_at(4, nfat_arch);
        if (!ok) { whyNot = "truncated fat header"; return std::nullopt; }

        if (nfat_arch == 0 || nfat_arch > 64) {
            whyNot = "CAFEBABE but invalid nfat_arch (likely not Mach-O)";
            return std::nullopt;
        }

        const std::uint64_t minEntrySize = (be == FAT_MAGIC_64 || be == FAT_CIGAM_64) ? 32 : 20;
        const std::uint64_t need = 8 + static_cast<std::uint64_t>(nfat_arch) * minEntrySize;
        if (need > static_cast<std::uint64_t>(fileSize)) { whyNot = "fat header larger than file"; return std::nullopt; }

        return BinaryType::MACHO;
    }

    whyNot = "unknown binary format";
    return std::nullopt;
}

} // namespace cdqt


